package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Target struct {
	ID            int64      `json:"id"`
	Domain        string     `json:"domain"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	LastScannedAt *time.Time `json:"last_scanned_at"`
	AssetCount    int        `json:"asset_count"`
	FindingCount  int        `json:"finding_count"`
}

type Asset struct {
	ID         int64     `json:"id"`
	Value      string    `json:"value"`
	ResolvedIP *string   `json:"resolved_ip"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type Finding struct {
	ID        int64     `json:"id"`
	Asset     string    `json:"asset"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
	Mitre     *mitre    `json:"mitre,omitempty"`
}

type targetDetail struct {
	Target
	Assets   []Asset   `json:"assets"`
	Findings []Finding `json:"findings"`
}

func normalizeDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	return d
}

func (s *server) createTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "niepoprawny JSON")
		return
	}
	domain := normalizeDomain(in.Domain)
	if !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /") {
		writeError(w, http.StatusBadRequest, "niepoprawna domena")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var t Target
	err := s.db.QueryRow(ctx,
		`INSERT INTO targets (domain) VALUES ($1)
		 RETURNING id, domain, status, created_at, last_scanned_at`,
		domain,
	).Scan(&t.ID, &t.Domain, &t.Status, &t.CreatedAt, &t.LastScannedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "taki cel już istnieje")
			return
		}
		writeError(w, http.StatusInternalServerError, "nie udało się dodać celu")
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *server) listTargets(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT t.id, t.domain, t.status, t.created_at, t.last_scanned_at,
		  (SELECT count(*) FROM assets a WHERE a.target_id = t.id),
		  (SELECT count(*) FROM findings f WHERE f.target_id = t.id)
		FROM targets t
		ORDER BY t.id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}
	defer rows.Close()

	list := []Target{}
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.Domain, &t.Status, &t.CreatedAt, &t.LastScannedAt, &t.AssetCount, &t.FindingCount); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu")
			return
		}
		list = append(list, t)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) getTarget(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var out targetDetail
	err = s.db.QueryRow(ctx,
		`SELECT id, domain, status, created_at, last_scanned_at FROM targets WHERE id=$1`, id).
		Scan(&out.ID, &out.Domain, &out.Status, &out.CreatedAt, &out.LastScannedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "nie znaleziono celu")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}

	out.Assets = []Asset{}
	aRows, err := s.db.Query(ctx,
		`SELECT id, value, resolved_ip, first_seen, last_seen
		 FROM assets WHERE target_id=$1 ORDER BY value`, id)
	if err == nil {
		for aRows.Next() {
			var a Asset
			if aRows.Scan(&a.ID, &a.Value, &a.ResolvedIP, &a.FirstSeen, &a.LastSeen) == nil {
				out.Assets = append(out.Assets, a)
			}
		}
		aRows.Close()
	}

	out.Findings = []Finding{}
	fRows, err := s.db.Query(ctx,
		`SELECT id, asset, severity, title, detail, created_at
		 FROM findings WHERE target_id=$1
		 ORDER BY CASE severity
		   WHEN 'critical' THEN 0 WHEN 'high' THEN 1
		   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id`, id)
	if err == nil {
		for fRows.Next() {
			var f Finding
			var detail *string
			if fRows.Scan(&f.ID, &f.Asset, &f.Severity, &f.Title, &detail, &f.CreatedAt) == nil {
				if detail != nil {
					f.Detail = *detail
				}
				f.Mitre = mitreForFinding(f.Title)
				out.Findings = append(out.Findings, f)
			}
		}
		fRows.Close()
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	tag, err := s.db.Exec(ctx, `DELETE FROM targets WHERE id=$1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nie udało się usunąć celu")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "nie znaleziono celu")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
