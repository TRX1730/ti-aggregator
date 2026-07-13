package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type IOC struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

type Enrichment struct {
	ID        int64           `json:"id"`
	Source    string          `json:"source"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
	Mitre     *mitre          `json:"mitre,omitempty"`
}

type IOCWithEnrichments struct {
	IOC
	Enrichments []Enrichment `json:"enrichments"`
	Risk        riskResult   `json:"risk"`
}

type createIOCInput struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

var allowedTypes = map[string]bool{"ip": true, "domain": true, "hash": true, "url": true}

func validateInput(in createIOCInput) error {
	if !allowedTypes[in.Type] {
		return errors.New("type musi być jednym z: ip, domain, hash, url")
	}
	if in.Value == "" {
		return errors.New("value nie może być puste")
	}
	if in.Type == "ip" && net.ParseIP(in.Value) == nil {
		return errors.New("value nie jest poprawnym adresem IP")
	}
	return nil
}

func (s *server) createIOC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var in createIOCInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "niepoprawny JSON")
		return
	}

	if err := validateInput(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var out IOC
	err := s.db.QueryRow(ctx,
		`INSERT INTO iocs (type, value, source)
		 VALUES ($1, $2, $3)
		 RETURNING id, type, value, source, created_at`,
		in.Type, in.Value, in.Source,
	).Scan(&out.ID, &out.Type, &out.Value, &out.Source, &out.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "taki IOC już istnieje")
			return
		}
		writeError(w, http.StatusInternalServerError, "nie udało się zapisać IOC")
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *server) getIOC(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var out IOC
	err = s.db.QueryRow(ctx,
		`SELECT id, type, value, source, created_at FROM iocs WHERE id=$1`,
		id,
	).Scan(&out.ID, &out.Type, &out.Value, &out.Source, &out.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "nie znaleziono IOC o tym id")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd zapytania do bazy")
		return
	}

	eRows, err := s.db.Query(ctx,
		`SELECT id, source, data, created_at
		 FROM enrichments
		 WHERE ioc_id = $1
		 ORDER BY id`,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd pobierania wzbogaceń")
		return
	}
	defer eRows.Close()

	enrichments := []Enrichment{}
	for eRows.Next() {
		var e Enrichment
		var raw []byte
		if err := eRows.Scan(&e.ID, &e.Source, &raw, &e.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu wzbogacenia")
			return
		}
		e.Data = raw
		e.Mitre = mitreForSource(e.Source)
		enrichments = append(enrichments, e)
	}
	if err := eRows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "błąd podczas iteracji wzbogaceń")
		return
	}

	resp := IOCWithEnrichments{IOC: out, Enrichments: enrichments}
	resp.Risk = computeRisk(out, enrichments)
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) listIOCs(w http.ResponseWriter, r *http.Request) {
	typeFilter := r.URL.Query().Get("type")
	if typeFilter != "" && !allowedTypes[typeFilter] {
		writeError(w, http.StatusBadRequest, "type musi być jednym z: ip, domain, hash, url")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx,
		`SELECT id, type, value, source, created_at
		 FROM iocs
		 WHERE ($1 = '' OR type = $1)
		 ORDER BY id`,
		typeFilter,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd zapytania do bazy")
		return
	}
	defer rows.Close()

	list := []IOC{}
	for rows.Next() {
		var it IOC
		if err := rows.Scan(&it.ID, &it.Type, &it.Value, &it.Source, &it.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu wiersza")
			return
		}
		list = append(list, it)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "błąd podczas iteracji")
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *server) deleteIOC(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	tag, err := s.db.Exec(ctx, `DELETE FROM iocs WHERE id=$1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nie udało się usunąć IOC")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "nie znaleziono IOC")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
