package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type watchItem struct {
	ID          int64      `json:"id"`
	Kind        string     `json:"kind"`
	RefID       int64      `json:"ref_id"`
	Label       string     `json:"label"`
	LastChecked *time.Time `json:"last_checked"`
	CreatedAt   time.Time  `json:"created_at"`
	AlertCount  int        `json:"alert_count"`
}

type alertItem struct {
	ID        int64     `json:"id"`
	Label     string    `json:"label"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *server) addWatch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind  string `json:"kind"`
		RefID int64  `json:"ref_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "niepoprawny JSON")
		return
	}
	if in.Kind != "ioc" && in.Kind != "target" {
		writeError(w, http.StatusBadRequest, "kind musi być 'ioc' albo 'target'")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var label string
	var err error
	if in.Kind == "ioc" {
		err = s.db.QueryRow(ctx, `SELECT value FROM iocs WHERE id=$1`, in.RefID).Scan(&label)
	} else {
		err = s.db.QueryRow(ctx, `SELECT domain FROM targets WHERE id=$1`, in.RefID).Scan(&label)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "nie znaleziono obiektu do śledzenia")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO watchlist (kind, ref_id, label) VALUES ($1, $2, $3)
		 ON CONFLICT (kind, ref_id) DO NOTHING`, in.Kind, in.RefID, label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nie udało się dodać do śledzenia")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok", "label": label})
}

func (s *server) listWatch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT w.id, w.kind, w.ref_id, w.label, w.last_checked, w.created_at,
		  (SELECT count(*) FROM alerts a WHERE a.watchlist_id = w.id)
		FROM watchlist w
		ORDER BY w.id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}
	defer rows.Close()

	list := []watchItem{}
	for rows.Next() {
		var it watchItem
		if err := rows.Scan(&it.ID, &it.Kind, &it.RefID, &it.Label, &it.LastChecked, &it.CreatedAt, &it.AlertCount); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu")
			return
		}
		list = append(list, it)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) deleteWatch(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	tag, err := s.db.Exec(ctx, `DELETE FROM watchlist WHERE id=$1`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nie udało się usunąć")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "nie znaleziono")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listAlerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT a.id, w.label, w.kind, a.severity, a.message, a.created_at
		FROM alerts a JOIN watchlist w ON w.id = a.watchlist_id
		ORDER BY a.id DESC
		LIMIT 100`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}
	defer rows.Close()

	list := []alertItem{}
	for rows.Next() {
		var it alertItem
		if err := rows.Scan(&it.ID, &it.Label, &it.Kind, &it.Severity, &it.Message, &it.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu")
			return
		}
		list = append(list, it)
	}
	writeJSON(w, http.StatusOK, list)
}
