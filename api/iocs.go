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

// ── STRUKTURY (typy danych) ──────────────────────────────────────────────
// struct to zestaw pól pod jedną nazwą. IOC odpowiada wierszowi w tabeli iocs.
// Napisy `json:"..."` mówią, jak pole nazywa się w JSON-ie na wejściu/wyjściu.
type IOC struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// Enrichment to jedno wzbogacenie IOC (wynik pracy workera).
// Data to gotowy JSON z bazy — RawMessage przepuszcza go bez base64.
type Enrichment struct {
	ID        int64           `json:"id"`
	Source    string          `json:"source"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
}

// IOCWithEnrichments "zawiera w sobie" IOC (embedding) i dokłada listę wzbogaceń.
// W JSON-ie pola IOC są na wierzchu, plus tablica "enrichments".
type IOCWithEnrichments struct {
	IOC
	Enrichments []Enrichment `json:"enrichments"`
}

// createIOCInput to TYLKO to, co klient ma prawo podać przy tworzeniu.
// (id i created_at nadaje baza, więc ich tu nie ma.)
type createIOCInput struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// mapa "dozwolona wartość -> true". Szybkie sprawdzenie, czy type jest OK.
var allowedTypes = map[string]bool{"ip": true, "domain": true, "hash": true, "url": true}

// ── WALIDACJA ─────────────────────────────────────────────────────────────
// Funkcja zwraca error. W Go błąd to zwykła wartość: nil = brak błędu.
func validateInput(in createIOCInput) error {
	if !allowedTypes[in.Type] {
		return errors.New("type musi być jednym z: ip, domain, hash, url")
	}
	if in.Value == "" {
		return errors.New("value nie może być puste")
	}
	// Gdy typ to ip, sprawdzamy, że value to faktycznie adres IP.
	if in.Type == "ip" && net.ParseIP(in.Value) == nil {
		return errors.New("value nie jest poprawnym adresem IP")
	}
	return nil
}

// ── HANDLER: POST /iocs (WZORZEC) ─────────────────────────────────────────
func (s *server) createIOC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// 1) Czytamy JSON z ciała żądania do zmiennej "in".
	var in createIOCInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "niepoprawny JSON")
		return
	}

	// 2) Walidujemy dane.
	if err := validateInput(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 3) Zapis do bazy. $1,$2,$3 to bezpieczne placeholdery (ochrona przed SQL injection).
	var out IOC
	err := s.db.QueryRow(ctx,
		`INSERT INTO iocs (type, value, source)
		 VALUES ($1, $2, $3)
		 RETURNING id, type, value, source, created_at`,
		in.Type, in.Value, in.Source,
	).Scan(&out.ID, &out.Type, &out.Value, &out.Source, &out.CreatedAt)
if err != nil {
		// Zaglądamy w błąd: czy to naruszenie unikalności (duplikat)?
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "taki IOC już istnieje")
			return
		}
		// Inny, nieznany błąd bazy → 500.
		writeError(w, http.StatusInternalServerError, "nie udało się zapisać IOC")
		return
	}
	// 4) Sukces: odsyłamy utworzony obiekt z kodem 201 Created.
	writeJSON(w, http.StatusCreated, out)
}

// ── HANDLER: GET /iocs/{id} ───────────────────────────────────────────────
func (s *server) getIOC(w http.ResponseWriter, r *http.Request) {
	// 1) Wyciągamy "id" ze ścieżki i zamieniamy tekst na liczbę.
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}

	// 2) Kontekst z limitem czasu na zapytanie.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// 3) Pobieramy jeden wiersz po id.
	var out IOC
	err = s.db.QueryRow(ctx,
		`SELECT id, type, value, source, created_at FROM iocs WHERE id=$1`,
		id,
	).Scan(&out.ID, &out.Type, &out.Value, &out.Source, &out.CreatedAt)

	// 4) Obsługa wyniku zapytania.
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "nie znaleziono IOC o tym id")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd zapytania do bazy")
		return
	}

	// 5) Dobieramy wzbogacenia tego IOC (może być zero — wtedy pusta lista).
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
		var raw []byte // jsonb wczytujemy do []byte...
		if err := eRows.Scan(&e.ID, &e.Source, &raw, &e.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu wzbogacenia")
			return
		}
		e.Data = raw // ...a potem oddajemy jako surowy JSON (RawMessage)
		enrichments = append(enrichments, e)
	}
	if err := eRows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "błąd podczas iteracji wzbogaceń")
		return
	}

	// 6) Sukces: IOC razem z jego wzbogaceniami.
	writeJSON(w, http.StatusOK, IOCWithEnrichments{IOC: out, Enrichments: enrichments})
}

// ── HANDLER: GET /iocs (lista z opcjonalnym filtrem ?type=) ───────────────
func (s *server) listIOCs(w http.ResponseWriter, r *http.Request) {
	// Filtr z query stringa, np. /iocs?type=ip  (pusty = wszystkie).
	typeFilter := r.URL.Query().Get("type")
	if typeFilter != "" && !allowedTypes[typeFilter] {
		writeError(w, http.StatusBadRequest, "type musi być jednym z: ip, domain, hash, url")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Query zwraca WIELE wierszy. Sztuczka: puste $1 przepuszcza wszystkie.
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
	defer rows.Close() // ZAWSZE zamknij kursor po zakończeniu

	// Zbieramy wiersze do listy.
	list := []IOC{}
	for rows.Next() {
		var it IOC
		if err := rows.Scan(&it.ID, &it.Type, &it.Value, &it.Source, &it.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu wiersza")
			return
		}
		list = append(list, it)
	}
	// Po pętli sprawdzamy, czy iteracja się nie wywaliła.
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "błąd podczas iteracji")
		return
	}

	writeJSON(w, http.StatusOK, list)
}