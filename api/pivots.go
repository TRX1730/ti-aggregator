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

// pivotResult = zestaw IP, przez które pivotujemy, + powiązane wskaźniki.
type pivotResult struct {
	PivotIPs []string `json:"pivot_ips"`
	Related  []IOC    `json:"related"`
}

// getPivots: znajduje inne IOC dzielące IP z danym wskaźnikiem.
func (s *server) getPivots(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 1) Pobierz typ i wartość IOC.
	var iocType, iocValue string
	err = s.db.QueryRow(ctx, `SELECT type, value FROM iocs WHERE id=$1`, id).
		Scan(&iocType, &iocValue)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "nie znaleziono IOC")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}

	// 2) Zbierz IP powiązane z tym IOC.
	ipset := map[string]struct{}{}
	if iocType == "ip" {
		ipset[iocValue] = struct{}{}
	}
	// ...oraz resolved_ips z enrichmentów dns/cdn (kolumna JSONB).
	rows, err := s.db.Query(ctx,
		`SELECT data->'resolved_ips' FROM enrichments
		 WHERE ioc_id=$1 AND source IN ('dns','cdn')
		   AND data->'resolved_ips' IS NOT NULL`, id)
	if err == nil {
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) == nil {
				var ips []string
				if json.Unmarshal(raw, &ips) == nil {
					for _, ip := range ips {
						ipset[ip] = struct{}{}
					}
				}
			}
		}
		rows.Close()
	}

	ips := make([]string, 0, len(ipset))
	for ip := range ipset {
		ips = append(ips, ip)
	}

	result := pivotResult{PivotIPs: ips, Related: []IOC{}}
	if len(ips) == 0 {
		writeJSON(w, http.StatusOK, result)
		return
	}

	// 3) Znajdź inne IOC dzielące którekolwiek z tych IP:
	//    - albo są IP z tej listy,
	//    - albo mają enrichment z resolved_ips zawierającym któreś z tych IP.
	//    jsonb_array_elements_text rozwija tablicę JSON na wiersze tekstowe.
	rel, err := s.db.Query(ctx, `
		SELECT DISTINCT i.id, i.type, i.value, i.source, i.created_at
		FROM iocs i
		WHERE i.id <> $1
		  AND (
		    (i.type = 'ip' AND i.value = ANY($2))
		    OR EXISTS (
		      SELECT 1 FROM enrichments e
		      WHERE e.ioc_id = i.id AND e.source IN ('dns','cdn')
		        AND EXISTS (
		          SELECT 1
		          FROM jsonb_array_elements_text(e.data->'resolved_ips') AS ip
		          WHERE ip = ANY($2)
		        )
		    )
		  )
		ORDER BY i.id`, id, ips)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd zapytania pivot")
		return
	}
	defer rel.Close()

	for rel.Next() {
		var it IOC
		if err := rel.Scan(&it.ID, &it.Type, &it.Value, &it.Source, &it.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu powiązania")
			return
		}
		result.Related = append(result.Related, it)
	}
	if err := rel.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "błąd iteracji powiązań")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
