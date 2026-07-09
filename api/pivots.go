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

type pivotIP struct {
	IP  string `json:"ip"`
	CDN bool   `json:"cdn"` // czy to IP należące do CDN (wtedy powiązanie jest słabe)
}

type pivotNode struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	SharedIPs  []string  `json:"shared_ips"`
	Confidence string    `json:"confidence"` // "high" albo "low" (gdy wspólne są tylko IP z CDN)
}

type pivotResult struct {
	PivotIPs []pivotIP   `json:"pivot_ips"`
	Related  []pivotNode `json:"related"`
}

func (s *server) getPivots(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "id musi być liczbą")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

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

	focalIPs := s.ipsForIOC(ctx, id, iocType, iocValue)

	result := pivotResult{PivotIPs: []pivotIP{}, Related: []pivotNode{}}
	if len(focalIPs) == 0 {
		writeJSON(w, http.StatusOK, result)
		return
	}

	// Zbiór IP, o których wiemy, że należą do CDN — powiązania przez nie są słabe.
	cdnIPs := s.cdnIPSet(ctx)

	ipList := make([]string, 0, len(focalIPs))
	for ip := range focalIPs {
		_, isCDN := cdnIPs[ip]
		result.PivotIPs = append(result.PivotIPs, pivotIP{IP: ip, CDN: isCDN})
		ipList = append(ipList, ip)
	}

	// Powiązane IOC dzielące którekolwiek z tych IP.
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
		          SELECT 1 FROM jsonb_array_elements_text(e.data->'resolved_ips') AS ip
		          WHERE ip = ANY($2)
		        )
		    )
		  )
		ORDER BY i.id`, id, ipList)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd zapytania pivot")
		return
	}
	var related []pivotNode
	for rel.Next() {
		var n pivotNode
		if err := rel.Scan(&n.ID, &n.Type, &n.Value, &n.Source, &n.CreatedAt); err != nil {
			rel.Close()
			writeError(w, http.StatusInternalServerError, "błąd odczytu powiązania")
			return
		}
		related = append(related, n)
	}
	rel.Close()

	// Dla każdego powiązania policz wspólne IP i pewność.
	// Pewność "low", gdy WSZYSTKIE wspólne IP należą do CDN (bo na CDN siedzą miliony
	// niepowiązanych domen — taki "wspólny adres" nic nie znaczy).
	for i := range related {
		theirIPs := s.ipsForIOC(ctx, related[i].ID, related[i].Type, related[i].Value)
		shared := []string{}
		allCDN := true
		for ip := range theirIPs {
			if _, ok := focalIPs[ip]; ok {
				shared = append(shared, ip)
				if _, isCDN := cdnIPs[ip]; !isCDN {
					allCDN = false
				}
			}
		}
		related[i].SharedIPs = shared
		if len(shared) > 0 && allCDN {
			related[i].Confidence = "low"
		} else {
			related[i].Confidence = "high"
		}
		result.Related = append(result.Related, related[i])
	}

	writeJSON(w, http.StatusOK, result)
}

// ipsForIOC zbiera IP powiązane z IOC: jego własne (gdy to IP) + resolved_ips z dns/cdn.
func (s *server) ipsForIOC(ctx context.Context, id int64, iocType, iocValue string) map[string]struct{} {
	ipset := map[string]struct{}{}
	if iocType == "ip" {
		ipset[iocValue] = struct{}{}
	}
	rows, err := s.db.Query(ctx,
		`SELECT data->'resolved_ips' FROM enrichments
		 WHERE ioc_id=$1 AND source IN ('dns','cdn') AND data->'resolved_ips' IS NOT NULL`, id)
	if err != nil {
		return ipset
	}
	defer rows.Close()
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
	return ipset
}

// cdnIPSet zwraca zbiór IP oznaczonych jako CDN (z enrichmentów cdn z behind_cdn=true).
func (s *server) cdnIPSet(ctx context.Context) map[string]struct{} {
	set := map[string]struct{}{}
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT jsonb_array_elements_text(data->'resolved_ips')
		FROM enrichments
		WHERE source='cdn' AND data->>'behind_cdn'='true' AND data->'resolved_ips' IS NOT NULL`)
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			set[ip] = struct{}{}
		}
	}
	return set
}
