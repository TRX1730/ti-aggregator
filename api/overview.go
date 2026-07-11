package main

import (
	"context"
	"net/http"
	"time"
)

type overviewFinding struct {
	Target   string `json:"target"`
	Asset    string `json:"asset"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

type overviewIOC struct {
	ID    int64  `json:"id"`
	Value string `json:"value"`
}

type overviewResult struct {
	Counts struct {
		IOCs     int            `json:"iocs"`
		IP       int            `json:"ip"`
		Domain   int            `json:"domain"`
		Targets  int            `json:"targets"`
		Assets   int            `json:"assets"`
		Findings map[string]int `json:"findings"`
	} `json:"counts"`
	TopFindings []overviewFinding `json:"top_findings"`
	TorIOCs     []overviewIOC     `json:"tor_iocs"`
}

func (s *server) getOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var out overviewResult
	out.Counts.Findings = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	out.TopFindings = []overviewFinding{}
	out.TorIOCs = []overviewIOC{}

	s.db.QueryRow(ctx, `SELECT count(*) FROM iocs`).Scan(&out.Counts.IOCs)
	s.db.QueryRow(ctx, `SELECT count(*) FROM iocs WHERE type='ip'`).Scan(&out.Counts.IP)
	s.db.QueryRow(ctx, `SELECT count(*) FROM iocs WHERE type='domain'`).Scan(&out.Counts.Domain)
	s.db.QueryRow(ctx, `SELECT count(*) FROM targets`).Scan(&out.Counts.Targets)
	s.db.QueryRow(ctx, `SELECT count(*) FROM assets`).Scan(&out.Counts.Assets)

	if frows, err := s.db.Query(ctx, `SELECT severity, count(*) FROM findings GROUP BY severity`); err == nil {
		for frows.Next() {
			var sev string
			var c int
			if frows.Scan(&sev, &c) == nil {
				out.Counts.Findings[sev] = c
			}
		}
		frows.Close()
	}

	if trows, err := s.db.Query(ctx, `
		SELECT t.domain, f.asset, f.severity, f.title, coalesce(f.detail,'')
		FROM findings f JOIN targets t ON t.id = f.target_id
		WHERE f.severity IN ('critical','high')
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END, f.id
		LIMIT 25`); err == nil {
		for trows.Next() {
			var f overviewFinding
			if trows.Scan(&f.Target, &f.Asset, &f.Severity, &f.Title, &f.Detail) == nil {
				out.TopFindings = append(out.TopFindings, f)
			}
		}
		trows.Close()
	}

	if irows, err := s.db.Query(ctx, `
		SELECT i.id, i.value
		FROM iocs i JOIN enrichments e ON e.ioc_id = i.id
		WHERE e.source = 'tor' AND e.data->>'is_tor_exit' = 'true'
		ORDER BY i.id LIMIT 25`); err == nil {
		for irows.Next() {
			var it overviewIOC
			if irows.Scan(&it.ID, &it.Value) == nil {
				out.TorIOCs = append(out.TorIOCs, it)
			}
		}
		irows.Close()
	}

	writeJSON(w, http.StatusOK, out)
}
