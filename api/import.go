package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var domainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)

// Końcówki, które wyglądają jak domena, ale to pliki/ścieżki z logów — pomijamy.
var fileExts = map[string]bool{
	"html": true, "htm": true, "php": true, "css": true, "js": true, "json": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "txt": true,
	"xml": true, "ico": true, "woff": true, "woff2": true, "map": true,
	"asp": true, "aspx": true, "jsp": true,
}

type importResult struct {
	FoundIPs     int `json:"found_ips"`
	FoundDomains int `json:"found_domains"`
	Created      int `json:"created"`
	Skipped      int `json:"skipped"`
}

// importLogs: przyjmuje surowy tekst (log), wyciąga IP i domeny, tworzy IOC hurtowo.
func (s *server) importLogs(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20)) // limit 2 MB
	if err != nil {
		writeError(w, http.StatusBadRequest, "nie mogę odczytać treści")
		return
	}
	text := string(raw)
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "import"
	}

	// Wyciągamy unikalne IP (z walidacją).
	ipset := map[string]struct{}{}
	for _, m := range ipRe.FindAllString(text, -1) {
		if net.ParseIP(m) != nil {
			ipset[m] = struct{}{}
		}
	}
	// Wyciągamy unikalne domeny (pomijając to, co jest IP lub plikiem).
	domset := map[string]struct{}{}
	for _, m := range domainRe.FindAllString(text, -1) {
		d := strings.ToLower(m)
		if ipRe.MatchString(d) {
			continue
		}
		parts := strings.Split(d, ".")
		if fileExts[parts[len(parts)-1]] {
			continue
		}
		domset[d] = struct{}{}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	res := importResult{FoundIPs: len(ipset), FoundDomains: len(domset)}
	insert := func(t, v string) {
		tag, err := s.db.Exec(ctx,
			`INSERT INTO iocs (type, value, source) VALUES ($1, $2, $3)
			 ON CONFLICT (type, value) DO NOTHING`, t, v, source)
		if err != nil {
			return
		}
		if tag.RowsAffected() == 1 {
			res.Created++
		} else {
			res.Skipped++
		}
	}
	for ip := range ipset {
		insert("ip", ip)
	}
	for d := range domset {
		insert("domain", d)
	}

	writeJSON(w, http.StatusOK, res)
}
