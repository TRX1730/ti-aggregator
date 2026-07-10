package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func uuid5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New()
	h.Write(ns)
	h.Write([]byte(name))
	sum := h.Sum(nil)[:16]
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func escapeSTIX(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return v
}

func stixPattern(t, v string) string {
	e := escapeSTIX(v)
	switch t {
	case "ip":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", e)
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", e)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", e)
	case "hash":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", e)
	}
	return ""
}

func (s *server) exportSTIX(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	typeFilter := r.URL.Query().Get("type")
	rows, err := s.db.Query(ctx,
		`SELECT id, type, value, source, created_at FROM iocs
		 WHERE ($1 = '' OR type = $1) ORDER BY id`, typeFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "błąd bazy")
		return
	}
	defer rows.Close()

	objects := []map[string]any{}
	for rows.Next() {
		var it IOC
		if err := rows.Scan(&it.ID, &it.Type, &it.Value, &it.Source, &it.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "błąd odczytu")
			return
		}
		pattern := stixPattern(it.Type, it.Value)
		if pattern == "" {
			continue
		}
		ts := it.CreatedAt.UTC().Format(time.RFC3339)
		obj := map[string]any{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           "indicator--" + uuid5(fmt.Sprintf("ioc:%d", it.ID)),
			"created":      ts,
			"modified":     ts,
			"name":         it.Type + ": " + it.Value,
			"pattern":      pattern,
			"pattern_type": "stix",
			"valid_from":   ts,
		}
		if it.Source != "" {
			obj["labels"] = []string{it.Source}
		}
		objects = append(objects, obj)
	}

	bundle := map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + uuid5("bundle:"+time.Now().UTC().Format(time.RFC3339Nano)),
		"objects": objects,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="ti-aggregator-stix.json"`)
	json.NewEncoder(w).Encode(bundle)
}
