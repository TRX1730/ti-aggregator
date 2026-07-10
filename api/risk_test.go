package main

import (
	"encoding/json"
	"testing"
)

func TestComputeRiskTorExit(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"is_tor_exit": true})
	ens := []Enrichment{{Source: "tor", Data: data}}
	r := computeRisk(IOC{Type: "ip", Value: "1.2.3.4"}, ens)
	if r.Score < 40 {
		t.Fatalf("węzeł Tor powinien dać >=40 pkt, dostałem %d", r.Score)
	}
	if r.Level == "unknown" || r.Level == "low" {
		t.Fatalf("oczekiwano medium/high, dostałem %s", r.Level)
	}
}

func TestComputeRiskUnknown(t *testing.T) {
	r := computeRisk(IOC{Type: "ip", Value: "1.2.3.4"}, nil)
	if r.Level != "unknown" {
		t.Fatalf("brak danych → unknown, dostałem %s", r.Level)
	}
}

func TestComputeRiskSourceHint(t *testing.T) {
	r := computeRisk(IOC{Type: "ip", Value: "1.2.3.4", Source: "wordpress-scan"}, []Enrichment{})
	if r.Score < 20 {
		t.Fatalf("etykieta 'scan' powinna dodać punkty, dostałem %d", r.Score)
	}
}
