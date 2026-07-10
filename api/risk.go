package main

import (
	"encoding/json"
	"strings"
	"time"
)

// riskResult — ocena ryzyka IOC złożona z przejrzystych, wyjaśnionych sygnałów.
type riskResult struct {
	Score   int      `json:"score"`   // 0–100
	Level   string   `json:"level"`   // low / medium / high / unknown
	Reasons []string `json:"reasons"` // co złożyło się na wynik
}

// Słowa w etykiecie źródła, które sugerują złośliwość.
var maliciousHints = []string{"scan", "malware", "phish", "attack", "c2", "botnet", "brute", "exploit", "spam"}

// computeRisk buduje ocenę z dostępnych wzbogaceń. Wszystko jest jawne i uzasadnione.
func computeRisk(ioc IOC, ens []Enrichment) riskResult {
	score := 0
	reasons := []string{}

	for _, e := range ens {
		switch e.Source {
		case "tor":
			var d struct {
				IsTorExit bool `json:"is_tor_exit"`
			}
			if json.Unmarshal(e.Data, &d) == nil && d.IsTorExit {
				score += 40
				reasons = append(reasons, "IP to węzeł wyjściowy Tora (+40)")
			}
		case "whois":
			if days, ok := registrationAgeDays(e.Data); ok && days >= 0 && days < 90 {
				score += 30
				reasons = append(reasons, "zarejestrowany < 90 dni temu (+30)")
			}
		}
	}

	low := strings.ToLower(ioc.Source)
	for _, hint := range maliciousHints {
		if strings.Contains(low, hint) {
			score += 20
			reasons = append(reasons, "etykieta źródła sugeruje złośliwość (+20)")
			break
		}
	}

	if score > 100 {
		score = 100
	}

	level := "low"
	switch {
	case len(ens) == 0 && score == 0:
		level = "unknown"
	case score >= 60:
		level = "high"
	case score >= 30:
		level = "medium"
	}
	return riskResult{Score: score, Level: level, Reasons: reasons}
}

// registrationAgeDays wyciąga z RDAP datę rejestracji i zwraca wiek w dniach.
func registrationAgeDays(raw json.RawMessage) (int, bool) {
	var d struct {
		Raw struct {
			Events []struct {
				EventAction string `json:"eventAction"`
				EventDate   string `json:"eventDate"`
			} `json:"events"`
		} `json:"raw"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return 0, false
	}
	for _, ev := range d.Raw.Events {
		if strings.Contains(strings.ToLower(ev.EventAction), "registration") {
			t, err := time.Parse(time.RFC3339, ev.EventDate)
			if err != nil {
				return 0, false
			}
			return int(time.Since(t).Hours() / 24), true
		}
	}
	return 0, false
}
