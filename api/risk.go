package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type riskResult struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

var maliciousHints = []string{"scan", "malware", "phish", "attack", "c2", "botnet", "brute", "exploit", "spam"}

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
		case "blocklist":
			var d struct {
				OnBlocklist bool     `json:"on_blocklist"`
				Sources     []string `json:"sources"`
			}
			if json.Unmarshal(e.Data, &d) == nil && d.OnBlocklist {
				score += 50
				reasons = append(reasons, "na publicznej blackliście CTI (+50)")
			}
		case "virustotal":
			var d struct {
				Malicious int `json:"malicious"`
			}
			if json.Unmarshal(e.Data, &d) == nil && d.Malicious > 0 {
				add := d.Malicious * 10
				if add > 50 {
					add = 50
				}
				score += add
				reasons = append(reasons, fmt.Sprintf("VirusTotal: %d silników flaguje jako złośliwe (+%d)", d.Malicious, add))
			}
		case "shodan":
			var d struct {
				Vulns []string `json:"vulns"`
			}
			if json.Unmarshal(e.Data, &d) == nil && len(d.Vulns) > 0 {
				add := len(d.Vulns) * 10
				if add > 30 {
					add = 30
				}
				score += add
				reasons = append(reasons, fmt.Sprintf("Shodan: %d znanych CVE (+%d)", len(d.Vulns), add))
			}
		case "threatfox":
			var d struct {
				OnThreatfox bool   `json:"on_threatfox"`
				Malware     string `json:"malware"`
			}
			if json.Unmarshal(e.Data, &d) == nil && d.OnThreatfox {
				score += 50
				reasons = append(reasons, "na feedzie ThreatFox (malware IOC) (+50)")
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
