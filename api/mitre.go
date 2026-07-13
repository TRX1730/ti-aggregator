package main

import "strings"

type mitre struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

var mitreBySource = map[string]mitre{
	"crt":         {"T1596.003", "Search Open Technical Databases: Digital Certificates", "Reconnaissance"},
	"dns":         {"T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance"},
	"dns_records": {"T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance"},
	"whois":       {"T1596.002", "Search Open Technical Databases: WHOIS", "Reconnaissance"},
	"tech":        {"T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"},
	"cdn":         {"T1590", "Gather Victim Network Information", "Reconnaissance"},
	"geoip":       {"T1590.005", "Gather Victim Network Information: IP Addresses", "Reconnaissance"},
	"wayback":     {"T1594", "Search Victim-Owned Websites", "Reconnaissance"},
	"shodan":      {"T1596.005", "Search Open Technical Databases: Scan Databases", "Reconnaissance"},
	"tor":         {"T1090.003", "Proxy: Multi-hop Proxy (Tor)", "Command and Control"},
}

func mitreForSource(source string) *mitre {
	if m, ok := mitreBySource[source]; ok {
		return &m
	}
	return nil
}

type mitreRule struct {
	needle string
	m      mitre
}

var mitreFindingRules = []mitreRule{
	{"zone transfer", mitre{"T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance"}},
	{"subdomain takeover", mitre{"T1584.001", "Compromise Infrastructure: Domains", "Resource Development"}},
	{".env", mitre{"T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"}},
	{".git", mitre{"T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"}},
	{"sekret w js", mitre{"T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"}},
	{"backup", mitre{"T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"}},
	{"panel", mitre{"T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"}},
	{"directory listing", mitre{"T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"}},
	{"dokumentacja api", mitre{"T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"}},
	{"robots", mitre{"T1594", "Search Victim-Owned Websites", "Reconnaissance"}},
	{"nagłówk", mitre{"T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance"}},
	{"wewnętrzne ip", mitre{"T1590.005", "Gather Victim Network Information: IP Addresses", "Reconnaissance"}},
	{"server ujawnia", mitre{"T1592.002", "Gather Victim Host Information: Software", "Reconnaissance"}},
}

func mitreForFinding(title string) *mitre {
	t := strings.ToLower(title)
	for _, r := range mitreFindingRules {
		if strings.Contains(t, r.needle) {
			m := r.m
			return &m
		}
	}
	return nil
}
