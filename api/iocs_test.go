package main

import "testing"

func TestValidateInput(t *testing.T) {
	valid := []createIOCInput{
		{Type: "ip", Value: "1.2.3.4"},
		{Type: "domain", Value: "example.com"},
		{Type: "hash", Value: "abc123"},
		{Type: "url", Value: "http://example.com"},
	}
	for _, in := range valid {
		if err := validateInput(in); err != nil {
			t.Errorf("oczekiwano OK dla %+v, dostałem błąd: %v", in, err)
		}
	}

	invalid := []createIOCInput{
		{Type: "cokolwiek", Value: "1.2.3.4"},
		{Type: "ip", Value: "to-nie-ip"},
		{Type: "domain", Value: ""},
	}
	for _, in := range invalid {
		if err := validateInput(in); err == nil {
			t.Errorf("oczekiwano błędu dla %+v", in)
		}
	}
}
