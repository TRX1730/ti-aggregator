package main

import "testing"

func TestEscapeSTIX(t *testing.T) {
	if got := escapeSTIX("a'b"); got != `a\'b` {
		t.Errorf("apostrof: got %q", got)
	}
	if got := escapeSTIX(`a\b`); got != `a\\b` {
		t.Errorf("backslash: got %q", got)
	}
}

func TestStixPattern(t *testing.T) {
	cases := []struct{ typ, val, want string }{
		{"ip", "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"},
		{"domain", "example.com", "[domain-name:value = 'example.com']"},
		{"url", "http://x", "[url:value = 'http://x']"},
	}
	for _, c := range cases {
		if got := stixPattern(c.typ, c.val); got != c.want {
			t.Errorf("%s: got %q want %q", c.typ, got, c.want)
		}
	}
	if stixPattern("nieznany", "x") != "" {
		t.Error("nieznany typ powinien dać pusty pattern")
	}
}

func TestUUID5Deterministic(t *testing.T) {
	a := uuid5("ioc:1")
	if a != uuid5("ioc:1") {
		t.Fatal("uuid5 nie jest deterministyczny dla tego samego wejścia")
	}
	if uuid5("ioc:2") == a {
		t.Fatal("różne wejścia dały ten sam uuid")
	}
	if len(a) != 36 {
		t.Fatalf("zły format uuid: %q", a)
	}
}
