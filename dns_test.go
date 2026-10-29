package main

import "testing"

func TestDefaultDomain(t *testing.T) {
	for _, tc := range []struct {
		ca    string
		hosts []string
		want  string
	}{
		{"Example.com", nil, "nebula.example.com"},
		{"solidpath", []string{"hs01.solidpath.com", "fe01.solidpath.com"}, "nebula.solidpath.com"},
		{"solidpath", []string{"hs01.nebula.solidpath.com"}, "nebula.solidpath.com"},
		{"Nebula CA", []string{"laptop"}, "nebula.internal"},
		{"Nebula CA", []string{"dave_dev_01.example.com"}, "nebula.example.com"},
	} {
		if got := defaultDomain(tc.ca, tc.hosts...); got != tc.want {
			t.Errorf("defaultDomain(%q, %v) = %q, want %q", tc.ca, tc.hosts, got, tc.want)
		}
	}
}
