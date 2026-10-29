package main

import "testing"

func TestDefaultDomain(t *testing.T) {
	for _, tc := range []struct {
		ca    string
		hosts []string
		want  string
	}{
		{"Example.com", nil, "example.internal"},
		{"solidpath", []string{"hs01.solidpath.com"}, "solidpath.internal"},
		{"", []string{"hs01.nebula.solidpath.com"}, "solidpath.internal"},
		{"", []string{"hs01.solidpath.internal"}, "solidpath.internal"},
		{"Nebula CA", []string{"laptop"}, "nebula.internal"},
		{"Nebula CA", []string{"dave_dev_01.example.com"}, "example.internal"},
	} {
		if got := defaultDomain(tc.ca, tc.hosts...); got != tc.want {
			t.Errorf("defaultDomain(%q, %v) = %q, want %q", tc.ca, tc.hosts, got, tc.want)
		}
	}
}
