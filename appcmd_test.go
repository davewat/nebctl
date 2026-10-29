package main

import (
	"reflect"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
)

func TestInbound(t *testing.T) {
	got, err := inbound("ping-ssh", "tcp/443, udp/53")
	if err != nil {
		t.Fatal(err)
	}
	want := []netconf.Rule{netconf.PingRule, netconf.SSHRule,
		{Port: "443", Proto: "tcp", Host: "any"}, {Port: "53", Proto: "udp", Host: "any"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, _ := inbound("all", "tcp/443"); !reflect.DeepEqual(got, []netconf.Rule{netconf.AllRule}) {
		t.Errorf("all: got %v", got)
	}
	if _, err := inbound("open", ""); err == nil {
		t.Error("an unknown preset was accepted")
	}
}

func TestCheckPlan(t *testing.T) {
	a := &app{root: t.TempDir(), goos: "darwin"}
	var p nodePlan
	p.Cert.Source = "keep"
	p.Lighthouses = []netconf.Lighthouse{{NebulaIP: "10.42.0.1", Endpoints: []string{"lh.example.com"}}}
	p.Firewall = "keep"
	errs := a.checkPlan(p)
	for _, f := range []string{"cert", "firewall"} {
		if errs[f] == "" {
			t.Errorf("%s: no error with nothing set up here", f)
		}
	}
	if len(errs) != 2 {
		t.Errorf("got %v", errs)
	}

	p.Firewall, p.ExtraPorts = "ping", "tcp/80"
	p.Lighthouses = append(p.Lighthouses, netconf.Lighthouse{NebulaIP: "10.42.0", Endpoints: []string{"lh2:0"}})
	errs = a.checkPlan(p)
	for _, f := range []string{"lighthouses.1.nebula_ip", "lighthouses.1.endpoints"} {
		if errs[f] == "" {
			t.Errorf("%s: no error", f)
		}
	}
	if errs["firewall"] != "" || errs["extra_ports"] != "" || errs["lighthouses.0.endpoints"] != "" {
		t.Errorf("good fields flagged: %v", errs)
	}
}
