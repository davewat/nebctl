package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/davewat/nebctl/internal/prompt"
)

// 2026-11-09: the console runs each request as its own `nebctl app` process,
// and two parallel signs both took NextFree from the same network.json, so
// two hosts got one overlay address (and one record overwrote the other).
// Each sign is now allocate -> sign -> record under the state lock. This runs
// N separate apps (separate processes in real life) on one config dir.
func TestConcurrentSignsGetDistinctAddresses(t *testing.T) {
	base := caApp(t, "")
	const n = 8
	ips := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := &app{root: base.root, console: true, p: prompt.New(strings.NewReader(""), io.Discard)}
			out, err := a.consoleSign(fmt.Sprintf("host%d", i), "", nil, false, "", false)
			if err != nil {
				t.Errorf("sign %d: %v", i, err)
				return
			}
			ips[i] = out["cert"].(issuedOut).NebulaIP
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			t.Fatalf("address %q issued twice or not at all: %v", ip, ips)
		}
		seen[ip] = true
	}
	net, err := base.loadNetwork()
	if err != nil {
		t.Fatal(err)
	}
	if len(net.Issued) != n {
		t.Fatalf("%d certs recorded, want %d (a record was lost)", len(net.Issued), n)
	}
}

// 2026-11-09: the CLI asks its questions before it signs, so the address it
// chose can be taken by another nebctl meanwhile. issue must notice under the
// lock and record nothing, rather than issue a second cert for the address.
func TestIssueRefusesAddressTakenMeanwhile(t *testing.T) {
	a := caApp(t, "")
	a.console = false
	n, _ := a.loadNetwork()
	// Someone else's sign lands after this one's questions were answered.
	other := &app{root: a.root, console: true, p: prompt.New(strings.NewReader(""), io.Discard)}
	if _, err := other.consoleSign("first", "10.9.0.5/24", nil, true, "", false); err != nil {
		t.Fatal(err)
	}
	r, _ := a.planCert(n, "second", "10.9.0.5/24", nil, true) // n is stale: it doesn't know first
	a.console = true
	if _, _, err := a.issue(n, r, "", t.TempDir()+"/k"); err == nil || !strings.Contains(err.Error(), "was given to") {
		t.Fatalf("issue: %v, want a refusal", err)
	}
	got, _ := a.loadNetwork()
	if _, ok := got.Find("second.test.internal"); ok || len(got.Issued) != 1 {
		t.Fatalf("recorded %+v", got.Issued)
	}
}

// 2026-11-09: the lock must live beside the state files the app really uses,
// so the CLI, the console and `nebctl app` on a host all take the same one.
func TestStorePathsMatchApp(t *testing.T) {
	a := &app{root: t.TempDir()}
	s := a.store()
	if s.HostPath() != a.stateFile() || s.NetworkPath() != a.networkFile() {
		t.Fatalf("store paths %s, %s differ from the app's %s, %s", s.HostPath(), s.NetworkPath(), a.stateFile(), a.networkFile())
	}
}
