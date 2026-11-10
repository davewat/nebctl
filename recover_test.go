package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/davewat/nebctl/internal/keep"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/prompt"
)

// recoverApp is an app in a temp root with a stand-in nebula whose `-test`
// exits with testExit, and a fake service whose state follows states.
func recoverApp(t *testing.T, testExit string, states ...string) (*app, *int) {
	t.Helper()
	zero := time.Duration(0)
	var out strings.Builder
	restarts := 0
	a := &app{root: t.TempDir(), goos: "linux", settle: &zero, p: prompt.New(strings.NewReader(""), &out)}
	os.MkdirAll(a.binDir(), 0o755)
	os.MkdirAll(a.cfgDir(), 0o755)
	if err := os.WriteFile(a.nebulaBin(), []byte("#!/bin/sh\necho \"config rejected\" >&2\nexit "+testExit+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	seq := states
	a.svcStatus = func() string {
		s := seq[0]
		if len(seq) > 1 {
			seq = seq[1:]
		}
		return s
	}
	a.svcRestart = func() error { restarts++; return nil }
	return a, &restarts
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 2026-11-09: a config rewrite overwrote config.yml with no previous copy.
// writeConfig must keep the old one as config.yml.prev (same mode), keep the
// real previous one when the same config is written again, and change
// nothing when nebula rejects the new config. The state lock must be let go
// afterwards.
func TestWriteConfigKeepsPreviousConfig(t *testing.T) {
	a, _ := recoverApp(t, "0", "running")
	h := &netconf.Host{Role: netconf.RoleLighthouse, Name: "lh", NebulaIP: "10.9.0.1/24", ListenPort: 4242}
	if _, err := a.writeConfig(h); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, a.cfgFile())
	if exists(keep.Prev(a.cfgFile())) {
		t.Fatal("the first config has nothing to keep")
	}
	h.ListenPort = 4343
	if _, err := a.writeConfig(h); err != nil {
		t.Fatal(err)
	}
	second := readFile(t, a.cfgFile())
	if second == first || readFile(t, keep.Prev(a.cfgFile())) != first {
		t.Fatalf("config.yml.prev should hold the first config")
	}
	if st, _ := os.Stat(keep.Prev(a.cfgFile())); st.Mode().Perm() != 0o600 {
		t.Fatalf("prev mode %v, want 0600", st.Mode())
	}
	if _, err := a.writeConfig(h); err != nil { // same again
		t.Fatal(err)
	}
	if readFile(t, keep.Prev(a.cfgFile())) != first {
		t.Fatal("rewriting an identical config overwrote the real previous one")
	}
	if a.release != nil {
		t.Fatal("the state lock is still held after writeConfig")
	}

	os.WriteFile(a.nebulaBin(), []byte("#!/bin/sh\necho bad >&2\nexit 1\n"), 0o755)
	h.ListenPort = 5555
	if _, err := a.writeConfig(h); err == nil {
		t.Fatal("a config nebula rejects was written")
	}
	if readFile(t, a.cfgFile()) != second || readFile(t, keep.Prev(a.cfgFile())) != first {
		t.Fatal("a rejected config changed config.yml or its previous copy")
	}
}

// 2026-11-09: after a restart nothing checked that nebula came up, and a
// failure said nothing about how to get back. verifyRunning must pass when
// nebula starts (even after a "starting" state), and fail with the log tail
// and the exact commands when it dies or never starts.
func TestVerifyRunning(t *testing.T) {
	a, _ := recoverApp(t, "0", "starting", "running")
	if err := a.verifyRunning(true, false); err != nil {
		t.Fatalf("starting then running: %v", err)
	}

	a, _ = recoverApp(t, "0", "running", "stopped") // up, then falls over inside the settle time
	os.WriteFile(a.cfgFile(), []byte("new"), 0o600)
	os.WriteFile(keep.Prev(a.cfgFile()), []byte("old"), 0o600)
	os.MkdirAll(a.path("/var/log"), 0o755)
	os.WriteFile(a.path("/var/log/nebula.log"), []byte("level=error msg=\"boom\"\n"), 0o644)
	err := a.verifyRunning(true, false)
	if err == nil {
		t.Fatal("a service that stopped was reported as running")
	}
	for _, want := range []string{"stopped", "boom", "sudo nebctl restore-config",
		"sudo cp -p " + keep.Prev(a.cfgFile()) + " " + a.cfgFile() + " && sudo systemctl restart nebula"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}

	a, _ = recoverApp(t, "0", "failed")
	os.WriteFile(a.nebulaBin(), []byte("new"), 0o755)
	os.WriteFile(a.certBin(), []byte("new"), 0o755)
	os.WriteFile(keep.Prev(a.nebulaBin()), []byte("old"), 0o755)
	os.WriteFile(keep.Prev(a.certBin()), []byte("old"), 0o755)
	err = a.verifyRunning(false, true)
	if err == nil || !strings.Contains(err.Error(), "sudo mv -f "+keep.Prev(a.nebulaBin())+" "+a.nebulaBin()+
		" && sudo mv -f "+keep.Prev(a.certBin())+" "+a.certBin()+" && sudo systemctl restart nebula") {
		t.Fatalf("update failure lacks the binary restore commands: %v", err)
	}
	if strings.Contains(err.Error(), "restore-config") {
		t.Fatalf("an update failure should not point at the config: %v", err)
	}

	a, _ = recoverApp(t, "0", "failed") // a first config has no previous copy
	if err := a.verifyRunning(true, false); err == nil || !strings.Contains(err.Error(), "No previous config was kept") {
		t.Fatalf("first config: %v", err)
	}
}

// 2026-11-09: restore-config puts config.yml.prev back only when the operator
// runs it: nebula -test first, then the swap (so running it again undoes it),
// then a restart that is checked.
func TestRestoreConfig(t *testing.T) {
	a, restarts := recoverApp(t, "0", "running")
	os.WriteFile(a.cfgFile(), []byte("new"), 0o600)
	os.WriteFile(keep.Prev(a.cfgFile()), []byte("old"), 0o600)
	if err := a.restoreConfig(); err != nil {
		t.Fatal(err)
	}
	if readFile(t, a.cfgFile()) != "old" || readFile(t, keep.Prev(a.cfgFile())) != "new" || *restarts != 1 {
		t.Fatalf("after restore: current %q prev %q restarts %d", readFile(t, a.cfgFile()), readFile(t, keep.Prev(a.cfgFile())), *restarts)
	}
	if err := a.restoreConfig(); err != nil || readFile(t, a.cfgFile()) != "new" {
		t.Fatalf("a second restore should swap back: %v", err)
	}

	// nebula rejects the kept copy: nothing is swapped, nothing restarts.
	a, restarts = recoverApp(t, "1", "running")
	os.WriteFile(a.cfgFile(), []byte("new"), 0o600)
	os.WriteFile(keep.Prev(a.cfgFile()), []byte("old"), 0o600)
	if err := a.restoreConfig(); err == nil || !strings.Contains(err.Error(), "config rejected") {
		t.Fatalf("restore of a bad copy: %v", err)
	}
	if readFile(t, a.cfgFile()) != "new" || readFile(t, keep.Prev(a.cfgFile())) != "old" || *restarts != 0 {
		t.Fatal("a rejected restore changed files or restarted nebula")
	}

	// nothing kept
	a, _ = recoverApp(t, "0", "running")
	if err := a.restoreConfig(); err == nil || !strings.Contains(err.Error(), "no previous config") {
		t.Fatalf("no prev: %v", err)
	}

	// it restarts, but nebula does not stay up: an error with the way back, no auto-rollback.
	a, restarts = recoverApp(t, "0", "failed")
	a.p = prompt.New(strings.NewReader(""), io.Discard)
	os.WriteFile(a.cfgFile(), []byte("new"), 0o600)
	os.WriteFile(keep.Prev(a.cfgFile()), []byte("old"), 0o600)
	if err := a.restoreConfig(); err == nil || !strings.Contains(err.Error(), "did not stay running") {
		t.Fatalf("restore onto a failing service: %v", err)
	}
	if readFile(t, a.cfgFile()) != "old" || *restarts != 1 {
		t.Fatal("nebctl must not roll back by itself")
	}
}
