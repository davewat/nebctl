package main

import (
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
	"github.com/davewat/nebctl/internal/prompt"
)

// caApp is a console-mode app whose CA is in a temp root, using the real
// nebula-cert.
func caApp(t *testing.T, passphrase string) *app {
	t.Helper()
	bin, err := exec.LookPath("nebula-cert")
	if err != nil {
		t.Skip("nebula-cert isn't installed")
	}
	a := &app{root: t.TempDir(), console: true, p: prompt.New(strings.NewReader(""), io.Discard)}
	os.MkdirAll(a.binDir(), 0o755)
	if err := os.Symlink(bin, a.certBin()); err != nil {
		t.Fatal(err)
	}
	if err := a.prepareCADir(); err != nil {
		t.Fatal(err)
	}
	if passphrase != "" {
		t.Setenv("NEBULA_CA_PASSPHRASE", passphrase)
	}
	tool := a.tool()
	tool.Stdout, tool.Stderr = nil, nil
	if err := tool.CreateCA(pki.CAOptions{Name: "test", Networks: []string{"10.9.0.0/24"},
		Encrypt: passphrase != "", OutCrt: a.caDirCrt(), OutKey: a.caDirKey()}); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("NEBULA_CA_PASSPHRASE")
	n := &netconf.Network{CIDR: "10.9.0.0/24", Domain: "test.internal",
		Lighthouses: []netconf.Lighthouse{{Name: "lh.test.internal", NebulaIP: "10.9.0.1", Endpoints: []string{"192.0.2.10:4242"}}}}
	if err := n.Save(a.networkFile()); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCAKeyOffline(t *testing.T) {
	a := caApp(t, "")
	key, err := os.ReadFile(a.caDirKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.consoleSign("web01", "", nil, false, "", false); err != nil {
		t.Fatalf("signing with ca.key here: %v", err)
	}

	// Removal needs a working copy of the key.
	if _, err := a.consoleCAKeyRemove(); err == nil || !a.haveCAKey() {
		t.Fatalf("removed without a copy: %v", err)
	}
	other := caApp(t, "")
	otherKey, _ := os.ReadFile(other.caDirKey())
	a.caKey = &caKeyInput{Key: string(otherKey)}
	if _, err := a.consoleCAKeyRemove(); err == nil || !strings.Contains(err.Error(), "isn't this CA's key") || !a.haveCAKey() {
		t.Fatalf("removed with another CA's key: %v", err)
	}
	a.caKey = &caKeyInput{Key: string(key)}
	if _, err := a.consoleCAKeyRemove(); err != nil {
		t.Fatal(err)
	}
	if a.haveCAKey() || !a.haveCA() {
		t.Fatalf("after removal: key here %v, CA here %v", a.haveCAKey(), a.haveCA())
	}

	// Without the key, a console sign says how to give it, and changes nothing.
	a.caKey = nil
	if _, err := a.consoleSign("web01", "", nil, false, "", false); err != errNoCAKey {
		t.Fatalf("sign without a key: %v", err)
	}
	if !exists(filepath.Join(a.issuedDir(), "web01.test.internal.crt")) {
		t.Fatal("a failed renewal removed the old cert")
	}

	// Handed in, it signs, and nothing is written back.
	a.caKey = &caKeyInput{Key: string(key)}
	out, err := a.consoleSign("web02", "", nil, false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if c := out["cert"].(issuedOut); c.Name != "web02.test.internal" || !strings.Contains(out["bundle"].(string), "NEBCTL") {
		t.Errorf("web02 got %v", out)
	}
	if a.haveCAKey() {
		t.Error("signing wrote ca.key")
	}
	entries, _ := os.ReadDir(a.caDir())
	for _, e := range entries {
		if data, _ := os.ReadFile(filepath.Join(a.caDir(), e.Name())); strings.Contains(string(data), "PRIVATE KEY") {
			t.Errorf("%s holds a private key", e.Name())
		}
	}
}

func TestCAKeyEncrypted(t *testing.T) {
	a := caApp(t, "correct horse")
	key, _ := os.ReadFile(a.caDirKey())
	if !pki.IsEncryptedKey(key) {
		t.Fatal("the test key isn't encrypted")
	}
	for _, tc := range []struct{ pass, want string }{
		{"", "protected by a passphrase"},
		{"wrong", "doesn't open the key"},
		{"correct horse", ""},
	} {
		a.caKey = &caKeyInput{Key: string(key), Passphrase: tc.pass}
		_, err := a.consoleCAKeyCheck()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("passphrase %q: %v, want %q", tc.pass, err, tc.want)
		}
	}
	os.Remove(a.caDirKey())
	if _, err := a.consoleSign("db01", "", []string{"db"}, true, "", false); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCAKeyText(t *testing.T) {
	for _, s := range []string{"", "hello", "-----BEGIN NEBULA CERTIFICATE-----\nAAAA\n-----END NEBULA CERTIFICATE-----\n"} {
		if checkCAKeyText(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

// initApp is an app rooted in a temp dir with the real nebula-cert, whose
// prompts are answered by input.
func initApp(t *testing.T, input string) (*app, *strings.Builder) {
	t.Helper()
	bin, err := exec.LookPath("nebula-cert")
	if err != nil {
		t.Skip("nebula-cert isn't installed")
	}
	var out strings.Builder
	a := &app{root: t.TempDir(), p: prompt.New(strings.NewReader(input), &out)}
	os.MkdirAll(a.binDir(), 0o755)
	if err := os.Symlink(bin, a.certBin()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.nebulaBin(), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	return a, &out
}

// Guards the 2026-11 change: a new CA's key is encrypted by default, so a run
// with no terminal (a script) must stop with a clear error, not hang or
// quietly write an unencrypted key.
func TestCAInitEncryptsByDefault(t *testing.T) {
	// name, network, years, passphrase (blank = the default), domain
	a, out := initApp(t, "Test CA\n10.9.0.0/24\n5\n\n\n")
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = func() bool { return true } })
	err := a.caInit(false)
	if err == nil || !strings.Contains(err.Error(), "-no-passphrase") {
		t.Fatalf("want an error naming -no-passphrase, got %v", err)
	}
	if !strings.Contains(out.String(), "[Y/n]") {
		t.Errorf("the passphrase prompt should default to yes: %q", out.String())
	}
	if a.haveCA() || exists(a.caDir()) {
		t.Error("a refused init must leave no CA behind")
	}
}

// The explicit unencrypted choice works without a terminal and without a
// passphrase question, and warns that the key should go offline.
func TestCAInitNoPassphrase(t *testing.T) {
	a, out := initApp(t, "Test CA\n10.9.0.0/24\n5\n\n")
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = func() bool { return true } })
	if err := a.caInit(true); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(a.caDirKey())
	if err != nil {
		t.Fatal(err)
	}
	if pki.IsEncryptedKey(key) {
		t.Error("-no-passphrase made an encrypted key")
	}
	if strings.Contains(out.String(), "Protect ca.key") {
		t.Error("-no-passphrase should not ask about a passphrase")
	}
	if !strings.Contains(out.String(), "NOT encrypted") || !strings.Contains(out.String(), "offline") {
		t.Errorf("missing the unencrypted warning: %q", out.String())
	}
}

// Guards the 2026-11 bug: a re-sign deleted the old cert before signing, so a
// signing failure (wrong passphrase, nebula-cert error) left issued/ without
// it while network.json still listed it.
func TestFailedResignKeepsOldCert(t *testing.T) {
	a := &app{root: t.TempDir(), console: true, p: prompt.New(strings.NewReader(""), io.Discard)}
	os.MkdirAll(a.binDir(), 0o755)
	os.MkdirAll(a.issuedDir(), 0o700)
	// A nebula-cert that always fails, as with a wrong passphrase.
	os.WriteFile(a.certBin(), []byte("#!/bin/sh\necho 'invalid passphrase' >&2\nexit 1\n"), 0o755)
	os.WriteFile(a.caDirCrt(), []byte("CA"), 0o644)
	os.WriteFile(a.caDirKey(), []byte("KEY"), 0o600)
	old := filepath.Join(a.issuedDir(), "web01.test.internal.crt")
	os.WriteFile(old, []byte("OLD CERT"), 0o644)
	n := &netconf.Network{CIDR: "10.9.0.0/24"}
	n.Record(netconf.Issued{Name: "web01.test.internal", NebulaIP: "10.9.0.2/24", Fingerprint: "f1"})

	r := certReq{name: "web01.test.internal", ip: netip.MustParsePrefix("10.9.0.2/24")}
	if _, _, err := a.issue(n, r, "", filepath.Join(t.TempDir(), "k")); err == nil || !strings.Contains(err.Error(), "invalid passphrase") {
		t.Fatalf("issue: %v", err)
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "OLD CERT" {
		t.Fatalf("the old cert is gone or changed: %q, %v", data, err)
	}
	if ents, _ := os.ReadDir(a.issuedDir()); len(ents) != 1 {
		t.Errorf("scratch files left in issued/: %v", ents)
	}
	if got, _ := n.Find("web01.test.internal"); got.Fingerprint != "f1" || len(got.History) != 0 {
		t.Errorf("the record changed: %+v", got)
	}
}

// A renewal keeps the old fingerprint revocable and shows it in the console's
// certificate list; revoking checks the fingerprint's format.
func TestRenewKeepsOldFingerprintRevocable(t *testing.T) {
	a := caApp(t, "")
	first, err := a.consoleSign("web01", "", nil, false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	oldFP := first["cert"].(issuedOut).Fingerprint
	second, err := a.consoleSign("web01", "", nil, false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if second["cert"].(issuedOut).Fingerprint == oldFP {
		t.Fatal("a re-sign gave the same cert")
	}
	n, err := a.loadNetwork()
	if err != nil {
		t.Fatal(err)
	}
	sup := supersededList(n, nil)
	if len(sup) != 1 || sup[0].Fingerprint != oldFP || sup[0].Revoked || sup[0].Current != "web01.test.internal" {
		t.Fatalf("superseded = %+v", sup)
	}
	if got := supersededList(n, []string{oldFP}); !got[0].Revoked {
		t.Error("an entry on the blocklist should show as revoked")
	}
	// The saved file keeps it too.
	if data, _ := os.ReadFile(a.networkFile()); !strings.Contains(string(data), oldFP) {
		t.Error("network.json lost the old fingerprint")
	}
	var out strings.Builder
	a.p = prompt.New(strings.NewReader(""), &out)
	if err := a.caList(); err != nil || !strings.Contains(out.String(), "superseded") || !strings.Contains(out.String(), oldFP) {
		t.Errorf("ca list: %v\n%s", err, out.String())
	}
}

// Guards the 2026-11 gap: revoke accepted any string.
func TestRevokeChecksFingerprintFormat(t *testing.T) {
	a := &app{root: t.TempDir(), console: true, p: prompt.New(strings.NewReader(""), io.Discard)}
	os.MkdirAll(a.cfgDir(), 0o755)
	(&netconf.Host{Role: netconf.RoleLighthouse}).Save(a.stateFile())
	for _, bad := range []string{"abc", "not hex", strings.Repeat("z", 64), strings.Repeat("a", 65)} {
		if _, err := a.consoleRevoke(bad); err == nil || !strings.Contains(err.Error(), "64 hexadecimal") {
			t.Errorf("revoke %q: %v", bad, err)
		}
		if err := a.consoleBlocklist([]string{strings.Repeat("a", 64), bad}); err == nil || !strings.Contains(err.Error(), "64 hexadecimal") {
			t.Errorf("blocklist with %q: %v", bad, err)
		}
	}
}
