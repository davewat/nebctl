package main

import (
	"io"
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
