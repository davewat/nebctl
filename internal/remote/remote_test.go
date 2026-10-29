package remote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/admin"
	"golang.org/x/crypto/ssh"
)

// fakeSudo stands in for sudo: -n works only with FAKE_NOPASSWD=1, and
// otherwise the first stdin line must be the password "sudopw".
const fakeSudo = `#!/bin/sh
need=1
while [ $# -gt 0 ]; do case "$1" in
  -n) shift; [ "$FAKE_NOPASSWD" = 1 ] || { echo "sudo: a password is required" >&2; exit 1; }; need=0;;
  -S|-k) shift;;
  -p) shift 2;;
  *) break;;
esac; done
if [ $need = 1 ]; then read -r pw; [ "$pw" = sudopw ] || { echo "Sorry, try again." >&2; exit 1; }; fi
exec "$@"
`

// fakeNebctl answers -version, and echoes `app` arguments one per line.
const fakeNebctl = `#!/bin/sh
[ "$1" = -version ] && { echo "nebctl v9.9.9"; exit 0; }
shift
for a in "$@"; do printf '%s\n' "$a"; done
`

// server is an SSH server that runs exec requests with sh, as the test's
// own user, with the fake sudo first on PATH.
type server struct {
	addr string
	bin  string
	ln   net.Listener
}

func newServer(t *testing.T, password string) *server {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return startServer(t, password, priv)
}

func startServer(t *testing.T, password string, hostKey ed25519.PrivateKey) *server {
	t.Helper()
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "sudo"), []byte(fakeSudo), 0o755)
	os.WriteFile(filepath.Join(bin, "nebctl"), []byte(fakeNebctl), 0o755)
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := serverConfig(password, signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{addr: ln.Addr().String(), bin: bin, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return s
}

// serverConfig accepts the password, or a key in $HOME/.ssh/authorized_keys
// (where AuthorizeKey writes, since the server's shells share $HOME).
func serverConfig(password string, hostKey ssh.Signer) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == password {
				return nil, nil
			}
			return nil, errors.New("no")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			data, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "authorized_keys"))
			for len(data) > 0 {
				k, _, _, rest, err := ssh.ParseAuthorizedKey(data)
				if err != nil {
					break
				}
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil, nil
				}
				data = rest
			}
			return nil, errors.New("no")
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg
}

func (s *server) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, reqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(req.Payload)
				cmd := exec.Command("sh", "-c", string(req.Payload[4:4+n]))
				cmd.Env = append(os.Environ(), "PATH="+s.bin+":"+os.Getenv("PATH"))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				req.Reply(true, nil)
				code := 0
				if err := cmd.Run(); err != nil {
					code = 1
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				ch.Close()
				return
			}
		}()
	}
}

func (s *server) opts() Options {
	host, port, _ := net.SplitHostPort(s.addr)
	o := Options{Host: host, User: "dave"}
	o.Port = atoi(port)
	return o
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestDialTrustAuthSudoAndRun(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir()) // no default keys
	s := newServer(t, "loginpw")
	known := filepath.Join(t.TempDir(), "known_hosts")
	o := s.opts()

	// An unknown host key comes back to be confirmed.
	o.Password = "loginpw"
	_, err := Dial(o, known)
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Changed || !strings.HasPrefix(hk.Fingerprint, "SHA256:") {
		t.Fatalf("first dial: %v", err)
	}

	// The confirmed key is trusted; a wrong password asks for the password.
	o.AcceptHostKey, o.Password = hk.Fingerprint, "wrong"
	_, err = Dial(o, known)
	var need *NeedError
	if !errors.As(err, &need) || need.Field != "password" {
		t.Fatalf("wrong password: %v", err)
	}
	// The key was saved when it was accepted.
	if data, _ := os.ReadFile(known); !strings.Contains(string(data), "ssh-ed25519") {
		t.Fatalf("known_hosts: %q", data)
	}

	// Logged in, but sudo wants a password.
	o.AcceptHostKey, o.Password = "", "loginpw"
	_, err = Dial(o, known)
	if !errors.As(err, &need) || need.Field != "sudoPassword" {
		t.Fatalf("no sudo password: %v", err)
	}
	o.SudoPassword = "bad"
	if _, err = Dial(o, known); !errors.As(err, &need) || need.Field != "sudoPassword" {
		t.Fatalf("bad sudo password: %v", err)
	}

	o.SudoPassword = "sudopw"
	c, err := Dial(o, known)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Nebctl = filepath.Join(s.bin, "nebctl")
	out, err := c.App([]string{"sign", "-name", "it's a host", "-groups", "a,b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSpace(string(out)), "\n"); strings.Join(got, "|") != "sign|-name|it's a host|-groups|a,b" {
		t.Errorf("arguments arrived as %q", got)
	}

	if v, err := c.FindNebctl(); err != nil || v != "" {
		// /usr/local/bin/nebctl is unlikely here; PATH has the fake one.
		if v != "v9.9.9" {
			t.Errorf("FindNebctl = %q, %v", v, err)
		}
	}

	c.InstallPath = filepath.Join(t.TempDir(), "bin dir", "nebctl")
	if err := c.Install([]byte("#!/bin/sh\necho installed\n")); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(c.InstallPath); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("installed file: %v %v", st, err)
	}

	// A password login can install the console's key; the next login uses it.
	if c.KeyLogin {
		t.Error("a password login was reported as a key login")
	}
	keys := admin.Keys{Dir: t.TempDir()}
	pub, err := keys.EnsureConsoleKey("nebctl-console@test")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.AuthorizeKey(pub); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "authorized_keys"))
	if strings.Count(string(data), "nebctl-console@test") != 1 {
		t.Errorf("authorized_keys should hold the key once:\n%s", data)
	}
	if err := c.AuthorizeKey("not a key; rm -rf /"); err == nil {
		t.Error("a non-key line was accepted")
	}
	keyOnly := o
	keyOnly.Password, keyOnly.KeyFiles = "", []string{keys.ConsoleKey()}
	k, err := Dial(keyOnly, known)
	if err != nil {
		t.Fatalf("logging in with the console key: %v", err)
	}
	defer k.Close()
	if !k.KeyLogin {
		t.Error("the key login wasn't reported as one")
	}
}

func TestChangedHostKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("FAKE_NOPASSWD", "1")
	known := filepath.Join(t.TempDir(), "known_hosts")
	s := newServer(t, "pw")
	o := s.opts()
	o.Password = "pw"
	_, err := Dial(o, known)
	var hk *HostKeyError
	errors.As(err, &hk)
	o.AcceptHostKey = hk.Fingerprint
	c, err := Dial(o, known)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// The same address with a new key is reported as changed.
	s.ln.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		t.Skip("couldn't reuse the port:", err)
	}
	ln.Close()
	s2 := startServerAt(t, "pw", priv, s.addr)
	_ = s2
	o.AcceptHostKey = ""
	_, err = Dial(o, known)
	if !errors.As(err, &hk) || !hk.Changed {
		t.Fatalf("changed key: %v", err)
	}
	o.AcceptHostKey = hk.Fingerprint
	if c, err = Dial(o, known); err != nil {
		t.Fatalf("after accepting the new key: %v", err)
	}
	c.Close()
	data, _ := os.ReadFile(known)
	if n := strings.Count(string(data), "\n"); n != 1 {
		t.Errorf("known_hosts should hold only the new key, has %d lines", n)
	}
}

func startServerAt(t *testing.T, password string, key ed25519.PrivateKey, addr string) *server {
	t.Helper()
	s := startServer(t, password, key)
	s.ln.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("couldn't reuse the port:", err)
	}
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := serverConfig(password, signer)
	s.ln, s.addr = ln, addr
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return s
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":       "plain",
		"10.42.0.1":   "10.42.0.1",
		"it's":        `'it'\''s'`,
		"":            "''",
		"a b":         "'a b'",
		`{"x":1}`:     `'{"x":1}'`,
		"$(rm -rf /)": "'$(rm -rf /)'",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}
