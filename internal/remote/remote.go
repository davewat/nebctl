// Package remote runs `sudo nebctl app ...` on another machine over SSH, so
// the web console can manage a lighthouse from any host.
package remote

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Options say where to connect and how to log in.
type Options struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Password      string `json:"password"`
	UseAgent      bool   `json:"use_agent"`
	KeyPath       string `json:"key_path"`
	Passphrase    string `json:"passphrase"`
	SudoPassword  string `json:"sudo_password"`
	AcceptHostKey string `json:"accept_host_key"`
}

func (o Options) addr() string {
	port := o.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(o.Host, strconv.Itoa(port))
}

// HostKeyError means the server's key is new or changed: show the
// fingerprint and retry with AcceptHostKey once the user trusts it.
type HostKeyError struct {
	Fingerprint string
	Type        string
	Changed     bool
}

func (e *HostKeyError) Error() string {
	if e.Changed {
		return "the host key CHANGED since last time: someone may be intercepting the connection, or the server was reinstalled"
	}
	return "this host's key isn't known yet: check its fingerprint before trusting it"
}

// NeedError means a credential is missing or wrong: ask for Field.
type NeedError struct {
	Field string // password, passphrase or sudoPassword
	Msg   string
}

func (e *NeedError) Error() string { return e.Msg }

// Conn is a logged-in SSH connection to a machine with sudo rights.
type Conn struct {
	opts       Options
	knownHosts string
	mu         sync.Mutex
	client     *ssh.Client
	noPassword bool // sudo needs no password there
	Nebctl     string
	// InstallPath is where Install puts nebctl.
	InstallPath string
}

// Dial connects, checks the host key against knownHosts (a file nebctl
// keeps) and checks sudo works.
func Dial(o Options, knownHosts string) (*Conn, error) {
	c := &Conn{opts: o, knownHosts: knownHosts, InstallPath: "/usr/local/bin/nebctl"}
	if err := c.dial(); err != nil {
		return nil, err
	}
	if err := c.checkSudo(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) dial() error {
	o := c.opts
	auth, closer, err := authMethods(o)
	if closer != nil {
		defer closer()
	}
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            o.User,
		Auth:            auth,
		HostKeyCallback: c.hostKeyCallback(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", o.addr(), cfg)
	if err != nil {
		var hk *HostKeyError
		if errors.As(err, &hk) {
			return hk
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			if o.Password != "" {
				return &NeedError{"password", "the server didn't accept that password"}
			}
			return &NeedError{"password", "the server didn't accept a key: give a password (or a key file)"}
		}
		return fmt.Errorf("connecting to %s: %w", o.addr(), err)
	}
	c.client = client
	return nil
}

func authMethods(o Options) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	var closer func()
	var signers []ssh.Signer
	addKey := func(path, passphrase string, required bool) error {
		data, err := os.ReadFile(path)
		if err != nil {
			if required {
				return fmt.Errorf("the key file: %w", err)
			}
			return nil
		}
		s, err := ssh.ParsePrivateKey(data)
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			if passphrase == "" {
				if required {
					return &NeedError{"passphrase", "the key file is protected: give its passphrase"}
				}
				return nil
			}
			s, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
			if err != nil {
				return &NeedError{"passphrase", "that passphrase doesn't open the key file"}
			}
		}
		if err != nil {
			if required {
				return fmt.Errorf("the key file: %w", err)
			}
			return nil
		}
		signers = append(signers, s)
		return nil
	}
	if o.KeyPath != "" {
		if err := addKey(o.KeyPath, o.Passphrase, true); err != nil {
			return nil, nil, err
		}
	} else if o.Password == "" {
		// The person who ran sudo's own keys, if unprotected.
		for _, p := range defaultKeys() {
			addKey(p, o.Passphrase, false)
		}
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" && (o.UseAgent || o.Password == "") {
		if conn, err := net.Dial("unix", sock); err == nil {
			closer = func() { conn.Close() }
			if agentSigners, err := agent.NewClient(conn).Signers(); err == nil {
				signers = append(signers, agentSigners...)
			}
		} else if o.UseAgent {
			return nil, nil, fmt.Errorf("ssh-agent: %w", err)
		}
	} else if o.UseAgent {
		return nil, nil, errors.New("no ssh-agent here: start the console with `sudo --preserve-env=SSH_AUTH_SOCK nebctl web`, or use a key file or password")
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if o.Password != "" {
		pw := o.Password
		methods = append(methods, ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range qs {
					ans[i] = pw
				}
				return ans, nil
			}))
	}
	if len(methods) == 0 {
		return nil, closer, &NeedError{"password", "no SSH key was found: give a password or a key file"}
	}
	return methods, closer, nil
}

// defaultKeys are the usual key files of the user who ran sudo.
func defaultKeys() []string {
	home, _ := os.UserHomeDir()
	if name := os.Getenv("SUDO_USER"); name != "" {
		if u, err := user.Lookup(name); err == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		return nil
	}
	var out []string
	for _, f := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		out = append(out, filepath.Join(home, ".ssh", f))
	}
	return out
}

// hostKeyCallback trusts keys in knownHosts, and a new or changed key only
// when its fingerprint is the one the user accepted (which is then saved).
func (c *Conn) hostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		os.MkdirAll(filepath.Dir(c.knownHosts), 0o700)
		if f, err := os.OpenFile(c.knownHosts, os.O_CREATE, 0o600); err == nil {
			f.Close()
		}
		check, err := knownhosts.New(c.knownHosts)
		if err != nil {
			return err
		}
		err = check(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return err
		}
		changed := len(ke.Want) > 0
		if c.opts.AcceptHostKey != fp {
			return &HostKeyError{Fingerprint: fp, Type: key.Type(), Changed: changed}
		}
		return saveHostKey(c.knownHosts, hostname, key, changed)
	}
}

func saveHostKey(path, hostname string, key ssh.PublicKey, replace bool) error {
	addr := knownhosts.Normalize(hostname)
	var keep []string
	if data, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l == "" {
				continue
			}
			if replace {
				if f := strings.Fields(l); len(f) > 0 && strings.Split(f[0], ",")[0] == addr {
					continue
				}
			}
			keep = append(keep, l)
		}
	}
	keep = append(keep, knownhosts.Line([]string{addr}, key))
	return os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0o600)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	c.client = nil
	return err
}

// session opens a session, redialling once if the connection dropped.
func (c *Conn) session() (*ssh.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		if s, err := c.client.NewSession(); err == nil {
			return s, nil
		}
		c.client.Close()
		c.client = nil
	}
	c.opts.AcceptHostKey = "" // a redial trusts only saved keys
	if err := c.dial(); err != nil {
		return nil, err
	}
	return c.client.NewSession()
}

// Output runs a command as the login user.
func (c *Conn) Output(cmd string) (string, error) {
	s, err := c.session()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	if err := s.Run(cmd); err != nil {
		return out.String(), fmt.Errorf("%s: %v %s", cmd, err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (c *Conn) checkSudo() error {
	if _, err := c.Output("sudo -n true"); err == nil {
		c.noPassword = true
		return nil
	}
	if c.opts.SudoPassword == "" {
		return &NeedError{"sudoPassword", "sudo on " + c.opts.Host + " needs " + c.opts.User + "'s password"}
	}
	if _, _, err := c.sudo("true", nil); err != nil {
		return &NeedError{"sudoPassword", "sudo didn't accept that password (is " + c.opts.User + " allowed to use sudo?)"}
	}
	return nil
}

// sudo runs cmd (a shell command line) as root, with input on its stdin.
func (c *Conn) sudo(cmd string, input []byte) (stdout, stderr []byte, err error) {
	s, err := c.session()
	if err != nil {
		return nil, nil, err
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	var in bytes.Buffer
	line := "sudo -n " + cmd
	if !c.noPassword {
		// -k makes sudo ask every time, so the password line is always read.
		line = "sudo -S -k -p '' " + cmd
		in.WriteString(c.opts.SudoPassword + "\n")
	}
	in.Write(input)
	s.Stdin = &in
	err = s.Run(line)
	return out.Bytes(), errb.Bytes(), err
}

// App runs `nebctl app <args>` as root there and returns its stdout. A
// failure carries nebctl's own message.
func (c *Conn) App(args []string) ([]byte, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = Quote(a)
	}
	out, errb, err := c.sudo(Quote(c.Nebctl)+" app "+strings.Join(quoted, " "), nil)
	if err != nil {
		msg := strings.TrimSpace(string(errb))
		msg = strings.TrimPrefix(msg, "error: ")
		if msg == "" {
			msg = err.Error()
		}
		return out, errors.New(msg)
	}
	return out, nil
}

// Platform is the remote's GOOS and GOARCH.
func (c *Conn) Platform() (goos, goarch string, err error) {
	out, err := c.Output("uname -sm")
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return "", "", fmt.Errorf("uname said %q", out)
	}
	goos = strings.ToLower(f[0])
	switch f[1] {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64":
		goarch = "arm64"
	case "armv7l", "armv6l", "armv5tel":
		goarch = "arm"
	default:
		return "", "", fmt.Errorf("no nebctl build for %s", f[1])
	}
	return goos, goarch, nil
}

// FindNebctl looks for nebctl there and returns its version ("" if missing).
func (c *Conn) FindNebctl() (string, error) {
	out, err := c.Output("for p in /usr/local/bin/nebctl \"$(command -v nebctl)\"; do [ -x \"$p\" ] && { echo \"$p\"; \"$p\" -version; exit 0; }; done; exit 0")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		c.Nebctl = "/usr/local/bin/nebctl"
		return "", nil
	}
	c.Nebctl = strings.TrimSpace(lines[0])
	return strings.TrimSpace(strings.TrimPrefix(lines[1], "nebctl ")), nil
}

// Install copies a nebctl binary to /usr/local/bin/nebctl there.
func (c *Conn) Install(binary []byte) error {
	dst := Quote(c.InstallPath)
	dir := Quote(filepath.Dir(c.InstallPath))
	script := "mkdir -p " + dir + " && cat > " + dst + ".new && chmod 0755 " + dst + ".new && mv " + dst + ".new " + dst
	_, errb, err := c.sudo("sh -c "+Quote(script), binary)
	if err != nil {
		return fmt.Errorf("copying nebctl there: %v %s", err, strings.TrimSpace(string(errb)))
	}
	c.Nebctl = c.InstallPath
	return nil
}

// Quote quotes s for a POSIX shell.
func Quote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=,@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
