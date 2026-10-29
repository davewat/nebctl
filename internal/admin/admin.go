// Package admin talks to nebula's SSH admin server (the sshd block in
// config.yml): list-hostmap, print-tunnel, close-tunnel and the rest. nebctl
// runs it on 127.0.0.1 with a host key and a client key of its own.
//
// Nebula answers every command with exit status 0, so errors are told apart
// by their text: a command asked for JSON that prints something else failed.
package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Keys are the admin server's host key and nebctl's client key.
type Keys struct {
	Dir string // e.g. /etc/nebula/admin (0700)
}

func (k Keys) HostKey() string   { return filepath.Join(k.Dir, "ssh_host_ed25519_key") }
func (k Keys) ClientKey() string { return filepath.Join(k.Dir, "nebctl_ed25519") }

// Ensure makes both keys once. It returns the client's public key in
// authorized_keys form, for config.yml.
func (k Keys) Ensure() (string, error) {
	if err := os.MkdirAll(k.Dir, 0o700); err != nil {
		return "", err
	}
	os.Chmod(k.Dir, 0o700)
	for _, p := range []string{k.HostKey(), k.ClientKey()} {
		if _, err := os.Stat(p); err == nil {
			continue
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		block, err := ssh.MarshalPrivateKey(priv, "nebctl")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			return "", err
		}
	}
	signer, err := k.signer(k.ClientKey())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

func (k Keys) signer(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// Client runs commands on nebula's admin server.
type Client struct {
	Addr string // 127.0.0.1:2242
	User string
	Keys Keys
}

// ErrNotRunning means nothing answered on the admin address.
var ErrNotRunning = errors.New("nebula's admin server isn't answering: is nebula running?")

// Run runs one command and returns what it printed.
func (c Client) Run(command string) (string, error) {
	signer, err := c.Keys.signer(c.Keys.ClientKey())
	if err != nil {
		return "", fmt.Errorf("nebctl's admin key: %w", err)
	}
	host, err := c.Keys.signer(c.Keys.HostKey())
	if err != nil {
		return "", fmt.Errorf("the admin server's host key: %w", err)
	}
	conn, err := ssh.Dial("tcp", c.Addr, &ssh.ClientConfig{
		User:            c.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) {
			return "", ErrNotRunning
		}
		return "", fmt.Errorf("logging in to nebula's admin server: %w", err)
	}
	defer conn.Close()
	s, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	// Separate buffers: the session copies stdout and stderr concurrently.
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(command)
	var missing *ssh.ExitMissingError
	if err != nil && !errors.As(err, &missing) {
		return "", err
	}
	text := strings.TrimSpace(out.String() + errb.String())
	if strings.HasPrefix(text, "did not understand") {
		return "", fmt.Errorf("nebula doesn't know %q", command)
	}
	return text, nil
}

// JSON runs a command that prints JSON and decodes it into v. Anything that
// isn't JSON is nebula's error message.
func (c Client) JSON(command string, v any) error {
	text, err := c.Run(command)
	if err != nil {
		return err
	}
	if text == "" {
		return nil // an empty list prints nothing
	}
	if text[0] != '{' && text[0] != '[' && text != "null" {
		return errors.New(text)
	}
	return json.Unmarshal([]byte(text), v)
}

// hostInfo is nebula's ControlHostInfo (control.go), as -json prints it.
type hostInfo struct {
	VpnAddrs               []string        `json:"vpnAddrs"`
	LocalIndex             uint32          `json:"localIndex"`
	RemoteIndex            uint32          `json:"remoteIndex"`
	RemoteAddrs            []string        `json:"remoteAddrs"`
	Cert                   json.RawMessage `json:"cert"`
	MessageCounter         uint64          `json:"messageCounter"`
	CurrentRemote          string          `json:"currentRemote"`
	CurrentRelaysToMe      []string        `json:"currentRelaysToMe"`
	CurrentRelaysThroughMe []string        `json:"currentRelaysThroughMe"`
}

// certJSON covers v1 and v2 certificates' JSON.
type certJSON struct {
	Details struct {
		Name     string    `json:"name"`
		Groups   []string  `json:"groups"`
		NotAfter time.Time `json:"notAfter"`
	} `json:"details"`
	Fingerprint string `json:"fingerprint"`
}

// Peer is one tunnel, flattened for display.
type Peer struct {
	VpnAddr        string    `json:"vpn_addr"`
	Name           string    `json:"name"`
	Groups         []string  `json:"groups"`
	NotAfter       time.Time `json:"not_after"`
	Fingerprint    string    `json:"fingerprint"`
	CurrentRemote  string    `json:"current_remote,omitempty"`
	RemoteAddrs    []string  `json:"remote_addrs"`
	RelayedThrough []string  `json:"relayed_through"`
	RelaysFor      []string  `json:"relays_for"`
	MessageCounter uint64    `json:"message_counter"`
	LocalIndex     uint32    `json:"local_index"`
	RemoteIndex    uint32    `json:"remote_index"`
	Pending        bool      `json:"pending"`
}

func (h hostInfo) peer(pending bool) Peer {
	p := Peer{
		RemoteAddrs: nonNil(h.RemoteAddrs), RelayedThrough: nonNil(h.CurrentRelaysToMe),
		RelaysFor: nonNil(h.CurrentRelaysThroughMe), MessageCounter: h.MessageCounter,
		LocalIndex: h.LocalIndex, RemoteIndex: h.RemoteIndex, Pending: pending,
		Groups: []string{},
	}
	if len(h.VpnAddrs) > 0 {
		p.VpnAddr = h.VpnAddrs[0]
	}
	// A relayed tunnel has no remote of its own; nebula prints the zero
	// address for it.
	if h.CurrentRemote != "" && !strings.HasPrefix(h.CurrentRemote, "invalid") && h.CurrentRemote != "0.0.0.0:0" {
		p.CurrentRemote = h.CurrentRemote
	}
	var c certJSON
	if len(h.Cert) > 0 && json.Unmarshal(h.Cert, &c) == nil {
		p.Name, p.NotAfter, p.Fingerprint = c.Details.Name, c.Details.NotAfter, c.Fingerprint
		if c.Details.Groups != nil {
			p.Groups = c.Details.Groups
		}
	}
	return p
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Peers lists established tunnels, then handshaking ones.
func (c Client) Peers() ([]Peer, error) {
	var main, pending []hostInfo
	if err := c.JSON("list-hostmap -json", &main); err != nil {
		return nil, err
	}
	if err := c.JSON("list-pending-hostmap -json", &pending); err != nil {
		return nil, err
	}
	peers := make([]Peer, 0, len(main)+len(pending))
	for _, h := range main {
		peers = append(peers, h.peer(false))
	}
	for _, h := range pending {
		peers = append(peers, h.peer(true))
	}
	return peers, nil
}

// Tunnel is print-tunnel for one address.
func (c Client) Tunnel(vpnAddr string) (Peer, error) {
	var h hostInfo
	if err := c.JSON("print-tunnel "+vpnAddr, &h); err != nil {
		return Peer{}, err
	}
	return h.peer(false), nil
}

// AddrEntry is what a lighthouse knows about one host.
type AddrEntry struct {
	VpnAddr  string   `json:"vpn_addr"`
	Learned  []string `json:"learned"`
	Reported []string `json:"reported"`
	Relays   []string `json:"relays"`
}

type cache struct {
	Learned  []string `json:"learned"`
	Reported []string `json:"reported"`
	Relay    []string `json:"relay"`
}

func flatten(vpnAddr string, m map[string]*cache) AddrEntry {
	e := AddrEntry{VpnAddr: vpnAddr, Learned: []string{}, Reported: []string{}, Relays: []string{}}
	for _, c := range m {
		if c == nil {
			continue
		}
		e.Learned = append(e.Learned, c.Learned...)
		e.Reported = append(e.Reported, c.Reported...)
		e.Relays = append(e.Relays, c.Relay...)
	}
	return e
}

// AddrMap is list-lighthouse-addrmap; only lighthouses have one.
func (c Client) AddrMap() ([]AddrEntry, error) {
	var raw []struct {
		VpnAddr string            `json:"vpnAddr"`
		Addrs   map[string]*cache `json:"addrs"`
	}
	if err := c.JSON("list-lighthouse-addrmap -json", &raw); err != nil {
		return nil, err
	}
	out := make([]AddrEntry, len(raw))
	for i, r := range raw {
		out[i] = flatten(r.VpnAddr, r.Addrs)
	}
	return out, nil
}

// Lookup asks the lighthouse where a host is (query-lighthouse). It returns
// nil when the lighthouse doesn't know yet; asking starts a query.
func (c Client) Lookup(vpnAddr string) (*AddrEntry, error) {
	var m map[string]*cache
	if err := c.JSON("query-lighthouse "+vpnAddr, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	e := flatten(vpnAddr, m)
	return &e, nil
}

// Message runs a command that answers with one line of text.
func (c Client) Message(command string) (string, error) {
	return c.Run(command)
}

// LogLevel returns or sets the running log level.
func (c Client) LogLevel(set string) (string, error) {
	text, err := c.Run(strings.TrimSpace("log-level " + set))
	if err != nil {
		return "", err
	}
	level, ok := strings.CutPrefix(text, "Log level is: ")
	if !ok {
		return "", errors.New(text)
	}
	return strings.TrimSpace(level), nil
}
