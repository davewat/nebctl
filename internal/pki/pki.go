// Package pki drives nebula-cert (CA, sign, keygen, print) and checks that
// a private key belongs to a certificate.
package pki

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Tool struct {
	Bin    string // path to nebula-cert
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// run passes the terminal through (an encrypted CA key asks for its
// passphrase) and keeps stderr for the error.
func (t Tool) run(args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(t.Bin, args...)
	cmd.Stdin = t.Stdin
	cmd.Stdout = t.Stdout
	cmd.Stderr = &stderr
	if t.Stderr != nil {
		cmd.Stderr = io.MultiWriter(t.Stderr, &stderr)
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(stderr.String()), "Error:"))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nebula-cert %s: %s", args[0], msg)
	}
	return nil
}

type CAOptions struct {
	Name     string
	Duration time.Duration
	Networks []string
	Encrypt  bool
	OutCrt   string
	OutKey   string
}

func (t Tool) CreateCA(o CAOptions) error {
	args := []string{"ca", "-name", o.Name, "-out-crt", o.OutCrt, "-out-key", o.OutKey}
	if o.Duration > 0 {
		args = append(args, "-duration", o.Duration.String())
	}
	if len(o.Networks) > 0 {
		args = append(args, "-networks", strings.Join(o.Networks, ","))
	}
	if o.Encrypt {
		args = append(args, "-encrypt")
	}
	return t.run(args...)
}

type SignOptions struct {
	CACrt, CAKey string
	Name         string
	Networks     []string
	Groups       []string
	InPub        string // sign this public key; otherwise a key is written to OutKey
	OutCrt       string
	OutKey       string
}

func (t Tool) Sign(o SignOptions) error {
	args := []string{"sign", "-ca-crt", o.CACrt, "-ca-key", o.CAKey,
		"-name", o.Name, "-networks", strings.Join(o.Networks, ","), "-out-crt", o.OutCrt}
	if len(o.Groups) > 0 {
		args = append(args, "-groups", strings.Join(o.Groups, ","))
	}
	if o.InPub != "" {
		args = append(args, "-in-pub", o.InPub)
	} else {
		args = append(args, "-out-key", o.OutKey)
	}
	return t.run(args...)
}

func (t Tool) Keygen(outKey, outPub string) error {
	return t.run("keygen", "-out-key", outKey, "-out-pub", outPub)
}

type Cert struct {
	Name        string
	Networks    []string
	Groups      []string
	IsCA        bool
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	PublicKey   string // hex
	Version     int
}

// Inspect reads every certificate in path (a CA file may hold several).
func (t Tool) Inspect(path string) ([]Cert, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(t.Bin, "print", "-json", "-path", path)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reading %s: %s", path, strings.TrimSpace(stderr.String()))
	}
	return ParsePrintJSON(out)
}

// InspectPEM reads certificates from memory.
func (t Tool) InspectPEM(data []byte) ([]Cert, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(t.Bin, "print", "-json", "-path", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %s", strings.TrimSpace(stderr.String()))
	}
	return ParsePrintJSON(out)
}

// ParsePrintJSON reads `nebula-cert print -json`. Version 1 certs keep the
// public key inside "details"; version 2 certs keep it at the top level.
func ParsePrintJSON(data []byte) ([]Cert, error) {
	type details struct {
		Name      string    `json:"name"`
		Networks  []string  `json:"networks"`
		Groups    []string  `json:"groups"`
		IsCA      bool      `json:"isCa"`
		Issuer    string    `json:"issuer"`
		NotBefore time.Time `json:"notBefore"`
		NotAfter  time.Time `json:"notAfter"`
		PublicKey string    `json:"publicKey"`
	}
	var raw []struct {
		Details     details `json:"details"`
		Fingerprint string  `json:"fingerprint"`
		PublicKey   string  `json:"publicKey"`
		Version     int     `json:"version"`
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' { // older nebula-cert printed one object
		data = append(append([]byte{'['}, data...), ']')
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("reading nebula-cert output: %w", err)
	}
	certs := make([]Cert, 0, len(raw))
	for _, r := range raw {
		pub := r.PublicKey
		if pub == "" {
			pub = r.Details.PublicKey
		}
		certs = append(certs, Cert{
			Name: r.Details.Name, Networks: r.Details.Networks, Groups: r.Details.Groups,
			IsCA: r.Details.IsCA, Issuer: r.Details.Issuer,
			NotBefore: r.Details.NotBefore, NotAfter: r.Details.NotAfter,
			Fingerprint: r.Fingerprint, PublicKey: pub, Version: r.Version,
		})
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}
	return certs, nil
}

// ErrUnknownKey means the key's type cannot be checked here.
var ErrUnknownKey = errors.New("unrecognised key type")

// PublicKeyHex derives the public key, as nebula-cert print shows it, from a
// private key or public key PEM.
func PublicKeyHex(keyPEM []byte) (string, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", errors.New("not a PEM key")
	}
	var pub []byte
	switch block.Type {
	case "NEBULA X25519 PUBLIC KEY", "NEBULA P256 PUBLIC KEY":
		pub = block.Bytes
	case "NEBULA X25519 PRIVATE KEY":
		k, err := ecdh.X25519().NewPrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		pub = k.PublicKey().Bytes()
	case "NEBULA P256 PRIVATE KEY":
		k, err := ecdh.P256().NewPrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		pub = k.PublicKey().Bytes()
	case "NEBULA ED25519 PRIVATE KEY":
		if len(block.Bytes) != 64 {
			return "", errors.New("bad ed25519 key length")
		}
		pub = block.Bytes[32:]
	default:
		return "", ErrUnknownKey
	}
	return hex.EncodeToString(pub), nil
}

// KeyMatches reports whether keyPEM is the key of c. It returns
// ErrUnknownKey for a key type it cannot check (an ECDSA P256 CA key).
func KeyMatches(keyPEM []byte, c Cert) (bool, error) {
	pub, err := PublicKeyHex(keyPEM)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(pub, c.PublicKey), nil
}

// IsPrivateKey reports whether data holds a private key PEM, so a public
// file is never handed out by mistake.
func IsPrivateKey(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil && strings.HasSuffix(block.Type, "PRIVATE KEY")
}

// CheckFile reads a file and confirms it is a PEM nebula object.
func CheckFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block == nil || !strings.HasPrefix(block.Type, "NEBULA ") {
		return nil, fmt.Errorf("%s is not a nebula certificate or key", path)
	}
	return data, nil
}
