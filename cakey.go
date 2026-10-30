package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/pki"
)

// The CA key can live offline. To sign, it is handed in for one run (pasted
// in a terminal, or sent by the console on stdin) and reaches nebula-cert
// through a pipe, so it is never written to this machine's disk.

type caKeyInput struct {
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
}

var errNoCAKey = errors.New("the CA key isn't on this machine: paste it on the console's Certificates page (or sign in a terminal, which asks for it)")

func (a *app) haveCAKey() bool { return exists(a.caDirKey()) }

// readCAKey takes {"key": ..., "passphrase": ...} from the console's stdin.
func (a *app) readCAKey(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return err
	}
	var in caKeyInput
	if err := json.Unmarshal(data, &in); err != nil {
		return fmt.Errorf("reading the CA key: %w", err)
	}
	if err := checkCAKeyText(in.Key); err != nil {
		return err
	}
	a.caKey = &in
	return nil
}

func checkCAKeyText(k string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(k)))
	if block == nil || !strings.HasPrefix(block.Type, "NEBULA ") || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return errors.New("that isn't a Nebula CA key: paste everything from -----BEGIN NEBULA ... PRIVATE KEY----- to the END line")
	}
	return nil
}

// caKeyFor says where nebula-cert gets the CA key: what was handed in, else
// ca.key, else (in a terminal) a paste.
func (a *app) caKeyFor(o *pki.SignOptions) error {
	if a.caKey == nil && !a.haveCAKey() {
		if a.console {
			return errNoCAKey
		}
		text, err := a.p.Paste("\nThe CA key isn't on this machine. Paste it to sign (it is used for this run only, never saved):", "-----END ")
		if err != nil {
			return err
		}
		if err := checkCAKeyText(text); err != nil {
			return err
		}
		a.caKey = &caKeyInput{Key: text} // an encrypted key's passphrase is asked by nebula-cert
	}
	if a.caKey != nil {
		o.CAKeyPEM, o.Passphrase = []byte(a.caKey.Key), a.caKey.Passphrase
		return nil
	}
	o.CAKey = a.caDirKey()
	return nil
}

// tryCAKey signs and discards a one-minute cert with in, which proves it is
// this CA's key and that its passphrase opens it.
func (a *app) tryCAKey(in *caKeyInput) error {
	cas, err := a.tool().Inspect(a.caDirCrt())
	if err != nil {
		return err
	}
	ip := "192.0.2.1/24"
	if nets := cas[0].Networks; len(nets) > 0 {
		if p, err := netip.ParsePrefix(nets[0]); err == nil {
			ip = netip.PrefixFrom(p.Masked().Addr().Next(), p.Bits()).String()
		}
	}
	tmp, err := os.MkdirTemp("", "nebctl-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	t := a.tool()
	t.Stdin, t.Stdout, t.Stderr = nil, nil, nil
	err = t.Sign(pki.SignOptions{
		CACrt: a.caDirCrt(), CAKeyPEM: []byte(in.Key), Passphrase: in.Passphrase,
		Name: "nebctl-key-check", Networks: []string{ip}, Duration: time.Minute,
		OutCrt: filepath.Join(tmp, "check.crt"), OutKey: filepath.Join(tmp, "check.key"),
	})
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "does not match"):
		return errors.New("that key isn't this CA's key")
	case strings.Contains(err.Error(), "invalid passphrase"):
		return errors.New("that passphrase doesn't open the key")
	case strings.Contains(err.Error(), "passphrase"), strings.Contains(err.Error(), "interactively"):
		return errors.New("that key is protected by a passphrase: enter it too")
	}
	return err
}

// consoleCAKeyCheck checks a key the console was handed before it holds it.
func (a *app) consoleCAKeyCheck() (map[string]any, error) {
	if a.caKey == nil {
		return nil, errors.New("no key was given")
	}
	if err := a.tryCAKey(a.caKey); err != nil {
		return nil, err
	}
	return map[string]any{"message": "That is this CA's key"}, nil
}

// consoleCAKeyShow hands out ca.key so it can be saved before removal.
func (a *app) consoleCAKeyShow() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	data, err := os.ReadFile(a.caDirKey())
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("the CA key isn't on this machine")
	}
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"key": string(data), "encrypted": pki.IsEncryptedKey(data)})
}

// consoleCAKeyRemove deletes ca.key once the copy handed back proves to be
// a working key for this CA, so nobody removes the only copy by mistake.
func (a *app) consoleCAKeyRemove() (map[string]any, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	if !a.haveCAKey() {
		return nil, errors.New("the CA key isn't on this machine")
	}
	if a.caKey == nil {
		return nil, errors.New("paste your saved copy of the key first")
	}
	if err := a.tryCAKey(a.caKey); err != nil {
		return nil, fmt.Errorf("your copy didn't work, so the key was kept: %w", err)
	}
	if err := removeOverwritten(a.caDirKey()); err != nil {
		return nil, err
	}
	a.p.Printf("Removed %s.\n", a.caDirKey())
	return map[string]any{"message": "The CA key is off this machine. Paste it here when you sign."}, nil
}

// removeOverwritten zeroes a file before deleting it. On SSDs and
// journaling filesystems the old blocks may survive; it still keeps the key
// out of backups and casual reads from here on.
func removeOverwritten(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if fi, err := f.Stat(); err == nil {
		f.Write(make([]byte, fi.Size()))
		f.Sync()
	}
	f.Close()
	return os.Remove(path)
}
