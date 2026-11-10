package relsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// 2026-11-09: guards the release-signature check on nebctl's own releases
// (a signed SHA256SUMS must verify; anything else must not).

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sigFile(priv ed25519.PrivateKey, data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
}

func TestPinnedKeyParses(t *testing.T) {
	k, err := ParsePublicKey(PublicKeyLine)
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatalf("pinned key: %v (%d bytes)", err, len(k))
	}
	_ = Pinned() // must not panic
}

func TestParsePublicKeyStrict(t *testing.T) {
	pub, _ := keypair(t)
	good := keyPrefix + " " + base64.StdEncoding.EncodeToString(pub)
	if _, err := ParsePublicKey(" " + good + "\n"); err != nil {
		t.Fatalf("surrounding whitespace: %v", err)
	}
	for name, line := range map[string]string{
		"wrong prefix": "other-key " + base64.StdEncoding.EncodeToString(pub),
		"no prefix":    base64.StdEncoding.EncodeToString(pub),
		"short key":    keyPrefix + " " + base64.StdEncoding.EncodeToString(pub[:31]),
		"unpadded":     keyPrefix + " " + strings.TrimRight(base64.StdEncoding.EncodeToString(pub), "="),
		"extra field":  good + " extra",
		"empty":        "",
	} {
		if _, err := ParsePublicKey(line); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerify(t *testing.T) {
	pub, priv := keypair(t)
	data := []byte("abc  nebctl-linux-amd64\n")

	if err := Verify(pub, data, sigFile(priv, data)); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	if err := Verify(pub, append([]byte("x"), data...), sigFile(priv, data)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("modified SHA256SUMS passed: %v", err)
	}
	other, _ := keypair(t)
	if err := Verify(other, data, sigFile(priv, data)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key passed: %v", err)
	}
	for name, sf := range map[string][]byte{
		"empty":      nil,
		"not base64": []byte("!!!!\n"),
		"short":      []byte(base64.StdEncoding.EncodeToString(make([]byte, 63))),
		"long":       []byte(base64.StdEncoding.EncodeToString(make([]byte, 65))),
		"unpadded":   []byte(strings.TrimRight(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)), "=")),
	} {
		if err := Verify(pub, data, sf); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s .sig: %v", name, err)
		}
	}
}
