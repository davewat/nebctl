// Package relsig verifies the signature on a nebctl release's SHA256SUMS.
//
// The release carries a sibling asset SHA256SUMS.sig: the standard padded
// base64 of a 64-byte plain Ed25519 signature over the exact bytes of
// SHA256SUMS, then a newline. The public key is pinned here as one line,
// "solidkit-release-ed25519 <base64 of the raw 32-byte key>". Standard
// library only.
package relsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PublicKeyLine is the release signing key nebctl trusts. It is the key
// that `solidctl signing-key show` prints; rotating it is a code change.
const PublicKeyLine = "solidkit-release-ed25519 XilRRKs3aMp0eJOm0/4Z8IydMPw1/jkpGui4JPjETC8="

const keyPrefix = "solidkit-release-ed25519"

// ErrBadSignature means a signature file is present but does not verify
// (or is malformed). Callers must never offer to override it.
var ErrBadSignature = errors.New("release signature does not verify")

// ParsePublicKey reads "solidkit-release-ed25519 <base64>" strictly: that
// prefix, one space-separated field, and exactly 32 decoded bytes. Only
// whitespace around the whole line is ignored.
func ParsePublicKey(line string) (ed25519.PublicKey, error) {
	f := strings.Split(strings.TrimSpace(line), " ")
	if len(f) != 2 || f[0] != keyPrefix {
		return nil, fmt.Errorf("public key must read %q followed by the key", keyPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return nil, fmt.Errorf("public key is not standard padded base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Pinned is the parsed PublicKeyLine.
func Pinned() ed25519.PublicKey {
	k, err := ParsePublicKey(PublicKeyLine)
	if err != nil {
		panic("relsig: the pinned key is malformed: " + err.Error())
	}
	return k
}

// Verify checks sigFile (the .sig asset's bytes) over data. Only whitespace
// around the .sig is trimmed; the base64 must be standard, padded and decode
// to exactly 64 bytes. Every failure wraps ErrBadSignature.
func Verify(pub ed25519.PublicKey, data, sigFile []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes", ErrBadSignature, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil {
		return fmt.Errorf("%w: the .sig is not standard padded base64", ErrBadSignature)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the .sig decodes to %d bytes, want %d", ErrBadSignature, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}
