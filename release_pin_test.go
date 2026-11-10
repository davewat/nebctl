package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 2026-11-09: nebctl's own release must carry a valid Ed25519 signature on
// SHA256SUMS (a checksum fetched beside the binary only detects corruption).

func releaseServer(t *testing.T, sums string, sig *string, bin []byte) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums)) })
	if sig != nil {
		mux.HandleFunc("/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(*sig)) })
	}
	mux.HandleFunc("/nebctl-linux-amd64", func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/"
}

func TestFetchNebctlRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("the real nebctl build")
	h := sha256.Sum256(bin)
	sums := hex.EncodeToString(h[:]) + "  nebctl-linux-amd64\n"
	sign := func(data string) *string {
		s := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(data))) + "\n"
		return &s
	}
	ctx := context.Background()

	t.Run("valid signature passes", func(t *testing.T) {
		srv, base := releaseServer(t, sums, sign(sums), bin)
		got, unsigned, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, false)
		if err != nil || unsigned || string(got) != string(bin) {
			t.Fatalf("got %q unsigned=%v err=%v", got, unsigned, err)
		}
	})
	t.Run("modified SHA256SUMS fails even with opt-in", func(t *testing.T) {
		evil := sha256.Sum256([]byte("evil"))
		tampered := hex.EncodeToString(evil[:]) + "  nebctl-linux-amd64\n"
		srv, base := releaseServer(t, tampered, sign(sums), []byte("evil"))
		for _, allow := range []bool{false, true} {
			if _, _, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, allow); err == nil || errors.Is(err, errUnsignedRelease) {
				t.Fatalf("allow=%v: tampered SHA256SUMS accepted or called unsigned: %v", allow, err)
			}
		}
	})
	t.Run("wrong key fails", func(t *testing.T) {
		srv, base := releaseServer(t, sums, sign(sums), bin)
		if _, _, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", otherPub, true); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
	t.Run("missing sig refuses without opt-in and passes with it", func(t *testing.T) {
		srv, base := releaseServer(t, sums, nil, bin)
		if _, _, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, false); !errors.Is(err, errUnsignedRelease) {
			t.Fatalf("want errUnsignedRelease, got %v", err)
		}
		got, unsigned, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, true)
		if err != nil || !unsigned || string(got) != string(bin) {
			t.Fatalf("opt-in: unsigned=%v err=%v", unsigned, err)
		}
	})
	t.Run("unsigned release still checks the binary hash", func(t *testing.T) {
		srv, base := releaseServer(t, sums, nil, []byte("swapped"))
		if _, _, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, true); err == nil || !strings.Contains(err.Error(), "doesn't match") {
			t.Fatalf("want hash mismatch, got %v", err)
		}
	})
	t.Run("bad sig refuses even with opt-in", func(t *testing.T) {
		garbage := "not a signature\n"
		srv, base := releaseServer(t, sums, &garbage, bin)
		for _, allow := range []bool{false, true} {
			_, _, err := fetchNebctlRelease(ctx, srv.Client(), base, "nebctl-linux-amd64", pub, allow)
			if err == nil || errors.Is(err, errUnsignedRelease) {
				t.Fatalf("allow=%v: bad .sig accepted or treated as unsigned: %v", allow, err)
			}
		}
	})
}
