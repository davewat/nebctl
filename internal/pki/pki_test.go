package pki

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Version 1 certs keep the public key under "details"; version 2 at the top.
const printV1 = `[{"details":{"curve":"CURVE25519","groups":[],"isCa":false,"issuer":"cd87","name":"n1","networks":["10.9.0.5/16"],"notAfter":"2027-10-28T17:02:32-04:00","notBefore":"2026-10-28T17:02:33-04:00","publicKey":"f54e","unsafeNetworks":[]},"fingerprint":"499a","version":1}]`
const printV2 = `[{"curve":"CURVE25519","details":{"groups":["a","b"],"isCa":false,"issuer":"9187","name":"h1","networks":["10.1.0.1/22"],"notAfter":"2027-10-28T16:59:31-04:00","notBefore":"2026-10-28T16:59:32-04:00","unsafeNetworks":null},"fingerprint":"07f6","publicKey":"b840","version":2}]`

func TestParsePrintJSONBothVersions(t *testing.T) {
	v1, err := ParsePrintJSON([]byte(printV1))
	if err != nil || v1[0].PublicKey != "f54e" || v1[0].Networks[0] != "10.9.0.5/16" || v1[0].Version != 1 {
		t.Fatalf("v1 = %+v, %v", v1, err)
	}
	v2, err := ParsePrintJSON([]byte(printV2))
	if err != nil || v2[0].PublicKey != "b840" || len(v2[0].Groups) != 2 || v2[0].Issuer != "9187" {
		t.Fatalf("v2 = %+v, %v", v2, err)
	}
}

// TestKeysMatchCerts runs the real nebula-cert: set NEBULA_CERT or put it on PATH.
func TestKeysMatchCerts(t *testing.T) {
	bin := os.Getenv("NEBULA_CERT")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("nebula-cert"); err != nil {
			t.Skip("nebula-cert not found")
		}
	}
	tool := Tool{Bin: bin}
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	for _, curve := range []string{"25519", "P256"} {
		t.Run(curve, func(t *testing.T) {
			ca, key := p(curve+"ca.crt"), p(curve+"ca.key")
			if out, err := exec.Command(bin, "ca", "-name", "t", "-curve", curve, "-out-crt", ca, "-out-key", key).CombinedOutput(); err != nil {
				t.Fatalf("%s", out)
			}
			if err := tool.Sign(SignOptions{CACrt: ca, CAKey: key, Name: "h", Networks: []string{"10.0.0.1/24"},
				OutCrt: p(curve + "h.crt"), OutKey: p(curve + "h.key")}); err != nil {
				t.Fatal(err)
			}
			certs, err := tool.Inspect(p(curve + "h.crt"))
			if err != nil {
				t.Fatal(err)
			}
			hostKey, _ := os.ReadFile(p(curve + "h.key"))
			if ok, err := KeyMatches(hostKey, certs[0]); err != nil || !ok {
				t.Fatalf("host key does not match its cert: %v", err)
			}
			cas, _ := tool.Inspect(ca)
			if ok, _ := KeyMatches(hostKey, cas[0]); ok {
				t.Fatal("host key matched the CA")
			}
			if curve == "25519" {
				caKey, _ := os.ReadFile(key)
				if ok, err := KeyMatches(caKey, cas[0]); err != nil || !ok {
					t.Fatalf("CA key does not match the CA: %v", err)
				}
			}
		})
	}
	// A signed public key matches the cert issued for it.
	if err := tool.Keygen(p("k.key"), p("k.pub")); err != nil {
		t.Fatal(err)
	}
	if err := tool.Sign(SignOptions{CACrt: p("25519ca.crt"), CAKey: p("25519ca.key"), Name: "r",
		Networks: []string{"10.0.0.2/24"}, InPub: p("k.pub"), OutCrt: p("r.crt")}); err != nil {
		t.Fatal(err)
	}
	crt, _ := os.ReadFile(p("r.crt"))
	certs, err := tool.InspectPEM(crt)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := os.ReadFile(p("k.key"))
	if ok, _ := KeyMatches(k, certs[0]); !ok {
		t.Fatal("requested key does not match its cert")
	}
}
