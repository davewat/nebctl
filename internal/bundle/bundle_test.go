package bundle

import (
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
)

func TestBundleSurvivesPasteMangling(t *testing.T) {
	b := Bundle{Name: "fe01", CACrt: "ca", HostCrt: "crt", HostKey: "key",
		Lighthouses: []netconf.Lighthouse{{NebulaIP: "10.0.0.1", Endpoints: []string{"1.2.3.4:4242"}, Relay: true}}}
	text, err := EncodeBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(text, "\n") {
		if len(l) > 64 && !strings.HasPrefix(l, "-----") {
			t.Fatalf("line longer than 64: %q", l)
		}
	}
	// Terminals add indentation, CRs and surrounding chatter.
	mangled := "here you go:\r\n" + strings.ReplaceAll(text, "\n", "\r\n   ") + "\nthanks"
	got, err := DecodeBundle(mangled)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "fe01" || got.HostKey != "key" || len(got.Lighthouses) != 1 || !got.Lighthouses[0].Relay {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeRejectsTruncatedAndWrongKind(t *testing.T) {
	text, _ := EncodeRequest(Request{Name: "n", PublicKey: "pub"})
	if _, err := DecodeBundle(text); err == nil {
		t.Fatal("a request decoded as a bundle")
	}
	lines := strings.Split(text, "\n")
	cut := strings.Join(append(lines[:2:2], lines[len(lines)-2:]...), "\n")
	if _, err := DecodeRequest(cut); err == nil && len(lines) > 4 {
		t.Fatal("a truncated request decoded")
	}
	if r, err := DecodeRequest(text); err != nil || r.Name != "n" {
		t.Fatalf("DecodeRequest = %+v, %v", r, err)
	}
}
