package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// 2026-11-09: nebula's upstream releases cannot be signed, so known versions
// are pinned in source; a pinned archive must match even when upstream's own
// SHASUM256.txt (served from the same place as the archive) agrees with a
// tampered archive.

func nebulaTarGz(t *testing.T, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range Binaries {
		body := []byte(payload + n)
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func serve(t *testing.T, tag, asset string, archive []byte, shasums bool) *Release {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(archive) })
	h := sha256.Sum256(archive)
	mux.HandleFunc("/SHASUM256.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hex.EncodeToString(h[:]) + "  " + asset + "\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rel := &Release{Tag: tag, Assets: map[string]string{asset: srv.URL + "/" + asset}}
	if shasums {
		rel.Assets["SHASUM256.txt"] = srv.URL + "/SHASUM256.txt"
	}
	return rel
}

func withPins(t *testing.T, m map[string]map[string]string) {
	old := pinnedSums
	pinnedSums = m
	t.Cleanup(func() { pinnedSums = old })
}

func TestPinnedTableWellFormed(t *testing.T) {
	if len(pinnedSums) == 0 {
		t.Skip("no versions pinned")
	}
	for tag, assets := range pinnedSums {
		if !strings.HasPrefix(tag, "v") {
			t.Errorf("tag %q needs its leading v (Release.Tag has one)", tag)
		}
		for a, sum := range assets {
			if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 || sum != strings.ToLower(sum) {
				t.Errorf("%s %s: %q is not a lowercase SHA-256", tag, a, sum)
			}
		}
	}
}

func TestPinnedMatchPasses(t *testing.T) {
	const asset = "nebula-linux-amd64.tar.gz"
	good := nebulaTarGz(t, "good")
	h := sha256.Sum256(good)
	withPins(t, map[string]map[string]string{"v9.9.9": {asset: hex.EncodeToString(h[:])}})
	rel := serve(t, "v9.9.9", asset, good, false) // no upstream SHASUM256.txt at all: not needed when pinned
	files, pinned, err := Download(context.Background(), http.DefaultClient, rel, asset, t.TempDir())
	if err != nil || !pinned || len(files) != 2 {
		t.Fatalf("pinned=%v files=%d err=%v", pinned, len(files), err)
	}
}

func TestPinnedMismatchRefusesEvenIfUpstreamSumAgrees(t *testing.T) {
	const asset = "nebula-linux-amd64.tar.gz"
	good := nebulaTarGz(t, "good")
	h := sha256.Sum256(good)
	withPins(t, map[string]map[string]string{"v9.9.9": {asset: hex.EncodeToString(h[:])}})
	evil := nebulaTarGz(t, "evil") // upstream's file below is computed from this archive, so it "agrees"
	rel := serve(t, "v9.9.9", asset, evil, true)
	if _, _, err := Download(context.Background(), http.DefaultClient, rel, asset, t.TempDir()); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("tampered archive accepted or wrong error: %v", err)
	}
}

func TestUnpinnedVersionWarnsAndFallsBack(t *testing.T) {
	const asset = "nebula-linux-amd64.tar.gz"
	withPins(t, map[string]map[string]string{"v9.9.9": {asset: strings.Repeat("0", 64)}})
	arc := nebulaTarGz(t, "newer")
	rel := serve(t, "v10.0.0", asset, arc, true)
	dir := t.TempDir()
	files, pinned, err := Download(context.Background(), http.DefaultClient, rel, asset, dir)
	if err != nil || pinned {
		t.Fatalf("unpinned version: pinned=%v err=%v", pinned, err)
	}
	if _, err := os.Stat(files["nebula"]); err != nil {
		t.Fatal(err)
	}
}
