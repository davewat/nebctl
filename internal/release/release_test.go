package release

import "testing"

func TestAssetName(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, arm, want string }{
		{"darwin", "arm64", "", "nebula-darwin.zip"},
		{"darwin", "amd64", "", "nebula-darwin.zip"},
		{"linux", "amd64", "", "nebula-linux-amd64.tar.gz"},
		{"linux", "arm64", "", "nebula-linux-arm64.tar.gz"},
		{"linux", "arm", "7", "nebula-linux-arm-7.tar.gz"},
	} {
		if got, err := AssetName(tc.goos, tc.goarch, tc.arm); err != nil || got != tc.want {
			t.Errorf("AssetName(%s, %s) = %q, %v", tc.goos, tc.goarch, got, err)
		}
	}
	if _, err := AssetName("windows", "amd64", ""); err == nil {
		t.Error("windows accepted")
	}
}

func TestParseShasums(t *testing.T) {
	sums := ParseShasums([]byte("AE23  nebula-darwin.zip\nb2ee  nebula-darwin.zip/nebula\n\njunk\n"))
	if sums["nebula-darwin.zip"] != "ae23" || sums["nebula-darwin.zip/nebula"] != "b2ee" || len(sums) != 2 {
		t.Fatalf("sums = %v", sums)
	}
}
