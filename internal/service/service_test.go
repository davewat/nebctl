package service

import (
	"strings"
	"testing"
)

func TestUnitSetsNebulaDNS(t *testing.T) {
	u := unit("/usr/local/bin/nebula", "/etc/nebula/config.yml", DNS{
		Resolvectl: "/usr/bin/resolvectl", Dev: "nebula1",
		Servers: []string{"10.221.221.1"}, Domain: "nebula.solidpath.com",
	})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/nebula -config /etc/nebula/config.yml\n" +
			"ExecStartPost=-/usr/bin/resolvectl dns nebula1 10.221.221.1\n" +
			"ExecStartPost=-/usr/bin/resolvectl domain nebula1 ~nebula.solidpath.com\n" +
			"ExecStartPost=-/usr/bin/resolvectl default-route nebula1 false\n" +
			"Restart=always\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	if u := unit("/n", "/c", DNS{}); strings.Contains(u, "ExecStartPost") {
		t.Errorf("unit without DNS has ExecStartPost:\n%s", u)
	}
}
