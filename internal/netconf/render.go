package netconf

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Files are the paths config.yml points at.
type Files struct {
	CACrt, HostCrt, HostKey string
	State                   string // nebctl.json, named in the header
	// The admin server's host key file, and the public key (authorized_keys
	// form) allowed to log in to it as user "nebctl".
	AdminHostKey, AdminUserKey string
}

// AdminUser is the name nebctl logs in to nebula's admin server as.
const AdminUser = "nebctl"

// Render writes nebula's config.yml for h. On macOS the tun device is left
// for nebula to pick (it must be a utun device).
func Render(h Host, f Files, goos string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	q := strconv.Quote

	self := ""
	if p, err := netip.ParsePrefix(h.NebulaIP); err == nil {
		self = p.Addr().String()
	}
	var others []Lighthouse
	for _, l := range h.Lighthouses {
		if l.NebulaIP != self {
			others = append(others, l)
		}
	}
	lighthouse := h.Role == RoleLighthouse

	w("# Written by nebctl from %s.", f.State)
	w("# Run `sudo nebctl config` to regenerate; edits here are overwritten.")
	w("pki:")
	w("  ca: %s", q(f.CACrt))
	w("  cert: %s", q(f.HostCrt))
	w("  key: %s", q(f.HostKey))
	if len(h.Blocklist) > 0 {
		w("  blocklist:")
		for _, fp := range h.Blocklist {
			w("    - %s", q(fp))
		}
	}
	w("")
	if len(others) == 0 {
		w("static_host_map: {}")
	} else {
		w("static_host_map:")
		for _, l := range others {
			eps := make([]string, len(l.Endpoints))
			for i, e := range l.Endpoints {
				eps[i] = q(e)
			}
			w("  %s: [%s]", q(l.NebulaIP), strings.Join(eps, ", "))
		}
	}
	w("")
	w("lighthouse:")
	if lighthouse {
		w("  am_lighthouse: true")
		if h.DNS && self != "" {
			w("  serve_dns: true")
			w("  dns:")
			w("    host: %s", q(self))
			w("    port: 53")
		}
	} else {
		w("  am_lighthouse: false")
		w("  interval: 60")
		w("  hosts:")
		for _, l := range others {
			w("    - %s", q(l.NebulaIP))
		}
	}
	w("")
	w("listen:")
	w("  host: %s", q("0.0.0.0"))
	w("  port: %d", h.ListenPort)
	w("")
	w("punchy:")
	w("  punch: true")
	w("  respond: true")
	w("")
	w("relay:")
	if lighthouse {
		w("  am_relay: %t", h.Relay)
		w("  use_relays: false")
	} else {
		var relays []string
		for _, l := range others {
			if l.Relay {
				relays = append(relays, l.NebulaIP)
			}
		}
		w("  use_relays: %t", len(relays) > 0)
		if len(relays) > 0 {
			w("  relays:")
			for _, r := range relays {
				w("    - %s", q(r))
			}
		}
	}
	w("")
	w("tun:")
	if goos == "darwin" {
		w("  disabled: false")
	} else {
		w("  dev: nebula1")
	}
	w("")
	w("logging:")
	w("  level: %s", h.LogLevel())
	w("  format: %s", h.LogFormat())
	w("")
	if h.Admin != nil && f.AdminHostKey != "" && f.AdminUserKey != "" {
		w("sshd:")
		w("  enabled: true")
		w("  listen: %s", q(h.Admin.Listen))
		w("  host_key: %s", q(f.AdminHostKey))
		w("  authorized_users:")
		w("    - user: %s", AdminUser)
		w("      keys:")
		w("        - %s", q(strings.TrimSpace(f.AdminUserKey)))
		w("")
	}
	if h.Metrics != nil {
		w("stats:")
		w("  type: prometheus")
		w("  listen: %s", q(h.Metrics.Listen))
		w("  path: /metrics")
		w("  namespace: nebula")
		w("  interval: 10s")
		w("")
	}
	w("firewall:")
	w("  outbound:")
	w("    - port: any")
	w("      proto: any")
	w("      host: any")
	inbound := Inbound(h)
	if len(inbound) == 0 {
		w("  inbound: []")
	} else {
		w("  inbound:")
		for _, r := range inbound {
			w("    - port: %s", q(r.Port))
			w("      proto: %s", r.Proto)
			switch {
			case r.Group != "":
				w("      group: %s", q(r.Group))
			case r.Host != "":
				w("      host: %s", q(r.Host))
			default:
				w("      host: any")
			}
		}
	}
	return b.String()
}

// Inbound is the inbound rules nebula's firewall gets: h's own, plus DNS on
// a lighthouse that answers it.
func Inbound(h Host) []Rule {
	inbound := h.Inbound
	if h.Role == RoleLighthouse && h.DNS && !allows(inbound, DNSRule) {
		inbound = append(inbound[:len(inbound):len(inbound)], DNSRule)
	}
	return inbound
}

// allows reports whether rules already let want's traffic in from any host.
func allows(rules []Rule, want Rule) bool {
	for _, r := range rules {
		if (r.Proto == want.Proto || r.Proto == "any") && (r.Port == want.Port || r.Port == "any") &&
			(r.Host == "any" || r.Host == "") && r.Group == "" {
			return true
		}
	}
	return false
}
