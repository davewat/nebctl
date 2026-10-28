# nebctl

Installs, updates and sets up [Nebula](https://github.com/slackhq/nebula) on
macOS and Linux: a lighthouse, the nodes that join it, and the CA that signs
their certificates. Run it with no arguments and answer the questions.

```bash
sudo nebctl
```

It is one static binary with no dependencies beyond the Go standard library.
Nebula itself is downloaded from the official `slackhq/nebula` releases and
checked against the release's `SHASUM256.txt` before it is installed.

## Getting nebctl

Binaries for macOS and Linux are on the
[releases page](https://github.com/davewat/nebctl/releases). The repo is
private, so download with `gh` (or copy the binary over with `scp`):

```bash
gh release download v0.1.0 -R davewat/nebctl -p nebctl-linux-amd64 -p SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS
sudo install -m 0755 nebctl-linux-amd64 /usr/local/bin/nebctl
```

Pick `nebctl-darwin-arm64` (Apple silicon), `nebctl-darwin-amd64` (Intel
Mac), `nebctl-linux-amd64`, `nebctl-linux-arm64` or `nebctl-linux-arm`.

## A new network in three steps

1. **On the lighthouse** (a machine with a public IP):
   `sudo nebctl lighthouse` → *Create a new CA here*. It installs nebula,
   creates the CA, signs the lighthouse's cert, writes the config, starts the
   service, then offers to sign certs for other hosts. Each one comes out as a
   **bundle**: a block of text to paste on that host.
2. **On each other host**: `sudo nebctl node` → *Paste a bundle*.
3. Check with `nebctl status`, then `ping` the lighthouse's Nebula address.

### Keeping private keys on their own machines

The bundle from `ca sign` carries the new host's private key. To avoid moving
keys around, use a request instead:

1. On the new host: `sudo nebctl node` → *Keep the private key here*. It
   prints a **request** that contains only the public key.
2. On the CA host: `sudo nebctl ca sign-request`, then paste the request.
   You get back a bundle with no key in it, which is safe to send by chat.
3. Paste that bundle back on the new host.

### Already have a CA and certs?

On the lighthouse, `sudo nebctl lighthouse` → *Import an existing CA*, and
point it at your `ca.crt`. Any certs that CA has already signed and that sit
in the same directory are recorded, so their addresses are never handed out
again. To give an existing cert to its host, run
`sudo nebctl ca bundle -crt fe01.crt -key fe01.key`.

## Where things go

| Path | What |
|---|---|
| `/usr/local/bin/nebula`, `nebula-cert` | the nebula binaries |
| `/etc/nebula/config.yml` | nebula's config, generated (`nebula -test` must pass before it replaces the old one) |
| `/etc/nebula/nebctl.json` | this host's answers; `sudo nebctl config` regenerates the config from it |
| `/etc/nebula/ca.crt`, `host.crt`, `host.key` | this host's certs |
| `/etc/nebula/ca/` (0700) | the CA, if this machine holds it: `ca.key`, `network.json` (address range, lighthouses, signed certs) and `issued/` |
| `/etc/systemd/system/nebula.service` | the Linux service |
| `/Library/LaunchDaemons/net.nebctl.nebula.plist` | the macOS service; logs go to `/var/log/nebula.log` |

Back up `/etc/nebula/ca/ca.key` somewhere offline. Host certs expire when the
CA does; `nebctl status` warns 30 days ahead, and signing the same name
again renews the cert at the same address.

## Commands

```
lighthouse | node | request | config | status
install [-version vX.Y.Z] [-force]     update [-version vX.Y.Z] [-force]
service start|stop|restart|status|uninstall
ca init | import | sign | sign-request | bundle | lighthouse | list
```

Global flags: `-root DIR` puts every path under DIR and skips the service
(for trying it out without sudo), `-repo owner/name` picks another release
source, and `-no-service` writes the config without starting nebula.

## Building

```bash
make release   # dist/nebctl-{darwin,linux}-{arm64,amd64}, linux-arm, SHA256SUMS
make test   # NEBULA_CERT=/path/to/nebula-cert also runs the key-matching tests
```
