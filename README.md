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

## Setup

Set up the lighthouse first: it holds the CA that signs every other host's
cert. Then add Linux and macOS nodes in any order.

The repo is private, so downloads go through `gh` (signed in to GitHub). If a
machine has no `gh`, download on your Mac and copy the file over with `scp`.

| Machine | `uname -m` says | File |
|---|---|---|
| Linux x86-64 | `x86_64` | `nebctl-linux-amd64` |
| Linux ARM64 | `aarch64` | `nebctl-linux-arm64` |
| Linux ARMv5-7 | `armv7l`, `armv6l` | `nebctl-linux-arm` |
| Apple silicon Mac | `arm64` | `nebctl-darwin-arm64` |
| Intel Mac | `x86_64` | `nebctl-darwin-amd64` |

### 1. Linux lighthouse

Needs a public IP (or DNS name) and UDP 4242 reachable from the internet.

1. Download and install nebctl:
   ```bash
   gh release download v0.1.0 -R davewat/nebctl -p nebctl-linux-amd64 -p SHA256SUMS
   sha256sum -c --ignore-missing SHA256SUMS
   sudo install -m 0755 nebctl-linux-amd64 /usr/local/bin/nebctl
   ```
   No `gh` on the server? On your Mac, run the `gh release download` line,
   then `scp nebctl-linux-amd64 root@<server>:/usr/local/bin/nebctl`, and
   `chmod 0755 /usr/local/bin/nebctl` on the server.
2. Run the lighthouse setup. It installs nebula itself if it is missing:
   ```bash
   sudo nebctl lighthouse
   ```
3. Answer the questions:

   | Question | Answer |
   |---|---|
   | Install the latest release now? | Enter for yes |
   | How should this host get its certificate? | `1` Create a new CA (a new network), or `2` Import an existing CA (see below) |
   | Name for the CA | your organisation or domain, e.g. `Example.com` |
   | Nebula network | the private range for the network, e.g. `10.42.0.0/22` |
   | Years the CA is valid | Enter for 5; every host cert expires with the CA |
   | Protect ca.key with a passphrase? | Enter for no, or `y` to be asked on every signing |
   | Host name for the cert | this server's name, e.g. `hs01.example.com` |
   | Nebula address | Enter for the first free address, or type one |
   | Groups | Enter for none |
   | UDP port to listen on | Enter for 4242 |
   | Public IP or DNS name | Enter if the detected IP is right, else type it |
   | Relay traffic for hosts that can't reach each other directly? | Enter for yes |
   | What may other Nebula hosts reach on this one? | `1` Ping and SSH |
   | Other ports to open | e.g. `tcp/443`, or Enter for none |
   | Sign a cert for another host now? | `y` once per host, then `n` (or do it later, see step 6) |

4. Open the UDP port, here and in your cloud provider's firewall:
   ```bash
   sudo ufw allow 4242/udp
   ```
5. Check that nebula is running:
   ```bash
   sudo nebctl status
   ```
   ```bash
   journalctl -u nebula -f
   ```
6. Sign a cert for each other host. Each run prints a **bundle**: copy
   everything from `-----BEGIN NEBCTL BUNDLE-----` to the `END` line.
   ```bash
   sudo nebctl ca sign
   ```
   The bundle holds that host's private key, so move it over SSH or a
   password manager, not chat or email. To keep keys off the lighthouse, use
   a request instead (see [Keeping a node's key on the node](#keeping-a-nodes-key-on-the-node)).

7. Audit the server's security. The lighthouse faces the internet, so check
   the machine around nebula too:
   ```bash
   sudo nebctl audit
   ```
   See [Security audit](#security-audit) for what it checks.

**Already have a CA?** In step 3, choose `2` Import an existing CA and give
the path to `ca.crt` (e.g. `/data/ca.crt`); `ca.key` is looked for beside it.
Certs that CA already signed in the same directory are recorded, so their
addresses are never handed out again. Signing one of those names again
renews it at the same address. To give a host the cert files you made
earlier, instead of a new cert:
```bash
sudo nebctl ca bundle -crt /data/fe01.example.com.crt -key /data/fe01.example.com.key
```

### 2. Linux node

1. Download and install nebctl:
   ```bash
   gh release download v0.1.0 -R davewat/nebctl -p nebctl-linux-amd64 -p SHA256SUMS
   sha256sum -c --ignore-missing SHA256SUMS
   sudo install -m 0755 nebctl-linux-amd64 /usr/local/bin/nebctl
   ```
2. On the lighthouse, sign a cert for this node and copy the bundle:
   ```bash
   sudo nebctl ca sign
   ```
3. On the node, run the node setup:
   ```bash
   sudo nebctl node
   ```
4. Answer the questions:

   | Question | Answer |
   |---|---|
   | Install the latest release now? | Enter for yes |
   | How should this host get its certificate? | `1` Paste a bundle, then paste it |
   | What may other Nebula hosts reach on this one? | `1` Ping and SSH |
   | Other ports to open | the ports this node serves, e.g. `tcp/443`, or Enter for none |

5. Check it reaches the lighthouse (use the lighthouse's Nebula address):
   ```bash
   ping 10.42.0.1
   ```
   ```bash
   sudo nebctl status
   ```

### 3. macOS node

1. Download and install nebctl (`nebctl-darwin-amd64` on an Intel Mac):
   ```bash
   gh release download v0.1.0 -R davewat/nebctl -p nebctl-darwin-arm64 -p SHA256SUMS
   shasum -a 256 -c --ignore-missing SHA256SUMS
   sudo mkdir -p /usr/local/bin
   sudo install -m 0755 nebctl-darwin-arm64 /usr/local/bin/nebctl
   ```
   Downloaded through a browser instead? Clear the quarantine flag first:
   `xattr -d com.apple.quarantine nebctl-darwin-arm64`.
2. On the lighthouse, sign a cert for this Mac and copy the bundle:
   ```bash
   sudo nebctl ca sign
   ```
3. On the Mac, run the node setup:
   ```bash
   sudo nebctl node
   ```
4. Answer the questions:

   | Question | Answer |
   |---|---|
   | Install the latest release now? | Enter for yes |
   | How should this host get its certificate? | `1` Paste a bundle, then paste it |
   | What may other Nebula hosts reach on this one? | `2` Ping only (or `1` if you SSH into this Mac) |
   | Other ports to open | Enter for none |

   If macOS asks whether `nebula` may accept incoming connections, allow it.
5. Check it reaches the lighthouse:
   ```bash
   ping 10.42.0.1
   ```
   ```bash
   sudo nebctl status
   ```
   ```bash
   tail -f /var/log/nebula.log
   ```

### Keeping a node's key on the node

Instead of steps 2 to 4 above, so the private key never leaves the node:

1. On the node, make a request. It holds only the public key, so chat or
   email is fine:
   ```bash
   sudo nebctl request
   ```
2. On the lighthouse, paste the request and copy the bundle it prints:
   ```bash
   sudo nebctl ca sign-request
   ```
3. On the node, run `sudo nebctl node`, choose `1` Paste a bundle, and paste it.

### Later

| Task | Command |
|---|---|
| Update nebula on any host (restarts it) | `sudo nebctl update` |
| Change a host's firewall or lighthouses | `sudo nebctl node` (or `lighthouse`), keep the cert, answer again |
| Renew a host's cert | on the lighthouse `sudo nebctl ca sign` with the same name; on the host `sudo nebctl node`, answer `n` to "Keep it?", paste the bundle |
| List every signed cert | `sudo nebctl ca list` |
| Stop or start nebula | `sudo nebctl service stop` / `start` |
| Review this machine's security | `sudo nebctl audit` |

### Security audit

`sudo nebctl audit` reviews the machine nebula runs on and prints each
finding as FAIL, WARN, info or pass. Under every finding that needs work are
the commands that fix it. The audit only reads: it changes nothing. It exits 1
while any FAIL remains, so it can run from cron; `-json` prints the findings
for scripts, and `-offline` skips asking GitHub for the latest nebula.

| Section | Checks |
|---|---|
| Nebula | the service is running; no other nebula was started by hand; nebula is the latest release; the host and CA certs aren't near expiry; only root can read the keys or change the config and binaries; whether `ca.key` sits on an internet-facing host without a passphrase; nebula's own firewall doesn't let every host reach every port |
| Firewall | ufw (or nftables/iptables) is on and denies inbound by default; on a lighthouse, ufw allows its UDP port |
| Listening ports | every service on a public address other than nebula and SSH, and whether the firewall lets the internet reach it |
| SSH | keys only, no root login, and SSH open only to the Nebula network; fail2ban or sshguard where SSH faces the internet |
| Updates | unattended-upgrades is on, no security updates are waiting, no reboot is pending |
| Kernel | SYN cookies, reverse-path filtering, no ICMP redirects or source routing |
| Accounts | only root has UID 0, no account has an empty password, and who can log in |

The host checks cover Ubuntu and Debian; on macOS only nebula's own setup
is checked. The audit can't see your cloud provider's firewall: check that
it lets in only the lighthouse's UDP port and SSH.

Once nebula works, the biggest gain is usually SSH over Nebula only. Do it
from a session over Nebula, with your provider's web console as a way back
in (the audit prints the exact rules):
```bash
sudo ufw allow from 10.42.0.0/22 to any port 22 proto tcp
```
```bash
sudo ufw delete allow OpenSSH
```

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
lighthouse | node | request | config | status | audit [-json] [-offline]
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
