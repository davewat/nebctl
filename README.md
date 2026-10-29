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
   gh release download -R davewat/nebctl -p nebctl-linux-amd64 -p SHA256SUMS --clobber
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
   | Domain for Nebula host names | Enter for the suggestion, e.g. `nebula.example.com` (see [Names over Nebula](#names-over-nebula-dns)); `-` for none |
   | Host name for the cert | a short name such as `hs01`; it gets the domain: `hs01.nebula.example.com` |
   | Nebula address | Enter for the first free address, or type one |
   | Groups | Enter for none |
   | UDP port to listen on | Enter for 4242 |
   | Public IP or DNS name | Enter if the detected IP is right, else type it |
   | Relay traffic for hosts that can't reach each other directly? | Enter for yes |
   | Answer DNS for *.nebula.example.com? | Enter for yes |
   | What may other Nebula hosts reach on this one? | `1` Ping and SSH |
   | Other ports to open | e.g. `tcp/443`, or Enter for none |
   | Look up *.nebula.example.com through 10.42.0.1? | Enter for yes |
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
renews it at the same address. If their names aren't under the Nebula
domain, sign each one's short name (`fe01` for `fe01.example.com`) and
nebctl offers to rename it, keeping its address and groups. To give a host the cert files you made
earlier, instead of a new cert:
```bash
sudo nebctl ca bundle -crt /data/fe01.example.com.crt -key /data/fe01.example.com.key
```

### 2. Linux node

1. Download and install nebctl:
   ```bash
   gh release download -R davewat/nebctl -p nebctl-linux-amd64 -p SHA256SUMS --clobber
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
   | Look up *.nebula.example.com through 10.42.0.1? | Enter for yes |

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
   gh release download -R davewat/nebctl -p nebctl-darwin-arm64 -p SHA256SUMS --clobber
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
   | Look up *.nebula.example.com through 10.42.0.1? | Enter for yes |

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

### macOS app (Nebula Node)

A Mac app that runs the same node setup as `sudo nebctl node`, in a window.
It carries its own nebctl, so it needs no Terminal steps. It asks the same
questions (install nebula, certificate, lighthouses, firewall, DNS) and
changes the Mac through the standard administrator password prompt.

1. Download it, check it and put it in Applications:
   ```bash
   gh release download -R davewat/nebctl -p NebulaNode-macos.zip -p SHA256SUMS --clobber
   ```
   ```bash
   shasum -a 256 -c --ignore-missing SHA256SUMS
   ```
   ```bash
   ditto -x -k NebulaNode-macos.zip /Applications
   ```
2. It is signed ad hoc, not notarized, so clear the download flag once (else
   macOS says it can't check the app):
   ```bash
   xattr -cr "/Applications/Nebula Node.app"
   ```
3. On the lighthouse, sign a cert for this Mac (`sudo nebctl ca sign`), or
   choose "Keep the private key here" in the app for a request instead.
4. Open Nebula Node, click **Set Up This Mac as a Node**, and follow it.
   Each step matches the table in section 3.

The window also shows the setup, cert expiry and service, with Start, Stop
and Restart. Signing this Mac's cert with a CA held on this Mac stays in
Terminal (`sudo nebctl node`).

**Open Admin Console** starts the admin console (below) after one password
prompt and shows it in a second window. Its **Open in browser** button
moves it to your browser. The console stops when you close its window or
quit the app. The app carries Linux builds of its nebctl, so the console
can install a matching nebctl on a lighthouse it connects to.

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
| Update nebctl itself | repeat step 1 (`--clobber` replaces the file downloaded last time), then `nebctl -version` |
| Update nebula on any host (restarts it) | `sudo nebctl update` |
| Change a host's firewall or lighthouses | `sudo nebctl node` (or `lighthouse`), keep the cert, answer again |
| Renew a host's cert | on the lighthouse `sudo nebctl ca sign` with the same name; on the host `sudo nebctl node`, answer `n` to "Keep it?", paste the bundle |
| List every signed cert | `sudo nebctl ca list` |
| Stop or start nebula | `sudo nebctl service stop` / `start` |
| Review this machine's security | `sudo nebctl audit` |
| Turn on, change or turn off Nebula DNS | `sudo nebctl dns` |
| See who's connected, sign or revoke certs, change the firewall or logging, forward logs to a SIEM | `sudo nebctl web` (see below) |

### Admin console (`nebctl web`)

```bash
sudo nebctl web
```

This opens the admin console in your browser. It is a web page served by
nebctl on `127.0.0.1` only, behind a link that works once. Press Ctrl+C to
stop it. It manages this machine, and any machine you connect it to over
SSH, usually the lighthouse:

| Page | What it does |
|---|---|
| Map | The network as this machine sees it: the lighthouse, each host, direct and relayed tunnels, hosts still handshaking. Click a host for its cert, addresses and relays, and to close or re-open its tunnel, try another address, or ask the lighthouse where it is. |
| Hosts | The same as a table, plus the lighthouse's address map (where it last saw each host). |
| Certificates | On the machine holding the CA: sign a cert for a new host (the bundle appears once, with its key), sign a request, renew one, or revoke one and push the blocklist to other machines. |
| Config | Nebula's firewall rules, the lighthouse's DNS, relay and port, a node's lighthouses, log level and format, and Prometheus metrics. Changes must pass `nebula -test`; most apply with a reload, and the port needs a restart. |
| Logs | Nebula's log, live, and forwarding it to a SIEM. |
| Health | Versions (with an update when nebula has a newer release), the service, cert and CA expiry, tunnel counts, metrics, and the security audit. |

**Admin access.** The console reads connections from nebula's own SSH admin
server (`list-hostmap` and the rest). nebctl turns it on for new setups, on
`127.0.0.1:2242`, for a key only nebctl holds (`/etc/nebula/admin/`). A host
set up before v0.5.0 shows a **Turn on admin access** button; it restarts
nebula once.

**Managing the lighthouse from another machine.** Choose **Connect to another
machine** at the top and give the lighthouse's address and your SSH login
(password, key file, or ssh-agent with `sudo --preserve-env=SSH_AUTH_SOCK nebctl web`).
The first time, check the host key's fingerprint before trusting it (on the
lighthouse: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). The console
runs `sudo nebctl app ...` there, so the CA key never leaves the lighthouse.
If nebctl is missing or older there, it offers to install a matching one.
Trusted host keys are kept in `/etc/nebula/admin/known_hosts`.

**Revoking a cert.** Nebula has no central revocation: each host refuses a
cert only when the cert's fingerprint is on its own blocklist. After revoking,
the console offers to push the list to every machine it is connected to.
Each one reloads nebula, which drops the revoked host's tunnel within a few
seconds. Connect to the hosts that matter before revoking, or push again
later.

**Sending logs to a SIEM (Linux).** Nebula writes its log to the journal.
On the Logs page, give the SIEM's syslog address and protocol (UDP, TCP, or
TLS with the CA that signed the SIEM's certificate). nebctl switches nebula
to JSON logs and writes an rsyslog rule that forwards nebula's lines in
RFC 5424 format. **Send test event** sends one line to search for. TLS needs
`sudo apt install rsyslog-gnutls`. macOS has no rsyslog: point your SIEM's
agent at `/var/log/nebula.log` instead.

### Names over Nebula (DNS)

Hosts can reach each other by name, such as `ssh fe01.nebula.example.com`,
instead of by Nebula address. Each lighthouse can answer DNS on its Nebula
address (port 53, reachable over Nebula only). It answers with the address
of every host that is connected, looked up by the name in that host's cert.
Every host sends lookups for names under the network's domain to the
lighthouse, and all other lookups go to its usual DNS.

The lighthouse returns "not found" for any name it doesn't know and never
passes the query on, so **the domain must be one only Nebula uses**. Your
public domain won't work: sending all of `example.com` to the lighthouse
would break `www.example.com`. A subdomain such as `nebula.example.com` (with
no public records) or `nebula.internal` works.

How a host sends those lookups:

| OS | How |
|---|---|
| Linux | systemd-resolved, through the `nebula1` device. The service sets it with `resolvectl` each time nebula starts. |
| macOS | `/etc/resolver/<domain>`. `ping`, `ssh` and browsers use it; `dig` and `nslookup` don't, so check with `dscacheutil -q host -a name <name>`. |

**Turning DNS on for a network set up before v0.3.0:**

1. On the lighthouse that holds the CA, run `sudo nebctl dns`. It asks for
   the domain, offers to sign the lighthouse's own cert again under the
   domain (same address), turns on DNS there, and lists the certs that still
   need new names.
2. Still on the lighthouse, for each other host, run `sudo nebctl ca sign`
   and type its short name (e.g. `fe01`). nebctl offers to rename the cert,
   keeping its address.
3. On each host, run `sudo nebctl node`, answer `n` to "Keep it?", and paste
   its new bundle. The bundle carries the domain, so DNS is set up as well.

The old certs keep working until they expire, so hosts can switch over one
at a time.

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
| `/etc/systemd/system/nebula.service` | the Linux service; with DNS on, it also routes the domain to the lighthouses each time nebula starts |
| `/etc/resolver/<domain>` | on macOS with DNS on: sends lookups for the Nebula domain to the lighthouses |
| `/Library/LaunchDaemons/net.nebctl.nebula.plist` | the macOS service; logs go to `/var/log/nebula.log` |
| `/etc/nebula/admin/` (0700) | the admin server's host key, nebctl's key for it, and `known_hosts` for machines the console connects to |
| `/etc/rsyslog.d/60-nebctl-siem.conf` | with SIEM forwarding on (Linux): sends nebula's log lines to the SIEM |

Back up `/etc/nebula/ca/ca.key` somewhere offline. Host certs expire when the
CA does; `nebctl status` warns 30 days ahead, and signing the same name
again renews the cert at the same address.

## Commands

```
lighthouse | node | request | config | status | dns | audit [-json] [-offline]
web [-port N] [-no-open]                          the admin console, on 127.0.0.1
app <command>      no questions, JSON out: what the console and the Mac app run
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
make web       # rebuild the console (web/, React) into internal/web/dist (Node needed)
make mac       # dist/Nebula Node.app and dist/NebulaNode-macos.zip (Xcode needed)
make mac-test  # walks the app's setup against a real nebctl in a scratch root
```

The app's code is in `macos/` (SwiftUI, macOS 14+). To try it without
changing the Mac, start it with nebctl working under a scratch directory:
no password prompts, no service.

```bash
NEBCTL_ROOT=/tmp/nebroot "dist/Nebula Node.app/Contents/MacOS/NebulaNode"
```
