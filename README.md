# Nebula Node and nebctl

Set up and run a [Nebula](https://github.com/slackhq/nebula) network: a
lighthouse on a Linux server, your Mac and other machines as nodes, and one
console to manage them all.

Website: https://davewat.github.io/nebctl/

## 1. Install the Mac app

1. Download [NebulaNode-macos.zip](https://github.com/davewat/nebctl/releases/latest/download/NebulaNode-macos.zip),
   unzip it, and drag **Nebula Node** to Applications.
2. The app isn't notarized yet, so clear the download flag:
   ```bash
   sudo xattr -cr "/Applications/Nebula Node.app"
   ```
3. It runs nebctl as root, so make it root's:
   ```bash
   sudo chown -R root:wheel "/Applications/Nebula Node.app"
   ```

macOS 14 or later, Apple silicon or Intel.

## 2. Set up the lighthouse

On a Linux server with a public IP:

```bash
curl -LO https://github.com/davewat/nebctl/releases/latest/download/nebctl-linux-amd64
```
```bash
sudo install -m 0755 nebctl-linux-amd64 /usr/local/bin/nebctl
```
```bash
sudo nebctl lighthouse
```

Press Enter to take the defaults. Hosts get names like `lh.example.internal`.
Keep the `.internal` ending: it is reserved for private networks, so it never
clashes with a real domain.

Then open UDP 4242 on the server, and in your cloud provider's firewall:

```bash
sudo ufw allow 4242/udp
```

On an ARM server, use `nebctl-linux-arm64` (or `nebctl-linux-arm` for 32-bit).

## 3. Add a machine

On the lighthouse, sign a cert for it. This prints a bundle:

```bash
sudo nebctl ca sign
```

Then on the new machine:

- **Mac:** open Nebula Node, click **Set Up This Mac as a Node**, and paste the bundle.
- **Linux:** install nebctl as in step 2, run `sudo nebctl node`, and paste the bundle.

The bundle holds the machine's private key, so move it over SSH or a password
manager, not email. To keep the key on the new machine instead, choose **Keep
the private key here** (or run `sudo nebctl request`), and sign the request on
the lighthouse with `sudo nebctl ca sign-request`.

Check it: `ping lh.example.internal`.

## 4. Manage it from the console

In Nebula Node, click **Open Admin Console**. On Linux, run `sudo nebctl web`.

Use **Connect to another machine** to reach the lighthouse over SSH. From there
you can:

- see who's connected, on a map
- sign, renew and revoke certs
- change firewall rules, DNS and logging
- forward logs to a SIEM (Linux, using rsyslog)
- update nebula and run a security audit

The console listens on 127.0.0.1 only, behind a link that works once. After a
password login it offers to save its own key on the lighthouse, so you don't
need the password next time. sudo may still ask for its own.

Machines set up before v0.5.0 show **Turn on admin access** once. It restarts
nebula.

## Command line

`sudo nebctl` with no command shows a menu.

| Command | What it does |
|---|---|
| `lighthouse`, `node` | set up this machine |
| `request` | make a key here and a request for the lighthouse to sign |
| `ca sign`, `ca sign-request`, `ca list` | sign and list certs (on the lighthouse) |
| `dns` | turn names over Nebula on or off |
| `status` | show what's set up |
| `update` | update nebula and restart it |
| `service start`, `stop`, `restart` | control nebula |
| `audit` | review this machine's security |
| `web` | open the admin console |

To update nebctl itself, repeat the `curl` and `install` lines from step 2.

## Good to know

- **Names.** The lighthouse answers DNS for your `.internal` domain only. Linux
  sends those lookups to it through systemd-resolved; macOS through
  `/etc/resolver/<domain>`. On a Mac, test with
  `dscacheutil -q host -a name lh.example.internal` (`dig` skips the resolver).
- **Revoking a cert.** Each machine keeps its own blocklist. After you revoke a
  cert, the console offers to push the list to the machines it's connected to.
- **Back up** `/etc/nebula/ca/ca.key` on the lighthouse. Every cert expires with
  the CA (5 years by default).

## Where things go

| Path | What |
|---|---|
| `/usr/local/bin/nebula`, `nebula-cert` | nebula |
| `/etc/nebula/config.yml` | nebula's config, written by nebctl |
| `/etc/nebula/nebctl.json` | your answers; `sudo nebctl config` rewrites the config from it |
| `/etc/nebula/ca/` | the CA, on the lighthouse |
| `/etc/nebula/admin/` | keys for the admin console |
| `/etc/systemd/system/nebula.service` | the Linux service |
| `/Library/LaunchDaemons/net.nebctl.nebula.plist` | the macOS service (log: `/var/log/nebula.log`) |

## Building

```bash
make test      # Go tests
make release   # CLI binaries, the Mac app and SHA256SUMS in dist/
make web       # rebuild the console (web/) into internal/web/dist
make mac-test  # the Mac app's tests
```
