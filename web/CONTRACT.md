# nebctl console: API contract

`nebctl web` serves the React console and this API on `http://127.0.0.1:<port>`.
It is started with `sudo nebctl web`, prints a one-time link
`http://127.0.0.1:<port>/?token=<t>`, and opens it.

- Visiting `/?token=<t>` sets an HttpOnly, SameSite=Strict session cookie and
  redirects to `/`. The token works once.
- Every `/api` request needs the cookie and the header `X-Nebctl: 1`
  (blocks cross-site form posts). Requests whose `Host` isn't `127.0.0.1:<port>`
  or `localhost:<port>` are refused (blocks DNS rebinding).
- Errors are `{"error": "<what went wrong and how to fix it>"}` with a 4xx/5xx
  status. Messages are written for the user and can be shown as they are.
- Times are RFC 3339 strings. Addresses are strings.

## Targets

A target is a machine the console manages. `local` is this machine and
always exists. Others are lighthouses (or any host) reached over SSH, where
the console runs `sudo nebctl app ...`.

```ts
interface Target {
  id: string;            // "local", or an id the server makes
  label: string;         // "This Mac (mac01)", "lh.example.internal"
  kind: "local" | "ssh";
  host?: string;         // ssh only: "203.0.113.10" or a name
  user?: string;
  role?: "lighthouse" | "node";   // from its state, when known
  haveCa: boolean;       // the CA key is on that machine: certificate pages apply
}
```

- `GET /api/targets` -> `Target[]`
- `POST /api/targets` with
  ```ts
  { host: string; port?: number; user: string;
    password?: string;          // SSH password, if not using a key
    useAgent?: boolean;         // use ssh-agent (SSH_AUTH_SOCK) keys
    keyPath?: string; passphrase?: string;
    sudoPassword?: string;      // asked for if sudo needs one
    acceptHostKey?: string;     // the fingerprint the user confirmed
  }
  ```
  - `200` -> `Target & { canSaveKey: boolean }` (connected and ready).
    `canSaveKey` is true when a password, not a key, logged in. Then offer:
    "Log in to <host> with a key next time?" and, on yes, call
    `POST /api/targets/{id}/save-key` -> `{ message }`, which installs the
    console's own public key in that user's `~/.ssh/authorized_keys`. The
    console tries that key first on every connection.
  - `409` -> `{ hostKey: { fingerprint: string; type: string; changed: boolean } }`:
    the host key is new (or changed). Show it, ask the user to confirm, and
    resend with `acceptHostKey`. `changed: true` deserves a loud warning.
  - `428` -> `{ nebctl: "missing" | "old"; remoteVersion?: string; arch: string; version: string }`:
    nebctl isn't on that machine (or is older than this one). Offer
    `POST /api/targets/install` with the same body plus `install: true`, which
    copies this release's nebctl for that arch to `/usr/local/bin/nebctl` there.
  - `401` -> `{ error, need: "password" | "passphrase" | "sudoPassword" }`: ask for
    that field and resend.
- `DELETE /api/targets/{id}` disconnects.
- `POST /api/link` -> `{ url: string }`: a fresh one-time link to this console.
  The Mac app shows the console in its own window and loads it with
  `?token=...&embedded=1`; the server keeps `embedded=1` on the redirect. When
  the page's URL has `embedded=1`, show an "Open in browser" button in the top
  bar that calls this and does `window.open(url, "_blank")` (the Mac app opens
  that in the default browser).

All endpoints below are under `/api/t/{targetId}/`.

## State and admin access

```ts
interface State {
  nebctl: string;            // "v0.5.0"
  nebula?: string;           // "1.11.2"; missing when not installed
  host?: Host;               // missing before setup
  cert?: CertInfo;
  ca?: string;               // CA cert name
  haveCa: boolean;
  service: string;           // "running", "not installed", "stopped (logs: ...)"
  hostname: string;
  admin: { enabled: boolean; listen: string };  // nebula's SSH admin server
}
interface CertInfo { name: string; networks: string[]; groups?: string[]; notAfter: string; daysLeft: number }
interface Host {
  role: "lighthouse" | "node"; name: string; nebulaIp: string; listenPort: number;
  relay?: boolean; dns?: boolean; domain?: string; resolve?: boolean;
  lighthouses: Lighthouse[]; inbound: Rule[];
}
interface Lighthouse { name?: string; nebulaIp: string; endpoints: string[]; relay?: boolean; dns?: boolean }
interface Rule { port: string; proto: "any" | "tcp" | "udp" | "icmp"; host?: string; group?: string }
```

- `GET state` -> `State`
- `POST admin/enable` -> `{ log: string }`. Turns on nebula's admin server
  (127.0.0.1 only) and restarts nebula. Every page except State and Health
  needs it: when `admin.enabled` is false, show one clear call to action.

## Connections (nebula's admin commands)

```ts
interface Peer {
  vpnAddr: string;              // "10.42.0.2"
  name: string;                 // from its cert, "fe01.example.internal"
  groups: string[];
  notAfter: string;             // its cert's expiry
  fingerprint: string;
  currentRemote?: string;       // "198.51.100.7:4242" the tunnel uses now; missing when relayed
  remoteAddrs: string[];        // every address known for it
  relayedThrough: string[];     // relays carrying our traffic to it (vpn addrs)
  relaysFor: string[];          // peers we relay for, through this tunnel
  messageCounter: number;       // packets sent on this tunnel so far
  localIndex: number; remoteIndex: number;
  pending: boolean;             // still handshaking
}
interface AddrMapEntry {        // lighthouses only: what it knows about each host
  vpnAddr: string; learned: string[]; reported: string[]; relays: string[];
}
interface Connections {
  self: { vpnAddr: string; name: string; role: "lighthouse" | "node" };
  peers: Peer[];                // established, then pending
  addrMap?: AddrMapEntry[];     // present on a lighthouse
  at: string;                   // when it was read
}
```

- `GET connections` -> `Connections` (poll every 5 s on the map page)
- `GET tunnel/{vpnAddr}` -> `Peer`
- `POST tunnel/{vpnAddr}/close` `{ localOnly?: boolean }` -> `{ message }`
- `POST tunnel/{vpnAddr}/create` `{ address?: string }` -> `{ message }`
  (message is "Created", "Tunnel already exists" or "Tunnel already handshaking")
- `POST tunnel/{vpnAddr}/remote` `{ address: string }` -> `{ message }`
- `GET lookup/{vpnAddr}` -> `{ vpnAddr, learned: string[], reported: string[], relays: string[] } | null`
  (asks the lighthouse where a host is)
- `GET log-level` -> `{ level }`; `POST log-level` `{ level: "trace"|"debug"|"info"|"warn"|"error" }`
  -> `{ level }` (changes it now, until the next restart; Configuration sets it for good)
- `POST reload` -> `{ message }` (re-reads config.yml; drops admin sessions)

## Certificates (targets with `haveCa`)

```ts
interface IssuedCert {
  name: string; nebulaIp: string; groups: string[];
  fingerprint: string; notAfter: string; issuedAt: string; daysLeft: number;
  revoked: boolean;            // its fingerprint is on the blocklist
  online?: boolean;            // has a tunnel to the target right now
}
interface Certificates {
  ca: { name: string; notAfter: string; daysLeft: number; fingerprint: string };
  cidr: string; domain?: string;
  lighthouses: Lighthouse[];
  issued: IssuedCert[];
  blocklist: string[];         // fingerprints
  caKey: 'here' | 'offline';   // ca.key on the target, or kept offline
  caKeyEncrypted?: boolean;    // when here: protected by a passphrase
  caKeyHeldUntil?: string;     // the console holds a pasted key until then
}
interface Signed { bundle: string; cert: IssuedCert; replaces?: string; nextIp: string }
```

- `GET certs` -> `Certificates`
- `GET certs/next-ip` -> `{ ip: string }` (first free address, "10.42.0.13/22")
- `POST certs` `{ name: string; ip?: string; groups?: string[] }` -> `Signed`.
  A short name gets the domain. Signing an existing name renews it at the same
  address. The bundle holds the new host's private key: show it once, with
  Copy and a warning to send it only over something trusted.
- `POST certs/request` `{ request: string; name?: string; ip?: string; groups?: string[] }` -> `Signed`
  (signs a pasted `NEBCTL REQUEST`; that bundle holds no key)
- `POST certs/revoke` `{ fingerprint: string }` -> `{ blocklist: string[]; log: string }`
  Adds it to this target's blocklist and reloads. Then the UI offers to push
  the list to other targets (below), listing the connected SSH targets.
- `PUT blocklist` `{ fingerprints: string[] }` -> `{ log }` (sets the whole list on
  this target and reloads; used for the push)

### The CA key, kept offline

The key can live off the lighthouse. The console then holds a pasted copy in
its own memory (never the browser's, never a file) for 15 minutes after its
last use, and sends it with each sign on nebctl's stdin (`-ca-key-stdin`),
which hands it to nebula-cert through a pipe. Disconnecting the target or
stopping the console wipes it.

- `POST ca-key/check` `{ key: string; passphrase?: string }` -> `{ caKeyHeldUntil }`
  Signs a throwaway cert with it to prove it's this CA's key, then holds it.
- `GET ca-key/file` -> `{ key: string; encrypted: boolean }` (ca.key, to save before removing)
- `POST ca-key/remove` `{ key: string; passphrase?: string }` -> `{ message; caKeyHeldUntil }`
  Removes ca.key only if the pasted copy works; then holds that copy.
- `DELETE ca-key` -> `{ message }` (forget the held copy)

`POST certs` and `POST certs/request` use the held key when there is one.
Without either, they fail with "the CA key isn't on this machine"; the UI asks
for the key before it signs.

## Configuration

```ts
interface Settings {
  host: Host;
  logging: { level: string; format: "text" | "json" };
  metrics: { enabled: boolean; listen: string };   // Prometheus, 127.0.0.1 only
  blocklist: string[];
}
interface SettingsChange {
  inbound?: Rule[];
  dns?: boolean; relay?: boolean;       // lighthouse only
  listenPort?: number;                  // lighthouse only; needs a restart
  lighthouses?: Lighthouse[];           // nodes
  resolve?: boolean;
  logging?: { level?: string; format?: "text" | "json" };
  metrics?: { enabled: boolean };
}
```

- `GET settings` -> `Settings`
- `PUT settings` `SettingsChange` -> `{ log: string; restarted: boolean }`.
  The new config must pass `nebula -test` first; on failure the old one stays
  and the error says why.

## Logs and SIEM

```ts
interface Siem {
  enabled: boolean;
  host: string; port: number;
  protocol: "udp" | "tcp" | "tls";
  caFile?: string;             // tls: the CA that signed the SIEM's cert
  supported: boolean;          // false on macOS (no rsyslog)
  note?: string;               // why not, or what to check
}
```

- `GET logs?lines=200` -> `{ lines: string[] }` (newest last)
- `GET siem` -> `Siem`
- `PUT siem` `Siem` (without `supported`, `note`) -> `{ log }`. Turns on JSON logs and
  writes the rsyslog rule that forwards nebula's log lines.
- `POST siem/test` -> `{ log }` (sends one test line tagged nebula)

## Health

```ts
interface Health {
  nebctl: string; nebula?: string; latest?: string;     // latest nebula release
  service: string;
  cert?: CertInfo; ca?: { name: string; daysLeft: number };
  metrics?: Record<string, number>;  // from nebula's Prometheus endpoint when on;
                                     // names as nebula exposes them
  tunnels: number; pending: number;  // from the admin server
}
interface Finding { section: string; level: "pass" | "info" | "warn" | "fail"; title: string; detail?: string; fix?: string[] }
```

- `GET health` -> `Health`
- `GET audit` -> `{ machine: string; findings: Finding[] }`
- `POST update` -> `{ log }` (updates nebula and restarts it)
- `POST service/{start|stop|restart}` -> `{ log }`
