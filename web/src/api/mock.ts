// A pretend `nebctl web`, used with ?mock (or VITE_MOCK=1 / `npm run dev`).
// It answers the same paths as web/CONTRACT.md, with latency and the same
// error shapes, so the console runs its real code path.
//
// Query switches (all optional):
//   ?mock&latency=0     no simulated delay
//   ?mock&noadmin       nebula's admin access is off on "This Mac"
//   ?mock&expired       every call answers 401 (session expired page)
//   ?mock&embedded=1    shows the "Open in browser" button, as in the Mac app window
//
// Hosts that exercise the connect flows (type any of these as the host):
//   anything            409: unknown host key, then connects
//   changed-key.example.com   409 with changed: true (loud warning)
//   sudo.example.com    401 need sudoPassword
//   bare.example.com    428 nebctl missing, offers an install
//   old.example.com     428 nebctl older than this console
// Password "wrong" gets 401 need password; a key file path containing "enc"
// gets 401 need passphrase.

import { ApiError } from './client';
import type {
  AddrMapEntry,
  Certificates,
  ConnectBody,
  Connections,
  Finding,
  Health,
  Host,
  HostFirewall,
  HostFirewallRule,
  IssuedCert,
  Lighthouse,
  Peer,
  Rule,
  Settings,
  SettingsChange,
  Signed,
  Siem,
  State,
  Target,
} from './types';

const DAY = 864e5;
const params = new URLSearchParams(location.search);
const LATENCY = params.has('latency') ? Number(params.get('latency')) || 0 : 300;
const DOMAIN = 'example.internal';
const NEBCTL = 'v0.5.0';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const iso = (days: number) => new Date(Date.now() + days * DAY).toISOString();
const daysLeft = (isoDate: string) => Math.floor((Date.parse(isoDate) - Date.now()) / DAY);

/** 64 hex characters from a seed (looks like a cert fingerprint). */
function fp(seed: string): string {
  let h = 2166136261;
  let out = '';
  for (let i = 0; i < 8; i++) {
    for (const c of seed + i) {
      h ^= c.charCodeAt(0);
      h = Math.imul(h, 16777619);
    }
    out += (h >>> 0).toString(16).padStart(8, '0');
  }
  return out;
}

// ---- the pretend network: 10.42.0.0/22 -----------------------------------

interface MHost {
  name: string;
  ip: string;
  groups: string[];
  days: number;
  remote?: string;
  remotes: string[];
  mode: 'direct' | 'relayed' | 'pending';
  revoked?: boolean;
  lighthouse?: boolean;
}

const HOSTS: MHost[] = [
  { name: 'lh', ip: '10.42.0.1', groups: ['lighthouse'], days: 341, remote: '203.0.113.10:4242', remotes: ['203.0.113.10:4242'], mode: 'direct', lighthouse: true },
  { name: 'mac01', ip: '10.42.0.2', groups: ['laptop', 'admin'], days: 301, remote: '198.51.100.23:4242', remotes: ['198.51.100.23:4242', '192.168.1.20:4242'], mode: 'direct' },
  { name: 'fe01', ip: '10.42.0.11', groups: ['web'], days: 280, remote: '198.51.100.7:4242', remotes: ['198.51.100.7:4242'], mode: 'direct' },
  { name: 'db01', ip: '10.42.0.20', groups: ['db'], days: 144, remote: '203.0.113.44:4242', remotes: ['203.0.113.44:4242', '10.0.0.44:4242'], mode: 'direct' },
  { name: 'hs01', ip: '10.42.0.30', groups: ['home'], days: 233, remotes: ['192.168.1.40:4242'], mode: 'relayed' },
  { name: 'laptop-old', ip: '10.42.0.40', groups: ['laptop'], days: 95, remote: '198.51.100.91:4242', remotes: ['198.51.100.91:4242'], mode: 'direct', revoked: true },
  { name: 'nas01', ip: '10.42.0.50', groups: ['home', 'storage'], days: 12, remote: '198.51.100.77:41234', remotes: ['198.51.100.77:41234'], mode: 'direct' },
  { name: 'pi01', ip: '10.42.1.5', groups: ['iot'], days: 360, remotes: ['198.51.100.60:4242'], mode: 'pending' },
];
const LH = HOSTS[0];
const full = (n: string) => (n.includes('.') ? n : `${n}.${DOMAIN}`);

function toPeer(self: MHost, h: MHost): Peer {
  const relayAddr = self.lighthouse ? '10.42.0.11' : LH.ip;
  const relayed = h.mode === 'relayed';
  const pending = h.mode === 'pending';
  return {
    vpnAddr: h.ip,
    name: full(h.name),
    groups: h.groups,
    notAfter: iso(h.days),
    fingerprint: fp(h.name),
    currentRemote: relayed || pending ? undefined : h.remote,
    remoteAddrs: h.remotes,
    relayedThrough: relayed ? [relayAddr] : [],
    relaysFor: self.lighthouse && h.name === 'fe01' ? ['10.42.0.30'] : [],
    messageCounter: pending ? 0 : 1200 + (fp(h.name).charCodeAt(3) % 40) * 311,
    localIndex: 1000 + (fp(h.name + 'l').charCodeAt(2) % 9000) * 17,
    remoteIndex: 2000 + (fp(h.name + 'r').charCodeAt(2) % 9000) * 13,
    pending,
  };
}

// ---- per-target state ------------------------------------------------------

interface Db {
  target: Target;
  me: MHost;
  state: State;
  peers: Peer[];
  settings: Settings;
  logLevel: string;
  logs: string[];
  siem: Siem;
  certs?: Certificates;
  latest: string;
  // nebctl's ufw rules there (as ufw shows them); undefined: no ufw (the Mac)
  ufw?: string[];
}

// The mock lighthouse's CA key. Pasting it back is what proves a copy works.
const MOCK_CA_KEY = '-----BEGIN NEBULA ED25519 PRIVATE KEY-----\nm0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3dKeyM0ck3d==\n-----END NEBULA ED25519 PRIVATE KEY-----\n';
const CA_KEY_TTL_MS = 15 * 60 * 1000;

function checkPastedKey(db: Db, b: Record<string, unknown>) {
  const key = String(b.key ?? '').trim();
  if (!/^-----BEGIN NEBULA [A-Z0-9 ]*PRIVATE KEY-----/.test(key)) {
    throw new ApiError(400, "that isn't a Nebula CA key: paste everything from -----BEGIN NEBULA ... PRIVATE KEY----- to the END line");
  }
  if (key !== MOCK_CA_KEY.trim()) throw new ApiError(400, "that key isn't this CA's key");
  db.certs!.caKeyHeldUntil = new Date(Date.now() + CA_KEY_TTL_MS).toISOString();
}

function spendCaKey(db: Db) {
  const c = db.certs!;
  if (c.caKeyHeldUntil && Date.parse(c.caKeyHeldUntil) < Date.now()) delete c.caKeyHeldUntil;
  if (c.caKey === 'offline' && !c.caKeyHeldUntil) {
    throw new ApiError(400, "the CA key isn't on this machine: paste it on the console's Certificates page (or sign in a terminal, which asks for it)");
  }
  if (c.caKeyHeldUntil) c.caKeyHeldUntil = new Date(Date.now() + CA_KEY_TTL_MS).toISOString();
}

const RULES: Rule[] = [
  { proto: 'icmp', port: 'any' },
  { proto: 'tcp', port: '22' },
];

function lhHost(): Host {
  return {
    role: 'lighthouse',
    name: full(LH.name),
    nebulaIp: LH.ip,
    listenPort: 4242,
    relay: true,
    dns: true,
    domain: DOMAIN,
    resolve: false,
    lighthouses: [],
    inbound: [...RULES, { proto: 'tcp', port: '443', group: 'web' }, { proto: 'tcp', port: '5432', host: 'fe01' }],
  };
}

const LH_ENTRY: Lighthouse = { name: full(LH.name), nebulaIp: LH.ip, endpoints: ['203.0.113.10:4242'], relay: true, dns: true };

function nodeHost(h: MHost): Host {
  return {
    role: 'node',
    name: full(h.name),
    nebulaIp: h.ip,
    listenPort: 0,
    domain: DOMAIN,
    resolve: true,
    lighthouses: [LH_ENTRY],
    inbound: [...RULES],
  };
}

function logLine(i: number, ms: number): string {
  const t = new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
  const peers = HOSTS.filter((h) => h.mode === 'direct' && !h.lighthouse);
  const h = peers[i % peers.length];
  const idx = 1000000 + ((i * 7919) % 900000);
  switch (i % 7) {
    case 0:
      return `time="${t}" level=info msg="Handshake message received" certName=${full(h.name)} fingerprint=${fp(h.name)} handshake="map[stage:1 style:ix_psk0]" initiatorIndex=${idx} remoteIndex=0 udpAddr="${h.remote}" vpnAddrs="[${h.ip}]"`;
    case 1:
      return `time="${t}" level=info msg="Handshake message sent" handshake="map[stage:2 style:ix_psk0]" initiatorIndex=${idx} remoteIndex=${idx + 11} udpAddr="${h.remote}" vpnAddrs="[${h.ip}]"`;
    case 2:
      return `time="${t}" level=info msg="Firewall rules reloaded" firewallHashes="map[new:7a4cc1 old:7a4cc1]"`;
    case 3:
      return `time="${t}" level=warning msg="Remote address changed" localIndex=${idx} remoteIndex=${idx + 3} udpAddr="${h.remote}" vpnAddrs="[${h.ip}]"`;
    case 4:
      return `time="${t}" level=info msg="Tunnel status" certName=${full(h.name)} localIndex=${idx} remoteIndex=${idx + 5} tunnelCheck="map[method:active state:alive]" vpnAddrs="[${h.ip}]"`;
    case 5:
      return `time="${t}" level=error msg="Failed to send handshake" error="sendto: no route to host" udpAddr="198.51.100.60:4242" vpnAddrs="[10.42.1.5]"`;
    default:
      return `time="${t}" level=info msg="Lighthouse update" lighthouse=10.42.0.1 numHosts=${HOSTS.length - 1}`;
  }
}

function seedLogs(): string[] {
  const out: string[] = [];
  const now = Date.now();
  for (let i = 0; i < 160; i++) out.push(logLine(i, now - (160 - i) * 9000));
  return out;
}

function buildDb(target: Target, me: MHost, host: Host): Db {
  const peers = HOSTS.filter((h) => h !== me).map((h) => toPeer(me, h));
  const db: Db = {
    target,
    me,
    peers,
    latest: '1.12.0',
    logLevel: 'info',
    logs: seedLogs(),
    state: {
      nebctl: NEBCTL,
      nebula: '1.11.2',
      host,
      cert: { name: full(me.name), networks: [`${me.ip}/22`], groups: me.groups, notAfter: iso(me.days), daysLeft: me.days },
      ca: target.haveCa ? 'Example.com' : undefined,
      haveCa: target.haveCa,
      service: 'running',
      hostname: me.name,
      admin: { enabled: true, listen: '127.0.0.1:2222' },
    },
    settings: {
      host,
      logging: { level: 'info', format: 'text' },
      metrics: { enabled: false, listen: '127.0.0.1:8080' },
      blocklist: [fp('laptop-old')],
    },
    siem: target.kind === 'local' && target.id === 'local'
      ? { enabled: false, host: '', port: 514, protocol: 'udp', supported: false, note: 'This Mac has no rsyslog. Forward nebula\'s log from a Linux machine, or point a log shipper at /var/log/nebula.log.' }
      : { enabled: false, host: 'siem.example.com', port: 6514, protocol: 'tls', caFile: '/etc/ssl/certs/siem-ca.pem', supported: true },
  };
  if (target.haveCa) db.certs = buildCerts(db);
  // The lighthouse's ufw predates DNS: its DNS rule is missing.
  if (target.kind !== 'local') db.ufw = wantedFw(host).map((r) => r.text).filter((t) => target.role !== 'lighthouse' || !t.startsWith('53/'));
  return db;
}

function issuedFrom(h: MHost, blocklist: string[], online: boolean): IssuedCert {
  const fpr = fp(h.name);
  const notAfter = iso(h.days);
  return {
    name: full(h.name),
    nebulaIp: h.ip,
    groups: h.groups,
    fingerprint: fpr,
    notAfter,
    issuedAt: iso(h.days - 365),
    daysLeft: daysLeft(notAfter),
    revoked: blocklist.includes(fpr) || !!h.revoked,
    online,
  };
}

function buildCerts(db: Db): Certificates {
  return {
    ca: { name: 'Example.com', notAfter: iso(1580), daysLeft: 1580, fingerprint: fp('ca') },
    cidr: '10.42.0.0/22',
    domain: DOMAIN,
    lighthouses: [LH_ENTRY],
    issued: HOSTS.map((h) => issuedFrom(h, db.settings.blocklist, h.mode !== 'pending' && !h.revoked && h !== db.me)),
    blocklist: [...db.settings.blocklist],
    caKey: 'here',
    caKeyEncrypted: false,
  };
}

const dbs = new Map<string, Db>();
const trusted = new Set<string>();
const installed = new Set<string>();

function init() {
  const local: Target = { id: 'local', label: 'This Mac (mac01)', kind: 'local', role: 'node', haveCa: false };
  const lh: Target = { id: 'lh', label: full(LH.name), kind: 'ssh', host: '203.0.113.10', user: 'root', role: 'lighthouse', haveCa: true };
  const fe: Target = { id: 'fe01', label: full('fe01'), kind: 'ssh', host: '198.51.100.7', user: 'ops', role: 'node', haveCa: false };
  const me = (n: string) => HOSTS.find((h) => h.name === n)!;
  dbs.set('local', buildDb(local, me('mac01'), nodeHost(me('mac01'))));
  dbs.set('lh', buildDb(lh, LH, lhHost()));
  dbs.set('fe01', buildDb(fe, me('fe01'), nodeHost(me('fe01'))));
  if (params.has('noadmin')) dbs.get('local')!.state.admin.enabled = false;
}
init();

const targetList = () => [...dbs.values()].map((d) => d.target);

// ---- connecting to another machine (409 / 401 / 428 flows) ---------------

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'host';
}

function connect(b: ConnectBody, installing: boolean): Target {
  const host = (b.host || '').trim();
  if (!host) throw new ApiError(400, 'Enter the machine\'s host name or address.');
  if (!b.user) throw new ApiError(400, 'Enter the user to sign in as.');

  const key = `SHA256:${fp(host).slice(0, 43)}`;
  if (!trusted.has(host)) {
    if (b.acceptHostKey !== key) {
      const changed = /changed/.test(host);
      throw new ApiError(409, 'This machine\'s host key is not trusted yet.', {
        error: 'This machine\'s host key is not trusted yet.',
        hostKey: { fingerprint: key, type: 'ssh-ed25519', changed },
      });
    }
    trusted.add(host);
  }

  if (!b.useAgent && !b.keyPath && !b.password) {
    throw new ApiError(401, 'SSH needs a password for this user.', { error: 'SSH needs a password for this user.', need: 'password' });
  }
  if (b.password === 'wrong') {
    throw new ApiError(401, 'The machine refused that password. Try again.', { error: 'The machine refused that password. Try again.', need: 'password' });
  }
  if (b.keyPath && /enc/.test(b.keyPath) && !b.passphrase) {
    throw new ApiError(401, 'That key file is protected by a passphrase.', { error: 'That key file is protected by a passphrase.', need: 'passphrase' });
  }
  if (/sudo/.test(host) && !b.sudoPassword) {
    throw new ApiError(401, 'sudo on that machine needs a password.', { error: 'sudo on that machine needs a password.', need: 'sudoPassword' });
  }
  if (!installed.has(host) && !installing && /bare|old/.test(host)) {
    const old = /old/.test(host);
    const msg = old
      ? `nebctl on ${host} is v0.3.1, older than this console's ${NEBCTL}.`
      : `nebctl isn't installed on ${host}.`;
    throw new ApiError(428, msg, {
      error: msg,
      nebctl: old ? 'old' : 'missing',
      remoteVersion: old ? 'v0.3.1' : undefined,
      arch: 'linux/arm64',
      version: NEBCTL,
    });
  }
  if (installing) installed.add(host);

  const id = slug(host);
  const canSaveKey = !!b.password && !keyed.has(host);
  const existing = dbs.get(id);
  if (existing) return { ...existing.target, canSaveKey };
  const short = host.split('.')[0];
  const target: Target = { id, label: host, kind: 'ssh', host, user: b.user, role: 'node', haveCa: false };
  const me: MHost = { name: short, ip: '10.42.0.99', groups: [], days: 200, remotes: [], mode: 'direct' };
  const db = buildDb(target, me, { ...nodeHost(me), name: full(short) });
  db.peers = db.peers.filter((p) => p.vpnAddr !== me.ip);
  dbs.set(id, db);
  return { ...target, canSaveKey };
}

// Hosts whose authorized_keys hold the console's key (save-key).
const keyed = new Set<string>();

// ---- helpers for each endpoint ---------------------------------------------

function ensureAdmin(db: Db) {
  if (!db.state.admin.enabled) {
    throw new ApiError(400, 'Nebula\'s admin access is off on this machine. Turn it on from the Map page, then try again.');
  }
}

function connections(db: Db): Connections {
  ensureAdmin(db);
  for (const p of db.peers) if (!p.pending) p.messageCounter += Math.floor(Math.random() * 38);
  const me = db.me;
  const out: Connections = {
    self: { vpnAddr: me.ip, name: full(me.name), role: db.state.host?.role ?? 'node' },
    peers: [...db.peers.filter((p) => !p.pending), ...db.peers.filter((p) => p.pending)].map((p) => ({ ...p })),
    at: new Date().toISOString(),
  };
  if (me.lighthouse) {
    out.addrMap = HOSTS.filter((h) => h !== me).map<AddrMapEntry>((h) => ({
      vpnAddr: h.ip,
      learned: h.remote ? [h.remote] : [],
      reported: h.remotes,
      relays: h.mode === 'relayed' ? ['10.42.0.11'] : [],
    }));
  }
  return out;
}

const addrRe = /^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:]+\]|[a-z0-9.-]+):\d{1,5}$/i;

function findPeer(db: Db, a: string): Peer {
  const p = db.peers.find((x) => x.vpnAddr === a);
  if (!p) throw new ApiError(404, `No tunnel to ${a}. It may have closed; try Re-open tunnel.`);
  return p;
}

function nextFreeIp(db: Db): string {
  const used = new Set(db.certs!.issued.map((c) => c.nebulaIp.split('/')[0]));
  for (let n = 2; n < 1020; n++) {
    const ip = `10.42.${n >> 8}.${n & 255}`;
    if (!used.has(ip)) return `${ip}/22`;
  }
  return '10.42.3.254/22';
}

function bundleText(withKey: boolean, seed: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let h = Math.imul(seed.length + 17, 2654435761) >>> 0;
  const lines: string[] = [];
  for (let l = 0; l < (withKey ? 14 : 9); l++) {
    let s = l === 0 ? 'H4sIAAAAAAAC/' : '';
    while (s.length < 64) {
      h = (Math.imul(h, 1664525) + 1013904223) >>> 0;
      s += alphabet[h >>> 26];
    }
    lines.push(s);
  }
  return `-----BEGIN NEBCTL BUNDLE-----\n${lines.join('\n')}\n-----END NEBCTL BUNDLE-----`;
}

function signCert(db: Db, name: string, ip: string | undefined, groups: string[] | undefined, withKey: boolean): Signed {
  const certs = db.certs!;
  const n = full(name.trim());
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(n)) {
    throw new ApiError(400, 'A host name can use letters, digits, dashes and dots, and must start and end with a letter or digit.');
  }
  const existing = certs.issued.find((c) => c.name === n);
  const addr = existing ? existing.nebulaIp.split('/')[0] : (ip && ip.trim() ? ip.trim() : nextFreeIp(db)).split('/')[0];
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) throw new ApiError(400, `${addr} isn't an IPv4 address. Use an address inside ${certs.cidr}.`);
  if (!existing) {
    const clash = certs.issued.find((c) => c.nebulaIp.split('/')[0] === addr);
    if (clash) throw new ApiError(400, `${addr} already belongs to ${clash.name}. Pick another address.`);
  }
  const notAfter = iso(365);
  const cert: IssuedCert = {
    name: n,
    nebulaIp: addr,
    groups: groups ?? existing?.groups ?? [],
    fingerprint: fp(n + Date.now()),
    notAfter,
    issuedAt: new Date().toISOString(),
    daysLeft: daysLeft(notAfter),
    revoked: false,
    online: false,
  };
  if (existing) certs.issued[certs.issued.indexOf(existing)] = cert;
  else certs.issued.push(cert);
  return { bundle: bundleText(withKey, n + addr), cert, replaces: existing?.fingerprint, nextIp: nextFreeIp(db) };
}

// What the host firewall must let in, as nebctl's hostfw package works it out.
function wantedFw(h: Host): HostFirewallRule[] {
  const out: HostFirewallRule[] = [];
  const add = (part: 'nebula' | 'over', port: string, proto: string, why: string) => {
    const dev = part === 'over' ? 'nebula1' : '';
    const text = `${port || 'Anywhere'}${proto ? `/${proto}` : ''}${dev ? ` on ${dev}` : ''}`;
    if (out.some((r) => r.text === text)) return;
    const args = dev ? `in on ${dev}${proto ? ` proto ${proto}` : ''} to any${port ? ` port ${port}` : ''}` : `${port}${proto ? `/${proto}` : ''}`;
    out.push({ part, port, proto, dev, why, text, command: `sudo ufw allow ${args} comment 'nebctl'`, ok: false });
  };
  if (h.role === 'lighthouse' && h.listenPort > 0) add('nebula', String(h.listenPort), 'udp', "nebula's port: every host reaches this lighthouse here");
  const inbound = [...h.inbound];
  const dnsOpen = inbound.some((r) => (r.proto === 'udp' || r.proto === 'any') && (r.port === '53' || r.port === 'any') && !r.group && (!r.host || r.host === 'any'));
  if (h.role === 'lighthouse' && h.dns && !dnsOpen) inbound.push({ port: '53', proto: 'udp', host: 'any' });
  for (const r of inbound) {
    if (r.proto === 'icmp') continue;
    const dns = r.port === '53' && r.proto === 'udp' && !r.group && (!r.host || r.host === 'any') && h.dns;
    const who = r.group ? `group ${r.group}` : r.host && r.host !== 'any' ? r.host : 'any host';
    const why = dns ? 'this lighthouse answers DNS for Nebula hosts' : `nebula lets ${r.proto}/${r.port} from ${who} in${who === 'any host' ? '' : '; nebula limits who'}`;
    const proto = r.proto === 'any' ? '' : r.proto;
    const port = r.port === 'any' ? '' : r.port.replace('-', ':');
    if (port.includes(':') && !proto) {
      add('over', port, 'tcp', why);
      add('over', port, 'udp', why);
    } else add('over', port, proto, why);
  }
  return out;
}

function hostFirewall(db: Db, changed: string[] = []): HostFirewall {
  const want = wantedFw(db.settings.host);
  const role = db.settings.host.role;
  if (!db.ufw) { // the Mac: its firewall allows apps, not ports
    return { role, changed, firewall: { tool: '', active: false, rules: [], stale: [], note: 'macOS: nothing to keep in step. Allow nebula if macOS asks about incoming connections.' } };
  }
  const have = db.ufw;
  const rules = want.map((r) => ({ ...r, ok: have.includes(r.text) }));
  const stale = have.filter((t) => !want.some((r) => r.text === t)).map((text): HostFirewallRule => ({ part: 'over', why: '', text, command: '', ok: true }));
  return { role, changed, firewall: { tool: 'ufw', active: true, rules, stale } };
}

function syncFw(db: Db): string[] {
  if (!db.ufw) return [];
  const want = wantedFw(db.settings.host);
  const did: string[] = [];
  for (const t of db.ufw.filter((t) => !want.some((r) => r.text === t))) did.push(`removed ${t}`);
  for (const r of want.filter((r) => !db.ufw!.includes(r.text))) did.push(`allowed ${r.text}: ${r.why}`);
  db.ufw = want.map((r) => r.text);
  return did;
}

function applySettings(db: Db, c: SettingsChange): { log: string; restarted: boolean } {
  const s = db.settings;
  let restarted = false;
  const notes: string[] = [];
  if (c.listenPort !== undefined) {
    if (!Number.isInteger(c.listenPort) || c.listenPort < 1 || c.listenPort > 65535) {
      throw new ApiError(400, 'The listen port must be a number from 1 to 65535. The old config is still in use.');
    }
    if (c.listenPort !== s.host.listenPort) {
      restarted = true;
      notes.push(`Listen port is now ${c.listenPort}. Open UDP ${c.listenPort} in your firewall.`);
    }
    s.host.listenPort = c.listenPort;
  }
  if (c.inbound) {
    for (const r of c.inbound) {
      if (!/^(any|\d{1,5}(-\d{1,5})?)$/.test(r.port)) throw new ApiError(400, `"${r.port}" isn't a port or range. Use a number, a range like 8000-8100, or any. The old config is still in use.`);
    }
    s.host.inbound = c.inbound;
    notes.push(`Firewall: ${c.inbound.length} inbound rule${c.inbound.length === 1 ? '' : 's'}.`);
  }
  if (c.dns !== undefined) s.host.dns = c.dns;
  if (c.relay !== undefined) s.host.relay = c.relay;
  if (c.resolve !== undefined) s.host.resolve = c.resolve;
  if (c.lighthouses) {
    s.host.lighthouses = c.lighthouses;
    restarted = true;
  }
  if (c.logging) {
    if (c.logging.level) {
      s.logging.level = c.logging.level;
      db.logLevel = c.logging.level;
    }
    if (c.logging.format) s.logging.format = c.logging.format;
  }
  if (c.metrics) {
    if (c.metrics.enabled !== s.metrics.enabled) restarted = true;
    s.metrics.enabled = c.metrics.enabled;
  }
  db.state.host = s.host;
  for (const d of syncFw(db)) notes.push(`ufw: ${d}`);
  return {
    log: `Wrote /etc/nebula/config.yml\nnebula -test -config /etc/nebula/config.yml: ok\n${notes.join('\n')}${notes.length ? '\n' : ''}${restarted ? 'Restarted nebula.' : 'Reloaded nebula (SIGHUP).'}`,
    restarted,
  };
}

function audit(db: Db): Finding[] {
  const lh = db.me.lighthouse;
  const f: Finding[] = [
    { section: 'Nebula', level: 'pass', title: 'Nebula runs as a service', detail: 'systemd unit nebula.service is enabled and active.' },
    { section: 'Nebula', level: 'pass', title: 'Config passes nebula -test' },
    { section: 'Nebula', level: 'warn', title: 'A newer nebula is available', detail: `Installed ${db.state.nebula}, latest ${db.latest}.`, fix: ['sudo nebctl update'] },
    { section: 'Certificates', level: 'warn', title: 'A host cert expires in 12 days', detail: 'nas01.example.internal ends soon. Renew it on the Certificates page, or sign the same name again.', fix: ['sudo nebctl ca sign   # name: nas01'] },
    { section: 'Certificates', level: 'pass', title: 'The CA has more than a year left' },
    { section: 'Certificates', level: 'info', title: 'ca.key is not passphrase protected', detail: 'Anyone who can read /etc/nebula/ca.key can sign certs. It is readable by root only.' },
    { section: 'SSH', level: 'fail', title: 'Root can sign in with a password', detail: 'PermitRootLogin and PasswordAuthentication are both on in /etc/ssh/sshd_config. This server faces the internet.', fix: ["sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config", "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config", 'sudo systemctl reload ssh'] },
    { section: 'SSH', level: 'pass', title: 'SSH uses protocol 2 only' },
    { section: 'Firewall', level: lh ? 'warn' : 'pass', title: lh ? 'TCP 22 is open to the whole internet' : 'No unexpected listening ports', detail: lh ? 'ufw allows 22/tcp from anywhere. Nebula only needs UDP 4242.' : undefined, fix: lh ? ['sudo ufw delete allow 22/tcp', 'sudo ufw allow from 10.42.0.0/22 to any port 22 proto tcp'] : undefined },
    { section: 'Firewall', level: 'pass', title: 'UDP 4242 is allowed' },
    { section: 'System', level: 'info', title: 'Unattended upgrades are installed', detail: 'Security updates apply on their own.' },
    { section: 'System', level: 'pass', title: 'No pending reboot' },
  ];
  return f;
}

function metricsFor(db: Db): Record<string, number> | undefined {
  if (!db.settings.metrics.enabled) return undefined;
  const est = db.peers.filter((p) => !p.pending).length;
  return {
    nebula_hostmap_main_hosts: est,
    nebula_hostmap_main_indexes: est,
    nebula_hostmap_pending_hosts: db.peers.filter((p) => p.pending).length,
    nebula_firewall_dropped_total: 1840,
    nebula_handshakes_total: 96,
    nebula_messages_tx_total: 482113,
    nebula_messages_rx_total: 479002,
  };
}

function health(db: Db): Health {
  const est = db.peers.filter((p) => !p.pending).length;
  return {
    nebctl: NEBCTL,
    nebula: db.state.nebula,
    latest: db.latest,
    service: db.state.service,
    cert: db.state.cert,
    ca: db.state.haveCa ? { name: 'Example.com', daysLeft: 1580 } : undefined,
    metrics: metricsFor(db),
    tunnels: est,
    pending: db.peers.length - est,
  };
}

// ---- the router ----------------------------------------------------------

type Body = Record<string, unknown>;
type Handler = (db: Db, m: RegExpMatchArray, body: Body, query: URLSearchParams) => unknown | Promise<unknown>;

const routes: Array<[string, RegExp, Handler, number?]> = [
  ['GET', /^state$/, (db) => ({ ...db.state, service: db.state.service })],
  ['POST', /^admin\/enable$/, (db) => {
    db.state.admin.enabled = true;
    return { log: 'Set admin.enabled: true in /etc/nebula/config.yml\nnebula -test: ok\nRestarted nebula.' };
  }, 1200],

  ['GET', /^connections$/, (db) => connections(db)],
  ['GET', /^tunnel\/([^/]+)$/, (db, m) => ({ ...findPeer(db, decodeURIComponent(m[1])) })],
  ['POST', /^tunnel\/([^/]+)\/close$/, (db, m) => {
    ensureAdmin(db);
    const p = findPeer(db, decodeURIComponent(m[1]));
    db.peers = db.peers.filter((x) => x !== p);
    return { message: 'Closed' };
  }],
  ['POST', /^tunnel\/([^/]+)\/create$/, (db, m, body) => {
    ensureAdmin(db);
    const a = decodeURIComponent(m[1]);
    const existing = db.peers.find((p) => p.vpnAddr === a);
    if (existing) return { message: existing.pending ? 'Tunnel already handshaking' : 'Tunnel already exists' };
    const h = HOSTS.find((x) => x.ip === a);
    if (!h) throw new ApiError(404, `${a} isn't a host on this network. Check the address.`);
    const peer = toPeer(db.me, h);
    const remote = typeof body.address === 'string' && body.address ? body.address : peer.currentRemote ?? h.remotes[0];
    peer.pending = true;
    peer.currentRemote = undefined;
    peer.relayedThrough = [];
    peer.messageCounter = 0;
    db.peers.push(peer);
    setTimeout(() => {
      peer.pending = false;
      peer.currentRemote = remote;
      peer.messageCounter = 12;
    }, 2500);
    return { message: 'Created' };
  }],
  ['POST', /^tunnel\/([^/]+)\/remote$/, (db, m, body) => {
    ensureAdmin(db);
    const p = findPeer(db, decodeURIComponent(m[1]));
    const address = String(body.address ?? '').trim();
    if (!addrRe.test(address)) throw new ApiError(400, `"${address}" isn't an address and port. Use something like 198.51.100.7:4242.`);
    p.currentRemote = address;
    p.relayedThrough = [];
    if (!p.remoteAddrs.includes(address)) p.remoteAddrs = [address, ...p.remoteAddrs];
    return { message: `Remote for ${p.vpnAddr} is now ${address}` };
  }],
  ['GET', /^lookup\/([^/]+)$/, (db, m) => {
    ensureAdmin(db);
    const a = decodeURIComponent(m[1]);
    const h = HOSTS.find((x) => x.ip === a);
    if (!h || h.mode === 'pending') return null;
    return { vpnAddr: a, learned: h.remote ? [h.remote] : [], reported: h.remotes, relays: h.mode === 'relayed' ? [LH.ip] : [] };
  }],
  ['GET', /^log-level$/, (db) => { ensureAdmin(db); return { level: db.logLevel }; }],
  ['POST', /^log-level$/, (db, _m, body) => {
    ensureAdmin(db);
    const level = String(body.level);
    if (!['trace', 'debug', 'info', 'warn', 'error'].includes(level)) throw new ApiError(400, `"${level}" isn't a log level. Use trace, debug, info, warn or error.`);
    db.logLevel = level;
    return { level };
  }],
  ['POST', /^reload$/, () => ({ message: 'Reloaded config.yml' })],

  ['GET', /^certs$/, (db) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine. Switch to the lighthouse to manage certificates.');
    const c = db.certs;
    if (c.caKeyHeldUntil && Date.parse(c.caKeyHeldUntil) < Date.now()) delete c.caKeyHeldUntil;
    const online = new Set(db.peers.filter((p) => !p.pending).map((p) => p.vpnAddr));
    c.issued.forEach((i) => {
      i.daysLeft = daysLeft(i.notAfter);
      i.revoked = c.blocklist.includes(i.fingerprint);
      i.online = online.has(i.nebulaIp.split('/')[0]) && !i.revoked;
    });
    return JSON.parse(JSON.stringify(c)) as Certificates;
  }],
  ['GET', /^certs\/next-ip$/, (db) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine.');
    return { ip: nextFreeIp(db) };
  }],
  ['POST', /^certs$/, (db, _m, b) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine.');
    if (!String(b.name ?? '').trim()) throw new ApiError(400, 'Enter a name for the host.');
    spendCaKey(db);
    return signCert(db, String(b.name), b.ip as string | undefined, b.groups as string[] | undefined, true);
  }, 600],
  ['POST', /^certs\/request$/, (db, _m, b) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine.');
    if (!/BEGIN NEBCTL REQUEST/.test(String(b.request ?? ''))) {
      throw new ApiError(400, 'That isn\'t a nebctl request. Paste everything from -----BEGIN NEBCTL REQUEST----- to the END line.');
    }
    spendCaKey(db);
    return signCert(db, String(b.name || 'requested-host'), b.ip as string | undefined, b.groups as string[] | undefined, false);
  }, 600],
  ['POST', /^certs\/revoke$/, (db, _m, b) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine.');
    const f = String(b.fingerprint ?? '');
    const cert = db.certs.issued.find((c) => c.fingerprint === f);
    if (!cert) throw new ApiError(404, 'No issued cert has that fingerprint.');
    if (!db.certs.blocklist.includes(f)) db.certs.blocklist.push(f);
    db.settings.blocklist = [...db.certs.blocklist];
    cert.revoked = true;
    db.peers = db.peers.filter((p) => p.fingerprint !== f);
    return { blocklist: [...db.certs.blocklist], log: `Added ${f.slice(0, 12)}… to pki.blocklist in /etc/nebula/config.yml\nnebula -test: ok\nReloaded nebula (SIGHUP).` };
  }, 700],
  ['POST', /^ca-key\/check$/, (db, _m, b) => {
    if (!db.certs) throw new ApiError(400, 'The CA is not on this machine.');
    checkPastedKey(db, b);
    return { message: "That is this CA's key", log: '', caKeyHeldUntil: db.certs.caKeyHeldUntil };
  }, 500],
  ['GET', /^ca-key\/file$/, (db) => {
    if (db.certs?.caKey !== 'here') throw new ApiError(400, "the CA key isn't on this machine");
    return { key: MOCK_CA_KEY, encrypted: false };
  }],
  ['POST', /^ca-key\/remove$/, (db, _m, b) => {
    if (db.certs?.caKey !== 'here') throw new ApiError(400, "the CA key isn't on this machine");
    try {
      checkPastedKey(db, b);
    } catch (e) {
      throw new ApiError(400, `your copy didn't work, so the key was kept: ${e instanceof Error ? e.message : String(e)}`);
    }
    db.certs.caKey = 'offline';
    delete db.certs.caKeyEncrypted;
    return { message: 'The CA key is off this machine. Paste it here when you sign.', log: 'Removed /etc/nebula/ca/ca.key.', caKeyHeldUntil: db.certs.caKeyHeldUntil };
  }, 700],
  ['DELETE', /^ca-key$/, (db) => {
    if (!db.certs?.caKeyHeldUntil) throw new ApiError(404, 'no CA key is held for that machine');
    delete db.certs.caKeyHeldUntil;
    return { message: 'The console forgot the CA key' };
  }],
  ['PUT', /^blocklist$/, (db, _m, b) => {
    if (db.target.id === 'fe01') throw new ApiError(502, `Couldn't reach ${db.target.host} over SSH: connection timed out. The blocklist was not changed there.`);
    const list = (b.fingerprints as string[]) ?? [];
    db.settings.blocklist = list;
    if (db.certs) db.certs.blocklist = [...list];
    return { log: `Wrote ${list.length} fingerprint${list.length === 1 ? '' : 's'} to pki.blocklist\nnebula -test: ok\nReloaded nebula (SIGHUP).` };
  }, 800],

  ['GET', /^settings$/, (db) => JSON.parse(JSON.stringify(db.settings)) as Settings],
  ['PUT', /^settings$/, (db, _m, b) => applySettings(db, b as SettingsChange), 900],
  ['GET', /^firewall$/, (db) => hostFirewall(db), 500],
  ['POST', /^firewall$/, (db) => hostFirewall(db, syncFw(db)), 900],

  ['GET', /^logs$/, (db, _m, _b, q) => {
    const n = Math.min(Math.max(Number(q.get('lines')) || 200, 10), 1000);
    const k = 1 + Math.floor(Math.random() * 2);
    for (let i = 0; i < k; i++) db.logs.push(logLine(db.logs.length, Date.now()));
    if (db.logs.length > 1500) db.logs.splice(0, db.logs.length - 1500);
    return { lines: db.logs.slice(-n) };
  }],
  ['GET', /^siem$/, (db) => ({ ...db.siem })],
  ['PUT', /^siem$/, (db, _m, b) => {
    if (!db.siem.supported) throw new ApiError(400, db.siem.note || 'SIEM forwarding isn\'t supported on this machine.');
    const port = Number(b.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ApiError(400, 'The SIEM port must be a number from 1 to 65535.');
    if (b.enabled && !String(b.host ?? '').trim()) throw new ApiError(400, 'Enter the SIEM host to forward to.');
    db.siem = { ...db.siem, enabled: !!b.enabled, host: String(b.host ?? ''), port, protocol: b.protocol as Siem['protocol'], caFile: b.protocol === 'tls' ? String(b.caFile ?? '') : undefined };
    db.settings.logging.format = 'json';
    return { log: `Turned on JSON logs.\nWrote /etc/rsyslog.d/30-nebula.conf (${db.siem.protocol} to ${db.siem.host}:${db.siem.port})\nsystemctl restart rsyslog: ok` };
  }, 700],
  ['POST', /^siem\/test$/, (db) => {
    if (!db.siem.enabled) throw new ApiError(400, 'Turn on forwarding and save before sending a test event.');
    return { log: `logger -t nebula "nebctl test event"\nSent one line to ${db.siem.host}:${db.siem.port}. Look for it tagged nebula on the SIEM.` };
  }, 600],

  ['GET', /^health$/, (db) => health(db)],
  ['GET', /^audit$/, (db) => ({ machine: db.state.hostname, findings: audit(db) }), 900],
  ['POST', /^update$/, (db) => {
    db.state.nebula = db.latest;
    return { log: `Downloaded nebula ${db.latest} (checksum ok)\nInstalled /usr/local/bin/nebula\nRestarted nebula.` };
  }, 2200],
  ['POST', /^service\/(start|stop|restart)$/, (db, m) => {
    const a = m[1];
    db.state.service = a === 'stop' ? 'stopped (logs: journalctl -u nebula)' : 'running';
    return { log: `systemctl ${a} nebula: ok` };
  }, 900],
];

export async function handle(method: string, path: string, body: unknown): Promise<unknown> {
  await sleep(LATENCY);
  if (params.has('expired')) throw new ApiError(401, 'Unauthorized');
  const [p, qs] = path.split('?');
  const query = new URLSearchParams(qs ?? '');
  const b = (body ?? {}) as Body;

  if (p === '/api/targets') {
    if (method === 'GET') return targetList();
    if (method === 'POST') return connect(b as unknown as ConnectBody, false);
  }
  if (p === '/api/link' && method === 'POST') {
    return { url: `${location.origin}/?token=mock-${Math.random().toString(36).slice(2, 10)}${params.has('mock') ? '&mock' : ''}` };
  }
  if (p === '/api/targets/install' && method === 'POST') {
    await sleep(LATENCY * 4);
    return connect(b as unknown as ConnectBody, true);
  }
  const save = p.match(/^\/api\/targets\/([^/]+)\/save-key$/);
  if (save && method === 'POST') {
    const d = dbs.get(decodeURIComponent(save[1]));
    if (!d || !d.target.host) throw new ApiError(404, 'That machine isn\'t connected any more: connect to it again.');
    keyed.add(d.target.host);
    return { message: `The console's key is in ${d.target.user}'s authorized_keys on ${d.target.host}. Next time it logs in without the SSH password; sudo may still ask for one. To remove it, delete the line ending in nebctl-console@mac01 there.` };
  }
  const del = p.match(/^\/api\/targets\/([^/]+)$/);
  if (del && method === 'DELETE') {
    const id = decodeURIComponent(del[1]);
    const d = dbs.get(id);
    if (!d) throw new ApiError(404, 'That machine is not connected.');
    if (d.target.kind === 'local') throw new ApiError(400, 'This machine can\'t be disconnected.');
    dbs.delete(id);
    return undefined;
  }

  const m = p.match(/^\/api\/t\/([^/]+)\/(.+)$/);
  if (m) {
    const db = dbs.get(decodeURIComponent(m[1]));
    if (!db) throw new ApiError(404, 'That machine is not connected. Pick another from the machine list.');
    for (const [verb, re, fn, extra] of routes) {
      if (verb !== method) continue;
      const mm = m[2].match(re);
      if (!mm) continue;
      if (extra) await sleep((extra * LATENCY) / 300);
      const out = await fn(db, mm, b, query);
      return out === undefined ? undefined : JSON.parse(JSON.stringify(out));
    }
  }
  throw new ApiError(404, `The console asked for ${method} ${p}, which nebctl doesn't know.`);
}
