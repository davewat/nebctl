// Mirrors web/CONTRACT.md. Keep the two in step.

export interface Target {
  id: string;
  label: string;
  kind: 'local' | 'ssh';
  host?: string;
  user?: string;
  role?: 'lighthouse' | 'node';
  haveCa: boolean;
}

export interface ConnectBody {
  host: string;
  port?: number;
  user: string;
  password?: string;
  useAgent?: boolean;
  keyPath?: string;
  passphrase?: string;
  sudoPassword?: string;
  acceptHostKey?: string;
}

export interface HostKeyInfo {
  fingerprint: string;
  type: string;
  changed: boolean;
}

export interface MissingNebctl {
  nebctl: 'missing' | 'old';
  remoteVersion?: string;
  arch: string;
  version: string;
}

export type NeedField = 'password' | 'passphrase' | 'sudoPassword';

export interface Rule {
  port: string;
  proto: 'any' | 'tcp' | 'udp' | 'icmp';
  host?: string;
  group?: string;
}

export interface Lighthouse {
  name?: string;
  nebulaIp: string;
  endpoints: string[];
  relay?: boolean;
  dns?: boolean;
}

export interface Host {
  role: 'lighthouse' | 'node';
  name: string;
  nebulaIp: string;
  listenPort: number;
  relay?: boolean;
  dns?: boolean;
  domain?: string;
  resolve?: boolean;
  lighthouses: Lighthouse[];
  inbound: Rule[];
}

export interface CertInfo {
  name: string;
  networks: string[];
  groups?: string[];
  notAfter: string;
  daysLeft: number;
}

export interface State {
  nebctl: string;
  nebula?: string;
  host?: Host;
  cert?: CertInfo;
  ca?: string;
  haveCa: boolean;
  service: string;
  hostname: string;
  admin: { enabled: boolean; listen: string };
}

export interface Peer {
  vpnAddr: string;
  name: string;
  groups: string[];
  notAfter: string;
  fingerprint: string;
  currentRemote?: string;
  remoteAddrs: string[];
  relayedThrough: string[];
  relaysFor: string[];
  messageCounter: number;
  localIndex: number;
  remoteIndex: number;
  pending: boolean;
}

export interface AddrMapEntry {
  vpnAddr: string;
  learned: string[];
  reported: string[];
  relays: string[];
}

export interface Connections {
  self: { vpnAddr: string; name: string; role: 'lighthouse' | 'node' };
  peers: Peer[];
  addrMap?: AddrMapEntry[];
  at: string;
}

export interface Lookup {
  vpnAddr: string;
  learned: string[];
  reported: string[];
  relays: string[];
}

export interface IssuedCert {
  name: string;
  nebulaIp: string;
  groups: string[];
  fingerprint: string;
  notAfter: string;
  issuedAt: string;
  daysLeft: number;
  revoked: boolean;
  online?: boolean;
}

export interface Certificates {
  ca: { name: string; notAfter: string; daysLeft: number; fingerprint: string };
  cidr: string;
  domain?: string;
  lighthouses: Lighthouse[];
  issued: IssuedCert[];
  blocklist: string[];
}

export interface Signed {
  bundle: string;
  cert: IssuedCert;
  replaces?: string;
  nextIp: string;
}

export interface Settings {
  host: Host;
  logging: { level: string; format: 'text' | 'json' };
  metrics: { enabled: boolean; listen: string };
  blocklist: string[];
}

export interface SettingsChange {
  inbound?: Rule[];
  dns?: boolean;
  relay?: boolean;
  listenPort?: number;
  lighthouses?: Lighthouse[];
  resolve?: boolean;
  logging?: { level?: string; format?: 'text' | 'json' };
  metrics?: { enabled: boolean };
}

export interface Siem {
  enabled: boolean;
  host: string;
  port: number;
  protocol: 'udp' | 'tcp' | 'tls';
  caFile?: string;
  supported: boolean;
  note?: string;
}

export interface Health {
  nebctl: string;
  nebula?: string;
  latest?: string;
  service: string;
  cert?: CertInfo;
  ca?: { name: string; daysLeft: number };
  metrics?: Record<string, number>;
  tunnels: number;
  pending: number;
}

export type FindingLevel = 'pass' | 'info' | 'warn' | 'fail';

export interface Finding {
  section: string;
  level: FindingLevel;
  title: string;
  detail?: string;
  fix?: string[];
}
