import { request } from './client';
import type {
  Certificates,
  ConnectBody,
  Connections,
  Health,
  Finding,
  Lookup,
  Peer,
  Settings,
  SettingsChange,
  Signed,
  Siem,
  State,
  Target,
} from './types';

const t = (id: string, path: string) => `/api/t/${encodeURIComponent(id)}/${path}`;
const addr = (a: string) => encodeURIComponent(a);

export const api = {
  // targets
  targets: () => request<Target[]>('GET', '/api/targets'),
  connect: (b: ConnectBody) => request<Target>('POST', '/api/targets', b),
  // The contract doesn't say what install returns; it is treated like a connect (a Target).
  install: (b: ConnectBody) => request<Target>('POST', '/api/targets/install', { ...b, install: true }),
  disconnect: (id: string) => request<void>('DELETE', `/api/targets/${encodeURIComponent(id)}`),

  // a fresh one-time link to this console (for "Open in browser" from the Mac app)
  link: () => request<{ url: string }>('POST', '/api/link'),

  // state
  state: (id: string) => request<State>('GET', t(id, 'state')),
  enableAdmin: (id: string) => request<{ log: string }>('POST', t(id, 'admin/enable')),

  // connections
  connections: (id: string) => request<Connections>('GET', t(id, 'connections')),
  tunnel: (id: string, a: string) => request<Peer>('GET', t(id, `tunnel/${addr(a)}`)),
  closeTunnel: (id: string, a: string, localOnly: boolean) =>
    request<{ message: string }>('POST', t(id, `tunnel/${addr(a)}/close`), { localOnly }),
  createTunnel: (id: string, a: string, address?: string) =>
    request<{ message: string }>('POST', t(id, `tunnel/${addr(a)}/create`), address ? { address } : {}),
  changeRemote: (id: string, a: string, address: string) =>
    request<{ message: string }>('POST', t(id, `tunnel/${addr(a)}/remote`), { address }),
  lookup: (id: string, a: string) => request<Lookup | null>('GET', t(id, `lookup/${addr(a)}`)),
  logLevel: (id: string) => request<{ level: string }>('GET', t(id, 'log-level')),
  setLogLevel: (id: string, level: string) => request<{ level: string }>('POST', t(id, 'log-level'), { level }),
  reload: (id: string) => request<{ message: string }>('POST', t(id, 'reload')),

  // certificates
  certs: (id: string) => request<Certificates>('GET', t(id, 'certs')),
  nextIp: (id: string) => request<{ ip: string }>('GET', t(id, 'certs/next-ip')),
  sign: (id: string, b: { name: string; ip?: string; groups?: string[] }) => request<Signed>('POST', t(id, 'certs'), b),
  signRequest: (id: string, b: { request: string; name?: string; ip?: string; groups?: string[] }) =>
    request<Signed>('POST', t(id, 'certs/request'), b),
  revoke: (id: string, fingerprint: string) =>
    request<{ blocklist: string[]; log: string }>('POST', t(id, 'certs/revoke'), { fingerprint }),
  putBlocklist: (id: string, fingerprints: string[]) =>
    request<{ log: string }>('PUT', t(id, 'blocklist'), { fingerprints }),

  // configuration
  settings: (id: string) => request<Settings>('GET', t(id, 'settings')),
  putSettings: (id: string, c: SettingsChange) => request<{ log: string; restarted: boolean }>('PUT', t(id, 'settings'), c),

  // logs and SIEM
  logs: (id: string, lines: number) => request<{ lines: string[] }>('GET', t(id, `logs?lines=${lines}`)),
  siem: (id: string) => request<Siem>('GET', t(id, 'siem')),
  putSiem: (id: string, s: Omit<Siem, 'supported' | 'note'>) => request<{ log: string }>('PUT', t(id, 'siem'), s),
  siemTest: (id: string) => request<{ log: string }>('POST', t(id, 'siem/test')),

  // health
  health: (id: string) => request<Health>('GET', t(id, 'health')),
  audit: (id: string) => request<{ machine: string; findings: Finding[] }>('GET', t(id, 'audit')),
  update: (id: string) => request<{ log: string }>('POST', t(id, 'update')),
  service: (id: string, action: 'start' | 'stop' | 'restart') => request<{ log: string }>('POST', t(id, `service/${action}`)),
};
