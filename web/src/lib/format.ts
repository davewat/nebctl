import type { Peer } from '../api/types';

export const EXPIRY_WARN_DAYS = 30;

/** "fe01.nebula.example.com" -> "fe01" */
export const shortName = (name: string): string => name.split('.')[0] || name;

export function daysUntil(iso: string): number {
  return Math.floor((Date.parse(iso) - Date.now()) / 864e5);
}

export function expiryText(days: number): string {
  if (days < -1) return `expired ${-days} days ago`;
  if (days === -1) return 'expired yesterday';
  if (days === 0) return 'expires today';
  if (days === 1) return 'in 1 day';
  return `in ${days} days`;
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function fmtTime(ms: number | string): string {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false });
}

export const fmtNumber = (n: number): string => n.toLocaleString();

export function plural(n: number, one: string, many?: string): string {
  return `${n} ${n === 1 ? one : many ?? one + 's'}`;
}

/** Numeric key for sorting dotted addresses. */
export function ipKey(a: string): number {
  const p = a.split('.').map((x) => parseInt(x, 10));
  if (p.length !== 4 || p.some(Number.isNaN)) return 0;
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

export type PeerState = 'connected' | 'relayed' | 'handshaking' | 'revoked';

export function peerState(p: Peer, blocked: Set<string>): PeerState {
  if (blocked.has(p.fingerprint)) return 'revoked';
  if (p.pending) return 'handshaking';
  if (!p.currentRemote && p.relayedThrough.length > 0) return 'relayed';
  return 'connected';
}

export const STATE_LABEL: Record<PeerState, string> = {
  connected: 'Connected',
  relayed: 'Relayed',
  handshaking: 'Handshaking',
  revoked: 'Revoked',
};

export function isExpiring(p: Peer): boolean {
  return daysUntil(p.notAfter) < EXPIRY_WARN_DAYS;
}

export function splitList(s: string): string[] {
  return s
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}
