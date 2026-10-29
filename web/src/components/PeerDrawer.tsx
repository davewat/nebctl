import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import type { Lookup, Peer } from '../api/types';
import { useConsole } from '../context';
import { daysUntil, expiryText, EXPIRY_WARN_DAYS, fmtDate, fmtNumber, peerState, shortName } from '../lib/format';
import { useTask } from '../lib/hooks';
import { Button, Chips, CopyValue, ErrorText, Field, StatePill } from '../ui';

export function PeerDrawer({ addr, onClose }: { addr: string; onClose: () => void }) {
  const { target, conns, blocked, nameOf, toast } = useConsole();
  const live = conns.data?.peers.find((p) => p.vpnAddr === addr);
  const last = useRef<Peer>();
  if (live) last.current = live;
  const peer = live ?? (last.current?.vpnAddr === addr ? last.current : undefined);
  const gone = !live && !!peer;

  const head = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    head.current?.focus();
  }, [addr]);

  // Escape closes the drawer, unless a dialog or menu has it.
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !document.querySelector('dialog[open]') && !document.querySelector('.menu')) onClose();
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [onClose]);

  const closeT = useTask();
  const openT = useTask();
  const remoteT = useTask();
  const lookT = useTask();
  const [localOnly, setLocalOnly] = useState(false);
  const [address, setAddress] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [lookup, setLookup] = useState<Lookup | null | undefined>(undefined);

  // Reset per-host state when the selection changes.
  useEffect(() => {
    setMsg(null);
    setLookup(undefined);
    setAddress('');
    closeT.setError(null);
    openT.setError(null);
    remoteT.setError(null);
    lookT.setError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [addr]);

  const state = peer ? peerState(peer, blocked) : undefined;
  const days = peer ? daysUntil(peer.notAfter) : 0;

  const relayNames = (list: string[]) => list.map((a) => `${nameOf(a)} (${a})`);

  return (
    <aside className="drawer" aria-label={`Details for ${peer ? shortName(peer.name) : addr}`}>
      <div className="drawer-head">
        <div className="drawer-title">
          <h2 ref={head} tabIndex={-1}>
            {peer ? shortName(peer.name) : addr}
          </h2>
          {state && <StatePill state={state} />}
        </div>
        <Button small variant="quiet" onClick={onClose} aria-label="Close details">
          Close
        </Button>
      </div>

      {!peer ? (
        <div className="drawer-body">
          <p className="dim">There is no tunnel to {addr} right now.</p>
          <Section title="Actions">
            <Button variant="primary" busy={openT.busy} onClick={async () => {
              const r = await openT.run(() => api.createTunnel(target.id, addr));
              if (r) { setMsg(r.message); await conns.reload(); }
            }}>
              Re-open tunnel
            </Button>
            <ErrorText>{openT.error}</ErrorText>
            {msg && <p className="act-msg" role="status">{msg}</p>}
          </Section>
        </div>
      ) : (
        <div className="drawer-body">
          {gone && <p className="notice notice-warn" role="status">This tunnel is closed. You can re-open it below.</p>}
          {state === 'revoked' && <p className="notice notice-danger">This host's cert is on the blocklist, so it can't reconnect.</p>}
          <dl className="kv">
            <dt>Cert name</dt>
            <dd>{peer.name}</dd>
            <dt>Address</dt>
            <dd className="mono">{peer.vpnAddr}</dd>
            <dt>Groups</dt>
            <dd><Chips items={peer.groups} empty="No groups" /></dd>
            <dt>Cert expires</dt>
            <dd className={days < EXPIRY_WARN_DAYS ? 'warn-text' : undefined}>
              {fmtDate(peer.notAfter)}, {expiryText(days)}
            </dd>
            <dt>Fingerprint</dt>
            <dd><CopyValue text={peer.fingerprint} /></dd>
            <dt>Current remote</dt>
            <dd>
              {peer.currentRemote ? (
                <span className="mono">{peer.currentRemote}</span>
              ) : peer.relayedThrough.length ? (
                <span>Relayed through {relayNames(peer.relayedThrough).join(', ')}</span>
              ) : (
                <span className="dim">{peer.pending ? 'Not known yet, still handshaking' : 'None'}</span>
              )}
            </dd>
            <dt>All remote addresses</dt>
            <dd>
              {peer.remoteAddrs.length ? (
                <ul className="plain mono">
                  {peer.remoteAddrs.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              ) : (
                <span className="dim">None known</span>
              )}
            </dd>
            <dt>Relays</dt>
            <dd>{peer.relayedThrough.length ? relayNames(peer.relayedThrough).join(', ') : <span className="dim">None in use</span>}</dd>
            {peer.relaysFor.length > 0 && (
              <>
                <dt>Relays for</dt>
                <dd>{relayNames(peer.relaysFor).join(', ')}</dd>
              </>
            )}
            <dt>Packets sent</dt>
            <dd className="num">{fmtNumber(peer.messageCounter)}</dd>
            <dt>Tunnel indexes</dt>
            <dd className="mono dim">
              local {peer.localIndex}, remote {peer.remoteIndex}
            </dd>
          </dl>

          <Section title="Actions">
            <div className="act">
              <div className="act-row">
                <Button variant="danger" busy={closeT.busy} onClick={async () => {
                  const r = await closeT.run(() => api.closeTunnel(target.id, peer.vpnAddr, localOnly));
                  if (r) { setMsg(r.message); toast(`Closed the tunnel to ${shortName(peer.name)}.`); await conns.reload(); }
                }}>
                  Close tunnel
                </Button>
                <label className="check">
                  <input type="checkbox" checked={localOnly} onChange={(e) => setLocalOnly(e.target.checked)} />
                  <span>Close it on this machine only</span>
                </label>
              </div>
              <ErrorText>{closeT.error}</ErrorText>
            </div>

            <div className="act">
              <div className="act-row">
                <Button busy={openT.busy} onClick={async () => {
                  const r = await openT.run(() => api.createTunnel(target.id, peer.vpnAddr));
                  if (r) { setMsg(r.message); await conns.reload(); }
                }}>
                  Re-open tunnel
                </Button>
              </div>
              <ErrorText>{openT.error}</ErrorText>
            </div>

            <form
              className="act"
              onSubmit={async (e) => {
                e.preventDefault();
                if (!address.trim()) return;
                const r = await remoteT.run(() => api.changeRemote(target.id, peer.vpnAddr, address.trim()));
                if (r) { setMsg(r.message); setAddress(''); await conns.reload(); }
              }}
            >
              <Field label="Use another address" htmlFor="d-addr" hint="Where nebula should send this host's packets, as address:port.">
                <div className="act-row">
                  <input id="d-addr" className="mono-input grow" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="198.51.100.7:4242" spellCheck={false} autoComplete="off" />
                  <Button type="submit" busy={remoteT.busy} disabled={!address.trim()}>
                    Use this address
                  </Button>
                </div>
              </Field>
              <ErrorText>{remoteT.error}</ErrorText>
            </form>

            <div className="act">
              <div className="act-row">
                <Button busy={lookT.busy} onClick={async () => {
                  const r = await lookT.run(() => api.lookup(target.id, peer.vpnAddr));
                  if (r !== undefined) setLookup(r);
                }}>
                  Ask the lighthouse where it is
                </Button>
              </div>
              <ErrorText>{lookT.error}</ErrorText>
              {lookup === null && <p className="act-msg" role="status">The lighthouse doesn't know where {shortName(peer.name)} is.</p>}
              {lookup && (
                <dl className="kv act-result" role="status">
                  <dt>Learned</dt>
                  <dd className="mono">{lookup.learned.length ? lookup.learned.join(', ') : <span className="dim sans">None</span>}</dd>
                  <dt>Reported</dt>
                  <dd className="mono">{lookup.reported.length ? lookup.reported.join(', ') : <span className="dim sans">None</span>}</dd>
                  <dt>Relays</dt>
                  <dd>{lookup.relays.length ? relayNames(lookup.relays).join(', ') : <span className="dim">None</span>}</dd>
                </dl>
              )}
            </div>
            {msg && <p className="act-msg" role="status">{msg}</p>}
          </Section>
        </div>
      )}
    </aside>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="drawer-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}
