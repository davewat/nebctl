import { useMemo, useState } from 'react';
import type { Peer } from '../api/types';
import { AdminGate } from '../components/AdminGate';
import { useConsole } from '../context';
import { daysUntil, EXPIRY_WARN_DAYS, expiryText, fmtDate, fmtNumber, fmtTime, ipKey, isExpiring, peerState, shortName, STATE_LABEL } from '../lib/format';
import type { PeerState } from '../lib/format';
import { Empty, PageHead, Panel, StatePill } from '../ui';

type SortKey = 'name' | 'addr' | 'remote' | 'expires' | 'packets' | 'state';
type StateFilter = 'all' | PeerState | 'expiring';

export function HostsPage() {
  return (
    <div className="page">
      <PageHead title="Hosts" sub="Every host this machine has a tunnel to, or is setting one up with." />
      <AdminGate>
        <HostsInner />
      </AdminGate>
    </div>
  );
}

function HostsInner() {
  const { conns, blocked, selected, selectPeer, nameOf, state, target } = useConsole();
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<StateFilter>('all');
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'addr', dir: 1 });
  const data = conns.data;

  const rows = useMemo(() => {
    const peers = data?.peers ?? [];
    const needle = q.trim().toLowerCase();
    const remoteText = (p: Peer) => p.currentRemote ?? (p.relayedThrough.length ? `via ${nameOf(p.relayedThrough[0])}` : '');
    const filtered = peers.filter((p) => {
      const st = peerState(p, blocked);
      if (filter === 'expiring' ? !isExpiring(p) : filter !== 'all' && st !== filter) return false;
      if (!needle) return true;
      return [p.name, p.vpnAddr, remoteText(p), ...p.groups].some((s) => s.toLowerCase().includes(needle));
    });
    const val = (p: Peer): string | number => {
      switch (sort.key) {
        case 'name': return p.name;
        case 'addr': return ipKey(p.vpnAddr);
        case 'remote': return remoteText(p);
        case 'expires': return Date.parse(p.notAfter);
        case 'packets': return p.messageCounter;
        case 'state': return STATE_LABEL[peerState(p, blocked)];
      }
    };
    return [...filtered].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
      return c * sort.dir || ipKey(a.vpnAddr) - ipKey(b.vpnAddr);
    });
  }, [data, q, filter, sort, blocked, nameOf]);

  if (!data) {
    return conns.error ? (
      <div className="panel gate">
        <h2>Can't read connections from {target.label}</h2>
        <p className="error-text">{conns.error}</p>
      </div>
    ) : (
      <p className="loading"><span className="spin" aria-hidden="true" /> Reading connections…</p>
    );
  }

  const th = (key: SortKey, label: string, cls?: string) => (
    <th scope="col" className={cls} aria-sort={sort.key === key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="th-btn" onClick={() => setSort((s) => (s.key === key ? { key, dir: (s.dir * -1) as 1 | -1 } : { key, dir: 1 }))}>
        {label}
        <span className={`sort${sort.key === key ? (sort.dir === 1 ? ' asc' : ' desc') : ''}`} aria-hidden="true" />
      </button>
    </th>
  );

  return (
    <>
      <div className="toolbar">
        <input type="search" aria-label="Filter hosts" placeholder="Filter by name, address or group" value={q} onChange={(e) => setQ(e.target.value)} className="grow" />
        <select aria-label="Show hosts in state" value={filter} onChange={(e) => setFilter(e.target.value as StateFilter)}>
          <option value="all">All states</option>
          <option value="connected">Connected</option>
          <option value="relayed">Relayed</option>
          <option value="handshaking">Handshaking</option>
          <option value="revoked">Revoked</option>
          <option value="expiring">Cert ends within 30 days</option>
        </select>
        <span className="dim num toolbar-meta">Updated {conns.at ? fmtTime(conns.at) : ''}</span>
      </div>

      <div className="table-wrap">
        <table className="data hosts-table">
          <colgroup>
            <col style={{ width: '17%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '23%' }} />
            <col style={{ width: '19%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '18%' }} />
          </colgroup>
          <thead>
            <tr>
              {th('name', 'Name')}
              {th('addr', 'Address')}
              {th('remote', 'Current remote')}
              {th('expires', 'Cert expires')}
              {th('packets', 'Packets', 'right')}
              {th('state', 'State')}
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => {
              const d = daysUntil(p.notAfter);
              return (
                <tr key={p.vpnAddr} className={selected === p.vpnAddr ? 'is-selected' : undefined} onClick={() => selectPeer(p.vpnAddr)}>
                  <td>
                    <button type="button" className="row-btn" aria-pressed={selected === p.vpnAddr} onClick={(e) => { e.stopPropagation(); selectPeer(p.vpnAddr); }}>
                      {shortName(p.name)}
                    </button>
                  </td>
                  <td className="mono">{p.vpnAddr}</td>
                  <td className="mono wrap-any">
                    {p.currentRemote ?? (p.relayedThrough.length ? <span className="sans relay-text">via {nameOf(p.relayedThrough[0])}</span> : <span className="dim sans">{p.pending ? 'Handshaking' : 'None'}</span>)}
                  </td>
                  <td className={d < EXPIRY_WARN_DAYS ? 'warn-text' : undefined}>
                    {fmtDate(p.notAfter)}
                    <span className="sub-line">{d < EXPIRY_WARN_DAYS ? 'Ends ' : ''}{expiryText(d)}</span>
                  </td>
                  <td className="right num">{fmtNumber(p.messageCounter)}</td>
                  <td><StatePill state={peerState(p, blocked)} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {data.peers.length === 0 && (
          <Empty>
            No hosts are connected yet.{' '}
            {state?.haveCa ? <a href="#/certs">Sign a cert for one on the Certificates page.</a> : 'Sign a cert for one on the Certificates page of the lighthouse.'}
          </Empty>
        )}
        {data.peers.length > 0 && rows.length === 0 && <Empty>No hosts match. Clear the filter to see all {data.peers.length}.</Empty>}
      </div>

      {data.addrMap && (
        <Panel title="What the lighthouse knows" sub="The addresses each host has reported or that this lighthouse learned from its handshakes.">
          <div className="table-wrap flush">
            <table className="data">
              <colgroup>
                <col style={{ width: '18%' }} />
                <col style={{ width: '14%' }} />
                <col style={{ width: '24%' }} />
                <col style={{ width: '26%' }} />
                <col style={{ width: '18%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Host</th>
                  <th scope="col">Address</th>
                  <th scope="col">Learned</th>
                  <th scope="col">Reported</th>
                  <th scope="col">Relays</th>
                </tr>
              </thead>
              <tbody>
                {data.addrMap.map((e) => (
                  <tr key={e.vpnAddr}>
                    <td>{nameOf(e.vpnAddr)}</td>
                    <td className="mono">{e.vpnAddr}</td>
                    <td className="mono">{e.learned.length ? e.learned.map((a) => <div key={a}>{a}</div>) : <span className="dim sans">None</span>}</td>
                    <td className="mono">{e.reported.length ? e.reported.map((a) => <div key={a}>{a}</div>) : <span className="dim sans">None</span>}</td>
                    <td>{e.relays.length ? e.relays.map((a) => <div key={a}>{nameOf(a)}</div>) : <span className="dim">None</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </>
  );
}
