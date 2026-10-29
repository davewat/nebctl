import { useMemo } from 'react';
import { AdminGate } from '../components/AdminGate';
import { useConsole } from '../context';
import { fmtTime, peerState, plural } from '../lib/format';
import { Empty } from '../ui';
import { MeshCanvas } from './MeshCanvas';

export function MapPage({ drawerWidth }: { drawerWidth: number }) {
  return (
    <div className="map">
      <h1 className="sr-only">Map</h1>
      <AdminGate>
        <MapInner drawerWidth={drawerWidth} />
      </AdminGate>
    </div>
  );
}

function MapInner({ drawerWidth }: { drawerWidth: number }) {
  const { state, conns, blocked, selected, selectPeer, target } = useConsole();
  const data = conns.data;

  const lighthouses = useMemo(() => {
    const s = new Set<string>();
    state?.host?.lighthouses.forEach((l) => s.add(l.nebulaIp));
    return s;
  }, [state]);

  if (!data) {
    return (
      <div className="map-center" role="status">
        {conns.error ? (
          <div className="panel gate">
            <h2>Can't read connections from {target.label}</h2>
            <p className="error-text">{conns.error}</p>
          </div>
        ) : (
          <p className="loading"><span className="spin" aria-hidden="true" /> Reading connections…</p>
        )}
      </div>
    );
  }

  const established = data.peers.filter((p) => !p.pending).length;
  const pending = data.peers.length - established;
  const revoked = data.peers.filter((p) => peerState(p, blocked) === 'revoked').length;
  const summary =
    data.peers.length === 0
      ? 'No hosts connected'
      : `${plural(established, 'host')} connected, ${pending} handshaking${revoked ? `, ${revoked} with a revoked cert` : ''}`;

  return (
    <>
      <MeshCanvas
        self={data.self}
        peers={data.peers}
        lighthouses={lighthouses}
        blocked={blocked}
        selected={selected}
        onSelect={selectPeer}
        coveredRight={selected ? drawerWidth : 0}
        summary={`Map of ${data.self.name}: ${summary}. Choose a host from the list that follows, or open the Hosts page, to see its details.`}
      />
      <div className="map-head" style={{ right: selected ? drawerWidth + 20 : 20 }}>
        <p className="map-title" aria-hidden="true">Map</p>
        <p className="dim">{summary}</p>
      </div>
      <ul className="legend" aria-label="Legend">
        <li><span className="key key-direct" aria-hidden="true" /> Direct tunnel</li>
        <li><span className="key key-relay" aria-hidden="true" /> Relayed tunnel</li>
        <li><span className="key key-pending" aria-hidden="true" /> Handshaking</li>
        <li><span className="key key-lh" aria-hidden="true" /> Lighthouse</li>
        <li><span className="key key-warn" aria-hidden="true">!</span> Cert ends within 30 days</li>
        <li><span className="key key-revoked" aria-hidden="true" /> Revoked cert</li>
      </ul>
      <p className="map-meta dim" aria-live="off">
        Updated <span className="num">{conns.at ? fmtTime(conns.at) : ''}</span>
        {conns.error ? <span className="error-inline"> (refresh failed)</span> : null}
      </p>
      {data.peers.length === 0 && (
        <div className="map-empty">
          <Empty>
            No hosts are connected yet.{' '}
            {state?.haveCa ? <a href="#/certs">Sign a cert for one on the Certificates page.</a> : 'Sign a cert for one on the Certificates page of the lighthouse.'}
          </Empty>
        </div>
      )}
    </>
  );
}
