import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';
import { ApiError, errMsg, isMock, onSessionExpired } from './api/client';
import type { Target } from './api/types';
import { ConnectDialog } from './components/ConnectDialog';
import { PeerDrawer } from './components/PeerDrawer';
import { TargetSwitcher } from './components/TargetSwitcher';
import { ConsoleContext, useConsole } from './context';
import type { ConsoleCtx } from './context';
import { shortName } from './lib/format';
import { useHashRoute, useResource } from './lib/hooks';
import { CertsPage } from './pages/CertsPage';
import { ConfigPage } from './pages/ConfigPage';
import { HealthPage } from './pages/HealthPage';
import { HostsPage } from './pages/HostsPage';
import { LogsPage } from './pages/LogsPage';
import { MapPage } from './pages/MapPage';
import { Button, Loading } from './ui';

const PAGES = [
  { id: 'map', label: 'Map' },
  { id: 'hosts', label: 'Hosts' },
  { id: 'certs', label: 'Certs' },
  { id: 'config', label: 'Config' },
  { id: 'logs', label: 'Logs' },
  { id: 'health', label: 'Health' },
] as const;
const PAGE_IDS = PAGES.map((p) => p.id) as string[];
const DRAWER_W = 360;
const embedded = (() => {
  try {
    return new URLSearchParams(location.search).get('embedded') === '1';
  } catch {
    return false;
  }
})();

export default function App() {
  const [expired, setExpired] = useState(false);
  useEffect(() => onSessionExpired(() => setExpired(true)), []);
  if (expired) return <Expired />;
  return <Boot />;
}

function Expired() {
  return (
    <main className="fullpage">
      <span className="brand-dot big" aria-hidden="true" />
      <h1>This console link has expired. Run <code className="mono">sudo nebctl web</code> again for a new one.</h1>
    </main>
  );
}

function Boot() {
  const res = useResource(() => api.targets(), []);
  if (res.data) return <Console initial={res.data} />;
  return (
    <main className="fullpage">
      <span className="brand-dot big pulse" aria-hidden="true" />
      {res.error ? (
        <>
          <h1>Can't reach the console</h1>
          <p className="error-text">{res.error}</p>
          <Button onClick={res.refresh}>Try again</Button>
        </>
      ) : (
        <Loading>Connecting to nebctl…</Loading>
      )}
    </main>
  );
}

function useNarrow(px: number): boolean {
  const [n, setN] = useState(() => window.innerWidth < px);
  useEffect(() => {
    const on = () => setN(window.innerWidth < px);
    window.addEventListener('resize', on);
    return () => window.removeEventListener('resize', on);
  }, [px]);
  return n;
}

interface Toast { id: number; message: string; tone: 'ok' | 'error' }

function Console({ initial }: { initial: Target[] }) {
  const [targets, setTargets] = useState<Target[]>(initial);
  const [targetId, setTargetId] = useState<string>(() => {
    let want: string | null = null;
    try {
      want = new URLSearchParams(location.search).get('target') ?? sessionStorage.getItem('nebctl.target');
    } catch { /* storage off */ }
    return initial.some((t) => t.id === want) ? (want as string) : 'local';
  });
  const route = useHashRoute('map', PAGE_IDS);
  const [selected, setSelected] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);
  const narrow = useNarrow(760);

  const baseTarget = targets.find((t) => t.id === targetId) ?? targets[0];

  const state = useResource(() => api.state(baseTarget.id), [baseTarget.id], { poll: 30000 });
  const st = state.data;
  const target = useMemo<Target>(() => ({ ...baseTarget, haveCa: st?.haveCa ?? baseTarget.haveCa, role: st?.host?.role ?? baseTarget.role }), [baseTarget, st]);

  const live = (route === 'map' || route === 'hosts') && !!st?.admin.enabled && !!st.host;
  const conns = useResource(live ? () => api.connections(target.id) : null, [target.id, live], { poll: 5000 });
  const settings = useResource(live ? () => api.settings(target.id) : null, [target.id, live], { poll: 30000 });
  const blocked = useMemo(() => new Set(settings.data?.blocklist ?? []), [settings.data]);

  useEffect(() => {
    setSelected(null);
  }, [target.id]);

  useEffect(() => {
    document.title = `${PAGES.find((p) => p.id === route)?.label ?? 'nebctl'}, ${target.label} - nebctl`;
  }, [route, target.label]);

  const toast = useCallback((message: string, tone: 'ok' | 'error' = 'ok') => {
    const id = ++toastId.current;
    setToasts((t) => [...t, { id, message, tone }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === 'error' ? 9000 : 5000);
  }, []);

  const refreshTargets = useCallback(async () => {
    try {
      setTargets(await api.targets());
    } catch (e) {
      toast(errMsg(e), 'error');
    }
  }, [toast]);

  const selectTarget = useCallback((id: string) => {
    setTargetId(id);
    try {
      sessionStorage.setItem('nebctl.target', id);
    } catch { /* storage off */ }
  }, []);

  const nameOf = useCallback(
    (a: string) => {
      const d = conns.data;
      if (d) {
        if (a === d.self.vpnAddr) return shortName(d.self.name);
        const p = d.peers.find((x) => x.vpnAddr === a);
        if (p) return shortName(p.name);
      }
      const lh = st?.host?.lighthouses.find((l) => l.nebulaIp === a);
      if (lh?.name) return shortName(lh.name);
      if (st?.host?.nebulaIp === a) return shortName(st.host.name);
      return a;
    },
    [conns.data, st],
  );

  const ctx: ConsoleCtx = {
    targets,
    target,
    state: st,
    stateError: state.error,
    stateLoading: state.loading,
    refreshState: () => void state.reload(),
    refreshTargets,
    selectTarget,
    openConnect: () => setConnecting(true),
    toast,
    conns: { data: conns.data, error: conns.error, loading: conns.loading, at: conns.at, reload: conns.reload },
    blocked,
    selected,
    selectPeer: setSelected,
    nameOf,
    caTarget: targets.find((t) => t.haveCa && t.id !== target.id),
  };

  const showDrawer = selected !== null && (route === 'map' || route === 'hosts');

  return (
    <ConsoleContext.Provider value={ctx}>
      <div className={`shell route-${route}`}>
        <header className="topbar">
          <a className="brand" href="#/map" aria-label="nebctl, go to the map">
            <span className="brand-dot" aria-hidden="true" />
            nebctl
          </a>
          <TargetSwitcher />
          <div className="topbar-space" />
          {embedded && <OpenInBrowser />}
          <p className="status" role="status" aria-live="polite">
            <StatusText />
          </p>
        </header>

        <nav className="side" aria-label="Pages">
          <ul>
            {PAGES.map((p) => (
              <li key={p.id}>
                <a href={`#/${p.id}`} aria-current={route === p.id ? 'page' : undefined}>
                  {p.id === 'certs' ? 'Certificates' : p.label}
                </a>
              </li>
            ))}
          </ul>
          {isMock && <p className="mock-note">Sample data. Nothing here is a real machine.</p>}
        </nav>

        <main className="main" id="main">
          {route === 'map' && <MapPage drawerWidth={narrow ? 0 : DRAWER_W} />}
          {route === 'hosts' && <HostsPage />}
          {route === 'certs' && <CertsPage />}
          {route === 'config' && <ConfigPage />}
          {route === 'logs' && <LogsPage />}
          {route === 'health' && <HealthPage />}
        </main>

        {showDrawer && <PeerDrawer addr={selected} onClose={() => setSelected(null)} />}

        <div className="toasts" aria-live="polite">
          {toasts.map((t) => (
            <p key={t.id} className={`toast toast-${t.tone}`} role={t.tone === 'error' ? 'alert' : 'status'}>{t.message}</p>
          ))}
        </div>
      </div>

      {connecting && (
        <ConnectDialog
          onClose={() => setConnecting(false)}
          onConnected={async (t) => {
            setConnecting(false);
            await refreshTargets();
            selectTarget(t.id);
            toast(`Connected to ${t.label}.`);
          }}
        />
      )}
    </ConsoleContext.Provider>
  );
}

function StatusText() {
  const { state, stateError, stateLoading } = useConsole();
  if (!state) return <span className="dim">{stateError ? "Can't read this machine" : stateLoading ? 'Reading…' : ''}</span>;
  if (!state.nebula) return <span className="dim">nebula isn't installed</span>;
  const running = state.service.startsWith('running');
  const word = running ? 'running' : state.service.startsWith('stopped') ? 'stopped' : state.service;
  return (
    <>
      <span className={`dot ${running ? 'dot-ok' : 'dot-off'}`} aria-hidden="true" />
      <span className="status-text">
        nebula {state.nebula}, <span className={running ? undefined : 'warn-text'}>{word}</span>
      </span>
    </>
  );
}

function OpenInBrowser() {
  const { toast } = useConsole();
  const [busy, setBusy] = useState(false);
  return (
    <Button
      small
      busy={busy}
      onClick={async () => {
        setBusy(true);
        try {
          const { url } = await api.link();
          const w = window.open(url, '_blank');
          if (!w) toast('The new window was blocked. Allow pop-ups for this page and try again.', 'error');
        } catch (e) {
          toast(e instanceof ApiError ? e.message : errMsg(e), 'error');
        } finally {
          setBusy(false);
        }
      }}
    >
      Open in browser
    </Button>
  );
}
