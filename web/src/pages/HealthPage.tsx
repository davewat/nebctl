import { useMemo, useState } from 'react';
import { api } from '../api';
import type { Finding, FindingLevel } from '../api/types';
import { useConsole } from '../context';
import { expiryText, plural } from '../lib/format';
import { useResource, useTask } from '../lib/hooks';
import { Button, CopyBlock, Dialog, ErrorText, Loading, Notice, PageHead, Panel } from '../ui';

const LEVEL: Record<FindingLevel, { label: string; mark: string }> = {
  fail: { label: 'Fail', mark: 'x' },
  warn: { label: 'Warning', mark: '!' },
  info: { label: 'Note', mark: 'i' },
  pass: { label: 'Pass', mark: '✓' },
};
const ORDER: FindingLevel[] = ['fail', 'warn', 'info', 'pass'];

/** "1.12.0" > "1.11.2" ? */
function newer(latest?: string, current?: string): boolean {
  if (!latest || !current) return false;
  const a = latest.replace(/^v/, '').split('.').map(Number);
  const b = current.replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return false;
}

export function HealthPage() {
  const { target } = useConsole();
  return <HealthInner key={target.id} />;
}

function HealthInner() {
  const { target, refreshState, toast } = useConsole();
  const res = useResource(() => api.health(target.id), [target.id]);
  const h = res.data;
  const svc = useTask();
  const upd = useTask();
  const [confirmUpdate, setConfirmUpdate] = useState(false);
  const [log, setLog] = useState<string | null>(null);
  const running = h?.service.startsWith('running');
  const installed = h?.service !== 'not installed';
  const hasUpdate = newer(h?.latest, h?.nebula);

  const service = async (a: 'start' | 'stop' | 'restart') => {
    setLog(null);
    const r = await svc.run(() => api.service(target.id, a));
    if (r) {
      setLog(r.log);
      toast(a === 'stop' ? 'Nebula stopped.' : a === 'start' ? 'Nebula started.' : 'Nebula restarted.');
      await res.refresh();
      refreshState();
    }
  };

  return (
    <div className="page">
      <PageHead title="Health" sub={`The state of nebula on ${target.label}.`} />
      {res.loading && !h && <Loading>Checking {target.label}…</Loading>}
      {res.error && !h && <Notice tone="danger" title="Can't read health">{res.error} <Button small onClick={res.refresh}>Try again</Button></Notice>}
      {h && (
        <>
          <div className="two-col">
            <Panel title="Versions">
              <dl className="kv kv-wide">
                <dt>nebctl</dt>
                <dd className="mono">{h.nebctl}</dd>
                <dt>nebula</dt>
                <dd>{h.nebula ? <span className="mono">{h.nebula}</span> : <span className="dim">Not installed</span>}</dd>
                {h.latest && (
                  <>
                    <dt>Latest nebula</dt>
                    <dd><span className="mono">{h.latest}</span>{hasUpdate ? '' : <span className="dim">, you're up to date</span>}</dd>
                  </>
                )}
              </dl>
              {hasUpdate && (
                <div className="panel-foot">
                  <Button variant="primary" busy={upd.busy} onClick={() => setConfirmUpdate(true)}>Update nebula</Button>
                  <span className="dim">Downloads {h.latest}, checks it against the release checksums and restarts nebula.</span>
                </div>
              )}
              <ErrorText>{upd.error}</ErrorText>
            </Panel>

            <Panel title="Service">
              <p className="svc-state">
                <span className={`dot ${running ? 'dot-ok' : 'dot-off'}`} aria-hidden="true" />
                <strong>{running ? 'Running' : installed ? 'Not running' : 'Not installed'}</strong>
                {!running && installed && h.service !== 'stopped' && <span className="dim wrap-any"> {h.service.replace(/^stopped\s*/, '')}</span>}
              </p>
              <div className="row">
                <Button busy={svc.busy} disabled={!installed || !!running} onClick={() => service('start')}>Start</Button>
                <Button busy={svc.busy} disabled={!installed || !running} onClick={() => service('stop')}>Stop</Button>
                <Button busy={svc.busy} disabled={!installed} onClick={() => service('restart')}>Restart</Button>
              </div>
              <ErrorText>{svc.error}</ErrorText>
              {log && <pre className="mono-block small" role="status">{log}</pre>}
            </Panel>
          </div>

          <Panel title="Certificates and tunnels">
            <dl className="kv kv-wide">
              <dt>This host's cert</dt>
              <dd>{h.cert ? <span className={h.cert.daysLeft < 30 ? 'warn-text' : undefined}>{h.cert.name}, ends {expiryText(h.cert.daysLeft)}</span> : <span className="dim">None yet</span>}</dd>
              {h.ca && (
                <>
                  <dt>CA</dt>
                  <dd><span className={h.ca.daysLeft < 90 ? 'warn-text' : undefined}>{h.ca.name}, ends {expiryText(h.ca.daysLeft)}</span></dd>
                </>
              )}
              <dt>Tunnels</dt>
              <dd className="num">{h.tunnels} established, {h.pending} handshaking</dd>
            </dl>
          </Panel>

          {h.metrics && (
            <Panel title="Metrics" sub="From nebula's Prometheus endpoint on this machine.">
              <div className="table-wrap flush">
                <table className="data">
                  <colgroup><col style={{ width: '70%' }} /><col style={{ width: '30%' }} /></colgroup>
                  <thead><tr><th scope="col">Metric</th><th scope="col" className="right">Value</th></tr></thead>
                  <tbody>
                    {Object.entries(h.metrics).map(([k, v]) => (
                      <tr key={k}><td className="mono wrap-any">{k}</td><td className="right num">{v.toLocaleString()}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}
        </>
      )}

      <Audit />

      {confirmUpdate && h && (
        <Dialog
          title={`Update nebula to ${h.latest}?`}
          busy={upd.busy}
          onClose={() => setConfirmUpdate(false)}
          footer={
            <>
              <Button onClick={() => setConfirmUpdate(false)} disabled={upd.busy}>Cancel</Button>
              <Button variant="primary" busy={upd.busy} onClick={async () => {
                const r = await upd.run(() => api.update(target.id));
                if (r) {
                  setConfirmUpdate(false);
                  setLog(r.log);
                  toast(`Updated nebula to ${h.latest}.`);
                  await res.refresh();
                  refreshState();
                }
              }}>Update nebula</Button>
            </>
          }
        >
          <p>Nebula restarts, so its tunnels drop for a few seconds and reconnect on their own. You have {h.nebula}.</p>
          <ErrorText>{upd.error}</ErrorText>
        </Dialog>
      )}
    </div>
  );
}

function Audit() {
  const { target } = useConsole();
  const res = useResource(() => api.audit(target.id), [target.id]);
  const [showPass, setShowPass] = useState(false);
  const findings = res.data?.findings ?? [];

  const counts = useMemo(() => {
    const c: Record<FindingLevel, number> = { fail: 0, warn: 0, info: 0, pass: 0 };
    findings.forEach((f) => { c[f.level] = (c[f.level] ?? 0) + 1; });
    return c;
  }, [findings]);

  const sections = useMemo(() => {
    const m = new Map<string, Finding[]>();
    findings.filter((f) => showPass || f.level !== 'pass').forEach((f) => m.set(f.section, [...(m.get(f.section) ?? []), f]));
    m.forEach((list) => list.sort((a, b) => ORDER.indexOf(a.level) - ORDER.indexOf(b.level)));
    return [...m.entries()];
  }, [findings, showPass]);

  const summary = res.data
    ? [counts.fail && plural(counts.fail, 'failure'), counts.warn && plural(counts.warn, 'warning'), counts.info && plural(counts.info, 'note')].filter(Boolean).join(', ') || 'Nothing needs attention'
    : '';

  return (
    <Panel
      title="Security audit"
      sub={res.data ? `${res.data.machine}: ${summary}.` : 'Reviews the machine around nebula and gives the fix for each finding.'}
      actions={<Button small busy={res.loading} onClick={res.refresh}>{res.data ? 'Run again' : 'Run audit'}</Button>}
    >
      {res.loading && !res.data && <Loading>Auditing {target.label}…</Loading>}
      {res.error && <ErrorText>{res.error}</ErrorText>}
      {res.data && (
        <>
          {counts.pass > 0 && (
            <label className="check audit-toggle">
              <input type="checkbox" checked={showPass} onChange={(e) => setShowPass(e.target.checked)} />
              <span>Show {plural(counts.pass, 'passed check')}</span>
            </label>
          )}
          {sections.length === 0 && <p className="empty">Every check passed.</p>}
          {sections.map(([name, list]) => (
            <section className="audit-section" key={name}>
              <h3>{name}</h3>
              <ul className="plain">
                {list.map((f, i) => (
                  <li className={`finding finding-${f.level}`} key={i}>
                    <span className={`level level-${f.level}`}><span className="level-mark" aria-hidden="true">{LEVEL[f.level].mark}</span>{LEVEL[f.level].label}</span>
                    <div className="finding-body">
                      <p className="finding-title">{f.title}</p>
                      {f.detail && <p className="dim">{f.detail}</p>}
                      {f.fix && f.fix.length > 0 && <CopyBlock text={f.fix.join('\n')} label={`Fix for ${f.title}`} />}
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </>
      )}
    </Panel>
  );
}
