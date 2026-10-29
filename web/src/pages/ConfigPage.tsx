import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import type { Lighthouse, Rule, Settings, SettingsChange } from '../api/types';
import { useConsole } from '../context';
import { splitList } from '../lib/format';
import { useResource, useTask } from '../lib/hooks';
import { Button, CopyBlock, ErrorText, Field, Loading, Notice, PageHead, Panel, Switch } from '../ui';

const LEVELS = ['trace', 'debug', 'info', 'warn', 'error'];

type FromKind = 'any' | 'group' | 'host';
interface RuleRow { proto: Rule['proto']; port: string; kind: FromKind; value: string }
interface LhRow { name: string; nebulaIp: string; endpoints: string; relay: boolean; dns: boolean }
interface Draft {
  rules: RuleRow[];
  dns: boolean;
  relay: boolean;
  listenPort: string;
  lighthouses: LhRow[];
  resolve: boolean;
  level: string;
  format: 'text' | 'json';
  metrics: boolean;
}

function toDraft(s: Settings): Draft {
  return {
    rules: s.host.inbound.map((r) => {
      const host = r.host && r.host !== 'any' ? r.host : '';
      return { proto: r.proto, port: r.port, kind: r.group ? 'group' : host ? 'host' : 'any', value: r.group || host };
    }),
    dns: !!s.host.dns,
    relay: !!s.host.relay,
    listenPort: String(s.host.listenPort),
    lighthouses: s.host.lighthouses.map((l) => ({ name: l.name ?? '', nebulaIp: l.nebulaIp, endpoints: l.endpoints.join(', '), relay: !!l.relay, dns: !!l.dns })),
    resolve: !!s.host.resolve,
    level: s.logging.level,
    format: s.logging.format,
    metrics: s.metrics.enabled,
  };
}

const rulesOut = (rows: RuleRow[]): Rule[] =>
  rows.map((r) => {
    const rule: Rule = { proto: r.proto, port: r.port.trim() || 'any' };
    if (r.kind === 'group') rule.group = r.value.trim();
    if (r.kind === 'host') rule.host = r.value.trim();
    return rule;
  });

const lhOut = (rows: LhRow[]): Lighthouse[] =>
  rows.map((l) => ({ ...(l.name.trim() ? { name: l.name.trim() } : {}), nebulaIp: l.nebulaIp.trim(), endpoints: splitList(l.endpoints), relay: l.relay, dns: l.dns }));

function diff(base: Draft, d: Draft, role: 'lighthouse' | 'node'): SettingsChange {
  const c: SettingsChange = {};
  if (JSON.stringify(base.rules) !== JSON.stringify(d.rules)) c.inbound = rulesOut(d.rules);
  if (role === 'lighthouse') {
    if (base.dns !== d.dns) c.dns = d.dns;
    if (base.relay !== d.relay) c.relay = d.relay;
    if (base.listenPort !== d.listenPort) c.listenPort = parseInt(d.listenPort, 10);
  } else {
    if (JSON.stringify(base.lighthouses) !== JSON.stringify(d.lighthouses)) c.lighthouses = lhOut(d.lighthouses);
    if (base.resolve !== d.resolve) c.resolve = d.resolve;
  }
  const logging: NonNullable<SettingsChange['logging']> = {};
  if (base.level !== d.level) logging.level = d.level;
  if (base.format !== d.format) logging.format = d.format;
  if (Object.keys(logging).length) c.logging = logging;
  if (base.metrics !== d.metrics) c.metrics = { enabled: d.metrics };
  return c;
}

const portOk = (p: string) => /^(any|\d{1,5}(-\d{1,5})?)$/.test(p.trim() || 'any');

export function ConfigPage() {
  const { target } = useConsole();
  return <ConfigInner key={target.id} />;
}

function ConfigInner() {
  const { target, state, refreshState, toast } = useConsole();
  const res = useResource(() => api.settings(target.id), [target.id]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [base, setBase] = useState<Draft | null>(null);
  const [result, setResult] = useState<{ log: string; restarted: boolean } | null>(null);
  const apply = useTask();

  useEffect(() => {
    if (res.data) {
      const d = toDraft(res.data);
      setDraft(d);
      setBase(d);
    }
  }, [res.data]);

  const s = res.data;
  const role = s?.host.role ?? 'node';

  const problems = useMemo(() => {
    if (!draft) return [] as string[];
    const out: string[] = [];
    draft.rules.forEach((r, i) => {
      if (!portOk(r.port)) out.push(`Rule ${i + 1}: "${r.port}" isn't a port. Use a number, a range like 8000-8100, or any.`);
      if (r.kind !== 'any' && !r.value.trim()) out.push(`Rule ${i + 1}: name the ${r.kind === 'group' ? 'group' : 'host'}.`);
    });
    if (role === 'lighthouse') {
      const p = parseInt(draft.listenPort, 10);
      if (!(p >= 1 && p <= 65535)) out.push('The listen port must be a number from 1 to 65535.');
    } else {
      draft.lighthouses.forEach((l, i) => {
        if (!l.nebulaIp.trim()) out.push(`Lighthouse ${i + 1}: enter its Nebula address.`);
        if (!splitList(l.endpoints).length) out.push(`Lighthouse ${i + 1}: enter at least one public address.`);
      });
    }
    return out;
  }, [draft, role]);

  if (res.loading && !s) return <div className="page"><PageHead title="Config" /><Loading>Reading the configuration…</Loading></div>;
  if (!s || !draft || !base) {
    return (
      <div className="page">
        <PageHead title="Config" />
        <Notice tone="danger" title="Can't read the configuration">{res.error} <Button small onClick={res.refresh}>Try again</Button></Notice>
      </div>
    );
  }

  const change = diff(base, draft, role);
  const dirty = Object.keys(change).length;
  const set = (p: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...p } : d));
  const setRule = (i: number, p: Partial<RuleRow>) => set({ rules: draft.rules.map((r, j) => (j === i ? { ...r, ...p } : r)) });
  const setLh = (i: number, p: Partial<LhRow>) => set({ lighthouses: draft.lighthouses.map((r, j) => (j === i ? { ...r, ...p } : r)) });
  const portChanged = role === 'lighthouse' && base.listenPort !== draft.listenPort;

  const doApply = async () => {
    setResult(null);
    const r = await apply.run(() => api.putSettings(target.id, change));
    if (r) {
      setResult(r);
      toast(r.restarted ? 'Changes applied. Nebula restarted.' : 'Changes applied.');
      await res.refresh();
      refreshState();
    }
  };

  return (
    <div className="page page-config">
      <PageHead title="Config" sub={`How nebula is set up on ${target.label}. Nothing changes until you apply.`} />

      <Panel title="Firewall: inbound rules" sub="What other hosts may reach on this machine. Anything not listed is dropped.">
        {draft.rules.length === 0 ? (
          <p className="empty">No inbound rules, so no host can reach anything here. Add one, such as ICMP from any host for ping.</p>
        ) : (
          <div className="rules" role="group" aria-label="Inbound rules">
            <div className="rule rule-head dim" aria-hidden="true"><span>Protocol</span><span>Port</span><span>From</span><span /><span /></div>
            {draft.rules.map((r, i) => (
              <div className="rule" key={i}>
                <select aria-label={`Rule ${i + 1} protocol`} value={r.proto} onChange={(e) => setRule(i, { proto: e.target.value as Rule['proto'] })}>
                  <option value="any">Any</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
                <input aria-label={`Rule ${i + 1} port`} className="mono-input" value={r.port} onChange={(e) => setRule(i, { port: e.target.value })} placeholder="any" spellCheck={false} aria-invalid={!portOk(r.port)} />
                <select aria-label={`Rule ${i + 1} from`} value={r.kind} onChange={(e) => setRule(i, { kind: e.target.value as FromKind })}>
                  <option value="any">Any host</option>
                  <option value="group">A group</option>
                  <option value="host">A host</option>
                </select>
                {r.kind === 'any' ? <span className="rule-any dim">All hosts on the network</span> : (
                  <input aria-label={`Rule ${i + 1} ${r.kind} name`} value={r.value} onChange={(e) => setRule(i, { value: e.target.value })} placeholder={r.kind === 'group' ? 'Group name' : 'Host name'} spellCheck={false} />
                )}
                <Button small variant="quiet" aria-label={`Remove rule ${i + 1}`} onClick={() => set({ rules: draft.rules.filter((_, j) => j !== i) })}>Remove</Button>
              </div>
            ))}
          </div>
        )}
        <div className="panel-foot">
          <Button small onClick={() => set({ rules: [...draft.rules, { proto: 'tcp', port: '', kind: 'any', value: '' }] })}>Add rule</Button>
        </div>
      </Panel>

      {role === 'lighthouse' ? (
        <Panel title="Lighthouse" sub="Other hosts use this machine to find each other.">
          <div className="stack">
            <Switch checked={draft.dns} onChange={(v) => set({ dns: v })} hint={s.host.domain ? `Hosts can look up names like fe01.${s.host.domain} through this lighthouse.` : undefined}>Answer DNS for Nebula host names</Switch>
            <Switch checked={draft.relay} onChange={(v) => set({ relay: v })} hint="Carries traffic between hosts that can't reach each other directly.">Relay traffic for other hosts</Switch>
            <Field label="Listen port (UDP)" htmlFor="c-port" hint="Changing the port needs a restart, and the new UDP port must be open in your firewall and your cloud provider's.">
              <input id="c-port" className="mono-input narrow" inputMode="numeric" value={draft.listenPort} onChange={(e) => set({ listenPort: e.target.value })} />
            </Field>
            {portChanged && <Notice tone="warn">Applying this restarts nebula, and every host must be told the new port in its lighthouse list.</Notice>}
          </div>
        </Panel>
      ) : (
        <Panel title="Lighthouses" sub="The machines this node checks in with to find other hosts.">
          <div className="stack">
            {draft.lighthouses.length === 0 && <p className="empty">No lighthouses are listed. This node can't find any other host.</p>}
            {draft.lighthouses.map((l, i) => (
              <fieldset className="lh-row" key={i}>
                <legend>Lighthouse {i + 1}</legend>
                <Field label="Name" htmlFor={`lh-n-${i}`}><input id={`lh-n-${i}`} value={l.name} onChange={(e) => setLh(i, { name: e.target.value })} spellCheck={false} placeholder="Optional" /></Field>
                <Field label="Nebula address" htmlFor={`lh-a-${i}`}><input id={`lh-a-${i}`} className="mono-input" value={l.nebulaIp} onChange={(e) => setLh(i, { nebulaIp: e.target.value })} spellCheck={false} /></Field>
                <Field label="Public addresses" htmlFor={`lh-e-${i}`} hint="Address and port, separated by commas." className="span-2">
                  <input id={`lh-e-${i}`} className="mono-input" value={l.endpoints} onChange={(e) => setLh(i, { endpoints: e.target.value })} spellCheck={false} />
                </Field>
                <div className="lh-flags">
                  <label className="check"><input type="checkbox" checked={l.relay} onChange={(e) => setLh(i, { relay: e.target.checked })} /><span>Relays traffic</span></label>
                  <label className="check"><input type="checkbox" checked={l.dns} onChange={(e) => setLh(i, { dns: e.target.checked })} /><span>Answers DNS</span></label>
                  <Button small variant="quiet" aria-label={`Remove lighthouse ${i + 1}`} onClick={() => set({ lighthouses: draft.lighthouses.filter((_, j) => j !== i) })}>Remove</Button>
                </div>
              </fieldset>
            ))}
            <div className="row">
              <Button small onClick={() => set({ lighthouses: [...draft.lighthouses, { name: '', nebulaIp: '', endpoints: '', relay: false, dns: false }] })}>Add lighthouse</Button>
            </div>
            <Switch checked={draft.resolve} onChange={(v) => set({ resolve: v })} hint={s.host.domain ? `Look up *.${s.host.domain} through the lighthouse, so ssh fe01.${s.host.domain} works.` : 'Resolve Nebula host names through the lighthouse.'}>Look up Nebula host names</Switch>
            <p className="dim">Changing the lighthouse list restarts nebula.</p>
          </div>
        </Panel>
      )}

      <Panel title="Logging">
        <div className="form-grid">
          <Field label="Level" htmlFor="l-level" hint="Saved in the config, so it survives restarts.">
            <select id="l-level" value={draft.level} onChange={(e) => set({ level: e.target.value })}>
              {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
          <Field label="Format" htmlFor="l-format" hint="JSON is what a SIEM wants to read.">
            <select id="l-format" value={draft.format} onChange={(e) => set({ format: e.target.value as 'text' | 'json' })}>
              <option value="text">Text</option>
              <option value="json">JSON</option>
            </select>
          </Field>
        </div>
        <LiveLevel enabled={!!state?.admin.enabled} saved={s.logging.level} />
      </Panel>

      <Panel title="Metrics">
        <Switch checked={draft.metrics} onChange={(v) => set({ metrics: v })} hint={<>Serves Prometheus metrics at <span className="mono">{s.metrics.listen}</span>, on this machine only.</>}>Prometheus metrics</Switch>
      </Panel>

      {s.blocklist.length > 0 && (
        <Panel title="Blocklist" sub={`${s.blocklist.length} revoked cert fingerprint${s.blocklist.length === 1 ? '' : 's'} nebula refuses. Revoke certs on the Certificates page.`}>
          <CopyBlock text={s.blocklist.join('\n')} label="Blocklist fingerprints" />
        </Panel>
      )}

      {result && (
        <Panel title="Last apply">
          <p role="status"><strong>{result.restarted ? 'Nebula restarted.' : 'Nebula kept running and reloaded its config.'}</strong></p>
          <pre className="mono-block small">{result.log}</pre>
        </Panel>
      )}

      <div className="applybar">
        <div className="applybar-text" role="status">
          {apply.error ? <ErrorText>{apply.error}</ErrorText> : problems.length ? <span className="error-text">{problems[0]}{problems.length > 1 ? ` (and ${problems.length - 1} more)` : ''}</span> : dirty ? <span>{dirty} {dirty === 1 ? 'change' : 'changes'} not applied yet. The config is tested with nebula -test first.</span> : <span className="dim">No changes to apply.</span>}
        </div>
        <Button onClick={() => setDraft(base)} disabled={!dirty || apply.busy}>Discard</Button>
        <Button variant="primary" busy={apply.busy} disabled={!dirty || problems.length > 0} onClick={doApply}>Apply changes</Button>
      </div>
    </div>
  );
}

function LiveLevel({ enabled, saved }: { enabled: boolean; saved: string }) {
  const { target, toast } = useConsole();
  const live = useResource(enabled ? () => api.logLevel(target.id) : null, [target.id, enabled]);
  const [pick, setPick] = useState('');
  const task = useTask();
  useEffect(() => {
    if (live.data) setPick(live.data.level);
  }, [live.data]);

  return (
    <div className="live-level">
      <h3>Change the level now</h3>
      <p className="dim">Takes effect straight away and lasts until nebula restarts. To keep a level, set it above and apply.</p>
      {!enabled ? (
        <p className="dim">Needs nebula's admin access, which is off on this machine. Turn it on from the Map page.</p>
      ) : (
        <div className="row">
          <label className="sr-only" htmlFor="ll-pick">Log level now</label>
          <select id="ll-pick" value={pick} onChange={(e) => setPick(e.target.value)} disabled={!live.data}>
            {!live.data && <option value="">Reading…</option>}
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <Button busy={task.busy} disabled={!live.data || pick === live.data.level} onClick={async () => {
            const r = await task.run(() => api.setLogLevel(target.id, pick));
            if (r) { toast(`Log level is now ${r.level} until nebula restarts.`); await live.refresh(); }
          }}>Change now</Button>
          <span className="dim">Running at {live.data?.level ?? '…'}, saved as {saved}.</span>
        </div>
      )}
      <ErrorText>{task.error ?? live.error}</ErrorText>
    </div>
  );
}
