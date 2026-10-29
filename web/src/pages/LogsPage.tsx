import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import type { Siem } from '../api/types';
import { useConsole } from '../context';
import { fmtTime } from '../lib/format';
import { useResource, useTask } from '../lib/hooks';
import { Button, ErrorText, Field, Loading, Notice, PageHead, Panel, Switch } from '../ui';

export function LogsPage() {
  const { target } = useConsole();
  return (
    <div className="page" key={target.id}>
      <PageHead title="Logs" sub={`Nebula's log on ${target.label}, and where a copy is sent.`} />
      <Tail />
      <SiemPanel />
    </div>
  );
}

function lineClass(l: string): string {
  if (/level=(error|fatal)|"level":"(error|fatal)"/.test(l)) return 'log-error';
  if (/level=warn|"level":"warn/.test(l)) return 'log-warn';
  return '';
}

function Tail() {
  const { target } = useConsole();
  const [follow, setFollow] = useState(true);
  const [count, setCount] = useState(200);
  const res = useResource(() => api.logs(target.id, count), [target.id, count], { poll: follow ? 3000 : undefined });
  const box = useRef<HTMLDivElement>(null);
  const programmatic = useRef(false);
  const lines = res.data?.lines ?? [];

  useEffect(() => {
    if (!follow || !box.current) return;
    programmatic.current = true;
    box.current.scrollTop = box.current.scrollHeight;
    requestAnimationFrame(() => { programmatic.current = false; });
  }, [lines, follow]);

  return (
    <Panel
      title="Live log"
      actions={
        <>
          <Switch checked={follow} onChange={setFollow}>Follow</Switch>
          <select aria-label="Lines to show" value={count} onChange={(e) => setCount(Number(e.target.value))}>
            <option value={100}>Last 100 lines</option>
            <option value={200}>Last 200 lines</option>
            <option value={500}>Last 500 lines</option>
          </select>
          <Button small busy={res.loading} onClick={res.refresh}>Refresh</Button>
        </>
      }
    >
      <div
        className="logbox"
        ref={box}
        tabIndex={0}
        role="log"
        aria-label="Nebula log, newest at the bottom"
        onScroll={(e) => {
          const el = e.currentTarget;
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          if (!atBottom && !programmatic.current) setFollow(false);
        }}
      >
        {res.loading && !res.data ? (
          <Loading>Reading the log…</Loading>
        ) : lines.length === 0 && !res.error ? (
          <p className="empty">The log is empty. Nebula writes here once it starts.</p>
        ) : (
          lines.map((l, i) => (
            <div className={`logline ${lineClass(l)}`} key={i}>{l}</div>
          ))
        )}
      </div>
      <div className="log-foot">
        <ErrorText>{res.error}</ErrorText>
        <span className="dim num">{res.at ? `Updated ${fmtTime(res.at)}${follow ? ', refreshing every 3 seconds' : ''}` : ''}</span>
      </div>
    </Panel>
  );
}

function SiemPanel() {
  const { target } = useConsole();
  const res = useResource(() => api.siem(target.id), [target.id]);
  const [f, setF] = useState<Omit<Siem, 'supported' | 'note'> | null>(null);
  const [saved, setSaved] = useState('');
  const [log, setLog] = useState<string | null>(null);
  const save = useTask();
  const test = useTask();

  useEffect(() => {
    if (res.data) {
      const { supported: _s, note: _n, ...rest } = res.data;
      void _s; void _n;
      setF(rest);
      setSaved(JSON.stringify(rest));
    }
  }, [res.data]);

  if (res.loading && !res.data) return <Panel title="Send logs to a SIEM"><Loading /></Panel>;
  if (!res.data || !f) return <Panel title="Send logs to a SIEM"><Notice tone="danger">{res.error}</Notice></Panel>;

  if (!res.data.supported) {
    return (
      <Panel title="Send logs to a SIEM">
        <Notice tone="info" title="Not available on this machine">{res.data.note || 'This machine can\'t forward nebula\'s log.'}</Notice>
      </Panel>
    );
  }

  const dirty = JSON.stringify(f) !== saved;
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p });

  return (
    <Panel title="Send logs to a SIEM" sub="Turns on JSON logs and adds an rsyslog rule that forwards each nebula log line.">
      <form
        className="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          setLog(null);
          const body = { ...f, caFile: f.protocol === 'tls' ? f.caFile : undefined };
          const r = await save.run(() => api.putSiem(target.id, body));
          if (r) { setLog(r.log); await res.refresh(); }
        }}
      >
        <Switch checked={f.enabled} onChange={(v) => set({ enabled: v })}>Forward nebula's log</Switch>
        <div className="form-grid">
          <Field label="Host" htmlFor="siem-host" className="grow"><input id="siem-host" value={f.host} onChange={(e) => set({ host: e.target.value })} spellCheck={false} placeholder="siem.example.com" /></Field>
          <Field label="Port" htmlFor="siem-port"><input id="siem-port" className="narrow mono-input" inputMode="numeric" value={f.port} onChange={(e) => set({ port: Number(e.target.value.replace(/\D/g, '')) || 0 })} /></Field>
          <Field label="Protocol" htmlFor="siem-proto">
            <select id="siem-proto" value={f.protocol} onChange={(e) => set({ protocol: e.target.value as Siem['protocol'] })}>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
              <option value="tls">TLS</option>
            </select>
          </Field>
          {f.protocol === 'tls' && (
            <Field label="CA file" htmlFor="siem-ca" className="span-all" hint="The CA file on this machine that signed the SIEM's certificate.">
              <input id="siem-ca" className="mono-input" value={f.caFile ?? ''} onChange={(e) => set({ caFile: e.target.value })} spellCheck={false} placeholder="/etc/ssl/certs/siem-ca.pem" />
            </Field>
          )}
        </div>
        <ErrorText>{save.error ?? test.error}</ErrorText>
        <div className="row">
          <Button type="submit" variant="primary" busy={save.busy} disabled={!dirty}>Save SIEM settings</Button>
          <Button busy={test.busy} disabled={dirty || !f.enabled} onClick={async () => {
            setLog(null);
            const r = await test.run(() => api.siemTest(target.id));
            if (r) setLog(r.log);
          }}>Send test event</Button>
          {dirty ? <span className="dim">Save before sending a test event.</span> : !f.enabled ? <span className="dim">Turn on forwarding and save to send a test event.</span> : null}
        </div>
        {log && <pre className="mono-block small" role="status">{log}</pre>}
      </form>
    </Panel>
  );
}
