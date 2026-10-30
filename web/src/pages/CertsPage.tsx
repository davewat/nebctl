import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Certificates, IssuedCert, Signed } from '../api/types';
import { useConsole } from '../context';
import { EXPIRY_WARN_DAYS, expiryText, fmtDate, shortName, splitList, plural } from '../lib/format';
import { useResource, useTask } from '../lib/hooks';
import { Button, Chips, CopyBlock, CopyValue, Dialog, Empty, ErrorText, Field, Loading, Notice, PageHead, Panel } from '../ui';

export function CertsPage() {
  const { target, caTarget, selectTarget, openConnect } = useConsole();

  if (!target.haveCa) {
    return (
      <div className="page">
        <PageHead title="Certificates" />
        <div className="panel gate">
          <h2>The CA lives on the lighthouse</h2>
          <p className="dim">
            {target.label} isn't the CA, so it can't sign or revoke certificates. Switch to the machine that is.
          </p>
          <div className="row">
            {caTarget ? (
              <Button variant="primary" onClick={() => selectTarget(caTarget.id)}>
                Switch to {caTarget.label}
              </Button>
            ) : (
              <Button variant="primary" onClick={openConnect}>
                Connect to the lighthouse
              </Button>
            )}
          </div>
        </div>
      </div>
    );
  }
  return <CertsInner key={target.id} />;
}

type Bundle = { signed: Signed; hasKey: boolean; renewal: boolean };

/** Resolves true once the CA key can be used: on disk there, or pasted. */
type EnsureKey = () => Promise<boolean>;

const keyHeld = (c?: Certificates | null) => !!c?.caKeyHeldUntil && Date.parse(c.caKeyHeldUntil) > Date.now();

function CertsInner() {
  const { target, toast, state } = useConsole();
  const certs = useResource(() => api.certs(target.id), [target.id]);
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [renewing, setRenewing] = useState<IssuedCert | null>(null);
  const [revoking, setRevoking] = useState<IssuedCert | null>(null);
  const [pushing, setPushing] = useState<{ name: string; blocklist: string[] } | null>(null);
  const [nextIp, setNextIp] = useState('');
  const [askKey, setAskKey] = useState<((ok: boolean) => void) | null>(null);
  const [removingKey, setRemovingKey] = useState(false);
  const ipTask = useTask();

  useEffect(() => {
    void ipTask.run(async () => setNextIp((await api.nextIp(target.id)).ip));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target.id]);

  const c = certs.data;

  // Show "Paste the key" again when the console forgets it.
  const heldUntil = c?.caKeyHeldUntil;
  useEffect(() => {
    if (!heldUntil) return;
    const ms = Date.parse(heldUntil) - Date.now() + 1000;
    const timer = window.setTimeout(() => void certs.reload(), Math.max(ms, 1000));
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [heldUntil]);

  const ensureKey: EnsureKey = () =>
    c?.caKey === 'here' || keyHeld(c) ? Promise.resolve(true) : new Promise((resolve) => setAskKey(() => resolve));

  const onSigned = (s: Signed, hasKey: boolean, renewal = false) => {
    setBundle({ signed: s, hasKey, renewal });
    setNextIp(s.nextIp);
    void certs.reload();
  };

  return (
    <div className="page">
      <PageHead title="Certificates" sub={`Signed by the CA on ${target.label}.`} />
      {certs.loading && !c && <Loading>Reading certificates…</Loading>}
      {certs.error && !c && (
        <Notice tone="danger" title="Can't read certificates">
          {certs.error} <Button small onClick={certs.refresh}>Try again</Button>
        </Notice>
      )}
      {c && (
        <>
          <Panel title="Certificate authority">
            <dl className="kv kv-wide">
              <dt>Name</dt>
              <dd>{c.ca.name}</dd>
              <dt>Valid until</dt>
              <dd className={c.ca.daysLeft < 90 ? 'warn-text' : undefined}>
                {fmtDate(c.ca.notAfter)}, {expiryText(c.ca.daysLeft)}. Every host cert ends when the CA does.
              </dd>
              <dt>Network</dt>
              <dd className="mono">{c.cidr}</dd>
              {c.domain && (
                <>
                  <dt>Domain</dt>
                  <dd>{c.domain}</dd>
                </>
              )}
              <dt>Lighthouses</dt>
              <dd>
                {c.lighthouses.length ? (
                  <ul className="plain">
                    {c.lighthouses.map((l) => (
                      <li key={l.nebulaIp}>
                        {l.name ? `${shortName(l.name)}, ` : ''}
                        <span className="mono">{l.nebulaIp}</span> at <span className="mono">{l.endpoints.join(', ')}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="dim">None listed</span>
                )}
              </dd>
              <dt>Private key</dt>
              <dd>
                <CaKeyStatus
                  certs={c}
                  onPaste={() => void ensureKey()}
                  onRemove={() => setRemovingKey(true)}
                  onForgot={() => void certs.reload()}
                />
              </dd>
              <dt>Fingerprint</dt>
              <dd><CopyValue text={c.ca.fingerprint} /></dd>
              <dt>Blocklist</dt>
              <dd>{plural(c.blocklist.length, 'revoked cert')}</dd>
            </dl>
          </Panel>

          <Panel title="Issued certificates" sub="Renew a host by signing its name again. It keeps its address.">
            <div className="table-wrap flush">
              <table className="data certs-table">
                <colgroup>
                  <col style={{ width: '15%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '17%' }} />
                  <col style={{ width: '17%' }} />
                  <col style={{ width: '21%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Address</th>
                    <th scope="col">Groups</th>
                    <th scope="col">Expires</th>
                    <th scope="col">State</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {c.issued.map((i) => {
                    const warn = !i.revoked && i.daysLeft < EXPIRY_WARN_DAYS;
                    return (
                      <tr key={i.fingerprint}>
                        <td>{shortName(i.name)}</td>
                        <td className="mono">{i.nebulaIp}</td>
                        <td><Chips items={i.groups} empty="None" /></td>
                        <td className={warn ? 'warn-text' : undefined}>
                          {fmtDate(i.notAfter)}
                          <span className="sub-line">{expiryText(i.daysLeft)}</span>
                        </td>
                        <td>
                          {i.nebulaIp.split('/')[0] === state?.host?.nebulaIp ? (
                            <span className="pill"><span className="dot dot-ok" aria-hidden="true" />This machine</span>
                          ) : i.revoked ? (
                            <span className="pill"><span className="dot dot-revoked" aria-hidden="true" />Revoked</span>
                          ) : i.daysLeft < 0 ? (
                            <span className="pill"><span className="dot dot-revoked" aria-hidden="true" />Expired</span>
                          ) : i.online ? (
                            <span className="pill"><span className="dot dot-ok" aria-hidden="true" />Online</span>
                          ) : (
                            <span className="pill dim"><span className="dot dot-off" aria-hidden="true" />Not connected</span>
                          )}
                        </td>
                        <td className="right actions-cell">
                          {!i.revoked && (
                            <>
                              <Button small onClick={() => void ensureKey().then((ok) => ok && setRenewing(i))}>Renew</Button>{' '}
                              <Button small variant="danger" onClick={() => setRevoking(i)}>Revoke</Button>
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {c.issued.length === 0 && <Empty>No certs have been signed yet. Sign one for the first host below.</Empty>}
            </div>
          </Panel>

          <div className="two-col">
            <SignForm nextIp={nextIp} ipError={ipTask.error} ensureKey={ensureKey} onSigned={(s) => onSigned(s, true)} />
            <RequestForm ensureKey={ensureKey} onSigned={(s) => onSigned(s, false)} />
          </div>
        </>
      )}

      {bundle && <BundleDialog bundle={bundle} onClose={() => setBundle(null)} />}

      {askKey && (
        <PasteKeyDialog
          encrypted={!!c?.caKeyEncrypted}
          onClose={(ok) => {
            askKey(ok);
            setAskKey(null);
            if (ok) void certs.reload();
          }}
        />
      )}

      {removingKey && (
        <RemoveKeyDialog
          onClose={(message) => {
            setRemovingKey(false);
            if (message) {
              toast(message);
              void certs.reload();
            }
          }}
        />
      )}

      {renewing && (
        <RenewDialog
          cert={renewing}
          onClose={() => setRenewing(null)}
          onSigned={(s) => {
            setRenewing(null);
            onSigned(s, true, true);
          }}
        />
      )}

      {revoking && (
        <RevokeDialog
          cert={revoking}
          onClose={() => setRevoking(null)}
          onRevoked={(blocklist) => {
            toast(`Revoked ${revoking.name}.`);
            setPushing({ name: revoking.name, blocklist });
            setRevoking(null);
            void certs.reload();
          }}
        />
      )}

      {pushing && <PushDialog name={pushing.name} blocklist={pushing.blocklist} onClose={() => setPushing(null)} />}
    </div>
  );
}

function SignForm({ nextIp, ipError, ensureKey, onSigned }: { nextIp: string; ipError: string | null; ensureKey: EnsureKey; onSigned: (s: Signed) => void }) {
  const { target } = useConsole();
  const [name, setName] = useState('');
  const [ip, setIp] = useState('');
  const [ipTouched, setIpTouched] = useState(false);
  const [groups, setGroups] = useState('');
  const task = useTask();
  useEffect(() => {
    if (!ipTouched) setIp(nextIp);
  }, [nextIp, ipTouched]);

  return (
    <Panel title="Sign a cert for a new host" sub="nebctl makes the host's key here, so the bundle holds a private key.">
      <form
        className="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!(await ensureKey())) return;
          const r = await task.run(() => api.sign(target.id, { name: name.trim(), ip: ip.trim() || undefined, groups: splitList(groups) }));
          if (r) {
            setName('');
            setGroups('');
            setIpTouched(false);
            onSigned(r);
          }
        }}
      >
        <Field label="Host name" htmlFor="s-name" hint={`A short name such as fe02 gets the domain added.`}>
          <input id="s-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" spellCheck={false} placeholder="fe02" />
        </Field>
        <Field label="Nebula address" htmlFor="s-ip" hint={ipError ? undefined : 'The first free address in the network is filled in.'}>
          <input id="s-ip" className="mono-input" value={ip} onChange={(e) => { setIp(e.target.value); setIpTouched(true); }} autoComplete="off" spellCheck={false} />
        </Field>
        {ipError && <ErrorText>{ipError}</ErrorText>}
        <Field label="Groups" htmlFor="s-groups" hint="Separate with commas. Firewall rules can match on a group.">
          <input id="s-groups" value={groups} onChange={(e) => setGroups(e.target.value)} autoComplete="off" spellCheck={false} placeholder="web, admin" />
        </Field>
        <ErrorText>{task.error}</ErrorText>
        <div><Button type="submit" variant="primary" busy={task.busy} disabled={!name.trim()}>Sign cert</Button></div>
      </form>
    </Panel>
  );
}

function RequestForm({ ensureKey, onSigned }: { ensureKey: EnsureKey; onSigned: (s: Signed) => void }) {
  const { target } = useConsole();
  const [req, setReq] = useState('');
  const [name, setName] = useState('');
  const [ip, setIp] = useState('');
  const [groups, setGroups] = useState('');
  const task = useTask();
  return (
    <Panel title="Sign a request" sub="A host can make its own key and send only a request. The key never leaves it.">
      <form
        className="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!(await ensureKey())) return;
          const r = await task.run(() => api.signRequest(target.id, { request: req.trim(), name: name.trim() || undefined, ip: ip.trim() || undefined, groups: groups.trim() ? splitList(groups) : undefined }));
          if (r) {
            setReq('');
            setName('');
            setIp('');
            setGroups('');
            onSigned(r);
          }
        }}
      >
        <Field label="Request" htmlFor="r-req" hint="Paste everything from BEGIN NEBCTL REQUEST to the END line.">
          <textarea id="r-req" className="mono-input" rows={5} value={req} onChange={(e) => setReq(e.target.value)} spellCheck={false} placeholder="-----BEGIN NEBCTL REQUEST-----" />
        </Field>
        <div className="row3">
          <Field label="Name" htmlFor="r-name"><input id="r-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" spellCheck={false} placeholder="From the request" /></Field>
          <Field label="Address" htmlFor="r-ip"><input id="r-ip" className="mono-input" value={ip} onChange={(e) => setIp(e.target.value)} autoComplete="off" spellCheck={false} placeholder="Next free" /></Field>
          <Field label="Groups" htmlFor="r-groups"><input id="r-groups" value={groups} onChange={(e) => setGroups(e.target.value)} autoComplete="off" spellCheck={false} /></Field>
        </div>
        <ErrorText>{task.error}</ErrorText>
        <div><Button type="submit" variant="primary" busy={task.busy} disabled={!req.trim()}>Sign request</Button></div>
      </form>
    </Panel>
  );
}

function BundleDialog({ bundle, onClose }: { bundle: Bundle; onClose: () => void }) {
  const { signed, hasKey, renewal } = bundle;
  return (
    <Dialog title={`${renewal ? 'Renewed' : 'Signed'} ${shortName(signed.cert.name)}`} wide onClose={onClose} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <p>
        {signed.cert.name} has the address <span className="mono">{signed.cert.nebulaIp}</span> and is valid until {fmtDate(signed.cert.notAfter)}.
        {signed.replaces ? ' This replaces its earlier cert.' : ''}
      </p>
      {hasKey ? (
        <Notice tone="warn" title="This bundle contains the host's private key.">
          Send it only over something you trust, such as an SSH session or a password manager.
        </Notice>
      ) : (
        <Notice tone="info" title="This bundle holds no private key.">
          Send it back to the host that made the request. The key stayed there.
        </Notice>
      )}
      <CopyBlock text={signed.bundle} label="Bundle" className="bundle" />
      <p className="dim">This is the only time the bundle is shown. Closing this window discards it; sign the name again to get a new one.</p>
    </Dialog>
  );
}

function RenewDialog({ cert, onClose, onSigned }: { cert: IssuedCert; onClose: () => void; onSigned: (s: Signed) => void }) {
  const { target } = useConsole();
  const task = useTask();
  return (
    <Dialog
      title={`Renew ${shortName(cert.name)}?`}
      busy={task.busy}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose} disabled={task.busy}>Cancel</Button>
          <Button variant="primary" busy={task.busy} onClick={async () => {
            const r = await task.run(() => api.sign(target.id, { name: cert.name, groups: cert.groups }));
            if (r) onSigned(r);
          }}>Sign cert</Button>
        </>
      }
    >
      <p>
        This signs {cert.name} again with a new expiry. It keeps <span className="mono">{cert.nebulaIp}</span> and its groups. You'll get a new bundle with a private key to deliver to the host.
      </p>
      <ErrorText>{task.error}</ErrorText>
    </Dialog>
  );
}

function RevokeDialog({ cert, onClose, onRevoked }: { cert: IssuedCert; onClose: () => void; onRevoked: (blocklist: string[]) => void }) {
  const { target } = useConsole();
  const task = useTask();
  return (
    <Dialog
      title={`Revoke the cert for ${cert.name}?`}
      tone="danger"
      busy={task.busy}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose} disabled={task.busy}>Cancel</Button>
          <Button variant="danger" busy={task.busy} onClick={async () => {
            const r = await task.run(() => api.revoke(target.id, cert.fingerprint));
            if (r) onRevoked(r.blocklist);
          }}>Revoke cert</Button>
        </>
      }
    >
      <p>
        Its fingerprint goes on this machine's blocklist and nebula reloads. {shortName(cert.name)} ({cert.nebulaIp}) can't join the network again with this cert. Other machines keep trusting it until you push the blocklist to them next.
      </p>
      <dl className="kv"><dt>Fingerprint</dt><dd className="mono wrap-any">{cert.fingerprint}</dd></dl>
      <ErrorText>{task.error}</ErrorText>
    </Dialog>
  );
}

type PushResult = { ok: boolean; text: string };

function PushDialog({ name, blocklist, onClose }: { name: string; blocklist: string[]; onClose: () => void }) {
  const { targets, target } = useConsole();
  const others = targets.filter((t) => t.id !== target.id);
  const [chosen, setChosen] = useState<Set<string>>(new Set(others.map((t) => t.id)));
  const [results, setResults] = useState<Record<string, PushResult>>({});
  const [running, setRunning] = useState(false);
  const done = Object.keys(results).length > 0 && !running;

  const push = async () => {
    setRunning(true);
    setResults({});
    for (const t of others) {
      if (!chosen.has(t.id)) continue;
      try {
        const r = await api.putBlocklist(t.id, blocklist);
        setResults((x) => ({ ...x, [t.id]: { ok: true, text: r.log } }));
      } catch (e) {
        setResults((x) => ({ ...x, [t.id]: { ok: false, text: e instanceof Error ? e.message : String(e) } }));
      }
    }
    setRunning(false);
  };

  return (
    <Dialog
      title="Push the blocklist"
      busy={running}
      onClose={onClose}
      footer={
        done || others.length === 0 ? (
          <Button variant="primary" onClick={onClose}>Done</Button>
        ) : (
          <>
            <Button onClick={onClose} disabled={running}>Not now</Button>
            <Button variant="primary" busy={running} disabled={chosen.size === 0} onClick={push}>Push the blocklist</Button>
          </>
        )
      }
    >
      <p>
        {name} is revoked here. Other machines only refuse it once they have the new blocklist ({plural(blocklist.length, 'fingerprint')}). Pushing replaces the blocklist on each machine you pick with this one.
      </p>
      {others.length === 0 ? (
        <Notice tone="info">No other machines are connected. Connect to them from the machine list in the top bar, then push the list from here the next time you revoke.</Notice>
      ) : (
        <ul className="plain push-list">
          {others.map((t) => (
            <li key={t.id}>
              <label className="check">
                <input
                  type="checkbox"
                  checked={chosen.has(t.id)}
                  disabled={running || done}
                  onChange={(e) => setChosen((s) => { const n = new Set(s); if (e.target.checked) n.add(t.id); else n.delete(t.id); return n; })}
                />
                <span>{t.label}</span>
              </label>
              {results[t.id] && (
                <div className={`push-result ${results[t.id].ok ? 'ok' : 'bad'}`} role="status">
                  <strong>{results[t.id].ok ? 'Updated' : 'Failed'}</strong>
                  <pre className="mono-block small">{results[t.id].text}</pre>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
}

function CaKeyStatus({ certs, onPaste, onRemove, onForgot }: { certs: Certificates; onPaste: () => void; onRemove: () => void; onForgot: () => void }) {
  const { target, toast } = useConsole();
  const task = useTask();
  if (certs.caKey === 'here') {
    return (
      <>
        <span className={certs.caKeyEncrypted || target.role !== 'lighthouse' ? undefined : 'warn-text'}>
          In ca.key on {target.label}
          {certs.caKeyEncrypted ? ', protected by a passphrase.' : '. Anyone who gets root there can sign certs.'}
        </span>
        <div className="row key-actions">
          <Button small onClick={onRemove}>Take it off this machine</Button>
        </div>
      </>
    );
  }
  if (keyHeld(certs)) {
    return (
      <>
        Kept offline. The console holds the copy you pasted, in memory only, until {fmtTime(certs.caKeyHeldUntil!)}.
        <div className="row key-actions">
          <Button
            small
            busy={task.busy}
            onClick={async () => {
              const r = await task.run(() => api.caKeyForget(target.id));
              if (r) toast(r.message);
              onForgot();
            }}
          >
            Forget it now
          </Button>
        </div>
        <ErrorText>{task.error}</ErrorText>
      </>
    );
  }
  return (
    <>
      Kept offline. Paste it when you sign; it is never saved on {target.label}.
      <div className="row key-actions">
        <Button small onClick={onPaste}>Paste the key</Button>
      </div>
    </>
  );
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

function KeyFields({ id, keyText, setKeyText, pass, setPass, encrypted }: { id: string; keyText: string; setKeyText: (v: string) => void; pass: string; setPass: (v: string) => void; encrypted: boolean }) {
  const needPass = encrypted || keyText.includes('ENCRYPTED');
  return (
    <>
      <Field label="CA key" htmlFor={`${id}-key`} hint="Everything from -----BEGIN NEBULA to the END line.">
        <textarea
          id={`${id}-key`}
          className="mono-input"
          rows={5}
          value={keyText}
          onChange={(e) => setKeyText(e.target.value)}
          spellCheck={false}
          autoComplete="off"
          placeholder="-----BEGIN NEBULA ED25519 PRIVATE KEY-----"
        />
      </Field>
      {needPass && (
        <Field label="Passphrase" htmlFor={`${id}-pass`}>
          <input id={`${id}-pass`} type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />
        </Field>
      )}
    </>
  );
}

function PasteKeyDialog({ encrypted, onClose }: { encrypted: boolean; onClose: (ok: boolean) => void }) {
  const { target } = useConsole();
  const [keyText, setKeyText] = useState('');
  const [pass, setPass] = useState('');
  const task = useTask();
  const submit = async () => {
    const r = await task.run(() => api.caKeyCheck(target.id, { key: keyText.trim() + '\n', passphrase: pass || undefined }));
    if (r) onClose(true);
  };
  return (
    <Dialog
      title="Paste the CA key"
      busy={task.busy}
      onClose={() => onClose(false)}
      footer={
        <>
          <Button onClick={() => onClose(false)} disabled={task.busy}>Cancel</Button>
          <Button variant="primary" busy={task.busy} disabled={!keyText.trim()} onClick={submit}>Use this key</Button>
        </>
      }
    >
      <p>
        {target.label} keeps no copy of the CA key, so signing needs yours. It goes to nebula-cert through a pipe and is never written to disk.
        The console keeps it in memory for 15 minutes after you last sign, then forgets it.
      </p>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <KeyFields id="pk" keyText={keyText} setKeyText={setKeyText} pass={pass} setPass={setPass} encrypted={encrypted} />
      </form>
      <ErrorText>{task.error}</ErrorText>
    </Dialog>
  );
}

function RemoveKeyDialog({ onClose }: { onClose: (message?: string) => void }) {
  const { target } = useConsole();
  const file = useResource(() => api.caKeyFile(target.id), [target.id]);
  const [step, setStep] = useState<'save' | 'confirm'>('save');
  const [keyText, setKeyText] = useState('');
  const [pass, setPass] = useState('');
  const task = useTask();
  const encrypted = !!file.data?.encrypted;
  const remove = async () => {
    const r = await task.run(() => api.caKeyRemove(target.id, { key: keyText.trim() + '\n', passphrase: pass || undefined }));
    if (r) onClose(r.message);
  };
  return (
    <Dialog
      title={step === 'save' ? 'Save the CA key first' : `Remove ca.key from ${target.label}?`}
      tone={step === 'confirm' ? 'danger' : 'normal'}
      wide
      busy={task.busy}
      onClose={() => onClose()}
      footer={
        step === 'save' ? (
          <>
            <Button onClick={() => onClose()}>Cancel</Button>
            <Button variant="primary" disabled={!file.data} onClick={() => setStep('confirm')}>I've saved it</Button>
          </>
        ) : (
          <>
            <Button onClick={() => setStep('save')} disabled={task.busy}>Back</Button>
            <Button variant="danger" busy={task.busy} disabled={!keyText.trim()} onClick={remove}>Remove ca.key</Button>
          </>
        )
      }
    >
      {step === 'save' ? (
        <>
          <Notice tone="warn" title="This is the only way to sign certs for your network.">
            Put it in a password manager or on an encrypted drive. If it's lost, you need a new CA and a new cert on every host.
          </Notice>
          {file.loading && <Loading>Reading ca.key…</Loading>}
          {file.error && <ErrorText>{file.error}</ErrorText>}
          {file.data && <CopyBlock text={file.data.key} label={`ca.key${encrypted ? ' (protected by a passphrase)' : ''}`} className="bundle" />}
        </>
      ) : (
        <>
          <p>
            Paste the key back from where you saved it. nebctl signs a test cert with it first, and removes ca.key only if that works.
            After that, you paste the key here each time you sign.
          </p>
          <form className="stack" onSubmit={(e) => { e.preventDefault(); void remove(); }}>
            <KeyFields id="rk" keyText={keyText} setKeyText={setKeyText} pass={pass} setPass={setPass} encrypted={encrypted} />
          </form>
          <ErrorText>{task.error}</ErrorText>
        </>
      )}
    </Dialog>
  );
}
