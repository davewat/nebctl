import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { ApiError, errMsg } from '../api/client';
import type { ConnectBody, HostKeyInfo, MissingNebctl, NeedField, Target } from '../api/types';
import { Button, Dialog, ErrorText, Field, Notice } from '../ui';

type Auth = 'agent' | 'password' | 'key';
type Stage =
  | { kind: 'form' }
  | { kind: 'hostkey'; info: HostKeyInfo }
  | { kind: 'install'; info: MissingNebctl }
  | { kind: 'savekey'; target: Target; saved?: string };

const NEED_TEXT: Record<NeedField, string> = {
  password: 'SSH needs a password for this user.',
  passphrase: 'The key file is protected. Enter its passphrase.',
  sudoPassword: 'sudo on that machine needs a password.',
};

export function ConnectDialog({ onClose, onConnected }: { onClose: () => void; onConnected: (t: Target) => void }) {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('22');
  const [user, setUser] = useState('root');
  const [auth, setAuth] = useState<Auth>('agent');
  const [password, setPassword] = useState('');
  const [keyPath, setKeyPath] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [sudoPassword, setSudoPassword] = useState('');
  const [acceptHostKey, setAcceptHostKey] = useState<string | undefined>();
  const [stage, setStage] = useState<Stage>({ kind: 'form' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [need, setNeed] = useState<NeedField | null>(null);
  const needRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (need) needRef.current?.focus();
  }, [need]);

  const body = (accept?: string): ConnectBody => {
    const b: ConnectBody = { host: host.trim(), user: user.trim() };
    const p = parseInt(port, 10);
    if (p && p !== 22) b.port = p;
    if (auth === 'agent') b.useAgent = true;
    if (auth === 'password') b.password = password;
    if (auth === 'key') {
      b.keyPath = keyPath.trim();
      if (passphrase) b.passphrase = passphrase;
    }
    if (sudoPassword) b.sudoPassword = sudoPassword;
    const a = accept ?? acceptHostKey;
    if (a) b.acceptHostKey = a;
    return b;
  };

  const run = async (call: (b: ConnectBody) => Promise<Target>, accept?: string) => {
    setBusy(true);
    setError(null);
    setNeed(null);
    try {
      const t = await call(body(accept));
      if (t.canSaveKey) setStage({ kind: 'savekey', target: t });
      else onConnected(t);
    } catch (e) {
      if (e instanceof ApiError) {
        const b = e.body as { hostKey?: HostKeyInfo } & Partial<MissingNebctl>;
        if (e.status === 409 && b?.hostKey) {
          setStage({ kind: 'hostkey', info: b.hostKey });
        } else if (e.status === 428 && b?.nebctl) {
          setStage({ kind: 'install', info: b as MissingNebctl });
        } else if (e.status === 401 && e.need) {
          const n = e.need as NeedField;
          setStage({ kind: 'form' });
          setNeed(n);
          if (n === 'password') setAuth('password');
          if (n === 'passphrase') setAuth('key');
          setError(e.message || NEED_TEXT[n]);
        } else {
          setStage({ kind: 'form' });
          setError(e.message);
        }
      } else {
        setStage({ kind: 'form' });
        setError(errMsg(e));
      }
    } finally {
      setBusy(false);
    }
  };

  const hostLabel = host.trim() || 'that machine';

  if (stage.kind === 'savekey') {
    const { target, saved } = stage;
    const done = () => onConnected(target);
    const save = async () => {
      setBusy(true);
      setError(null);
      try {
        const r = await api.saveKey(target.id);
        setStage({ kind: 'savekey', target, saved: r.message });
      } catch (e) {
        setError(errMsg(e));
      } finally {
        setBusy(false);
      }
    };
    return (
      <Dialog
        title={saved ? `Key added on ${hostLabel}` : `Log in to ${hostLabel} with a key next time?`}
        onClose={done}
        busy={busy}
        footer={
          saved ? (
            <Button variant="primary" onClick={done}>
              Done
            </Button>
          ) : (
            <>
              <Button onClick={done} disabled={busy}>
                Not now
              </Button>
              <Button variant="primary" busy={busy} onClick={() => void save()}>
                Add the console's key
              </Button>
            </>
          )
        }
      >
        {saved ? (
          <p>{saved}</p>
        ) : (
          <>
            <p>
              You signed in with a password. The console can add its own key to {target.user ?? user}'s{' '}
              <span className="mono">~/.ssh/authorized_keys</span> on {hostLabel}, so next time it connects without the SSH password.
            </p>
            <p className="dim">
              Only the key's public half goes there; the private half stays on this machine, readable by root only. Your own SSH keys aren't copied. sudo may still ask for its password.
            </p>
          </>
        )}
        <ErrorText>{error}</ErrorText>
      </Dialog>
    );
  }

  if (stage.kind === 'hostkey') {
    const { info } = stage;
    return (
      <Dialog
        title={info.changed ? 'This machine\'s host key has changed' : 'Trust this machine?'}
        onClose={onClose}
        busy={busy}
        tone={info.changed ? 'danger' : 'normal'}
        footer={
          <>
            <Button onClick={() => setStage({ kind: 'form' })} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant={info.changed ? 'danger' : 'primary'}
              busy={busy}
              onClick={() => {
                setAcceptHostKey(info.fingerprint);
                void run(api.connect, info.fingerprint);
              }}
            >
              {info.changed ? 'Trust the new key and connect' : 'Trust and connect'}
            </Button>
          </>
        }
      >
        {info.changed ? (
          <Notice tone="danger" title="Someone may be intercepting this connection.">
            You connected to {hostLabel} before with a different key. That happens when the machine was reinstalled, and also when another machine is pretending to be it. Continue only if you know the key should have changed.
          </Notice>
        ) : (
          <p>
            You haven't connected to {hostLabel} before. Check that this fingerprint matches what that machine shows (<span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>) before you trust it.
          </p>
        )}
        <dl className="kv">
          <dt>Key type</dt>
          <dd className="mono">{info.type}</dd>
          <dt>Fingerprint</dt>
          <dd className="mono wrap-any">{info.fingerprint}</dd>
        </dl>
        <ErrorText>{error}</ErrorText>
      </Dialog>
    );
  }

  if (stage.kind === 'install') {
    const { info } = stage;
    return (
      <Dialog
        title={info.nebctl === 'old' ? 'nebctl on that machine is out of date' : 'nebctl isn\'t installed on that machine'}
        onClose={onClose}
        busy={busy}
        footer={
          <>
            <Button onClick={() => setStage({ kind: 'form' })} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" busy={busy} onClick={() => void run(api.install)}>
              Install nebctl on {hostLabel}
            </Button>
          </>
        }
      >
        <p>
          {info.nebctl === 'old'
            ? `${hostLabel} has nebctl ${info.remoteVersion ?? 'of an older version'}; this console is ${info.version}.`
            : `${hostLabel} has no nebctl, and the console needs it there to manage nebula.`}{' '}
          Installing copies this release ({info.version}, {info.arch}) to <span className="mono">/usr/local/bin/nebctl</span> over SSH.
        </p>
        <ErrorText>{error}</ErrorText>
      </Dialog>
    );
  }

  const needKey = (n: NeedField) => (need === n ? 'field-need' : '');

  return (
    <Dialog
      title="Connect to another machine"
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="connect-form" busy={busy} disabled={!host.trim() || !user.trim()}>
            Connect
          </Button>
        </>
      }
    >
      <form
        id="connect-form"
        className="form-grid"
        onSubmit={(e) => {
          e.preventDefault();
          if (!busy) void run(api.connect);
        }}
      >
        <p className="dim span-all">The console signs in over SSH and runs nebctl there with sudo. Nothing you type here is stored.</p>
        <Field label="Host" htmlFor="c-host" className="grow">
          <input id="c-host" value={host} onChange={(e) => { setHost(e.target.value); setAcceptHostKey(undefined); }} placeholder="lh.example.internal" autoComplete="off" spellCheck={false} />
        </Field>
        <Field label="Port" htmlFor="c-port">
          <input id="c-port" value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" className="narrow" />
        </Field>
        <Field label="User" htmlFor="c-user">
          <input id="c-user" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" spellCheck={false} />
        </Field>

        <fieldset className="span-all seg">
          <legend>Sign in with</legend>
          {(['agent', 'password', 'key'] as Auth[]).map((a) => (
            <label key={a} className="radio">
              <input type="radio" name="auth" checked={auth === a} onChange={() => setAuth(a)} />
              <span>{a === 'agent' ? 'Saved key or ssh-agent' : a === 'password' ? 'Password' : 'Key file'}</span>
            </label>
          ))}
        </fieldset>

        {auth === 'password' && (
          <Field label="SSH password" htmlFor="c-pass" className={`span-all ${needKey('password')}`}>
            <input id="c-pass" ref={need === 'password' ? needRef : undefined} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
          </Field>
        )}
        {auth === 'key' && (
          <>
            <Field label="Key file" htmlFor="c-key" className="span-all" hint="The path on this machine, such as ~/.ssh/id_ed25519.">
              <input id="c-key" value={keyPath} onChange={(e) => setKeyPath(e.target.value)} className="mono-input" spellCheck={false} autoComplete="off" />
            </Field>
            <Field label="Passphrase" htmlFor="c-phrase" className={`span-all ${needKey('passphrase')}`} hint="Leave empty if the key has none.">
              <input id="c-phrase" ref={need === 'passphrase' ? needRef : undefined} type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
            </Field>
          </>
        )}
        <Field label="sudo password" htmlFor="c-sudo" className={`span-all ${needKey('sudoPassword')}`} hint="Only if sudo on that machine asks for one.">
          <input id="c-sudo" ref={need === 'sudoPassword' ? needRef : undefined} type="password" value={sudoPassword} onChange={(e) => setSudoPassword(e.target.value)} autoComplete="off" />
        </Field>
        <div className="span-all">
          <ErrorText>{error}</ErrorText>
        </div>
      </form>
    </Dialog>
  );
}
