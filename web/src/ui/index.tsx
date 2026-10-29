import { useEffect, useId, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import type { PeerState } from '../lib/format';
import { STATE_LABEL } from '../lib/format';

// ---- buttons ---------------------------------------------------------------

type Variant = 'primary' | 'secondary' | 'danger' | 'quiet';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  small?: boolean;
  /** A request is running: disabled, with a spinner. */
  busy?: boolean;
}

export function Spinner() {
  return <span className="spin" aria-hidden="true" />;
}

export function Button({ variant = 'secondary', small, busy, disabled, className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={`btn btn-${variant}${small ? ' btn-sm' : ''}${className ? ' ' + className : ''}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy && <Spinner />}
      <span>{children}</span>
    </button>
  );
}

// ---- dialog (native <dialog>: focus trap, Escape and inert background) ------

interface DialogProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  /** Escape is ignored while a request runs. */
  busy?: boolean;
  tone?: 'normal' | 'danger';
}

export function Dialog({ title, onClose, children, footer, wide, busy, tone = 'normal' }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    const prev = document.activeElement as HTMLElement | null;
    if (!d.open) d.showModal();
    return () => {
      if (d.open) d.close();
      if (prev && document.contains(prev)) prev.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={`dlg${wide ? ' dlg-wide' : ''}${tone === 'danger' ? ' dlg-danger' : ''}`}
      aria-labelledby={id}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <div className="dlg-head">
        <h2 id={id}>{title}</h2>
      </div>
      <div className="dlg-body">{children}</div>
      {footer && <div className="dlg-foot">{footer}</div>}
    </dialog>
  );
}

// ---- copy ------------------------------------------------------------------

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      ok = false;
    }
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label = 'Copy', small = true }: { text: string; label?: string; small?: boolean }) {
  const [state, setState] = useState<'idle' | 'done' | 'fail'>('idle');
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <Button
      small={small}
      onClick={async () => {
        const ok = await copyText(text);
        setState(ok ? 'done' : 'fail');
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setState('idle'), 2000);
      }}
    >
      {state === 'done' ? 'Copied' : state === 'fail' ? 'Copy failed' : label}
    </Button>
  );
}

/** A literal block (command, bundle, log) with a Copy button. */
export function CopyBlock({ text, label, className }: { text: string; label?: string; className?: string }) {
  return (
    <div className={`copyblock${className ? ' ' + className : ''}`}>
      <pre className="mono-block" tabIndex={0} aria-label={label}>
        {text}
      </pre>
      <div className="copyblock-btn">
        <CopyButton text={text} />
      </div>
    </div>
  );
}

/** Inline mono value with a small Copy button after it. */
export function CopyValue({ text }: { text: string }) {
  return (
    <span className="copyvalue">
      <span className="mono wrap-any">{text}</span>
      <CopyButton text={text} />
    </span>
  );
}

// ---- small pieces ------------------------------------------------------------

export function Notice({ tone = 'info', title, children, role }: { tone?: 'info' | 'warn' | 'danger'; title?: string; children?: ReactNode; role?: string }) {
  return (
    <div className={`notice notice-${tone}`} role={role ?? (tone === 'danger' ? 'alert' : undefined)}>
      {title && <p className="notice-title">{title}</p>}
      {children && <div>{children}</div>}
    </div>
  );
}

export function ErrorText({ children }: { children?: ReactNode }) {
  if (!children) return null;
  return (
    <p className="error-text" role="alert">
      {children}
    </p>
  );
}

export function Switch({ checked, onChange, children, disabled, hint }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; disabled?: boolean; hint?: ReactNode }) {
  return (
    <label className={`switch${disabled ? ' is-disabled' : ''}`}>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="track" aria-hidden="true" />
      <span className="switch-text">
        <span>{children}</span>
        {hint && <span className="hint">{hint}</span>}
      </span>
    </label>
  );
}

export function Field({ label, hint, children, htmlFor, className }: { label: ReactNode; hint?: ReactNode; children: ReactNode; htmlFor?: string; className?: string }) {
  return (
    <div className={`field${className ? ' ' + className : ''}`}>
      <label htmlFor={htmlFor}>{label}</label>
      {children}
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function Chips({ items, empty }: { items: string[]; empty?: string }) {
  if (!items.length) return <span className="dim">{empty ?? 'None'}</span>;
  return (
    <span className="chips">
      {items.map((g) => (
        <span className="chip" key={g}>
          {g}
        </span>
      ))}
    </span>
  );
}

export function StatePill({ state }: { state: PeerState }) {
  return (
    <span className="pill">
      <span className={`dot dot-${state}`} aria-hidden="true" />
      {STATE_LABEL[state]}
    </span>
  );
}

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="pagehead">
      <div>
        <h1>{title}</h1>
        {sub && <p className="dim">{sub}</p>}
      </div>
      {children && <div className="pagehead-actions">{children}</div>}
    </header>
  );
}

export function Panel({ title, sub, children, actions, className }: { title?: ReactNode; sub?: ReactNode; children: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <section className={`panel${className ? ' ' + className : ''}`}>
      {(title || actions) && (
        <div className="panel-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <p className="dim sub">{sub}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Loading({ children = 'Loading…' }: { children?: ReactNode }) {
  return (
    <p className="loading" role="status">
      <Spinner /> {children}
    </p>
  );
}
