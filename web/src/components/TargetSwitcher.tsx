import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useConsole } from '../context';
import { useTask } from '../lib/hooks';
import { Button, ErrorText } from '../ui';

export function TargetSwitcher() {
  const { targets, target, selectTarget, openConnect, refreshTargets, toast } = useConsole();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const task = useTask();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    // move focus to the current machine
    requestAnimationFrame(() => root.current?.querySelector<HTMLElement>('[aria-current="true"]')?.focus());
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const onMenuKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const items = [...(root.current?.querySelectorAll<HTMLElement>('.menu-item') ?? [])];
    const i = items.indexOf(document.activeElement as HTMLElement);
    const next = e.key === 'ArrowDown' ? items[(i + 1) % items.length] : items[(i - 1 + items.length) % items.length];
    next?.focus();
    e.preventDefault();
  };

  const disconnect = async (id: string, label: string) => {
    const ok = await task.run(() => api.disconnect(id));
    if (ok === undefined && task.error) return;
    toast(`Disconnected from ${label}.`);
    if (id === target.id) selectTarget('local');
    await refreshTargets();
  };

  return (
    <div className="switcher" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="switcher-btn"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="switcher-label">{target.label}</span>
        <span className="caret" aria-hidden="true" />
      </button>
      {open && (
        <div className="menu" role="group" aria-label="Machines" onKeyDown={onMenuKey}>
          <p className="menu-title">Manage</p>
          <ul>
            {targets.map((t) => (
              <li key={t.id} className="menu-row">
                <button
                  type="button"
                  className="menu-item"
                  aria-current={t.id === target.id ? 'true' : undefined}
                  onClick={() => {
                    selectTarget(t.id);
                    setOpen(false);
                    trigger.current?.focus();
                  }}
                >
                  <span className="menu-item-label">{t.label}</span>
                  <span className="menu-item-sub dim">
                    {t.kind === 'local' ? 'This machine' : `${t.user ?? ''}@${t.host ?? ''}`}
                    {t.role ? `, ${t.role}` : ''}
                    {t.haveCa ? ', has the CA' : ''}
                  </span>
                </button>
                {t.kind === 'ssh' && (
                  <Button small variant="quiet" aria-label={`Disconnect from ${t.label}`} busy={task.busy} onClick={() => disconnect(t.id, t.label)}>
                    Disconnect
                  </Button>
                )}
              </li>
            ))}
          </ul>
          <ErrorText>{task.error}</ErrorText>
          <div className="menu-foot">
            <button
              type="button"
              className="menu-item menu-connect"
              onClick={() => {
                setOpen(false);
                openConnect();
              }}
            >
              Connect to another machine…
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
