import type { ReactNode } from 'react';
import { api } from '../api';
import { useConsole } from '../context';
import { useTask } from '../lib/hooks';
import { Button, CopyBlock, ErrorText, Loading, Notice } from '../ui';

/**
 * Pages that read nebula's admin commands wrap their content in this. It
 * shows one clear next step when nebula isn't set up or admin access is off.
 */
export function AdminGate({ children }: { children: ReactNode }) {
  const { target, state, stateError, stateLoading, refreshState, toast } = useConsole();
  const task = useTask();

  if (!state) {
    if (stateError) {
      return (
        <div className="gate">
          <Notice tone="danger" title={`Can't read ${target.label}`}>
            {stateError}
          </Notice>
          <Button onClick={refreshState}>Try again</Button>
        </div>
      );
    }
    return <Loading>{stateLoading ? `Reading ${target.label}…` : 'Loading…'}</Loading>;
  }

  if (!state.nebula || !state.host) {
    const role = target.role === 'lighthouse' ? 'lighthouse' : 'node';
    return (
      <div className="gate panel">
        <h2>Nebula isn't set up on this machine</h2>
        <p className="dim">Run the setup there, then come back to this page.</p>
        <CopyBlock text={`sudo nebctl ${role}`} />
      </div>
    );
  }

  if (!state.admin.enabled) {
    return (
      <div className="gate panel">
        <h2>Nebula's admin access is off on this machine. Turn it on to see connections.</h2>
        <p className="dim">
          Admin access is nebula's own SSH server, reachable only from this machine ({state.admin.listen || '127.0.0.1'}). Turning it on restarts nebula, which briefly drops its tunnels.
        </p>
        <div>
          <Button
            variant="primary"
            busy={task.busy}
            onClick={async () => {
              const r = await task.run(() => api.enableAdmin(target.id));
              if (r) {
                toast('Admin access is on. Nebula restarted.');
                refreshState();
              }
            }}
          >
            Turn on admin access
          </Button>
        </div>
        <ErrorText>{task.error}</ErrorText>
      </div>
    );
  }
  return <>{children}</>;
}
