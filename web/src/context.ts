import { createContext, useContext } from 'react';
import type { Connections, State, Target } from './api/types';

export interface ConnsResource {
  data?: Connections;
  error?: string;
  loading: boolean;
  at?: number;
  reload: () => Promise<void>;
}

export interface ConsoleCtx {
  targets: Target[];
  target: Target;
  state?: State;
  stateError?: string;
  stateLoading: boolean;
  refreshState: () => void;
  refreshTargets: () => Promise<void>;
  selectTarget: (id: string) => void;
  openConnect: () => void;
  toast: (message: string, tone?: 'ok' | 'error') => void;
  conns: ConnsResource;
  /** Fingerprints on this target's blocklist (empty until loaded). */
  blocked: Set<string>;
  selected: string | null;
  selectPeer: (addr: string | null) => void;
  /** Short host name for a Nebula address, or the address itself. */
  nameOf: (addr: string) => string;
  /** Switch to the first lighthouse-with-CA target, if one is connected. */
  caTarget?: Target;
}

export const ConsoleContext = createContext<ConsoleCtx | null>(null);

export function useConsole(): ConsoleCtx {
  const c = useContext(ConsoleContext);
  if (!c) throw new Error('useConsole outside the console');
  return c;
}
