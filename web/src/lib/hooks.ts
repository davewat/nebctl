import { useCallback, useEffect, useRef, useState } from 'react';
import { errMsg } from '../api/client';

/** Runs one async action at a time and tracks busy and error state. */
export function useTask() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      if (alive.current) setError(errMsg(e));
      return undefined;
    } finally {
      if (alive.current) setBusy(false);
    }
  }, []);
  return { busy, error, run, setError };
}

interface ResourceOptions {
  /** Re-fetch every this many ms while the page is visible. */
  poll?: number;
}

/**
 * Loads `fetcher` when `deps` change (null fetcher = idle). While polling, a
 * failed refresh keeps the last good data so the page does not jump.
 */
export function useResource<T>(fetcher: (() => Promise<T>) | null, deps: unknown[], opts: ResourceOptions = {}) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(!!fetcher);
  const [at, setAt] = useState<number | undefined>(undefined);
  const seq = useRef(0);
  const inflight = useRef(false);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const load = useCallback(async (silent = false) => {
    const f = fetcherRef.current;
    if (!f) return;
    const id = ++seq.current;
    inflight.current = true;
    if (!silent) setLoading(true);
    try {
      const d = await f();
      if (id !== seq.current) return;
      setData(d);
      setError(undefined);
      setAt(Date.now());
    } catch (e) {
      if (id !== seq.current) return;
      setError(errMsg(e));
    } finally {
      if (id === seq.current) {
        inflight.current = false;
        setLoading(false);
      }
    }
  }, []);

  const poll = opts.poll;
  const active = !!fetcher;
  useEffect(() => {
    setData(undefined);
    setError(undefined);
    setAt(undefined);
    if (!active) {
      setLoading(false);
      return;
    }
    void load();
    if (!poll) {
      return () => {
        seq.current++;
      };
    }
    const tick = () => {
      if (document.visibilityState === 'visible' && !inflight.current) void load(true);
    };
    const timer = setInterval(tick, poll);
    const onVis = () => {
      if (document.visibilityState === 'visible') void load(true);
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVis);
      seq.current++;
      inflight.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, active, poll]);

  const reload = useCallback(() => load(true), [load]);
  const reloadWithSpinner = useCallback(() => load(false), [load]);
  return { data, error, loading, at, reload, refresh: reloadWithSpinner, setData };
}

export function useReducedMotion(): boolean {
  const q = '(prefers-reduced-motion: reduce)';
  const [reduce, setReduce] = useState(() => window.matchMedia(q).matches);
  useEffect(() => {
    const m = window.matchMedia(q);
    const on = () => setReduce(m.matches);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);
  return reduce;
}

/** The current route from the URL hash: "#/hosts" -> "hosts". */
export function useHashRoute(fallback: string, known: string[]): string {
  const read = () => {
    const h = location.hash.replace(/^#\/?/, '').split(/[/?]/)[0];
    return known.includes(h) ? h : fallback;
  };
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return route;
}

export function usePageVisible(): boolean {
  const [v, setV] = useState(document.visibilityState === 'visible');
  useEffect(() => {
    const on = () => setV(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', on);
    return () => document.removeEventListener('visibilitychange', on);
  }, []);
  return v;
}
