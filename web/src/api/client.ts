// The one place that talks to `nebctl web`. In mock mode the same calls are
// answered by src/api/mock.ts, so every page runs the code path it will use
// for real (including the errors).

export const isMock: boolean = (() => {
  try {
    if (new URLSearchParams(location.search).has('mock')) return true;
  } catch {
    /* no location */
  }
  return import.meta.env.VITE_MOCK === '1';
})();

/** An API failure. `body` is the parsed JSON (or undefined) for 409/428/401 handling. */
export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
  /** `need` of a 401 that asks for one more credential. */
  get need(): string | undefined {
    const b = this.body as { need?: unknown } | undefined;
    return b && typeof b.need === 'string' ? b.need : undefined;
  }
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

type Listener = () => void;
const expiredListeners = new Set<Listener>();
/** Called when the session cookie is no longer accepted. Returns an unsubscribe. */
export function onSessionExpired(fn: Listener): () => void {
  expiredListeners.add(fn);
  return () => expiredListeners.delete(fn);
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (isMock) {
    const { handle } = await import('./mock');
    try {
      return (await handle(method, path, body)) as T;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401 && !e.need) expiredListeners.forEach((f) => f());
      throw e;
    }
  }

  let res: Response;
  try {
    res = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: {
        'X-Nebctl': '1',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Can't reach nebctl. Check that `sudo nebctl web` is still running.");
  }

  let parsed: unknown;
  const text = await res.text();
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }

  if (!res.ok) {
    const b = parsed as { error?: unknown; need?: unknown } | undefined;
    const message = b && typeof b.error === 'string' && b.error ? b.error : res.statusText || `Request failed (${res.status})`;
    const err = new ApiError(res.status, message, parsed);
    if (res.status === 401 && !err.need) expiredListeners.forEach((f) => f());
    throw err;
  }
  return parsed as T;
}
