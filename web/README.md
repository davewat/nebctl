# nebctl console

The React front end for `nebctl web`. The Go side serves it on 127.0.0.1 and
implements the API in [CONTRACT.md](CONTRACT.md); this directory is only the
front end.

## Run it with sample data

```bash
cd web
npm install
npm run dev        # http://127.0.0.1:5173, mock API on
```

`npm run dev` loads `.env.mock` (`VITE_MOCK=1`), so no server is needed. Any
build also answers from the mock when the page URL has `?mock`.

Useful switches (add to the URL, e.g. `/?mock&latency=0`):

| Switch | Effect |
|---|---|
| `latency=0` | No simulated delay (default is about 300 ms) |
| `noadmin` | Nebula's admin access is off on "This Mac" (shows the turn-on panel) |
| `expired` | Every call answers 401 (shows the expired-link page) |
| `embedded=1` | Shows "Open in browser", as in the Mac app window |
| `target=lh` | Start on a target (`local`, `lh`, `fe01`) |

Connect dialog flows in mock mode: any host gets the 409 host key prompt first.
`changed-key.example.com` shows the loud warning, `sudo.example.com` asks for
the sudo password (401), `bare.example.com` and `old.example.com` offer to
install nebctl (428). The password `wrong` is refused (401).

## Run it against a real `nebctl web`

```bash
NEBCTL_API=http://127.0.0.1:<port> npm run dev:live
```

The session cookie is set when you open the one-time `/?token=...` link on the
same origin, so in practice use the built console served by `nebctl web`.

## Build

```bash
npm run build      # tsc --noEmit, then vite build
```

The build writes to `../internal/web/dist` (emptied first, no source maps).
**That directory is committed**, because Go embeds it with `go:embed`. Rebuild
and commit it whenever the console changes.

## Layout

- `src/api/`: `types.ts` (mirrors the contract), `client.ts` (fetch wrapper, `ApiError`), `index.ts` (typed calls), `mock.ts` (the pretend server, loaded only in mock mode)
- `src/pages/`: Map (`MeshCanvas.tsx` draws the mesh), Hosts, Certificates, Config, Logs, Health
- `src/components/`: top-bar machine switcher, connect dialog, peer drawer, admin-access gate
- `src/ui/`: buttons, dialog (native `<dialog>`), copy blocks, switches, notices
- `src/styles.css`: all the styling, as custom properties on `:root`

Fonts (Sora 400/600, IBM Plex Mono 400, Latin) are bundled from
`@fontsource`, so the console works offline.
