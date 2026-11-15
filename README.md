# servlink (`slink`)

Expose a local port to [Lapseed](https://lapseed.com) through one **outbound**, Ed25519-authenticated WebSocket. You don't need to open inbound ports, configure DNS or set up TLS on your machine. Visitors reach your app at `https://lapseed.app/project/<slug>` only through lease links you control from Lapseed (`lseed lease …`).

```bash
npx servlink init                       # or: npm i -g servlink && slink init
slink connect --port 3000
```

## Commands

| Command | What it does |
|---|---|
| `slink init [--node-id <id>] [--force]` | Generates an Ed25519 keypair and a `node_id` (`<hostname>-<8 hex>`), saved to `~/.servlink/identity.json` with mode `0600`. Prints the `node_id` and public key (raw hex, which Lapseed's `PUT /api/users/server` accepts; base64 and PEM are printed too). Paste them into **Lapseed → Settings → Server**. |
| `slink connect` | Opens and maintains the tunnel. Prompts for port, host and relay when run interactively without `--port`, and remembers the answers in `~/.servlink/config.json`. |
| `slink status` | Shows the `node_id`, public key, saved target and limits, and whether a `slink connect` daemon is running and its tunnel state. |
| `slink logs [-n 50] [--no-follow]` | Tails `~/.servlink/logs/requests.log`: `[timestamp] [lease_id] METHOD /path -> STATUS (latency_ms)`. |

### `slink connect` flags

| Flag | Default | |
|---|---|---|
| `--port <n>` | (required) | local port to expose |
| `--host <ip>` | `127.0.0.1` | `127.0.0.1`, `::1`, `localhost`, or an explicit private IP |
| `--relay <wss_url>` | `wss://lapseed.app/tunnel` | |
| `--max-rps <n>` | `30` | local token bucket (burst 3×) |
| `--max-body-mb <n>` | `5` | local request-body cap |
| `--wake-cmd "<cmd>"` | | run when the port refuses connections |
| `--sleep-cmd "<cmd>"` | | run after `--idle-minutes` without traffic |
| `--idle-minutes <n>` | `15` | |
| `--force` | | start even if another daemon is running |

## Host-protection guardrails

These run on your machine as a second line of defence, after Lapseed's own lease checks.

- **Target lock (no SSRF or lateral movement).** Host and port are fixed when `slink connect` starts. Only loopback (`127.0.0.0/8`, `::1`, `localhost` pinned to `127.0.0.1`) or private IPs you pass explicitly (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) are accepted. Hostnames are refused, which rules out DNS rebinding, and so is link-local `169.254/16`, which hosts cloud metadata. Relay frames carry only a path. The path must be origin-form (`/…`): `//host`, `scheme://`, backslashes and control characters get a `400`. WebSocket URLs are built from the locked authority and checked again after parsing.
- **Rate limit.** Over `--max-rps`, slink answers `429` with `Retry-After: 1` without touching your server. The same limit applies to WebSocket opens and visitor messages.
- **Body cap.** An oversized body is rejected with `413` before it is decoded, based on its base64 size. A streaming byte counter also aborts the local request if the cap is crossed mid-write. WebSocket messages are capped too.
- **Timeouts.** Connecting to your server and receiving response headers has a hard 15 s limit; slink returns an error and the visitor gets a `502`. An established response stream may idle for up to 5 minutes. At most 128 concurrent streams are allowed.
- **Crash safety.** Every frame, socket, HTTP and WebSocket handler is wrapped in an error boundary. Malformed frames are dropped, connection refusals become `502`s, and the process logs any stray exception and keeps running.
- **Header sanitising.** slink drops `X-Forwarded-*`, `X-Real-IP`, `Forwarded`, hop-by-hop headers and malformed headers. It sets `Host: <host>:<port>` and adds `X-Servlink-Verified: 1`.
- **Wake/sleep.** On `ECONNREFUSED` with `--wake-cmd` set, slink runs the command once (a mutex covers concurrent requests) and polls the port for up to 10 s before forwarding. Command output goes to `~/.servlink/logs/wake.log`. Commands come only from your local flags/config, never from the relay.
- **Logs.** Logs never contain request or response bodies, cookies or query strings. The query is replaced by `?…`, and control characters are escaped to prevent log injection. The file rotates at 5 MB and keeps 3 old copies.

## Connection behaviour

- **Handshake.** The relay sends a 32-byte hex nonce. slink signs the UTF-8 nonce with Ed25519 and replies `{type:"auth", node_id, signature(base64)}`.
- **Reconnects.** slink reconnects with exponential backoff and jitter (1 s doubling up to 30 s, reset after each successful auth). It pings the relay every 20 s and terminates the socket when a pong is missed.
- **Close codes.** `4401`: key not bound or wrong (keeps retrying). `4410`: binding changed in Lapseed (retries). `4409`: another `slink` connected with the same `node_id` (this one exits).
- **Wire format.** Identical to the Lapseed backend's `src/modules/lease/protocol.ts`. See `src/protocol.ts`.

## Files

```
~/.servlink/identity.json      Ed25519 identity (0600)   ← keep secret
~/.servlink/config.json        last connect settings
~/.servlink/daemon.json        pid + live tunnel state (for `slink status`)
~/.servlink/logs/requests.log  sanitized request log (+ .1 .2 .3)
~/.servlink/logs/wake.log      wake/sleep command output
```

`SERVLINK_HOME` overrides the directory.

## Development

```bash
npm install
npm run build
npm test        # build + unit tests + mock-relay tunnel tests + compiled CLI tests
```
