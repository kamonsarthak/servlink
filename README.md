# servlink (`slink`)

A standalone, zero-trust tunnel that exposes a local server through one **outbound**, Ed25519-authenticated WebSocket to a relay server you choose. You don't open inbound ports, configure DNS or set up TLS on your machine.

- **Ed25519 hardware-style identity.** A keypair is generated once on the machine and the private key never leaves it. The relay only ever holds the public key, and every connection proves possession by signing a fresh challenge.
- **Strict loopback target locking.** The local host and port are fixed at startup. Nothing the relay sends can make `slink` connect anywhere else.
- **Local token-bucket rate limiting and payload caps.** Enforced on your machine, before a request reaches your app.
- **Wake/sleep process hooks.** Start your app on the first request and stop it after a quiet period.

`slink` is the client half. It works with any relay that speaks the [wire protocol](#relay-wire-protocol) below.

## Quick start

```bash
npm i -g servlink                       # or run any command as: npx servlink <command>

slink init                              # create this machine's identity
# register the printed node_id and public key with your relay, then:
slink connect --port 3000 --relay wss://relay.example.com/tunnel

slink status                            # identity, saved target, daemon state
slink logs                              # tail the sanitized request log
```

The relay is remembered after the first connect, so later runs only need `slink connect --port 3000`.

Requires Node.js 20.12 or newer.

## Commands

| Command | What it does |
|---|---|
| `slink init [--node-id <id>] [--force]` | Generates an Ed25519 keypair and a `node_id` (`<hostname>-<8 hex>`), saved to `~/.servlink/identity.json` with mode `0600`. Prints the `node_id` and the public key as raw hex, base64 and PEM. Register the `node_id` and public key with your relay. |
| `slink connect` | Opens and maintains the tunnel. Settings are saved to `~/.servlink/config.json` and reused on the next run. |
| `slink status` | Shows the `node_id`, public key, saved target, relay and limits, and whether a `slink connect` daemon is running and its tunnel state. |
| `slink logs [-n 50] [--no-follow]` | Tails `~/.servlink/logs/requests.log`: `[timestamp] [lease_id] METHOD /path -> STATUS (latency_ms)`. |

### `slink connect` flags

| Flag | Default | |
|---|---|---|
| `--port <n>` | saved value, else prompted | local port to expose |
| `--host <ip>` | `127.0.0.1` | `127.0.0.1`, `::1`, `localhost`, or an explicit private IP |
| `--relay <wss_url>` | none, see below | the relay's tunnel endpoint (`wss://` or `ws://`) |
| `--max-rps <n>` | `30` | local token bucket (burst 3×) |
| `--max-body-mb <n>` | `5` | local request-body cap |
| `--wake-cmd "<cmd>"` | | run when the port refuses connections |
| `--sleep-cmd "<cmd>"` | | run after `--idle-minutes` without traffic |
| `--idle-minutes <n>` | `15` | |
| `--force` | | start even if another daemon is running |

### Choosing the relay

There is no built-in relay. `slink connect` uses the first of these that is set:

1. the `--relay <wss_url>` flag
2. the `SERVLINK_RELAY_URL` environment variable
3. the `relay` saved in `~/.servlink/config.json` by an earlier connect
4. an interactive prompt, when run in a terminal

The relay in use is written to `~/.servlink/config.json` each time `slink connect` starts. Without a terminal and with none of the first three set, `slink connect` exits with an error.

## Host-protection guardrails

These run on your machine and do not depend on the relay behaving well.

- **Target lock (no SSRF or lateral movement).** Host and port are fixed when `slink connect` starts. Only loopback (`127.0.0.0/8`, `::1`, `localhost` pinned to `127.0.0.1`) or private IPs you pass explicitly (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) are accepted. Hostnames are refused, which rules out DNS rebinding, and so is link-local `169.254/16`, which hosts cloud metadata. Relay frames carry only a path. The path must be origin-form (`/…`): `//host`, `scheme://`, backslashes and control characters get a `400`. WebSocket URLs are built from the locked authority and checked again after parsing.
- **Rate limit.** Over `--max-rps`, slink answers `429` with `Retry-After: 1` without touching your server. The same limit applies to WebSocket opens and visitor messages.
- **Body cap.** An oversized body is rejected with `413` before it is decoded, based on its base64 size. A streaming byte counter also aborts the local request if the cap is crossed mid-write. WebSocket messages are capped too.
- **Timeouts.** Connecting to your server and receiving response headers has a hard 15 s limit, after which slink reports an error to the relay. An established response stream may idle for up to 5 minutes. At most 128 concurrent streams are allowed.
- **Crash safety.** Every frame, socket, HTTP and WebSocket handler is wrapped in an error boundary. Malformed frames are dropped, connection refusals are reported as errors, and the process logs any stray exception and keeps running.
- **Header sanitising.** slink drops `X-Forwarded-*`, `X-Real-IP`, `Forwarded`, hop-by-hop headers and malformed headers. It sets `Host: <host>:<port>` and adds `X-Servlink-Verified: 1`, so your app can tell a request came through the tunnel.
- **Wake/sleep.** On `ECONNREFUSED` with `--wake-cmd` set, slink runs the command once (a mutex covers concurrent requests) and polls the port for up to 10 s before forwarding. Command output goes to `~/.servlink/logs/wake.log`. Commands come only from your local flags and config, never from the relay.
- **Logs.** Logs never contain request or response bodies, cookies or query strings. The query is replaced by `?…`, and control characters are escaped to prevent log injection. The file rotates at 5 MB and keeps 3 old copies.

## Relay wire protocol

Everything travels as **JSON text frames** over the single WebSocket that `slink` opens to the relay URL. Binary frames are ignored. A relay that implements this section works with `slink` unchanged. The TypeScript types are in `src/protocol.ts`.

In the tables, **R→N** is relay to node (`slink`) and **N→R** is node to relay.

### Registration (out of band)

Before a node can connect, the relay must know its `node_id` and its raw 32-byte Ed25519 public key (`slink init` prints it as 64 hex characters). How you register them is up to the relay. A `node_id` matches `^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$`.

### Handshake

| Dir | Frame |
|---|---|
| R→N | `{ "type": "challenge", "nonce": "<64 hex chars>", "server_time": <ms> }` |
| N→R | `{ "type": "auth", "node_id": "<id>", "signature": "<base64>" }` |
| R→N | `{ "type": "auth_ok", "node_id": "<id>" }` |
| R→N | `{ "type": "auth_error", "reason": "<text>" }`, then close with `4401` |

The relay sends `challenge` as soon as the socket opens. The nonce must be exactly 64 hex characters (32 random bytes). The signature is Ed25519 over the **UTF-8 bytes of the nonce string** (the 64 characters, not the decoded 32 bytes), base64-encoded. The relay verifies it against the public key registered for `node_id`.

### HTTP

| Dir | Frame |
|---|---|
| R→N | `{ "type": "http_request", "id", "method", "path", "headers", "body"?, "lease_id"? }` |
| R→N | `{ "type": "http_cancel", "id" }` |
| N→R | `{ "type": "http_response", "id", "status", "headers", "body"? }` |
| N→R | `{ "type": "http_response_start", "id", "status", "headers" }` |
| N→R | `{ "type": "http_response_chunk", "id", "data" }` |
| N→R | `{ "type": "http_response_end", "id" }` |
| N→R | `{ "type": "http_error", "id", "message" }` |

- `id` is chosen by the relay: 1 to 64 characters of `A-Z a-z 0-9 -`, unique among open streams.
- `path` is origin-form and includes the query string, for example `/api/items?page=2`.
- `headers` is an object whose values are strings or arrays of strings.
- `body` and `data` are base64.
- `lease_id` is optional and opaque to `slink`. It is only written to the request log, so a relay can use it to tag which grant or link a request arrived through.
- Responses from the local server are streamed: `http_response_start`, zero or more `http_response_chunk`, then `http_response_end`. The single-shot `http_response` is used for replies `slink` generates itself (`400`, `413`, `429`, `503`); these carry the header `x-servlink-guard: 1`.
- `http_error` means the local server could not be reached, timed out or failed. If it arrives before `http_response_start`, the relay should answer the visitor with `502` or `504`. If it arrives after, the relay should abort the visitor's response.
- `http_cancel` tells `slink` the visitor went away. It aborts the local request and sends nothing further for that `id`.

### WebSocket

Visitor WebSockets are multiplexed over the tunnel by stream `id`.

| Dir | Frame |
|---|---|
| R→N | `{ "type": "ws_open", "id", "path", "headers", "lease_id"? }` |
| N→R | `{ "type": "ws_opened", "id" }` |
| N→R | `{ "type": "ws_error", "id", "message" }` |
| both | `{ "type": "ws_message", "id", "data", "binary" }` |
| both | `{ "type": "ws_close", "id", "code"?, "reason"? }` |

`slink` answers `ws_open` with `ws_opened` once the local socket is open, or `ws_error` if it cannot be opened. In `ws_message`, `data` is base64 when `binary` is `true` and plain text otherwise. Subprotocols are taken from the `sec-websocket-protocol` header of `ws_open`.

### Liveness

`slink` sends a WebSocket-level ping every 20 s and drops the connection if no pong arrives before the next one. Standard WebSocket servers answer these automatically. The relay may ping too. An application-level `{ "type": "pong" }` frame from the relay is accepted and ignored.

### Close codes

| Code | Meaning | What `slink` does |
|---|---|---|
| `4400` | protocol error | reconnects |
| `4401` | authentication failed: unknown `node_id` or bad signature | reconnects, in case the key is registered later |
| `4408` | authentication timed out | reconnects |
| `4409` | superseded: another `slink` connected with the same `node_id` | exits |
| `4410` | the node's registration changed or was removed | reconnects |

Any other close is treated as a dropped connection. Reconnects use exponential backoff with jitter: 1 s doubling up to 30 s, reset after each successful auth.

### Requirements for a relay

A relay decides who may reach a node and how visitors are routed to it. Whatever it does there, it should:

- send requests only to the node whose signature it verified on that socket
- allow one live socket per `node_id`, closing the older one with `4409`

It does not need to scrub `X-Servlink-Verified` or forwarding headers from visitor requests: `slink` drops whatever arrives and sets `X-Servlink-Verified: 1` itself on every request it forwards.

## Files

```
~/.servlink/identity.json      Ed25519 identity (0600)   ← keep secret
~/.servlink/config.json        last connect settings, including the relay
~/.servlink/daemon.json        pid + live tunnel state (for `slink status`)
~/.servlink/logs/requests.log  sanitized request log (+ .1 .2 .3)
~/.servlink/logs/wake.log      wake/sleep command output
```

## Environment

| Variable | |
|---|---|
| `SERVLINK_RELAY_URL` | relay used when `--relay` is not passed |
| `SERVLINK_HOME` | state directory, default `~/.servlink` |
| `NO_COLOR` | disable coloured output |

## Development

```bash
npm install
npm run build
npm test        # build + unit tests + mock-relay tunnel tests + compiled CLI tests
```

## License

[MIT](LICENSE) © Sarthak Kamon ([@kamonsarthak](https://github.com/kamonsarthak))
