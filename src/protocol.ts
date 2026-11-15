/**
 * slink <-> relay tunnel wire protocol: JSON text frames over one outbound WebSocket.
 * Any relay that speaks these frames works; the README documents them for implementers.
 *
 * Handshake
 *   S→C  { type: "challenge", nonce: <64 hex chars>, server_time }
 *   C→S  { type: "auth", node_id, signature }      // Ed25519 over the UTF-8 nonce string, base64
 *   S→C  { type: "auth_ok", node_id } | { type: "auth_error", reason }  (then close 4401)
 *
 * HTTP
 *   S→C  { type: "http_request", id, method, path, headers, body?, lease_id? }   // body = base64
 *   S→C  { type: "http_cancel", id }
 *   C→S  { type: "http_response", id, status, headers, body? }                   // single shot
 *   C→S  { type: "http_response_start", id, status, headers }                    // or streamed
 *   C→S  { type: "http_response_chunk", id, data }                               // base64
 *   C→S  { type: "http_response_end", id }
 *   C→S  { type: "http_error", id, message }
 *
 * WebSocket (multiplexed by stream id)
 *   S→C  { type: "ws_open", id, path, headers, lease_id? }
 *   C→S  { type: "ws_opened", id } | { type: "ws_error", id, message }
 *   both { type: "ws_message", id, data, binary }                                // base64 when binary
 *   both { type: "ws_close", id, code?, reason? }
 *
 * Liveness: WebSocket ping/pong in both directions; app-level { type: "ping" } → { type: "pong" }.
 */

export type HeaderMap = Record<string, string | string[]>;

/** Frames the relay sends to slink. */
export type RelayFrame =
  | { type: 'challenge'; nonce: string; server_time: number }
  | { type: 'auth_ok'; node_id: string }
  | { type: 'auth_error'; reason: string }
  | { type: 'pong' }
  | { type: 'http_request'; id: string; method: string; path: string; headers: HeaderMap; body?: string; lease_id?: string }
  | { type: 'http_cancel'; id: string }
  | { type: 'ws_open'; id: string; path: string; headers: HeaderMap; lease_id?: string }
  | { type: 'ws_message'; id: string; data: string; binary: boolean }
  | { type: 'ws_close'; id: string; code?: number; reason?: string };

/** Frames slink sends to the relay. */
export type NodeFrame =
  | { type: 'auth'; node_id: string; signature: string }
  | { type: 'ping' }
  | { type: 'http_response'; id: string; status: number; headers?: HeaderMap; body?: string }
  | { type: 'http_response_start'; id: string; status: number; headers?: HeaderMap }
  | { type: 'http_response_chunk'; id: string; data: string }
  | { type: 'http_response_end'; id: string }
  | { type: 'http_error'; id: string; message?: string }
  | { type: 'ws_opened'; id: string }
  | { type: 'ws_error'; id: string; message?: string }
  | { type: 'ws_message'; id: string; data: string; binary?: boolean }
  | { type: 'ws_close'; id: string; code?: number; reason?: string };

/** Close codes the relay uses on the tunnel socket. */
export const RelayClose = {
  PROTOCOL: 4400,
  AUTH_FAILED: 4401,
  AUTH_TIMEOUT: 4408,
  SUPERSEDED: 4409,
  UNBOUND: 4410,
} as const;

/** Allowed node_id shape; relays should enforce the same rule when registering a node. */
export const NODE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;

const STREAM_ID_RE = /^[A-Za-z0-9-]{1,64}$/;

/**
 * Parse and structurally validate a relay frame. Anything malformed returns null and is
 * dropped. Nothing in a frame can choose where slink connects: only path/method/headers/body.
 */
export function parseRelayFrame(raw: string): RelayFrame | null {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const f = v as Record<string, unknown>;
  const str = (k: string) => typeof f[k] === 'string';
  const id = () => typeof f.id === 'string' && STREAM_ID_RE.test(f.id);
  const headers = () => f.headers === undefined || (typeof f.headers === 'object' && f.headers !== null && !Array.isArray(f.headers));
  switch (f.type) {
    case 'challenge':
      return str('nonce') && /^[0-9a-f]{64}$/i.test(f.nonce as string) ? (f as RelayFrame) : null;
    case 'auth_ok':
    case 'auth_error':
    case 'pong':
      return f as RelayFrame;
    case 'http_request':
      if (!id() || !str('method') || !str('path') || !headers()) return null;
      if (f.body !== undefined && typeof f.body !== 'string') return null;
      if (f.lease_id !== undefined && typeof f.lease_id !== 'string') return null;
      return { ...(f as RelayFrame & object), headers: (f.headers ?? {}) as HeaderMap } as RelayFrame;
    case 'http_cancel':
      return id() ? (f as RelayFrame) : null;
    case 'ws_open':
      if (!id() || !str('path') || !headers()) return null;
      return { ...(f as RelayFrame & object), headers: (f.headers ?? {}) as HeaderMap } as RelayFrame;
    case 'ws_message':
      return id() && str('data') ? ({ ...f, binary: f.binary === true } as RelayFrame) : null;
    case 'ws_close':
      return id() ? (f as RelayFrame) : null;
    default:
      return null;
  }
}
