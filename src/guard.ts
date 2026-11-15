/**
 * Host-protection guardrails. Everything here is pure and unit-tested.
 *
 *  - Target lock: host/port are fixed at startup and must be loopback or a private IP that
 *    the operator passed explicitly. Hostnames (other than `localhost`) are refused, so DNS
 *    rebinding cannot redirect traffic. Relay frames only ever supply a *path*.
 *  - Header sanitisation: untrusted forwarding headers are stripped and `Host` is rewritten.
 *  - Token bucket: second-line rate limit in front of the local server.
 */
import { isIP } from 'node:net';
import type { HeaderMap } from './protocol.js';

export class GuardError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = 'GuardError';
  }
}

export interface Target {
  /** Address actually dialled (never a hostname needing DNS). */
  host: string;
  port: number;
  /** `host:port` as sent in the Host header, IPv6 bracketed. */
  authority: string;
}

function ipv4Octets(ip: string): number[] {
  return ip.split('.').map(Number);
}

export function isLoopback(ip: string): boolean {
  if (isIP(ip) === 4) return ipv4Octets(ip)[0] === 127;
  return ip === '::1' || ip === '0:0:0:0:0:0:0:1';
}

/** RFC 1918 IPv4 and RFC 4193 IPv6 (fc00::/7). Link-local (169.254/16, fe80::/10) is excluded: it hosts cloud metadata endpoints. */
export function isPrivate(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ipv4Octets(ip) as [number, number];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (isIP(ip) === 6) return /^f[cd][0-9a-f]{0,2}:/i.test(ip);
  return false;
}

/** Validate and lock the forwarding target. Throws GuardError for anything not loopback/private. */
export function lockTarget(hostInput: string, portInput: number | string): Target {
  const port = typeof portInput === 'number' ? portInput : Number(portInput);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new GuardError(`Invalid port "${portInput}" (1-65535)`);

  let host = String(hostInput).trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host === 'localhost') host = '127.0.0.1';

  const family = isIP(host);
  if (family === 0) {
    throw new GuardError(`Refusing hostname "${hostInput}": use 127.0.0.1, ::1, localhost or an explicit private IP`);
  }
  if (host.startsWith('::ffff:')) throw new GuardError('IPv4-mapped IPv6 addresses are not allowed; pass the IPv4 address');
  if (!isLoopback(host) && !isPrivate(host)) {
    throw new GuardError(`Refusing ${host}: only loopback (127.0.0.1, ::1) or private (10/8, 172.16/12, 192.168/16, fc00::/7) targets are allowed`);
  }
  return { host, port, authority: family === 6 ? `[${host}]:${port}` : `${host}:${port}` };
}

const MAX_PATH = 8192;

/**
 * Validate a relay-supplied request path. It must be origin-form (`/…`), so it can never
 * name another host: no scheme, no `//authority`, no backslashes, no control characters.
 */
export function safePath(path: unknown): string {
  if (typeof path !== 'string' || path.length === 0 || path.length > MAX_PATH) throw new GuardError('Invalid request path');
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) throw new GuardError('Request path must be origin-form (/…)');
  if (/[\u0000- \u007f]/.test(path)) throw new GuardError('Request path contains illegal characters');
  return path;
}

const METHOD_RE = /^[A-Z]{1,16}$/;
export function safeMethod(method: unknown): string {
  if (typeof method !== 'string' || !METHOD_RE.test(method)) throw new GuardError('Invalid HTTP method');
  return method;
}

/** Build the local WebSocket URL from the locked target, and prove the authority did not change. */
export function targetWsUrl(target: Target, path: string): string {
  const url = `ws://${target.authority}${safePath(path)}`;
  const parsed = new URL(url);
  const expectedHost = target.authority.replace(/:\d+$/, '');
  if (parsed.hostname !== expectedHost || Number(parsed.port) !== target.port) {
    throw new GuardError('Resolved WebSocket URL escaped the locked target');
  }
  return url;
}

const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;

const STRIP = new Set([
  // hop-by-hop
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  // rewritten / recomputed locally
  'host',
  'content-length',
  // untrusted forwarding metadata
  'forwarded',
  'x-real-ip',
  'x-servlink-verified',
]);

const WS_HANDSHAKE = new Set(['sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions', 'sec-websocket-accept', 'sec-websocket-protocol']);

/**
 * Sanitise relay-supplied request headers before they reach the local server: drop
 * hop-by-hop, `X-Forwarded-*`, `X-Real-IP`, `Forwarded`; drop malformed names/values;
 * force `Host: <host>:<port>` and add `X-Servlink-Verified: 1`.
 */
export function sanitizeHeaders(input: HeaderMap | undefined, target: Target, opts: { websocket?: boolean } = {}): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [rawName, rawValue] of Object.entries(input ?? {})) {
    const name = rawName.toLowerCase();
    if (!TOKEN_RE.test(name) || STRIP.has(name) || name.startsWith('x-forwarded-')) continue;
    if (opts.websocket && WS_HANDSHAKE.has(name)) continue;
    const values = (Array.isArray(rawValue) ? rawValue : [rawValue]).filter(
      (v): v is string => typeof v === 'string' && !/[\r\n\0]/.test(v),
    );
    if (values.length === 0) continue;
    out[name] = values.length === 1 ? values[0]! : values;
  }
  out.host = target.authority;
  out['x-servlink-verified'] = '1';
  return out;
}

/** Token bucket: refills `ratePerSec` tokens/s up to `burst`. */
export class TokenBucket {
  private tokens: number;
  private last = Date.now();
  constructor(
    readonly ratePerSec: number,
    readonly burst: number = Math.max(1, ratePerSec * 3),
  ) {
    this.tokens = burst;
  }
  take(now = Date.now()): boolean {
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.last) / 1000) * this.ratePerSec);
    this.last = now;
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

/** Upper bound of decoded bytes for a base64 string, computed without decoding it. */
export function base64DecodedSize(b64: string): number {
  const padding = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((b64.length * 3) / 4) - padding);
}
