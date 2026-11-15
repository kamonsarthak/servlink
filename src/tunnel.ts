/**
 * The slink tunnel: one outbound WebSocket to a relay server, authenticated by Ed25519
 * challenge-response, auto-reconnecting with exponential backoff + full jitter, and
 * multiplexing visitor HTTP requests / WebSockets onto the *locked* local target.
 */
import http, { type ClientRequest, type IncomingMessage } from 'node:http';
import type { KeyObject } from 'node:crypto';
import WebSocket from 'ws';
import { base64DecodedSize, GuardError, safeMethod, safePath, sanitizeHeaders, targetWsUrl, TokenBucket, type Target } from './guard.js';
import { signChallenge } from './identity.js';
import type { RequestLog } from './logs.js';
import { parseRelayFrame, RelayClose, type HeaderMap, type NodeFrame, type RelayFrame } from './protocol.js';
import type { WakeManager } from './wake.js';

export type TunnelState = 'connecting' | 'authenticating' | 'online' | 'reconnecting' | 'stopped';

export interface TunnelOptions {
  relay: string;
  nodeId: string;
  privateKey: KeyObject;
  /** Locked at startup; relay frames can never change it. */
  target: Target;
  maxRps: number;
  maxBodyMb: number;
  wake?: WakeManager;
  requestLog?: RequestLog;
  /** Hard limit for connecting + receiving response headers from the local server. */
  localTimeoutMs?: number;
  /** Idle limit for a response stream once headers have arrived. */
  streamIdleMs?: number;
  heartbeatMs?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  maxConcurrent?: number;
  onState?: (state: TunnelState, detail?: string) => void;
  log?: (msg: string) => void;
}

interface HttpEntry {
  req?: ClientRequest;
  res?: IncomingMessage;
  cancelled: boolean;
}

const HIGH_WATER = 4 * 1024 * 1024;
const LOW_WATER = 1024 * 1024;
const CHUNK = 64 * 1024;

class LocalError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

function errCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | undefined)?.code;
}

export class SlinkTunnel {
  private ws: WebSocket | null = null;
  private state: TunnelState = 'connecting';
  private attempt = 0;
  private stopped = false;
  private heartbeat: NodeJS.Timeout | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private awaitingPong = false;
  private readonly http = new Map<string, HttpEntry>();
  private readonly sockets = new Map<string, WebSocket>();
  private readonly bucket: TokenBucket;
  private readonly maxBodyBytes: number;
  private readonly o: Required<Pick<TunnelOptions, 'localTimeoutMs' | 'streamIdleMs' | 'heartbeatMs' | 'backoffBaseMs' | 'backoffMaxMs' | 'maxConcurrent'>> &
    TunnelOptions;
  /** Count of authenticated sessions (observable for tests / status). */
  connections = 0;

  constructor(opts: TunnelOptions) {
    this.o = {
      localTimeoutMs: 15_000,
      streamIdleMs: 300_000,
      heartbeatMs: 20_000,
      backoffBaseMs: 1_000,
      backoffMaxMs: 30_000,
      maxConcurrent: 128,
      ...opts,
    };
    this.bucket = new TokenBucket(opts.maxRps);
    this.maxBodyBytes = Math.floor(opts.maxBodyMb * 1024 * 1024);
  }

  get currentState(): TunnelState {
    return this.state;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.stopHeartbeat();
    this.teardownStreams();
    this.ws?.close(1000, 'slink stopping');
    this.setState('stopped');
  }

  // ─── connection lifecycle ─────────────────────────────────────────────────

  private setState(state: TunnelState, detail?: string): void {
    this.state = state;
    this.o.onState?.(state, detail);
  }

  private connect(): void {
    if (this.stopped) return;
    this.setState('connecting', this.o.relay);
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.o.relay, {
        handshakeTimeout: 15_000,
        perMessageDeflate: false,
        // Room for a 50 MB body in base64 (≈ 1.37×) with headroom, while still bounding memory.
        maxPayload: 100 * 1024 * 1024,
      });
    } catch (err) {
      this.o.log?.(`invalid relay URL: ${(err as Error).message}`);
      this.scheduleReconnect('invalid relay URL');
      return;
    }
    this.ws = ws;

    ws.on('open', () => {
      this.setState('authenticating');
      this.startHeartbeat(ws);
    });
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      try {
        const frame = parseRelayFrame(data.toString());
        if (!frame) {
          this.o.log?.('dropped malformed relay frame');
          return;
        }
        this.onFrame(frame);
      } catch (err) {
        this.o.log?.(`frame handler error: ${(err as Error).message}`);
      }
    });
    ws.on('pong', () => {
      this.awaitingPong = false;
    });
    ws.on('error', (err) => this.o.log?.(`tunnel error: ${err.message}`));
    ws.on('close', (code, reasonBuf) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.stopHeartbeat();
      this.teardownStreams();
      const reason = reasonBuf.toString();
      if (this.stopped) return;
      if (code === RelayClose.SUPERSEDED) {
        this.o.log?.('another slink connected with this node_id; this one is standing down');
        this.stopped = true;
        this.setState('stopped', 'superseded by another slink using this node_id');
        return;
      }
      const why =
        code === RelayClose.AUTH_FAILED
          ? `authentication rejected (${reason || 'is this node_id + public key registered with the relay?'})`
          : code === RelayClose.UNBOUND
            ? 'node binding changed on the relay'
            : `closed (${code}${reason ? ` ${reason}` : ''})`;
      this.scheduleReconnect(why);
    });
  }

  private scheduleReconnect(why: string): void {
    if (this.stopped) return;
    const exp = Math.min(this.o.backoffMaxMs, this.o.backoffBaseMs * 2 ** this.attempt);
    const delay = Math.round(exp / 2 + Math.random() * (exp / 2)); // "equal jitter": never 0, never > cap
    this.attempt++;
    this.setState('reconnecting', `${why}; retrying in ${(delay / 1000).toFixed(1)}s`);
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private startHeartbeat(ws: WebSocket): void {
    this.stopHeartbeat();
    this.awaitingPong = false;
    this.heartbeat = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (this.awaitingPong) {
        this.o.log?.('relay heartbeat lost; reconnecting');
        ws.terminate();
        return;
      }
      this.awaitingPong = true;
      ws.ping();
    }, this.o.heartbeatMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }

  private teardownStreams(): void {
    for (const e of this.http.values()) {
      e.cancelled = true;
      e.req?.destroy();
      e.res?.destroy();
    }
    this.http.clear();
    for (const s of this.sockets.values()) s.terminate();
    this.sockets.clear();
  }

  private send(frame: NodeFrame): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(frame));
  }

  // ─── frame dispatch ───────────────────────────────────────────────────────

  private onFrame(f: RelayFrame): void {
    switch (f.type) {
      case 'challenge':
        this.send({ type: 'auth', node_id: this.o.nodeId, signature: signChallenge(this.o.privateKey, f.nonce) });
        return;
      case 'auth_ok':
        this.attempt = 0;
        this.connections++;
        this.setState('online', f.node_id);
        return;
      case 'auth_error':
        this.o.log?.(`relay rejected authentication: ${f.reason}`);
        return;
      case 'pong':
        return;
      case 'http_request':
        this.handleHttp(f).catch((err) => this.o.log?.(`http handler error: ${(err as Error).message}`));
        return;
      case 'http_cancel': {
        const e = this.http.get(f.id);
        if (!e) return;
        e.cancelled = true;
        e.req?.destroy();
        e.res?.destroy();
        this.http.delete(f.id);
        return;
      }
      case 'ws_open':
        this.handleWsOpen(f).catch((err) => this.o.log?.(`ws handler error: ${(err as Error).message}`));
        return;
      case 'ws_message': {
        const s = this.sockets.get(f.id);
        if (!s || s.readyState !== WebSocket.OPEN) return;
        const size = f.binary ? base64DecodedSize(f.data) : Buffer.byteLength(f.data);
        if (size > this.maxBodyBytes) return this.closeStream(f.id, 1009, 'message too large');
        if (!this.bucket.take()) return this.closeStream(f.id, 1008, 'rate limit exceeded');
        s.send(f.binary ? Buffer.from(f.data, 'base64') : f.data);
        return;
      }
      case 'ws_close': {
        const s = this.sockets.get(f.id);
        this.sockets.delete(f.id);
        s?.close();
        return;
      }
    }
  }

  // ─── HTTP ─────────────────────────────────────────────────────────────────

  private async handleHttp(f: Extract<RelayFrame, { type: 'http_request' }>): Promise<void> {
    const started = Date.now();
    const pathForLog = typeof f.path === 'string' ? f.path : '?';
    const log = (status: number | string) =>
      this.o.requestLog?.write({ leaseId: f.lease_id, method: f.method, path: pathForLog, status, ms: Date.now() - started });
    const guardReply = (status: number, message: string, extra: HeaderMap = {}) => {
      this.send({
        type: 'http_response',
        id: f.id,
        status,
        headers: { 'content-type': 'text/plain; charset=utf-8', 'x-servlink-guard': '1', ...extra },
        body: Buffer.from(`${message}\n`).toString('base64'),
      });
      log(status);
    };

    let method: string;
    let path: string;
    try {
      method = safeMethod(f.method);
      path = safePath(f.path);
    } catch (err) {
      return guardReply(400, (err as Error).message);
    }
    if (this.http.size >= this.o.maxConcurrent) return guardReply(503, 'slink: too many concurrent requests', { 'retry-after': '1' });
    if (!this.bucket.take()) return guardReply(429, 'slink: local rate limit exceeded', { 'retry-after': '1' });
    if (f.body && base64DecodedSize(f.body) > this.maxBodyBytes) {
      return guardReply(413, `slink: request body exceeds ${this.o.maxBodyMb} MB`);
    }

    this.o.wake?.touch();
    const headers = sanitizeHeaders(f.headers, this.o.target);
    const body = f.body ? Buffer.from(f.body, 'base64') : undefined;
    if (body) headers['content-length'] = String(body.length);
    const entry: HttpEntry = { cancelled: false };
    this.http.set(f.id, entry);

    try {
      let status: number;
      try {
        status = await this.forward(f.id, entry, method, path, headers, body);
      } catch (err) {
        if (errCode(err) === 'ECONNREFUSED' && this.o.wake?.canWake && !entry.cancelled) {
          await this.o.wake.ensureAwake();
          status = await this.forward(f.id, entry, method, path, headers, body);
        } else throw err;
      }
      log(status);
    } catch (err) {
      if (entry.cancelled) return log('cancelled');
      if (err instanceof LocalError && err.code === 'BODY_TOO_LARGE') return guardReply(413, err.message);
      const code = errCode(err) ?? (err as LocalError).code;
      const message =
        code === 'ECONNREFUSED'
          ? `local service at ${this.o.target.authority} refused the connection`
          : code === 'LOCAL_TIMEOUT'
            ? `local service at ${this.o.target.authority} did not respond within ${this.o.localTimeoutMs / 1000}s`
            : `local service error: ${(err as Error).message}`;
      this.send({ type: 'http_error', id: f.id, message });
      log(code === 'LOCAL_TIMEOUT' ? 504 : 502);
    } finally {
      this.http.delete(f.id);
    }
  }

  /** One attempt against the local server. Resolves with the status once the response has fully streamed. */
  private forward(
    id: string,
    entry: HttpEntry,
    method: string,
    path: string,
    headers: Record<string, string | string[]>,
    body: Buffer | undefined,
  ): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      let settled = false;
      let responded = false;
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(hard);
        reject(err);
      };

      const req = http.request({
        host: this.o.target.host,
        port: this.o.target.port,
        method,
        path,
        headers,
        agent: false,
        setHost: false,
      });
      entry.req = req;

      // Hard limit: connect + response headers within localTimeoutMs.
      const hard = setTimeout(() => {
        if (responded) return;
        req.destroy(new LocalError('local timeout', 'LOCAL_TIMEOUT'));
      }, this.o.localTimeoutMs);

      req.on('error', (err) => {
        if (responded) return; // mid-stream failures are handled on the response
        fail(err);
      });

      req.on('response', (res) => {
        responded = true;
        clearTimeout(hard);
        entry.res = res;
        if (entry.cancelled) {
          res.destroy();
          return fail(new LocalError('cancelled', 'CANCELLED'));
        }
        const outHeaders: HeaderMap = {};
        for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) outHeaders[k] = v;
        this.send({ type: 'http_response_start', id, status: res.statusCode ?? 502, headers: outHeaders });

        res.setTimeout(this.o.streamIdleMs, () => res.destroy(new LocalError('response stream idle', 'STREAM_IDLE')));
        res.on('data', (chunk: Buffer) => {
          if (entry.cancelled) return;
          this.send({ type: 'http_response_chunk', id, data: chunk.toString('base64') });
          this.applyBackpressure(res);
        });
        res.on('end', () => {
          if (!entry.cancelled) this.send({ type: 'http_response_end', id });
          if (!settled) {
            settled = true;
            resolve(res.statusCode ?? 502);
          }
        });
        res.on('error', (err) => {
          // Headers already went out: tell the relay the stream broke so it can abort the visitor.
          if (!entry.cancelled) this.send({ type: 'http_error', id, message: `local stream error: ${err.message}` });
          if (!settled) {
            settled = true;
            resolve(res.statusCode ?? 502);
          }
        });
      });

      // Streaming body counter: abort the local stream if the cap is crossed.
      if (body && body.length > 0) {
        let sent = 0;
        for (let off = 0; off < body.length; off += CHUNK) {
          const piece = body.subarray(off, off + CHUNK);
          sent += piece.length;
          if (sent > this.maxBodyBytes) {
            req.destroy();
            return fail(new LocalError(`slink: request body exceeds ${this.o.maxBodyMb} MB`, 'BODY_TOO_LARGE'));
          }
          req.write(piece);
        }
      }
      req.end();
    });
  }

  /** Pause the local response while the tunnel socket has too much unsent data. */
  private applyBackpressure(res: IncomingMessage): void {
    const ws = this.ws;
    if (!ws || ws.bufferedAmount < HIGH_WATER || res.isPaused()) return;
    res.pause();
    const check = setInterval(() => {
      if (!this.ws || this.ws !== ws || res.destroyed) {
        clearInterval(check);
        res.destroy();
        return;
      }
      if (ws.bufferedAmount < LOW_WATER) {
        clearInterval(check);
        res.resume();
      }
    }, 20);
  }

  // ─── WebSocket ────────────────────────────────────────────────────────────

  private closeStream(id: string, code: number, reason: string): void {
    const s = this.sockets.get(id);
    this.sockets.delete(id);
    s?.close(code, reason);
    this.send({ type: 'ws_close', id, code, reason });
  }

  private async handleWsOpen(f: Extract<RelayFrame, { type: 'ws_open' }>): Promise<void> {
    const started = Date.now();
    const log = (status: number | string) =>
      this.o.requestLog?.write({ leaseId: f.lease_id, method: 'WS', path: f.path, status, ms: Date.now() - started });
    const refuse = (message: string, status: number) => {
      this.send({ type: 'ws_error', id: f.id, message });
      log(status);
    };

    let url: string;
    try {
      url = targetWsUrl(this.o.target, f.path);
    } catch (err) {
      return refuse((err as GuardError).message, 400);
    }
    if (this.sockets.size + this.http.size >= this.o.maxConcurrent) return refuse('slink: too many concurrent streams', 503);
    if (!this.bucket.take()) return refuse('slink: local rate limit exceeded', 429);
    this.o.wake?.touch();

    const protoHeader = f.headers['sec-websocket-protocol'];
    const protocols = (Array.isArray(protoHeader) ? protoHeader.join(',') : (protoHeader ?? ''))
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    const headers = sanitizeHeaders(f.headers, this.o.target, { websocket: true });

    const open = (allowWake: boolean) => {
      const up = new WebSocket(url, protocols, {
        headers: headers as Record<string, string>,
        handshakeTimeout: this.o.localTimeoutMs,
        maxPayload: this.maxBodyBytes,
        perMessageDeflate: false,
      });
      let opened = false;
      this.sockets.set(f.id, up);
      up.on('open', () => {
        opened = true;
        this.send({ type: 'ws_opened', id: f.id });
        log(101);
      });
      up.on('message', (data, isBinary) => {
        const buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
        this.send({ type: 'ws_message', id: f.id, binary: isBinary, data: isBinary ? buf.toString('base64') : buf.toString('utf8') });
      });
      up.on('unexpected-response', (_req, res) => {
        this.sockets.delete(f.id);
        refuse(`local server answered the upgrade with HTTP ${res.statusCode}`, res.statusCode ?? 502);
        up.terminate();
      });
      up.on('close', (code, reason) => {
        if (!opened) return;
        if (this.sockets.get(f.id) === up) {
          this.sockets.delete(f.id);
          this.send({ type: 'ws_close', id: f.id, code, reason: reason.toString() });
        }
      });
      up.on('error', (err) => {
        if (opened || this.sockets.get(f.id) !== up) return;
        this.sockets.delete(f.id);
        if (allowWake && errCode(err) === 'ECONNREFUSED' && this.o.wake?.canWake) {
          this.o.wake
            .ensureAwake()
            .then(() => open(false))
            .catch((wakeErr: Error) => refuse(`wake failed: ${wakeErr.message}`, 502));
          return;
        }
        refuse(`local WebSocket error: ${err.message}`, 502);
      });
    };
    open(true);
  }
}
