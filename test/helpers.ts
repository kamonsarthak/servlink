import { createPublicKey, randomBytes, verify } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createServer } from 'node:net';
import WebSocket, { WebSocketServer } from 'ws';

export type Frame = Record<string, any> & { type: string };

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until(cond: () => boolean, timeoutMs = 5000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await sleep(20);
  }
}

/**
 * Minimal Lapseed relay: issues the challenge, verifies the Ed25519 signature exactly like
 * the backend, then lets the test drive frames and collect replies by stream id.
 */
export class MockRelay {
  readonly wss: WebSocketServer;
  url = '';
  authenticated = 0;
  rejected = 0;
  current: WebSocket | null = null;
  private readonly replies = new Map<string, Frame[]>();

  constructor(private readonly nodeId: string, private readonly publicKeyHex: string) {
    this.wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    this.wss.on('connection', (ws) => this.onConnection(ws));
  }

  async ready(): Promise<this> {
    await new Promise<void>((r) => (this.wss.address() ? r() : this.wss.once('listening', () => r())));
    this.url = `ws://127.0.0.1:${(this.wss.address() as AddressInfo).port}/tunnel`;
    return this;
  }

  private onConnection(ws: WebSocket): void {
    const nonce = randomBytes(32).toString('hex');
    let authed = false;
    ws.on('message', (raw) => {
      const f = JSON.parse(raw.toString()) as Frame;
      if (!authed) {
        const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(this.publicKeyHex, 'hex')]), format: 'der', type: 'spki' });
        const ok =
          f.type === 'auth' &&
          f.node_id === this.nodeId &&
          verify(null, Buffer.from(nonce, 'utf8'), key, Buffer.from(String(f.signature), 'base64'));
        if (!ok) {
          this.rejected++;
          ws.send(JSON.stringify({ type: 'auth_error', reason: 'invalid node_id or signature' }));
          ws.close(4401, 'invalid node_id or signature');
          return;
        }
        authed = true;
        this.authenticated++;
        this.current = ws;
        ws.send(JSON.stringify({ type: 'auth_ok', node_id: f.node_id }));
        return;
      }
      if (typeof f.id === 'string') {
        const list = this.replies.get(f.id) ?? [];
        list.push(f);
        this.replies.set(f.id, list);
      }
    });
    ws.send(JSON.stringify({ type: 'challenge', nonce, server_time: Date.now() }));
  }

  send(frame: Frame | string): void {
    if (!this.current) throw new Error('no authenticated slink');
    this.current.send(typeof frame === 'string' ? frame : JSON.stringify(frame));
  }

  framesFor(id: string): Frame[] {
    return this.replies.get(id) ?? [];
  }

  /** Send an http_request and wait for the complete reply (single-shot, streamed, or error). */
  async http(req: { method?: string; path: string; headers?: Record<string, string>; body?: Buffer; lease_id?: string }, timeoutMs = 8000) {
    const id = randomBytes(8).toString('hex');
    this.send({
      type: 'http_request',
      id,
      method: req.method ?? 'GET',
      path: req.path,
      headers: req.headers ?? {},
      ...(req.body ? { body: req.body.toString('base64') } : {}),
      ...(req.lease_id ? { lease_id: req.lease_id } : {}),
    });
    await until(
      () => this.framesFor(id).some((f) => ['http_response', 'http_response_end', 'http_error'].includes(f.type)),
      timeoutMs,
      `reply to ${req.path}`,
    );
    const frames = this.framesFor(id);
    const err = frames.find((f) => f.type === 'http_error');
    const single = frames.find((f) => f.type === 'http_response');
    const start = frames.find((f) => f.type === 'http_response_start');
    const head = single ?? start;
    const body = single
      ? Buffer.from(single.body ?? '', 'base64')
      : Buffer.concat(frames.filter((f) => f.type === 'http_response_chunk').map((f) => Buffer.from(f.data, 'base64')));
    return { id, status: head?.status as number | undefined, headers: (head?.headers ?? {}) as Record<string, any>, body: body.toString(), error: err?.message as string | undefined, frames };
  }

  async close(): Promise<void> {
    for (const c of this.wss.clients) c.terminate();
    await new Promise((r) => this.wss.close(r));
  }
}

/** Local "developer app" that records what it receives. */
export async function startUpstream() {
  const seen: { method: string; url: string; headers: http.IncomingHttpHeaders }[] = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method!, url: req.url!, headers: req.headers });
    if (req.url === '/slow') return; // never answers
    if (req.url === '/stream') {
      res.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': ['a=1; Path=/'] });
      let i = 0;
      const t = setInterval(() => {
        res.write(`chunk${i}\n`);
        if (++i === 3) {
          clearInterval(t);
          res.end();
        }
      }, 10);
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/plain', 'x-path': req.url! });
      res.end(req.url === '/echo' ? Buffer.concat(chunks) : `hello ${req.url}`);
    });
  });
  const wss = new WebSocketServer({ server });
  wss.on('connection', (s, req) => {
    seen.push({ method: 'WS', url: req.url!, headers: req.headers });
    s.on('message', (m, binary) => s.send(binary ? m : `echo:${m.toString()}`));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    server,
    seen,
    port: (server.address() as AddressInfo).port,
    async close() {
      for (const c of wss.clients) c.terminate();
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
  };
}
