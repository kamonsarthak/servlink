import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { lockTarget } from '../src/guard.js';
import { createIdentity, privateKeyOf } from '../src/identity.js';
import { RequestLog } from '../src/logs.js';
import { SlinkTunnel, type TunnelOptions } from '../src/tunnel.js';
import { WakeManager } from '../src/wake.js';
import { freePort, MockRelay, sleep, startUpstream, until } from './helpers.js';

const home = mkdtempSync(join(tmpdir(), 'servlink-tunnel-'));
process.env.SERVLINK_HOME = home;

const identity = createIdentity('test-node-1');
const cleanups: (() => unknown)[] = [];
after(async () => {
  for (const fn of cleanups.reverse()) await fn();
  rmSync(home, { recursive: true, force: true });
});

async function setup(overrides: Partial<TunnelOptions> = {}, upstreamPort?: number) {
  const relay = await new MockRelay(identity.node_id, identity.public_key_hex).ready();
  const up = upstreamPort === undefined ? await startUpstream() : null;
  const tunnel = new SlinkTunnel({
    relay: relay.url,
    nodeId: identity.node_id,
    privateKey: privateKeyOf(identity),
    target: lockTarget('127.0.0.1', upstreamPort ?? up!.port),
    maxRps: 1000,
    maxBodyMb: 5,
    backoffBaseMs: 50,
    backoffMaxMs: 200,
    ...overrides,
  });
  tunnel.start();
  cleanups.push(() => tunnel.stop(), () => relay.close(), () => up?.close());
  await until(() => tunnel.currentState === 'online', 5000, 'tunnel online');
  return { relay, up, tunnel };
}

describe('slink tunnel', () => {
  it('authenticates with Ed25519 and streams HTTP responses', async () => {
    const { relay, up } = await setup();
    assert.equal(relay.authenticated, 1);
    const r = await relay.http({ path: '/stream' });
    assert.equal(r.status, 200);
    assert.equal(r.body, 'chunk0\nchunk1\nchunk2\n');
    assert.deepEqual(r.headers['set-cookie'], ['a=1; Path=/']);
    assert.ok(r.frames.some((f) => f.type === 'http_response_chunk'), 'response was streamed in chunks');
    assert.equal(up!.seen.length, 1);
  });

  it('rejects a wrong key at the relay', async () => {
    const relay = await new MockRelay('test-node-1', createIdentity('test-node-1').public_key_hex).ready();
    const t = new SlinkTunnel({ relay: relay.url, nodeId: identity.node_id, privateKey: privateKeyOf(identity), target: lockTarget('127.0.0.1', 1), maxRps: 10, maxBodyMb: 1, backoffBaseMs: 5000 });
    t.start();
    cleanups.push(() => t.stop(), () => relay.close());
    await until(() => relay.rejected === 1, 5000, 'rejection');
    assert.equal(relay.authenticated, 0);
    assert.notEqual(t.currentState, 'online');
  });

  it('sanitizes headers and rewrites Host before the local server sees them', async () => {
    const { relay, up } = await setup();
    const r = await relay.http({
      path: '/hello?x=1',
      headers: { host: 'relay.example', 'x-forwarded-for': '6.6.6.6', 'x-real-ip': '6.6.6.6', 'x-forwarded-prefix': '/project/x', cookie: 'app=1', 'user-agent': 'ua' },
    });
    assert.equal(r.status, 200);
    const h = up!.seen.at(-1)!.headers;
    assert.equal(h.host, `127.0.0.1:${up!.port}`);
    assert.equal(h['x-servlink-verified'], '1');
    assert.equal(h['x-forwarded-for'], undefined);
    assert.equal(h['x-real-ip'], undefined);
    assert.equal(h['x-forwarded-prefix'], undefined);
    assert.equal(h.cookie, 'app=1');
  });

  it('never lets a frame choose another host (SSRF lock)', async () => {
    const { relay, up } = await setup();
    for (const path of ['//evil.example/x', 'http://evil.example/', 'evil.example:80/x']) {
      const r = await relay.http({ path });
      assert.equal(r.status, 400, path);
      assert.equal(r.headers['x-servlink-guard'], '1');
    }
    relay.send({ type: 'ws_open', id: 'ws-evil', path: '//evil.example/socket', headers: {} });
    await until(() => relay.framesFor('ws-evil').length > 0);
    assert.equal(relay.framesFor('ws-evil')[0]!.type, 'ws_error');
    assert.equal(up!.seen.length, 0, 'nothing reached any server');
  });

  it('answers 429 locally once the rate limit is exhausted', async () => {
    const { relay, up } = await setup({ maxRps: 2 }); // burst 6
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => relay.http({ path: `/r${i}` })));
    const limited = results.filter((r) => r.status === 429);
    assert.ok(limited.length >= 5, `statuses: ${results.map((r) => r.status)}`);
    assert.ok(up!.seen.length <= 7, 'limited requests never hit the local server');
    assert.equal(limited[0]!.headers['retry-after'], '1');
  });

  it('answers 413 for oversized bodies without touching the local server', async () => {
    const { relay, up } = await setup({ maxBodyMb: 0.001 }); // ~1 KB
    const ok = await relay.http({ method: 'POST', path: '/echo', body: Buffer.from('small') });
    assert.equal(ok.body, 'small');
    const big = await relay.http({ method: 'POST', path: '/echo', body: Buffer.alloc(5000, 7) });
    assert.equal(big.status, 413);
    assert.equal(up!.seen.length, 1);
  });

  it('enforces the local timeout and survives refused connections', async () => {
    const { relay } = await setup({ localTimeoutMs: 300 });
    const slow = await relay.http({ path: '/slow' });
    assert.match(slow.error ?? '', /did not respond within 0\.3s/);

    const deadPort = await freePort();
    const dead = await setup({}, deadPort);
    const refused = await dead.relay.http({ path: '/' });
    assert.match(refused.error ?? '', /refused the connection/);
    assert.equal(dead.tunnel.currentState, 'online', 'refusal did not take the tunnel down');
  });

  it('drops malformed frames and keeps serving', async () => {
    const { relay, tunnel } = await setup();
    relay.send('not json at all');
    relay.send({ type: 'http_request' });
    relay.send({ type: 'http_request', id: 'x', method: 'get', path: '/' });
    relay.send({ type: 'ws_message', id: 'nope', data: 'x' });
    relay.send({ type: 'teleport', id: 'x' });
    relay.current!.send(Buffer.from([0, 1, 2]), { binary: true });
    await sleep(100);
    const bad = relay.framesFor('x');
    assert.equal(bad[0]?.status, 400, 'lower-case method rejected by the guard');
    const r = await relay.http({ path: '/still-alive' });
    assert.equal(r.status, 200);
    assert.equal(tunnel.currentState, 'online');
  });

  it('proxies WebSockets (e.g. Vite HMR)', async () => {
    const { relay } = await setup();
    relay.send({ type: 'ws_open', id: 'hmr1', path: '/@vite/client', headers: { 'sec-websocket-protocol': 'vite-hmr' } });
    await until(() => relay.framesFor('hmr1').some((f) => f.type === 'ws_opened'), 5000, 'ws_opened');
    relay.send({ type: 'ws_message', id: 'hmr1', data: 'ping', binary: false });
    await until(() => relay.framesFor('hmr1').some((f) => f.type === 'ws_message'), 5000, 'ws echo');
    assert.equal(relay.framesFor('hmr1').find((f) => f.type === 'ws_message')!.data, 'echo:ping');
  });

  it('wakes a sleeping service exactly once for concurrent requests', async () => {
    const port = await freePort();
    const counter = join(home, `wake-${randomBytes(4).toString('hex')}.txt`);
    const fixture = fileURLToPath(new URL('./fixtures/wake-server.mjs', import.meta.url));
    const target = lockTarget('127.0.0.1', port);
    const wake = new WakeManager({ target, wakeCmd: `node "${fixture}" ${port} "${counter}"` });
    const { relay } = await setup({ wake }, port);
    cleanups.push(() => {
      if (!existsSync(counter)) return;
      for (const pid of readFileSync(counter, 'utf8').split('\n').filter(Boolean)) {
        try {
          process.kill(Number(pid));
        } catch {
          /* already gone */
        }
      }
    });

    const results = await Promise.all(Array.from({ length: 5 }, (_, i) => relay.http({ path: `/w${i}` }, 15000)));
    assert.deepEqual(results.map((r) => r.status), [200, 200, 200, 200, 200], JSON.stringify(results.map((r) => r.error)));
    assert.equal(results[3]!.body, 'woken /w3');
    assert.equal(wake.wakeRuns, 1, 'mutex: one wake for five concurrent requests');
    assert.equal(readFileSync(counter, 'utf8').split('\n').filter(Boolean).length, 1);
  });

  it('reconnects with backoff after the relay drops, and stands down when superseded', async () => {
    const { relay, tunnel } = await setup();
    relay.current!.terminate();
    await until(() => relay.authenticated === 2 && tunnel.currentState === 'online', 5000, 'reconnect');
    assert.equal(tunnel.connections, 2);
    relay.current!.close(4409, 'superseded by a newer connection');
    await until(() => tunnel.currentState === 'stopped', 5000, 'stand down');
    await sleep(400);
    assert.equal(relay.authenticated, 2, 'no reconnect after 4409');
  });

  it('writes sanitized request logs with the lease id and no secrets', async () => {
    const log = new RequestLog(join(home, 'req-test.log'));
    const { relay } = await setup({ requestLog: log });
    await relay.http({ path: '/logged?token=supersecret', headers: { cookie: 'sid=topsecret' }, lease_id: 'lease-42' });
    const text = readFileSync(join(home, 'req-test.log'), 'utf8');
    assert.match(text, /^\[\d{4}-\d\d-\d\dT[\d:.]+Z\] \[lease-42\] GET \/logged\?… -> 200 \(\d+ms\)$/m);
    assert.doesNotMatch(text, /supersecret|topsecret|sid=/);
  });
});
