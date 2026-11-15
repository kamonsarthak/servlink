import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { base64DecodedSize, GuardError, lockTarget, safePath, sanitizeHeaders, targetWsUrl, TokenBucket } from '../src/guard.js';
import { formatLogLine, sanitizeLogPath } from '../src/logs.js';
import { parseRelayFrame } from '../src/protocol.js';

describe('target lock', () => {
  it('accepts loopback and explicit private IPs', () => {
    assert.equal(lockTarget('127.0.0.1', 3000).authority, '127.0.0.1:3000');
    assert.equal(lockTarget('localhost', '8080').host, '127.0.0.1', 'localhost is pinned to 127.0.0.1 (no DNS)');
    assert.equal(lockTarget('::1', 5173).authority, '[::1]:5173');
    assert.equal(lockTarget('[::1]', 5173).host, '::1');
    for (const ip of ['10.0.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.20', 'fd12:3456::1']) {
      assert.doesNotThrow(() => lockTarget(ip, 80), ip);
    }
  });

  it('refuses public IPs, hostnames, link-local metadata and bad ports', () => {
    for (const host of ['8.8.8.8', '172.32.0.1', '169.254.169.254', '0.0.0.0', 'example.com', 'internal.corp', '::ffff:8.8.8.8', 'fe80::1', '2001:db8::1']) {
      assert.throws(() => lockTarget(host, 80), GuardError, host);
    }
    for (const port of [0, 65536, -1, 1.5, 'abc']) assert.throws(() => lockTarget('127.0.0.1', port as number), GuardError);
  });

  it('only accepts origin-form paths so frames can never pick a host', () => {
    assert.equal(safePath('/a/b?c=1'), '/a/b?c=1');
    for (const p of ['//evil.example/x', 'http://evil.example/', 'evil', '/a b', '/a\r\nHost: x', '\\\\evil', '/x\\..\\y', '']) {
      assert.throws(() => safePath(p), GuardError, JSON.stringify(p));
    }
    const t = lockTarget('127.0.0.1', 3000);
    assert.equal(targetWsUrl(t, '/@vite/client'), 'ws://127.0.0.1:3000/@vite/client');
    assert.throws(() => targetWsUrl(t, '//evil.example/x'), GuardError);
    assert.throws(() => targetWsUrl(t, '@evil.example/x'), GuardError);
  });
});

describe('header sanitisation', () => {
  it('strips forwarding headers, rewrites Host, marks the request verified', () => {
    const t = lockTarget('127.0.0.1', 3000);
    const h = sanitizeHeaders(
      {
        host: 'relay.example',
        'x-forwarded-for': '1.2.3.4',
        'X-Forwarded-Prefix': '/project/x',
        'x-real-ip': '1.2.3.4',
        forwarded: 'for=1.2.3.4',
        'x-servlink-verified': '0',
        connection: 'keep-alive',
        'transfer-encoding': 'chunked',
        cookie: 'a=1',
        accept: 'text/html',
        'bad header': 'x',
        'x-inject': 'a\r\nb',
      },
      t,
    );
    assert.deepEqual(h, { cookie: 'a=1', accept: 'text/html', host: '127.0.0.1:3000', 'x-servlink-verified': '1' });
    const ws = sanitizeHeaders({ 'sec-websocket-key': 'k', 'sec-websocket-protocol': 'vite-hmr', origin: 'https://relay.example' }, t, { websocket: true });
    assert.deepEqual(ws, { origin: 'https://relay.example', host: '127.0.0.1:3000', 'x-servlink-verified': '1' });
  });
});

describe('limits and logs', () => {
  it('token bucket bursts then refills at the configured rate', () => {
    const b = new TokenBucket(10, 3);
    const t0 = Date.now();
    assert.deepEqual([b.take(t0), b.take(t0), b.take(t0), b.take(t0)], [true, true, true, false]);
    assert.equal(b.take(t0 + 100), true, '100ms at 10/s refills one token');
    assert.equal(b.take(t0 + 100), false);
  });

  it('computes decoded base64 size without decoding', () => {
    for (const n of [0, 1, 2, 3, 4, 1000, 1001]) assert.equal(base64DecodedSize(Buffer.alloc(n).toString('base64')), n);
  });

  it('formats sanitized log lines with no query strings or control characters', () => {
    const line = formatLogLine({ leaseId: 'abc-123', method: 'GET', path: '/a?token=secret', status: 200, ms: 12.4, at: new Date('2026-01-01T00:00:00Z') });
    assert.equal(line, '[2026-01-01T00:00:00.000Z] [abc-123] GET /a?… -> 200 (12ms)');
    assert.equal(sanitizeLogPath('/x\n[fake] GET / -> 200'), '/x\\x0a[fake] GET / -> 200');
    assert.match(formatLogLine({ leaseId: 'bad lease\n', method: 'get', path: '/', status: 1, ms: 1 }), /\] \[-\] \? \/ -> 1/);
  });

  it('drops malformed relay frames', () => {
    for (const raw of ['nope', '[]', '{"type":"http_request"}', '{"type":"http_request","id":"../x","method":"GET","path":"/"}', '{"type":"challenge","nonce":"zz"}', '{"type":"mystery","id":"a"}']) {
      assert.equal(parseRelayFrame(raw), null, raw);
    }
    assert.ok(parseRelayFrame('{"type":"http_request","id":"a1","method":"GET","path":"/"}'));
  });
});
