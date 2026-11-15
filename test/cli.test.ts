import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MockRelay, startUpstream, until } from './helpers.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const home = mkdtempSync(join(tmpdir(), 'servlink-cli-'));
const env = { ...process.env, SERVLINK_HOME: home, NO_COLOR: '1' };

function slink(...args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8', input: '' });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

let daemon: ChildProcess | null = null;
after(() => {
  daemon?.kill();
  rmSync(home, { recursive: true, force: true });
});

before(() => {
  assert.ok(existsSync(CLI), 'run `npm run build` first (dist/cli.js missing)');
});

describe('slink CLI (compiled dist/cli.js)', () => {
  let nodeId = '';
  let publicKey = '';

  it('init creates a 0600 identity and prints what Lapseed needs', () => {
    const r = slink('init', '--node-id', 'cli-test-node');
    assert.equal(r.code, 0, r.out);
    const id = JSON.parse(readFileSync(join(home, 'identity.json'), 'utf8'));
    nodeId = id.node_id;
    publicKey = id.public_key_hex;
    assert.equal(nodeId, 'cli-test-node');
    assert.match(publicKey, /^[0-9a-f]{64}$/);
    assert.ok(r.out.includes(nodeId) && r.out.includes(publicKey));
    assert.match(r.out, /PUT https:\/\/lapseed\.com\/api\/users\/server/);
    if (process.platform !== 'win32') assert.equal(statSync(join(home, 'identity.json')).mode & 0o777, 0o600);

    const again = slink('init');
    assert.equal(again.code, 1);
    assert.match(again.out, /already exists/);
    assert.equal(slink('init', '--node-id', 'x').code, 1, 'invalid node id rejected');
  });

  it('refuses non-loopback/non-private targets and missing ports', () => {
    const pub = slink('connect', '--port', '3000', '--host', '8.8.8.8');
    assert.equal(pub.code, 1);
    assert.match(pub.out, /Refusing 8\.8\.8\.8/);
    const named = slink('connect', '--port', '3000', '--host', 'example.com');
    assert.match(named.out, /Refusing hostname/);
    const noPort = slink('connect');
    assert.equal(noPort.code, 1);
    assert.match(noPort.out, /--port <number> is required/);
  });

  it('status reports identity and an idle daemon', () => {
    const r = slink('status');
    assert.equal(r.code, 0);
    assert.match(r.out, /node_id\s+cli-test-node/);
    assert.match(r.out, /not running/);
  });

  it('connect runs a real tunnel; status and logs reflect it', async () => {
    const relay = await new MockRelay(nodeId, publicKey).ready();
    const up = await startUpstream();
    let stdout = '';
    daemon = spawn(process.execPath, [CLI, 'connect', '--port', String(up.port), '--relay', relay.url, '--max-rps', '50'], { env });
    daemon.stdout!.on('data', (d) => (stdout += d));
    daemon.stderr!.on('data', (d) => (stdout += d));
    try {
      await until(() => stdout.includes('ONLINE'), 15000, `slink ONLINE (output: ${stdout})`);
      assert.match(stdout, new RegExp(`target\\s+http://127\\.0\\.0\\.1:${up.port} \\(locked\\)`));

      const r = await relay.http({ path: '/from-cli?secret=1', headers: { cookie: 'session=abc' }, lease_id: 'lease-cli' });
      assert.equal(r.status, 200);
      assert.equal(r.body, 'hello /from-cli?secret=1');

      const status = slink('status');
      assert.match(status.out, /running · ONLINE/);
      assert.match(status.out, new RegExp(`target\\s+127\\.0\\.0\\.1:${up.port}`));

      const second = slink('connect', '--port', String(up.port), '--relay', relay.url);
      assert.equal(second.code, 1);
      assert.match(second.out, /already running/);

      const logs = slink('logs', '--no-follow', '-n', '5');
      assert.match(logs.out, /\[lease-cli\] GET \/from-cli\?… -> 200 \(\d+ms\)/);
      assert.doesNotMatch(logs.out, /secret=1|session=abc/);
    } finally {
      daemon.kill();
      await new Promise((r) => daemon!.once('exit', r));
      daemon = null;
      await relay.close();
      await up.close();
    }
    assert.match(slink('status').out, /not running/);
  });
});
