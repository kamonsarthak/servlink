#!/usr/bin/env node
/**
 * slink — connect a local port to Lapseed through an outbound, Ed25519-authenticated tunnel.
 *
 *   slink init [--node-id <id>] [--force]
 *   slink connect --port <n> [--host 127.0.0.1] [--relay wss://lapseed.app/tunnel]
 *                 [--max-rps 30] [--max-body-mb 5] [--wake-cmd "<cmd>"] [--sleep-cmd "<cmd>"] [--idle-minutes 15]
 *   slink status
 *   slink logs [-n 50] [--no-follow]
 */
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { GuardError, lockTarget } from './guard.js';
import { createIdentity, identityPermissionWarning, loadIdentity, privateKeyOf, saveIdentity } from './identity.js';
import { followFile, RequestLog, tailLines } from './logs.js';
import { paths } from './paths.js';
import { activeDaemon, clearDaemonState, DEFAULTS, loadConfig, saveConfig, writeDaemonState, type SavedConfig } from './state.js';
import { SlinkTunnel, type TunnelState } from './tunnel.js';
import { WakeManager } from './wake.js';

const VERSION = '1.0.0';

const color = process.stdout.isTTY === true && !process.env.NO_COLOR;
const paint = (code: string) => (s: string | number) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { green: paint('38;2;16;185;129'), orange: paint('38;2;255;77;0'), dim: paint('2'), bold: paint('1') };

function out(msg = ''): void {
  process.stdout.write(`${msg}\n`);
}

function fail(msg: string): never {
  process.stderr.write(`${c.orange('✗')} ${msg}\n`);
  process.exit(1);
}

function stamp(): string {
  return c.dim(new Date().toISOString().slice(11, 19));
}

// ─── init ─────────────────────────────────────────────────────────────────

function cmdInit(argv: string[]): void {
  const { values } = parseArgs({ args: argv, options: { 'node-id': { type: 'string' }, force: { type: 'boolean', default: false } } });
  const existing = loadIdentity();
  if (existing && !values.force) {
    fail(`An identity already exists for node ${c.bold(existing.node_id)} (${paths.identity}). Use --force to replace it.`);
  }
  let id;
  try {
    id = createIdentity(values['node-id']);
  } catch (err) {
    fail((err as Error).message);
  }
  saveIdentity(id);
  out(`${c.green('~>')} ${c.bold('slink identity created')} ${c.dim(`(${paths.identity}, mode 0600)`)}`);
  out();
  out(`  ${c.dim('node_id   ')} ${c.bold(id.node_id)}`);
  out(`  ${c.dim('public_key')} ${c.bold(id.public_key_hex)}`);
  out(`  ${c.dim('  base64  ')} ${id.public_key_base64}`);
  out();
  out(`${c.orange('Next:')} paste both values into ${c.bold('Lapseed → Settings → Server')},`);
  out(`or call ${c.dim('PUT https://lapseed.com/api/users/server')} with:`);
  out(c.dim(`  {"node_id":"${id.node_id}","public_key":"${id.public_key_hex}"}`));
  out(`then run ${c.green('slink connect --port <your-app-port>')}.`);
  out(c.dim('PEM form of the public key, if you need it:'));
  out(c.dim(id.public_key_pem.trim()));
}

// ─── connect ──────────────────────────────────────────────────────────────

function num(name: string, v: string | undefined, min: number, max: number): number | undefined {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) fail(`--${name} must be a number between ${min} and ${max}`);
  return n;
}

async function ask(rl: ReturnType<typeof createInterface>, q: string, def?: string | number): Promise<string> {
  const answer = (await rl.question(`${c.green('?')} ${q}${def !== undefined ? c.dim(` (${def})`) : ''}: `)).trim();
  return answer || (def !== undefined ? String(def) : '');
}

async function resolveConnectConfig(argv: string[]): Promise<{ cfg: SavedConfig; force: boolean }> {
  const { values } = parseArgs({
    args: argv,
    options: {
      port: { type: 'string', short: 'p' },
      host: { type: 'string' },
      relay: { type: 'string' },
      'max-rps': { type: 'string' },
      'max-body-mb': { type: 'string' },
      'wake-cmd': { type: 'string' },
      'sleep-cmd': { type: 'string' },
      'idle-minutes': { type: 'string' },
      force: { type: 'boolean', default: false },
    },
  });
  const saved = loadConfig();
  let port = num('port', values.port, 1, 65535);
  let host = values.host;
  let relay = values.relay;

  if (port === undefined) {
    if (process.stdin.isTTY) {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        port = num('port', await ask(rl, 'Local port to expose', saved?.port), 1, 65535);
        host = host ?? (await ask(rl, 'Local host (loopback or private IP)', saved?.host ?? DEFAULTS.host));
        relay = relay ?? (await ask(rl, 'Relay', saved?.relay ?? DEFAULTS.relay));
      } finally {
        rl.close();
      }
    } else if (saved) {
      port = saved.port;
    }
  }
  if (port === undefined) fail('--port <number> is required (no saved config and no interactive terminal)');

  const cfg: SavedConfig = {
    port,
    host: host ?? saved?.host ?? DEFAULTS.host,
    relay: relay ?? saved?.relay ?? DEFAULTS.relay,
    maxRps: num('max-rps', values['max-rps'], 1, 10_000) ?? saved?.maxRps ?? DEFAULTS.maxRps,
    maxBodyMb: num('max-body-mb', values['max-body-mb'], 0.001, 1024) ?? saved?.maxBodyMb ?? DEFAULTS.maxBodyMb,
    wakeCmd: values['wake-cmd'] ?? saved?.wakeCmd,
    sleepCmd: values['sleep-cmd'] ?? saved?.sleepCmd,
    idleMinutes: num('idle-minutes', values['idle-minutes'], 1, 10_080) ?? saved?.idleMinutes ?? DEFAULTS.idleMinutes,
  };
  if (!/^wss?:\/\//i.test(cfg.relay)) fail('--relay must be a ws:// or wss:// URL');
  return { cfg, force: values.force ?? false };
}

async function cmdConnect(argv: string[]): Promise<void> {
  const identity = loadIdentity();
  if (!identity) fail(`No identity yet. Run ${c.green('slink init')} first.`);
  const permWarning = identityPermissionWarning();
  if (permWarning) out(`${c.orange('!')} ${permWarning}`);

  const { cfg, force } = await resolveConnectConfig(argv);
  let target;
  try {
    target = lockTarget(cfg.host, cfg.port);
  } catch (err) {
    fail(err instanceof GuardError ? err.message : String(err));
  }
  const running = activeDaemon();
  if (running && running.pid !== process.pid && !force) {
    fail(`slink is already running (pid ${running.pid}, ${running.target}). Stop it first or pass --force.`);
  }
  saveConfig(cfg);

  // Error boundary: a misbehaving local service or malformed frame must never kill the tunnel.
  process.on('uncaughtException', (err) => out(`${stamp()} ${c.orange('error')} ${err.message}`));
  process.on('unhandledRejection', (err) => out(`${stamp()} ${c.orange('error')} ${(err as Error)?.message ?? String(err)}`));

  const startedAt = new Date().toISOString();
  const persist = (state: TunnelState, detail?: string) => {
    try {
      writeDaemonState({ pid: process.pid, started_at: startedAt, node_id: identity.node_id, relay: cfg.relay, target: target.authority, state, detail });
    } catch {
      /* status file is best-effort */
    }
  };
  persist('connecting');

  const log = (msg: string) => out(`${stamp()} ${c.dim(msg)}`);
  const wake = cfg.wakeCmd || cfg.sleepCmd ? new WakeManager({ target, wakeCmd: cfg.wakeCmd, sleepCmd: cfg.sleepCmd, idleMinutes: cfg.idleMinutes, log }) : undefined;

  out(`${c.green('~>')} ${c.bold('slink')} ${c.dim(`v${VERSION}`)}`);
  out(`  ${c.dim('node  ')} ${identity.node_id}`);
  out(`  ${c.dim('relay ')} ${cfg.relay}`);
  out(`  ${c.dim('target')} http://${target.authority} ${c.dim('(locked)')}`);
  out(`  ${c.dim('limits')} ${cfg.maxRps} req/s · ${cfg.maxBodyMb} MB body · 15s local timeout`);
  if (cfg.wakeCmd) out(`  ${c.dim('wake  ')} ${cfg.wakeCmd}`);
  if (cfg.sleepCmd) out(`  ${c.dim('sleep ')} ${cfg.sleepCmd} ${c.dim(`after ${cfg.idleMinutes}m idle`)}`);
  out(`  ${c.dim('logs  ')} ${paths.requestLog} ${c.dim('(slink logs)')}`);
  out();

  const tunnel = new SlinkTunnel({
    relay: cfg.relay,
    nodeId: identity.node_id,
    privateKey: privateKeyOf(identity),
    target,
    maxRps: cfg.maxRps,
    maxBodyMb: cfg.maxBodyMb,
    wake,
    requestLog: new RequestLog(),
    log,
    onState: (state, detail) => {
      persist(state, detail);
      const label =
        state === 'online' ? c.green('● ONLINE') : state === 'stopped' ? c.orange('■ stopped') : c.dim(`○ ${state}`);
      out(`${stamp()} ${label}${detail ? c.dim(`  ${detail}`) : ''}`);
      if (state === 'stopped' && detail) shutdown(1);
    },
  });

  let exiting = false;
  function shutdown(code = 0): void {
    if (exiting) return;
    exiting = true;
    tunnel.stop();
    wake?.stop();
    clearDaemonState();
    setTimeout(() => process.exit(code), 100).unref();
  }
  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
  process.on('exit', () => clearDaemonState());

  tunnel.start();
}

// ─── status / logs ────────────────────────────────────────────────────────

function cmdStatus(): void {
  const id = loadIdentity();
  const cfg = loadConfig();
  const d = activeDaemon();
  out(`${c.green('~>')} ${c.bold('slink status')}`);
  out(`  ${c.dim('home      ')} ${paths.home}`);
  if (!id) {
    out(`  ${c.dim('identity  ')} ${c.orange('none')} ${c.dim('(run slink init)')}`);
  } else {
    out(`  ${c.dim('node_id   ')} ${c.bold(id.node_id)}`);
    out(`  ${c.dim('public_key')} ${id.public_key_hex}`);
  }
  if (cfg) {
    out(`  ${c.dim('target    ')} ${cfg.host}:${cfg.port}`);
    out(`  ${c.dim('relay     ')} ${cfg.relay}`);
    out(`  ${c.dim('limits    ')} ${cfg.maxRps} req/s · ${cfg.maxBodyMb} MB body`);
    if (cfg.wakeCmd) out(`  ${c.dim('wake      ')} ${cfg.wakeCmd}`);
    if (cfg.sleepCmd) out(`  ${c.dim('sleep     ')} ${cfg.sleepCmd} (after ${cfg.idleMinutes}m idle)`);
  } else {
    out(`  ${c.dim('target    ')} ${c.dim('not configured (slink connect --port <n>)')}`);
  }
  if (d) {
    const label = d.state === 'online' ? c.green('● running · ONLINE') : c.orange(`● running · ${d.state}`);
    out(`  ${c.dim('daemon    ')} ${label} ${c.dim(`pid ${d.pid} since ${d.started_at}`)}`);
    if (d.detail && d.state !== 'online') out(`  ${c.dim('            ')}${c.dim(d.detail)}`);
  } else {
    out(`  ${c.dim('daemon    ')} ${c.dim('○ not running')}`);
  }
}

function cmdLogs(argv: string[]): void {
  const { values } = parseArgs({
    args: argv,
    options: { lines: { type: 'string', short: 'n', default: '50' }, 'no-follow': { type: 'boolean', default: false } },
  });
  const n = Math.max(0, Math.min(10_000, Number(values.lines) || 50));
  const { lines, size } = tailLines(paths.requestLog, n);
  for (const l of lines) out(l);
  if (values['no-follow']) {
    if (lines.length === 0) out(c.dim(`no requests logged yet (${paths.requestLog})`));
    return;
  }
  out(c.dim(`— following ${paths.requestLog} (Ctrl+C to stop)`));
  const stop = followFile(paths.requestLog, size, (line) => out(line));
  process.on('SIGINT', () => {
    stop();
    process.exit(0);
  });
}

function help(): void {
  out(`${c.green('~>')} ${c.bold('slink')} ${c.dim(`v${VERSION}`)}  ${c.dim('servlink: expose a local port to Lapseed')}

  ${c.green('slink init')} [--node-id <id>] [--force]      create ~/.servlink/identity.json (Ed25519)
  ${c.green('slink connect')} --port <n> [options]          open the tunnel (prompts when flags are omitted)
      --host <ip>          127.0.0.1 | ::1 | localhost | explicit private IP   (default 127.0.0.1)
      --relay <wss_url>    default wss://lapseed.app/tunnel
      --max-rps <n>        local rate limit, default 30 (burst 3×)
      --max-body-mb <n>    local request body cap, default 5
      --wake-cmd "<cmd>"   run when the port refuses connections, then wait up to 10s
      --sleep-cmd "<cmd>"  run after --idle-minutes <n> (default 15) without traffic
      --force              start even if another slink daemon is running
  ${c.green('slink status')}                                 identity, saved target, daemon state
  ${c.green('slink logs')} [-n 50] [--no-follow]             tail sanitized request logs

${c.dim('Env: SERVLINK_HOME (default ~/.servlink), NO_COLOR')}`);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'init':
      return cmdInit(rest);
    case 'connect':
    case 'up':
      return cmdConnect(rest);
    case 'status':
      return cmdStatus();
    case 'logs':
      return cmdLogs(rest);
    case '--version':
    case '-v':
    case 'version':
      return out(VERSION);
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      return help();
    default:
      fail(`Unknown command "${cmd}". Run slink help.`);
  }
}

main().catch((err: unknown) => fail(err instanceof Error ? err.message : String(err)));
