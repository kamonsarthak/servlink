/**
 * Wake/sleep hooks for a local service that is not always running (a stopped container,
 * a dev server). Commands come only from the local operator (CLI flags / config file);
 * nothing received from the relay can influence what is executed.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { closeSync, openSync } from 'node:fs';
import { connect } from 'node:net';
import type { Target } from './guard.js';
import { ensureHome, paths } from './paths.js';

export function isPortOpen(target: Target, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host: target.host, port: target.port });
    const done = (ok: boolean) => {
      sock.removeAllListeners();
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

export async function waitForPort(target: Target, timeoutMs: number, intervalMs = 200): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isPortOpen(target, Math.min(1000, Math.max(50, deadline - Date.now())))) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

export interface WakeOptions {
  target: Target;
  wakeCmd?: string;
  sleepCmd?: string;
  idleMinutes?: number;
  /** How long to wait for the port after running the wake command (spec: 10s). */
  wakeTimeoutMs?: number;
  log?: (msg: string) => void;
}

function runShell(cmd: string): ChildProcess {
  ensureHome();
  const fd = openSync(paths.wakeLog, 'a', 0o600);
  try {
    return spawn(cmd, { shell: true, stdio: ['ignore', fd, fd], windowsHide: true, env: process.env });
  } finally {
    closeSync(fd);
  }
}

export class WakeManager {
  private waking: Promise<void> | null = null;
  private idleTimer: NodeJS.Timeout | null = null;
  private activeSinceSleep = false;
  private sleeping = false;
  /** Number of times the wake command has actually been spawned (observable for tests/status). */
  wakeRuns = 0;

  constructor(private readonly opts: WakeOptions) {}

  get canWake(): boolean {
    return Boolean(this.opts.wakeCmd);
  }

  /** Call on every proxied request: resets the idle-sleep countdown. */
  touch(): void {
    this.activeSinceSleep = true;
    if (!this.opts.sleepCmd) return;
    if (this.idleTimer) this.idleTimer.refresh();
    else {
      const ms = Math.max(1, this.opts.idleMinutes ?? 15) * 60_000;
      this.idleTimer = setTimeout(() => void this.sleep(), ms);
      this.idleTimer.unref();
    }
  }

  /**
   * Run the wake command once, however many requests hit a refused port at the same time
   * (they all await the same promise), then poll until the port accepts connections.
   */
  ensureAwake(): Promise<void> {
    if (!this.opts.wakeCmd) return Promise.reject(new Error('no wake command configured'));
    if (this.waking) return this.waking;
    this.waking = (async () => {
      if (await isPortOpen(this.opts.target, 500)) return;
      this.opts.log?.(`waking local service: ${this.opts.wakeCmd}`);
      this.wakeRuns++;
      const child = runShell(this.opts.wakeCmd!);
      let exitedBadly: number | null = null;
      child.once('exit', (code) => {
        if (code !== 0 && code !== null) exitedBadly = code;
      });
      child.once('error', () => {
        exitedBadly = -1;
      });
      child.unref();
      const deadline = Date.now() + (this.opts.wakeTimeoutMs ?? 10_000);
      while (Date.now() < deadline) {
        if (await isPortOpen(this.opts.target, 500)) {
          this.sleeping = false;
          this.opts.log?.('local service is up');
          return;
        }
        if (exitedBadly !== null) throw new Error(`wake command exited with code ${exitedBadly}`);
        await new Promise((r) => setTimeout(r, 200));
      }
      throw new Error(`local service did not open ${this.opts.target.authority} within ${(this.opts.wakeTimeoutMs ?? 10_000) / 1000}s of waking`);
    })().finally(() => {
      this.waking = null;
    });
    return this.waking;
  }

  private async sleep(): Promise<void> {
    this.idleTimer = null;
    if (!this.opts.sleepCmd || !this.activeSinceSleep || this.sleeping || this.waking) return;
    this.activeSinceSleep = false;
    this.sleeping = true;
    this.opts.log?.(`idle for ${this.opts.idleMinutes ?? 15}m, running sleep command: ${this.opts.sleepCmd}`);
    await new Promise<void>((resolve) => {
      const child = runShell(this.opts.sleepCmd!);
      const kill = setTimeout(() => child.kill(), 60_000);
      child.once('exit', () => {
        clearTimeout(kill);
        resolve();
      });
      child.once('error', () => {
        clearTimeout(kill);
        resolve();
      });
    });
  }

  stop(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
  }
}
