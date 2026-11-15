import { existsSync, readFileSync, rmSync } from 'node:fs';
import { paths, writePrivate } from './paths.js';

export interface SavedConfig {
  host: string;
  port: number;
  relay: string;
  maxRps: number;
  maxBodyMb: number;
  wakeCmd?: string;
  sleepCmd?: string;
  idleMinutes?: number;
}

export const DEFAULTS = {
  host: '127.0.0.1',
  relay: 'wss://lapseed.app/tunnel',
  maxRps: 30,
  maxBodyMb: 5,
  idleMinutes: 15,
} as const;

export function loadConfig(): SavedConfig | null {
  try {
    return existsSync(paths.config) ? (JSON.parse(readFileSync(paths.config, 'utf8')) as SavedConfig) : null;
  } catch {
    return null;
  }
}

export function saveConfig(cfg: SavedConfig): void {
  writePrivate(paths.config, `${JSON.stringify(cfg, null, 2)}\n`);
}

export interface DaemonState {
  pid: number;
  started_at: string;
  node_id: string;
  relay: string;
  target: string;
  state: string;
  detail?: string;
  updated_at: string;
}

export function writeDaemonState(s: Omit<DaemonState, 'updated_at'>): void {
  writePrivate(paths.daemon, `${JSON.stringify({ ...s, updated_at: new Date().toISOString() }, null, 2)}\n`);
}

export function clearDaemonState(pid = process.pid): void {
  const s = readDaemonState();
  if (s && s.pid === pid) rmSync(paths.daemon, { force: true });
}

export function readDaemonState(): DaemonState | null {
  try {
    return existsSync(paths.daemon) ? (JSON.parse(readFileSync(paths.daemon, 'utf8')) as DaemonState) : null;
  } catch {
    return null;
  }
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** The running `slink connect` daemon, if any (stale state files are ignored). */
export function activeDaemon(): DaemonState | null {
  const s = readDaemonState();
  return s && isProcessAlive(s.pid) ? s : null;
}
