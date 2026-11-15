import { chmodSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Root of slink's local state. `SERVLINK_HOME` overrides it (tests, multiple identities). */
export function servlinkHome(): string {
  return process.env.SERVLINK_HOME || join(homedir(), '.servlink');
}

export const paths = {
  get home() {
    return servlinkHome();
  },
  get identity() {
    return join(servlinkHome(), 'identity.json');
  },
  get config() {
    return join(servlinkHome(), 'config.json');
  },
  get daemon() {
    return join(servlinkHome(), 'daemon.json');
  },
  get logDir() {
    return join(servlinkHome(), 'logs');
  },
  get requestLog() {
    return join(servlinkHome(), 'logs', 'requests.log');
  },
  get wakeLog() {
    return join(servlinkHome(), 'logs', 'wake.log');
  },
};

export function ensureHome(): void {
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  mkdirSync(paths.logDir, { recursive: true, mode: 0o700 });
}

/** Atomically write a file readable only by the current user (0600). */
export function writePrivate(file: string, content: string): void {
  ensureHome();
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, content, { mode: 0o600 });
  try {
    chmodSync(tmp, 0o600);
  } catch {
    /* chmod is a no-op on some filesystems (e.g. Windows) */
  }
  renameSync(tmp, file);
}
