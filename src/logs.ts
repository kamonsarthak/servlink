import { appendFileSync, closeSync, existsSync, openSync, readSync, renameSync, rmSync, statSync } from 'node:fs';
import { ensureHome, paths } from './paths.js';

export interface RequestLogEntry {
  leaseId?: string | null;
  method: string;
  path: string;
  status: number | string;
  ms: number;
  at?: Date;
}

/**
 * Sanitise a path for logging: query strings are dropped (they routinely carry tokens),
 * control characters are escaped to prevent log injection, length is capped.
 */
export function sanitizeLogPath(path: string): string {
  const q = path.indexOf('?');
  const base = q === -1 ? path : `${path.slice(0, q)}?…`;
  const clean = base.replace(/[\u0000-\u001f\u007f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
  return clean.length > 512 ? `${clean.slice(0, 511)}…` : clean;
}

const LEASE_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** `[timestamp] [lease_id] METHOD /path -> STATUS (latency_ms)`. Bodies and cookies are never passed in. */
export function formatLogLine(e: RequestLogEntry): string {
  const lease = e.leaseId && LEASE_RE.test(e.leaseId) ? e.leaseId : '-';
  const method = /^[A-Z]{1,16}$/.test(e.method) ? e.method : '?';
  return `[${(e.at ?? new Date()).toISOString()}] [${lease}] ${method} ${sanitizeLogPath(e.path)} -> ${e.status} (${Math.max(0, Math.round(e.ms))}ms)`;
}

/** Append-only request log with size-based rotation (requests.log → .1 → .2 → .3). */
export class RequestLog {
  private size = 0;
  constructor(
    readonly file: string = paths.requestLog,
    private readonly maxBytes = 5 * 1024 * 1024,
    private readonly keep = 3,
  ) {
    ensureHome();
    this.size = existsSync(file) ? statSync(file).size : 0;
  }

  write(entry: RequestLogEntry): void {
    const line = `${formatLogLine(entry)}\n`;
    try {
      if (this.size + line.length > this.maxBytes) this.rotate();
      appendFileSync(this.file, line, { mode: 0o600 });
      this.size += Buffer.byteLength(line);
    } catch {
      /* logging must never take the tunnel down */
    }
  }

  private rotate(): void {
    for (let i = this.keep; i >= 1; i--) {
      const from = i === 1 ? this.file : `${this.file}.${i - 1}`;
      const to = `${this.file}.${i}`;
      if (!existsSync(from)) continue;
      if (existsSync(to)) rmSync(to);
      renameSync(from, to);
    }
    this.size = 0;
  }
}

/** Last `n` lines of a file (reads from the end in blocks; fine for multi-MB logs). */
export function tailLines(file: string, n: number): { lines: string[]; size: number } {
  if (!existsSync(file)) return { lines: [], size: 0 };
  const size = statSync(file).size;
  const fd = openSync(file, 'r');
  try {
    let pos = size;
    let text = '';
    const block = Buffer.alloc(64 * 1024);
    while (pos > 0 && text.split('\n').length <= n + 1) {
      const len = Math.min(block.length, pos);
      pos -= len;
      readSync(fd, block, 0, len, pos);
      text = block.subarray(0, len).toString('utf8') + text;
    }
    const lines = text.split('\n').filter(Boolean);
    return { lines: lines.slice(-n), size };
  } finally {
    closeSync(fd);
  }
}

/** Follow a log file, surviving rotation/truncation. Returns a stop function. */
export function followFile(file: string, fromOffset: number, onLine: (line: string) => void, intervalMs = 400): () => void {
  let offset = fromOffset;
  let carry = '';
  const timer = setInterval(() => {
    if (!existsSync(file)) return;
    const size = statSync(file).size;
    if (size < offset) offset = 0; // rotated or truncated
    if (size === offset) return;
    const fd = openSync(file, 'r');
    try {
      const buf = Buffer.alloc(size - offset);
      readSync(fd, buf, 0, buf.length, offset);
      offset = size;
      const parts = (carry + buf.toString('utf8')).split('\n');
      carry = parts.pop() ?? '';
      for (const line of parts) if (line) onLine(line);
    } finally {
      closeSync(fd);
    }
  }, intervalMs);
  return () => clearInterval(timer);
}
