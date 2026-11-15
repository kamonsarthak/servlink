import { createPrivateKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { hostname } from 'node:os';
import { paths, writePrivate } from './paths.js';
import { NODE_ID_RE } from './protocol.js';

export interface Identity {
  version: 1;
  node_id: string;
  /** Raw 32-byte Ed25519 public key, hex. This is the form to register with a relay. */
  public_key_hex: string;
  public_key_base64: string;
  public_key_pem: string;
  private_key_pem: string;
  created_at: string;
}

export function defaultNodeId(): string {
  const host = hostname()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `${host || 'node'}-${randomBytes(4).toString('hex')}`;
}

export function createIdentity(nodeId: string = defaultNodeId()): Identity {
  if (!NODE_ID_RE.test(nodeId)) {
    throw new Error('node_id must be 3-128 chars: letters, digits, . _ : - (and start with a letter or digit)');
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'der', type: 'spki' })).subarray(-32);
  return {
    version: 1,
    node_id: nodeId,
    public_key_hex: raw.toString('hex'),
    public_key_base64: raw.toString('base64'),
    public_key_pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    private_key_pem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    created_at: new Date().toISOString(),
  };
}

export function saveIdentity(id: Identity): void {
  writePrivate(paths.identity, `${JSON.stringify(id, null, 2)}\n`);
}

export function loadIdentity(): Identity | null {
  if (!existsSync(paths.identity)) return null;
  const parsed = JSON.parse(readFileSync(paths.identity, 'utf8')) as Identity;
  if (!parsed.node_id || !parsed.private_key_pem || !parsed.public_key_hex) {
    throw new Error(`${paths.identity} is incomplete; re-run "slink init --force"`);
  }
  return parsed;
}

/** POSIX only: warn when the identity file is readable by group/others. */
export function identityPermissionWarning(): string | null {
  if (process.platform === 'win32' || !existsSync(paths.identity)) return null;
  const mode = statSync(paths.identity).mode & 0o777;
  return mode & 0o077 ? `${paths.identity} has mode ${mode.toString(8)}; run: chmod 600 ${paths.identity}` : null;
}

export function privateKeyOf(id: Identity): KeyObject {
  return createPrivateKey(id.private_key_pem);
}

/** Answer the relay's challenge: Ed25519 over the UTF-8 nonce string, base64-encoded. */
export function signChallenge(key: KeyObject, nonce: string): string {
  return sign(null, Buffer.from(nonce, 'utf8'), key).toString('base64');
}
