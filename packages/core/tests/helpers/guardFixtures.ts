import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import {
  createGuardString,
  signGuardList,
  type GuardListContent,
  type MaintainerKeySet,
} from '../../src/trust/TrustedGuards';
import type { GuardStore } from '../../src/trust/GuardManager';

export const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
export const DAY = 24 * 60 * 60 * 1000;
export const NOW = Date.UTC(2026, 9, 1);

export interface Maintainer {
  keyset: MaintainerKeySet;
  secretKey: Uint8Array;
}

export async function makeMaintainer(): Promise<Maintainer> {
  await sodiumReady;
  const kp = sodium.crypto_sign_keypair();
  return { keyset: { threshold: 1, keys: [kp.publicKey] }, secretKey: kp.privateKey };
}

/** 信頼リストを署名して文字列にする */
export function makeList(
  m: Maintainer,
  guards: NodeIdentity[],
  opts: { version?: number; now?: number; validityMs?: number; revoked?: NodeIdentity[] } = {},
): string {
  const now = opts.now ?? NOW;
  const content: GuardListContent = {
    version: opts.version ?? 1,
    issuedAt: now - 1000,
    expiresAt: now + (opts.validityMs ?? 30 * DAY),
    guards: guards.map(g => createGuardString(g, now)),
    revoked: (opts.revoked ?? []).map(g => g.peerId),
  };
  return signGuardList(content, m.secretKey);
}

export async function mineIdentities(n: number): Promise<NodeIdentity[]> {
  return Promise.all(Array.from({ length: n }, () => NodeIdentity.mine(FAST)));
}

/** メモリ上の保存先。`data` を直接のぞける */
export class MemoryStore implements GuardStore {
  public data = new Map<string, unknown>();
  async get(name: string) {
    const v = this.data.get(name);
    return v === undefined ? undefined : structuredClone(v);
  }
  async set(name: string, value: unknown) {
    this.data.set(name, structuredClone(value));
  }
}
