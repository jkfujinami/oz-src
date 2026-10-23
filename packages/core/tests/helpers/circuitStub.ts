import { vi } from 'vitest';
import sodium from '../../src/crypto/sodium';
import { OnionCircuit } from '../../src/network/onion/OnionCircuit';
import { OnionRouter, type OnionPayload } from '../../src/crypto/OnionRouter';
import { WireType } from '../../src/network/wire/WireTypes';

/**
 * OnionCircuit を単体で動かすための最小の代役 (Guard 1 人 + M1 候補 n 人)。
 * ネットワークは無く、Guard へ出たセルを `sent` に溜める。Guard / M1 の鍵を持っているので、
 * 「Guard から見える次ホップ」と「M1 で現れる断片」を実際に剥いて確かめられる。
 */
export interface CircuitStub {
  circuit: OnionCircuit;
  sent: Array<{ at: number; cell: Uint8Array }>;
  guard: { peerId: string; pubkey: Uint8Array; privkey: Uint8Array };
  middles: Array<{ peerId: string; pubkey: Uint8Array; privkey: Uint8Array }>;
  awaitEcho: ReturnType<typeof vi.fn>;
  /** Guard が剥いた層 (次ホップ) */
  nextHop(cell: Uint8Array): string;
  /** M1 が剥いた中身 */
  atM1(cell: Uint8Array): OnionPayload | null;
}

const hexId = (b: Uint8Array) => Buffer.from(b.subarray(0, 16)).toString('hex');

export function makeCircuitStub(opts: {
  middles?: number;
  circuitOptions?: Record<string, unknown>;
  echo?: (attempt: number) => boolean;
} = {}): CircuitStub {
  const kp = () => {
    const k = sodium.crypto_sign_keypair();
    return { peerId: hexId(sodium.randombytes_buf(16)), pubkey: k.publicKey, privkey: k.privateKey };
  };
  const guard = kp();
  const middles = Array.from({ length: opts.middles ?? 3 }, kp);
  const sent: CircuitStub['sent'] = [];
  const pm: any = {
    myPeerId: 'a'.repeat(32),
    peers: new Map(),
    verifiedPeersWithKeys: [{ peerId: guard.peerId, pubkey: guard.pubkey }],
    sendMessage: (_to: string, type: number, payload: any) => {
      if (type === WireType.ONION_STEM) sent.push({ at: Date.now(), cell: payload.onionBytes });
    },
  };
  let attempt = 0;
  const awaitEcho = vi.fn(async () => (opts.echo ? opts.echo(attempt++) : true));
  const dandelion: any = {
    onGuardChange: () => {},
    getPinnedGuard: () => ({ peerId: guard.peerId, pubkey: guard.pubkey }),
    getPinnedGuardId: () => guard.peerId,
    awaitEcho,
    notifyEcho: () => {},
  };
  const circuit = new OnionCircuit(pm, { register: () => {}, dispatch: () => {} } as any, dandelion, {
    coverIntervalMs: 5, relayDelayMs: 1, echoTimeoutMs: 200, readyWaitMs: 100, ...opts.circuitOptions,
  });
  for (const m of middles) {
    (circuit as any).guardNeighbors.set(m.peerId, { pubkey: m.pubkey, firstSeen: 0, seenAt: Date.now() });
  }
  return {
    circuit, sent, guard, middles, awaitEcho,
    nextHop: (cell) => {
      const l = OnionRouter.unwrap(cell, guard.pubkey, guard.privkey);
      if (l?.type !== 'relay') throw new Error('guard layer is not relay');
      return l.nextHop;
    },
    atM1: (cell) => {
      const l = OnionRouter.unwrap(cell, guard.pubkey, guard.privkey);
      if (l?.type !== 'relay') return null;
      const m = middles.find(x => x.peerId === l.nextHop)!;
      return OnionRouter.unwrap(OnionRouter.padCell(l.innerOnion), m.pubkey, m.privkey);
    },
  };
}
