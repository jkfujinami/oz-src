import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import {
  NodeIdentity,
  NODE_ID_POW,
  NODE_ID_POW_FAST,
  PEER_ID_BYTES,
  CHALLENGE_BYTES,
  NODE_ID_POW_COUNTER_MAX,
  joinMessage,
  type NodeClaim,
  type NodeIdPowParams,
  type JoinBinding,
} from '../../src/crypto/NodeIdentity';
import { meetsDifficulty } from '../../src/crypto/PowPolicy';
import { Encoding } from '../../src/common/Encoding';

const FREE: NodeIdPowParams = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const P4: NodeIdPowParams = { difficulty: 4, opsLimit: 1, memLimit: 8192 };
const hex = (u: Uint8Array) => Encoding.toHex(u);
const enc = (s: string) => new TextEncoder().encode(s);
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => Array.from(x)));

const BINDING: JoinBinding = { verifierId: 'v'.repeat(32), signerFingerprint: 'sha-256 AA', verifierFingerprint: 'sha-256 BB' };

/** seed から決定的な鍵ペア */
function seeded(n: number) {
  return sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(n));
}

/** 先頭ゼロビット数 */
function leadingZeroBits(h: Uint8Array): number {
  let n = 0;
  for (const b of h) {
    if (b === 0) { n += 8; continue; }
    return n + Math.clz32(b) - 24;
  }
  return n;
}

let alice: NodeIdentity; // P4 で採掘済み (決定的な鍵)
let mallory: NodeIdentity;

beforeAll(async () => {
  await sodiumReady;
  const a = seeded(1);
  alice = NodeIdentity.fromKeyPair(a.publicKey, a.privateKey, NodeIdentity.solveNodeIdPow(a.publicKey, P4));
  const m = seeded(2);
  mallory = NodeIdentity.fromKeyPair(m.publicKey, m.privateKey, NodeIdentity.solveNodeIdPow(m.publicKey, P4));
});

describe('NodeIdentity: 定数とパラメータ', () => {
  it('既定の NodeId PoW は難易度 > 0、FAST は既定より軽い', () => {
    expect(NODE_ID_POW.difficulty).toBeGreaterThan(0);
    expect(NODE_ID_POW_FAST.difficulty).toBeLessThan(NODE_ID_POW.difficulty);
    expect(PEER_ID_BYTES).toBe(16);
    expect(CHALLENGE_BYTES).toBe(32);
  });
});

describe('NodeIdentity: peerId = H(pubkey) の束縛', () => {
  it('peerId は SHA256("OZ/v3/peerid" ‖ pubkey) の先頭 16 バイトの小文字 hex', () => {
    const want = hex(sodium.crypto_hash_sha256(cat(enc('OZ/v3/peerid'), alice.pubkey)).slice(0, 16));
    expect(alice.peerId).toBe(want);
    expect(NodeIdentity.derivePeerId(alice.pubkey)).toBe(want);
    expect(alice.peerId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('ドメイン分離: 素の SHA256(pubkey) とは一致しない', () => {
    expect(alice.peerId).not.toBe(hex(sodium.crypto_hash_sha256(alice.pubkey).slice(0, 16)));
  });

  it('position は peerId の純粋関数で [0,1) に収まる', () => {
    const idBytes = Encoding.fromHex(alice.peerId);
    const h = sodium.crypto_hash_sha256(cat(enc('OZ/v3/position'), idBytes));
    const want = Number(new DataView(h.buffer, h.byteOffset).getBigUint64(0, false)) / 2 ** 64;
    expect(alice.position).toBe(want);
    expect(NodeIdentity.derivePosition(alice.peerId)).toBe(alice.position);
    for (let i = 0; i < 50; i++) {
      const p = NodeIdentity.derivePosition(hex(sodium.randombytes_buf(16)));
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThan(1);
    }
  });

  it('別の鍵からは別の peerId / position になる', () => {
    expect(mallory.peerId).not.toBe(alice.peerId);
    expect(mallory.position).not.toBe(alice.position);
  });

  it('fromKeyPair は同じ鍵から同じ peerId / position を復元する', () => {
    const s = alice.exportSecret();
    const again = NodeIdentity.fromKeyPair(s.pubkey, s.privkey, s.powCounter);
    expect(again.peerId).toBe(alice.peerId);
    expect(again.position).toBe(alice.position);
    expect(again.powCounter).toBe(alice.powCounter);
  });
});

describe('NodeIdentity: 採掘と NodeId PoW', () => {
  it('difficulty 0 の採掘は counter 0 で、主張は検証を通る', async () => {
    const id = await NodeIdentity.mine(FREE);
    expect(id.powCounter).toBe(0);
    expect(NodeIdentity.verifyClaim(id.claim(), FREE)).toBe(true);
    expect(id.position).toBe(NodeIdentity.derivePosition(id.peerId));
  });

  it('difficulty > 0 で採掘した identity は PoW を満たし、検証を通る', async () => {
    const id = await NodeIdentity.mine(P4);
    expect(meetsDifficulty(NodeIdentity.nodeIdPowHash(id.pubkey, id.powCounter, P4), 4)).toBe(true);
    expect(NodeIdentity.verifyClaim(id.claim(), P4)).toBe(true);
  });

  it('solveNodeIdPow は最小の解を返す (それ未満の counter はすべて不合格)', () => {
    for (let c = 0; c < alice.powCounter; c++) {
      expect(NodeIdentity.verifyClaim({ ...alice.claim(), powCounter: c }, P4)).toBe(false);
    }
    expect(NodeIdentity.verifyClaim(alice.claim(), P4)).toBe(true);
  });

  it('PoW を満たさない counter は拒否する', () => {
    let bad = 0;
    while (meetsDifficulty(NodeIdentity.nodeIdPowHash(alice.pubkey, bad, P4), 4)) bad++;
    expect(NodeIdentity.verifyClaim({ ...alice.claim(), powCounter: bad }, P4)).toBe(false);
  });

  it('要求難易度を上げると、それを満たさない保存済みの解は拒否される', () => {
    const z = leadingZeroBits(NodeIdentity.nodeIdPowHash(alice.pubkey, alice.powCounter, P4));
    expect(z).toBeGreaterThanOrEqual(4);
    expect(NodeIdentity.verifyClaim(alice.claim(), { ...P4, difficulty: z })).toBe(true);
    expect(NodeIdentity.verifyClaim(alice.claim(), { ...P4, difficulty: z + 1 })).toBe(false);
  });

  it('NodeId PoW のハッシュは Argon2id パラメータ (ops/mem) と counter と pubkey に依存する', () => {
    const base = hex(NodeIdentity.nodeIdPowHash(alice.pubkey, 0, P4));
    expect(hex(NodeIdentity.nodeIdPowHash(alice.pubkey, 0, P4))).toBe(base);
    const variants = [
      NodeIdentity.nodeIdPowHash(alice.pubkey, 1, P4),
      NodeIdentity.nodeIdPowHash(mallory.pubkey, 0, P4),
      NodeIdentity.nodeIdPowHash(alice.pubkey, 0, { ...P4, memLimit: 16384 }),
      NodeIdentity.nodeIdPowHash(alice.pubkey, 0, { ...P4, opsLimit: 2 }),
    ].map(hex);
    expect(new Set([base, ...variants]).size).toBe(5);
  });

  it('NodeId PoW は Argon2id(pubkey ‖ u64be(counter), salt="OZ/v3/nodeid-pow")', () => {
    const counter = 3;
    const input = cat(alice.pubkey, Uint8Array.of(0, 0, 0, 0, 0, 0, 0, counter));
    const want = sodium.crypto_pwhash(32, input, enc('OZ/v3/nodeid-pow'), P4.opsLimit, P4.memLimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
    expect(hex(NodeIdentity.nodeIdPowHash(alice.pubkey, counter, P4))).toBe(hex(want));
  });

  it('difficulty 0 の検証では PoW を省き、束縛だけを確認する', () => {
    expect(NodeIdentity.verifyClaim({ ...alice.claim(), powCounter: 123456 }, FREE)).toBe(true);
  });
});

describe('NodeIdentity.verifyClaim: 改竄・詐称・不正な入力の拒否', () => {
  it('他人の pubkey に差し替えた主張 (peerId はそのまま) は拒否', () => {
    expect(NodeIdentity.verifyClaim({ ...alice.claim(), pubkey: mallory.pubkey }, FREE)).toBe(false);
  });

  it('他人の peerId を名乗る主張 (pubkey は自分) は拒否', () => {
    expect(NodeIdentity.verifyClaim({ ...mallory.claim(), peerId: alice.peerId }, FREE)).toBe(false);
  });

  it('pubkey を 1 ビットでも変えると拒否', () => {
    for (const i of [0, 15, 31]) {
      const pk = Uint8Array.from(alice.pubkey); pk[i] ^= 1;
      expect(NodeIdentity.verifyClaim({ ...alice.claim(), pubkey: pk }, FREE)).toBe(false);
    }
  });

  it('peerId を 1 文字でも変えると拒否', () => {
    const id = alice.peerId;
    const flipped = (id[0] === '0' ? '1' : '0') + id.slice(1);
    expect(NodeIdentity.verifyClaim({ ...alice.claim(), peerId: flipped }, FREE)).toBe(false);
  });

  it('peerId の表記揺れ (大文字・長さ違い・非 hex・型違い) は拒否', () => {
    const c = alice.claim();
    const bads: unknown[] = [
      c.peerId.toUpperCase(),
      c.peerId.slice(0, 31),
      c.peerId + '0',
      c.peerId.slice(0, 31) + 'g',
      ` ${c.peerId.slice(1)}`,
      '',
      123,
      null,
      Encoding.fromHex(c.peerId),
    ];
    for (const peerId of bads) {
      expect(NodeIdentity.verifyClaim({ ...c, peerId } as any, FREE), String(peerId)).toBe(false);
    }
  });

  it('pubkey の形の不正 (長さ・配列・Buffer 以外の型) は拒否', () => {
    const c = alice.claim();
    const bads: unknown[] = [
      c.pubkey.subarray(0, 31),
      cat(c.pubkey, Uint8Array.of(0)),
      Array.from(c.pubkey),
      { data: Array.from(c.pubkey) },
      hex(c.pubkey),
      null,
      undefined,
    ];
    for (const pubkey of bads) expect(NodeIdentity.verifyClaim({ ...c, pubkey } as any, FREE)).toBe(false);
  });

  it('powCounter の不正 (負・小数・NaN・Infinity・2^53 以上・文字列) は拒否', () => {
    const c = alice.claim();
    for (const powCounter of [-1, 1.5, NaN, Infinity, -Infinity, 2 ** 53, '0', null, undefined, 0n]) {
      expect(NodeIdentity.verifyClaim({ ...c, powCounter } as any, FREE), String(powCounter)).toBe(false);
    }
  });

  it('主張そのものが無い・空でも例外を投げず false', () => {
    expect(NodeIdentity.verifyClaim(null as any, FREE)).toBe(false);
    expect(NodeIdentity.verifyClaim(undefined as any, FREE)).toBe(false);
    expect(NodeIdentity.verifyClaim({} as NodeClaim, FREE)).toBe(false);
  });
});

describe('NodeIdentity: 所有証明つきの主張 (signClaim / verifySignedClaim)', () => {
  it('自分の challenge に対する正しい署名と PoW なら受理', () => {
    const c = NodeIdentity.newChallenge();
    expect(NodeIdentity.verifySignedClaim(alice.signClaim(c, BINDING), c, BINDING, P4)).toBe(true);
  });

  it('newChallenge は 32 バイトの乱数で毎回異なる', () => {
    const a = NodeIdentity.newChallenge();
    const b = NodeIdentity.newChallenge();
    expect(a).toHaveLength(CHALLENGE_BYTES);
    expect(hex(a)).not.toBe(hex(b));
  });

  it('別の challenge に対する署名の再生 (replay) は拒否', () => {
    const old = NodeIdentity.newChallenge();
    const replay = alice.signClaim(old, BINDING);
    const fresh = NodeIdentity.newChallenge();
    expect(NodeIdentity.verifySignedClaim(replay, fresh, BINDING, P4)).toBe(false);
    // ★ JOIN は challenge を運ばない: 検証は常に「自分が出した値」で行うので、相手が何を主張しても
    //   (echo の書き換えといった攻撃面は無い) 別の challenge への署名は通らない
    expect(Object.keys(replay)).not.toContain('challenge');
    expect(NodeIdentity.verifySignedClaim(replay, old, BINDING, P4)).toBe(true);
  });

  it('検証側の challenge が 32 バイトでなければ、一致していても拒否', () => {
    const short = new Uint8Array(16).fill(9);
    const forged = {
      ...alice.claim(),
      signature: sodium.crypto_sign_detached(joinMessage(short, alice.peerId, BINDING), alice.exportSecret().privkey),
    };
    expect(NodeIdentity.verifySignedClaim(forged, short, BINDING, P4)).toBe(false);
  });

  it('他人 (mallory) の鍵で署名して alice を名乗る主張は拒否', () => {
    const c = NodeIdentity.newChallenge();
    const sig = mallory.signClaim(c, BINDING).signature;
    // pubkey/peerId は alice、署名は mallory
    expect(NodeIdentity.verifySignedClaim({ ...alice.claim(), signature: sig }, c, BINDING, P4)).toBe(false);
  });

  it('自分の鍵で正しく署名しても、peerId を他人のものにすり替えると拒否 (束縛検査)', () => {
    const c = NodeIdentity.newChallenge();
    const secret = mallory.exportSecret();
    const claim = {
      peerId: alice.peerId,
      pubkey: mallory.pubkey,
      powCounter: mallory.powCounter,
      signature: sodium.crypto_sign_detached(joinMessage(c, alice.peerId, BINDING), secret.privkey),
    };
    expect(NodeIdentity.verifySignedClaim(claim, c, BINDING, P4)).toBe(false);
  });

  it('署名は正しくても NodeId PoW を満たさなければ拒否', () => {
    const c = NodeIdentity.newChallenge();
    let bad = 0;
    while (meetsDifficulty(NodeIdentity.nodeIdPowHash(alice.pubkey, bad, P4), 4)) bad++;
    const weak = NodeIdentity.fromKeyPair(alice.pubkey, alice.exportSecret().privkey, bad);
    expect(NodeIdentity.verifySignedClaim(weak.signClaim(c, BINDING), c, BINDING, P4)).toBe(false);
    expect(NodeIdentity.verifySignedClaim(weak.signClaim(c, BINDING), c, BINDING, FREE)).toBe(true);
  });

  it('署名・challenge のどの 1 ビットを反転しても拒否', () => {
    const c = NodeIdentity.newChallenge();
    const claim = alice.signClaim(c, BINDING);
    for (const i of [0, 31, 32, 63]) {
      const s = Uint8Array.from(claim.signature); s[i] ^= 1;
      expect(NodeIdentity.verifySignedClaim({ ...claim, signature: s }, c, BINDING, P4)).toBe(false);
    }
    // 検証側の challenge が 1 ビット違っても拒否
    const c2 = Uint8Array.from(c); c2[5] ^= 1;
    expect(NodeIdentity.verifySignedClaim(claim, c2, BINDING, P4)).toBe(false);
  });

  it('powCounter を書き換えた主張は (署名対象外でも) PoW 検査で拒否', () => {
    const c = NodeIdentity.newChallenge();
    const claim = alice.signClaim(c, BINDING);
    let bad = alice.powCounter + 1;
    while (meetsDifficulty(NodeIdentity.nodeIdPowHash(alice.pubkey, bad, P4), 4)) bad++;
    expect(NodeIdentity.verifySignedClaim({ ...claim, powCounter: bad }, c, BINDING, P4)).toBe(false);
  });

  it('署名・challenge の形が不正 (長さ・型・欠落) なら例外を投げず false', () => {
    const c = NodeIdentity.newChallenge();
    const claim = alice.signClaim(c, BINDING);
    const variants: any[] = [
      { ...claim, signature: claim.signature.subarray(0, 63) },
      { ...claim, signature: cat(claim.signature, Uint8Array.of(0)) },
      { ...claim, signature: Array.from(claim.signature) },
      { ...claim, signature: undefined },
      { ...claim, pubkey: claim.pubkey.subarray(0, 31) },
      { ...claim, pubkey: Array.from(claim.pubkey) },
      { ...claim, peerId: 42 },
      null,
      undefined,
      {},
    ];
    for (const v of variants) {
      expect(() => NodeIdentity.verifySignedClaim(v, c, BINDING, P4)).not.toThrow();
      expect(NodeIdentity.verifySignedClaim(v, c, BINDING, P4)).toBe(false);
    }
    // 検証側の期待値 (challenge) の形が不正でも例外を投げず false
    for (const bad of [c.subarray(0, 31), Array.from(c), undefined, null, new Uint8Array(0)] as any[]) {
      expect(() => NodeIdentity.verifySignedClaim(claim, bad, BINDING, P4)).not.toThrow();
      expect(NodeIdentity.verifySignedClaim(claim, bad, BINDING, P4)).toBe(false);
    }
  });

  it('powCounter が u32 の範囲 (0..0xFFFFFFFF) を外れる主張は、PoW を調べる前に拒否 (ワイヤで運べない値)', () => {
    const c = NodeIdentity.newChallenge();
    const claim = alice.signClaim(c, BINDING);
    for (const powCounter of [-1, 0x100000000, Number.MAX_SAFE_INTEGER]) {
      expect(NodeIdentity.verifySignedClaim({ ...claim, powCounter }, c, BINDING, FREE)).toBe(false);
      expect(NodeIdentity.verifyClaim({ ...alice.claim(), powCounter }, FREE)).toBe(false);
    }
    expect(NodeIdentity.verifyClaim({ ...alice.claim(), powCounter: 0xffffffff }, FREE)).toBe(true);
    expect(NODE_ID_POW_COUNTER_MAX).toBe(0xffffffff);
  });

  it('signClaim は固定長以外の challenge を拒否する (署名オラクル化の防止)', () => {
    for (const n of [0, 31, 33, 64]) {
      expect(() => alice.signClaim(new Uint8Array(n), BINDING)).toThrow(RangeError);
    }
  });

  it('signClaim の結果には秘密鍵が含まれない', () => {
    const claim = alice.signClaim(NodeIdentity.newChallenge(), BINDING) as any;
    expect(Object.keys(claim).sort()).toEqual(['peerId', 'powCounter', 'pubkey', 'signature']);
    expect(Object.keys(alice.claim()).sort()).toEqual(['peerId', 'powCounter', 'pubkey']);
  });
});

describe('NodeIdentity.joinMessage: 正準化', () => {
  const c = new Uint8Array(32).fill(1);

  it('"OZ/v4/join" ‖ challenge ‖ 長さ前置きの各フィールド', () => {
    const m = joinMessage(c, 'ab', { verifierId: 'x', signerFingerprint: 'fp1', verifierFingerprint: '' });
    const domain = enc('OZ/v4/join');
    expect(Array.from(m.subarray(0, domain.length))).toEqual(Array.from(domain));
    expect(Array.from(m.subarray(domain.length, domain.length + 32))).toEqual(Array.from(c));
    expect(Array.from(m.subarray(domain.length + 32))).toEqual([
      0, 1, 0x78, // verifierId "x"
      0, 2, 0x61, 0x62, // signerId "ab"
      0, 3, 0x66, 0x70, 0x31, // "fp1"
      0, 0, // ""
    ]);
  });

  it('フィールド境界をずらした入力は別のメッセージになる', () => {
    const a = joinMessage(c, 'ab', { verifierId: 'c', signerFingerprint: 'f', verifierFingerprint: 'g' });
    const b = joinMessage(c, 'a', { verifierId: 'c', signerFingerprint: 'bf', verifierFingerprint: 'g' });
    const d = joinMessage(c, 'ab', { verifierId: 'c', signerFingerprint: 'fg', verifierFingerprint: '' });
    expect(new Set([hex(a), hex(b), hex(d)]).size).toBe(3);
  });

  it('65535 バイトを超えるフィールドは拒否する', () => {
    expect(() => joinMessage(c, 'x'.repeat(0x10000), BINDING)).toThrow(RangeError);
    expect(() => joinMessage(c, 'x'.repeat(0xffff), BINDING)).not.toThrow();
  });

  it('巨大な binding で署名させようとしても signClaim は例外を投げる', () => {
    expect(() => alice.signClaim(c, { ...BINDING, verifierId: 'v'.repeat(0x10000) })).toThrow(RangeError);
  });
});
