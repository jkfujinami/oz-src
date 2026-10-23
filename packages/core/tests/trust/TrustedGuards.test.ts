import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import {
  createGuardString,
  parseGuardString,
  signGuardList,
  verifyGuardList,
  maintainerKeyId,
  GUARD_STRING_PREFIX,
  GUARD_LIST_PREFIX,
  TRUSTED_GUARD_LIMITS,
  type GuardListContent,
  type MaintainerKeySet,
} from '../../src/trust/TrustedGuards';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 9, 1);

const b64u = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);
const unb64u = (s: string) => sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);

describe('信頼 Guard: 運用者の申告 (Guard 文字列)', () => {
  let op: NodeIdentity;

  beforeAll(async () => {
    await sodiumReady;
    op = await NodeIdentity.mine(FAST);
  });

  it('運用者ノードの鍵で署名した文字列は検証を通る', () => {
    const s = createGuardString(op, NOW);
    expect(s.startsWith(GUARD_STRING_PREFIX)).toBe(true);
    const g = parseGuardString(s, FAST);
    expect(g?.peerId).toBe(op.peerId);
    expect(Array.from(g!.pubkey)).toEqual(Array.from(op.exportSecret().pubkey));
  });

  it('1 バイトでも改竄されたら拒否する', () => {
    const s = createGuardString(op, NOW);
    const raw = unb64u(s.slice(GUARD_STRING_PREFIX.length));
    raw[raw.length - 3] ^= 0x01;
    expect(parseGuardString(GUARD_STRING_PREFIX + b64u(raw), FAST)).toBeNull();
  });

  it('他人の peerId を自分の鍵で名乗る申告は拒否する (束縛の不一致)', async () => {
    const victim = await NodeIdentity.mine(FAST);
    const secret = op.exportSecret();
    const decl = [1, victim.peerId, secret.pubkey, secret.powCounter, NOW];
    const message = new Uint8Array([...new TextEncoder().encode('OZ/v1/guard-decl'), ...msgpackEncode(decl)]);
    const sig = sodium.crypto_sign_detached(message, secret.privkey);
    const forged = GUARD_STRING_PREFIX + b64u(msgpackEncode([...decl, sig]));
    expect(parseGuardString(forged, FAST)).toBeNull();
  });

  it('NodeId PoW を満たさない ID は拒否する', () => {
    const s = createGuardString(op, NOW);
    // 難易度を上げて検証すると、FAST で採掘した ID はまず通らない
    expect(parseGuardString(s, { difficulty: 24, opsLimit: 1, memLimit: 8192 })).toBeNull();
  });

  it('形式違い・別の接頭辞・長すぎる文字列は拒否する', () => {
    expect(parseGuardString('oz-guard:!!!', FAST)).toBeNull();
    expect(parseGuardString('something-else:abc', FAST)).toBeNull();
    expect(parseGuardString(GUARD_STRING_PREFIX + 'A'.repeat(5000), FAST)).toBeNull();
  });
});

describe('信頼 Guard: メンテナ署名つきリスト', () => {
  let guards: NodeIdentity[];
  let guardStrings: string[];
  let m1: { publicKey: Uint8Array; privateKey: Uint8Array };
  let m2: { publicKey: Uint8Array; privateKey: Uint8Array };
  let m3: { publicKey: Uint8Array; privateKey: Uint8Array };

  beforeAll(async () => {
    await sodiumReady;
    guards = await Promise.all([1, 2, 3].map(() => NodeIdentity.mine(FAST)));
    guardStrings = guards.map((g) => createGuardString(g, NOW));
    [m1, m2, m3] = [1, 2, 3].map(() => sodium.crypto_sign_keypair());
  });

  const content = (over: Partial<GuardListContent> = {}): GuardListContent => ({
    version: 3,
    issuedAt: NOW,
    expiresAt: NOW + 90 * DAY,
    guards: guardStrings,
    revoked: [],
    ...over,
  });
  const solo = (): MaintainerKeySet => ({ threshold: 1, keys: [m1.publicKey] });
  const verify = (text: string, keyset: MaintainerKeySet, opts: { now?: number; minVersion?: number } = {}) =>
    verifyGuardList(text, keyset, { now: NOW + DAY, powParams: FAST, ...opts });

  it('メンテナ 1 人 (1-of-1) の署名で受け入れ、Guard を返す', () => {
    const list = signGuardList(content(), m1.privateKey);
    expect(list.startsWith(GUARD_LIST_PREFIX)).toBe(true);
    const r = verify(list, solo());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.version).toBe(3);
    expect(r.guards.map((g) => g.peerId)).toEqual(guards.map((g) => g.peerId));
  });

  it('組み込まれていない鍵の署名は数えない', () => {
    const list = signGuardList(content(), m2.privateKey);
    const r = verify(list, solo());
    expect(r).toMatchObject({ ok: false, reason: 'insufficient-signatures' });
  });

  it('メンテナ鍵が組み込まれていなければ、どのリストも受け入れない', () => {
    const list = signGuardList(content(), m1.privateKey);
    expect(verify(list, { threshold: 1, keys: [] })).toMatchObject({ ok: false, reason: 'no-keyset' });
  });

  it('2-of-3 では署名 1 つでは足りず、2 つで受け入れる。同じ鍵の重複は 1 つと数える', () => {
    const keyset: MaintainerKeySet = { threshold: 2, keys: [m1.publicKey, m2.publicKey, m3.publicKey] };
    const one = signGuardList(content(), m1.privateKey);
    expect(verify(one, keyset)).toMatchObject({ ok: false, reason: 'insufficient-signatures' });

    const sameTwice = signGuardList(content(), m1.privateKey, one);
    expect(verify(sameTwice, keyset)).toMatchObject({ ok: false, reason: 'insufficient-signatures' });

    const two = signGuardList(content(), m2.privateKey, one);
    expect(verify(two, keyset).ok).toBe(true);
  });

  it('既存リストと中身の違うリストに署名を足そうとすると失敗する', () => {
    const one = signGuardList(content(), m1.privateKey);
    expect(() => signGuardList(content({ version: 4 }), m2.privateKey, one)).toThrow();
  });

  it('署名後に中身を書き換えたリストは拒否する', () => {
    const list = signGuardList(content(), m1.privateKey);
    // version を書き換えて詰め直す (署名はそのまま)
    const tampered = signGuardList(content({ version: 99 }), m2.privateKey);
    const raw = msgpackDecode(unb64u(tampered.slice(GUARD_LIST_PREFIX.length))) as any[];
    const original = msgpackDecode(unb64u(list.slice(GUARD_LIST_PREFIX.length))) as any[];
    raw[6] = original[6]; // 元のリストの m1 署名を移植
    const forged = GUARD_LIST_PREFIX + b64u(msgpackEncode(raw));
    expect(verify(forged, solo())).toMatchObject({ ok: false, reason: 'insufficient-signatures' });
  });

  it('手元より古い版は拒否し (巻き戻し防止)、同じ版の再取り込みは許す', () => {
    const list = signGuardList(content({ version: 3 }), m1.privateKey);
    expect(verify(list, solo(), { minVersion: 4 })).toMatchObject({ ok: false, reason: 'rollback' });
    expect(verify(list, solo(), { minVersion: 3 }).ok).toBe(true);
  });

  it('期限切れ・発行が未来すぎるリストは拒否する', () => {
    const list = signGuardList(content(), m1.privateKey);
    expect(verify(list, solo(), { now: NOW + 91 * DAY })).toMatchObject({ ok: false, reason: 'expired' });
    expect(verify(list, solo(), { now: NOW - DAY })).toMatchObject({ ok: false, reason: 'not-yet-valid' });
  });

  it('有効期間が長すぎるリストは作れない', () => {
    expect(() => signGuardList(content({ expiresAt: NOW + 400 * DAY }), m1.privateKey)).toThrow(RangeError);
  });

  it('不正な Guard 文字列が 1 つでも混ざったら、リスト全体を拒否する', () => {
    const bad = createGuardString(guards[0], NOW).slice(0, -4) + 'AAAA';
    const list = signGuardList(content({ guards: [...guardStrings, bad] }), m1.privateKey);
    expect(verify(list, solo())).toMatchObject({ ok: false, reason: 'bad-guard' });
  });

  it('同じ Guard の重複は拒否する', () => {
    const list = signGuardList(content({ guards: [guardStrings[0], guardStrings[0]] }), m1.privateKey);
    expect(verify(list, solo())).toMatchObject({ ok: false, reason: 'bad-guard' });
  });

  it('失効させた Guard は返さない', () => {
    const list = signGuardList(content({ revoked: [guards[1].peerId] }), m1.privateKey);
    const r = verify(list, solo());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.guards.map((g) => g.peerId)).toEqual([guards[0].peerId, guards[2].peerId]);
  });

  it('壊れた文字列・巨大な文字列は拒否する', () => {
    expect(verify('oz-guards:@@@', solo())).toMatchObject({ ok: false, reason: 'malformed' });
    expect(verify('hello', solo())).toMatchObject({ ok: false, reason: 'malformed' });
    expect(verify(GUARD_LIST_PREFIX + 'A'.repeat(TRUSTED_GUARD_LIMITS.MAX_STRING_LENGTH), solo()))
      .toMatchObject({ ok: false, reason: 'too-large' });
  });

  it('鍵 ID は公開鍵から一意に決まる', () => {
    expect(maintainerKeyId(m1.publicKey)).toMatch(/^[0-9a-f]{16}$/);
    expect(maintainerKeyId(m1.publicKey)).not.toBe(maintainerKeyId(m2.publicKey));
  });
});
