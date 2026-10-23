import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';

import { guardTrustFromEnv, parseMaintainerKeySet } from '../src/lib/guardSetting';
import { describeGuardStatus, importFailureText } from '../src/lib/guardStatus';

/** ビルド時の環境変数の書式 (base64url、パディングなし) で公開鍵を作る */
function encodeKey(pk: Uint8Array): string {
  return sodium.to_base64(pk, sodium.base64_variants.URLSAFE_NO_PADDING);
}

describe('環境変数からの信頼設定', () => {
  it('鍵が未設定なら信頼設定なし (オープン動作)', () => {
    expect(guardTrustFromEnv({})).toBeNull();
    expect(guardTrustFromEnv({ maintainerKeys: '   ' })).toBeNull();
  });

  it('公開鍵を base64url から元のバイト列に戻す。閾値の既定値は 1', async () => {
    await sodium.ready;
    const a = sodium.crypto_sign_keypair().publicKey;
    const b = sodium.crypto_sign_keypair().publicKey;
    const result = parseMaintainerKeySet(`${encodeKey(a)}, ${encodeKey(b)}`, undefined);
    expect(result).not.toBeNull();
    expect(result!.threshold).toBe(1);
    expect(result!.keys.map((k) => Array.from(k))).toEqual([Array.from(a), Array.from(b)]);
  });

  it('閾値を指定できる (鍵の数以下)', async () => {
    await sodium.ready;
    const a = sodium.crypto_sign_keypair().publicKey;
    const b = sodium.crypto_sign_keypair().publicKey;
    const result = parseMaintainerKeySet(`${encodeKey(a)},${encodeKey(b)}`, '2');
    expect(result?.threshold).toBe(2);
  });

  it('閾値が不正なら信頼設定を無効にする (黙って直さない)', async () => {
    await sodium.ready;
    const a = encodeKey(sodium.crypto_sign_keypair().publicKey);
    expect(parseMaintainerKeySet(a, '2')).toBeNull(); // 鍵より多い
    expect(parseMaintainerKeySet(a, '0')).toBeNull();
    expect(parseMaintainerKeySet(a, '1.5')).toBeNull();
    expect(parseMaintainerKeySet(a, 'abc')).toBeNull();
  });

  it('鍵の形式が違えば無効 (長さ違い・記号・パディング)', async () => {
    await sodium.ready;
    const good = encodeKey(sodium.crypto_sign_keypair().publicKey);
    expect(parseMaintainerKeySet(encodeKey(new Uint8Array(16)), undefined)).toBeNull();
    expect(parseMaintainerKeySet(`${good},not base64!`, undefined)).toBeNull();
    expect(parseMaintainerKeySet(`${good}==`, undefined)).toBeNull();
    expect(parseMaintainerKeySet(`${good.slice(0, -1)}+`, undefined)).toBeNull(); // 標準 base64 の記号
  });

  it('初期のリストは、空白を除いて渡す。空なら渡さない', async () => {
    await sodium.ready;
    const a = encodeKey(sodium.crypto_sign_keypair().publicKey);
    expect(guardTrustFromEnv({ maintainerKeys: a, guardList: '  oz-guards:x  ' })?.guardList).toBe('oz-guards:x');
    expect(guardTrustFromEnv({ maintainerKeys: a, guardList: '   ' })).not.toHaveProperty('guardList');
    expect(guardTrustFromEnv({ maintainerKeys: a })).not.toHaveProperty('guardList');
  });
});

describe('Guard の状態の文言', () => {
  const base = { guardId: null, listVersion: null, listExpiresAt: null };

  it('モードごとに表示が決まる', () => {
    expect(describeGuardStatus({ ...base, mode: 'trusted' }).tone).toBe('calm');
    expect(describeGuardStatus({ ...base, mode: 'fallback', reason: 'no-trusted-guard-connected' }).tone).toBe('warn');
    expect(describeGuardStatus({ ...base, mode: 'open', reason: 'no-list' }).tone).toBe('warn');
    expect(describeGuardStatus({ ...base, mode: 'none', reason: 'waiting-for-candidates' }).tone).toBe('pending');
  });

  it('警告状態の説明は、1 ホップ目が普通の隣人で匿名性が弱いことを必ず含む', () => {
    for (const view of [
      describeGuardStatus({ ...base, mode: 'fallback' }),
      describeGuardStatus({ ...base, mode: 'open' }),
    ]) {
      expect(view.details.join('\n')).toMatch(/普通の隣人/);
      expect(view.details.join('\n')).toMatch(/弱く/);
    }
  });

  it('知らない理由でも落ちない', () => {
    expect(describeGuardStatus({ ...base, mode: 'open', reason: 'something-new' }).details.length).toBeGreaterThan(0);
  });

  it('取り込みの失敗理由は、すべて固有の日本語にする', () => {
    const reasons = [
      'malformed', 'too-large', 'no-keyset', 'insufficient-signatures', 'rollback',
      'expired', 'not-yet-valid', 'validity-too-long', 'bad-guard', 'too-many-guards',
    ] as const;
    const texts = reasons.map((r) => importFailureText(r));
    expect(new Set(texts).size).toBe(reasons.length);
    expect(importFailureText('rollback')).toBe('手元のリストより古い版です');
    expect(importFailureText('expired')).toBe('期限切れのリストです');
    expect(importFailureText('insufficient-signatures')).toBe('メンテナの署名が足りません');
  });
});
