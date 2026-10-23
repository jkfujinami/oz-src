import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import type { IIdentity } from '../../src/types';
import { fakePowEngine as powEngine } from '../helpers/postFixtures';

function identityWith(tripPubkey: Uint8Array | null, tripSign: ((d: Uint8Array) => Uint8Array) | null): IIdentity {
  const session = sodium.crypto_sign_keypair();
  return {
    hasTrip: tripPubkey !== null,
    sign: (data: Uint8Array) => ({
      sessionPubkey: session.publicKey,
      sessionSignature: sodium.crypto_sign_detached(data, session.privateKey),
      tripPubkey,
      tripSignature: tripSign ? tripSign(data) : null,
    }),
  };
}

async function roundTrip(identity: IIdentity) {
  const threadKey = sodium.randombytes_buf(32);
  const engine = new CryptoEngine();
  const packet = await PacketBuilder.build({
    content: 'hello', key: threadKey, identity, cryptoEngine: engine, powEngine, boardId: 'b', threadId: 't',
  });
  return PacketBuilder.verifyAndDecrypt(packet, threadKey, { kind: 'reply', boardId: 'b', threadId: 't' }, engine);
}

describe('PacketBuilder トリップ署名', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('トリップ無しの投稿は trip_pubkey=null で受理される', async () => {
    const post = await roundTrip(identityWith(null, null));
    expect(post).not.toBeNull();
    expect(post!.trip_pubkey).toBeNull();
  });

  it('正しいトリップ署名は受理され、公開鍵が返る', async () => {
    const trip = sodium.crypto_sign_keypair();
    const post = await roundTrip(identityWith(trip.publicKey, d => sodium.crypto_sign_detached(d, trip.privateKey)));
    expect(post).not.toBeNull();
    expect(Array.from(post!.trip_pubkey!)).toEqual(Array.from(trip.publicKey));
  });

  it('他人のトリップ公開鍵に不正な署名を付けた投稿は拒否される', async () => {
    const victim = sodium.crypto_sign_keypair();
    const post = await roundTrip(identityWith(victim.publicKey, () => new Uint8Array(64)));
    expect(post).toBeNull();
  });

  it('トリップ公開鍵だけで署名の無い投稿は拒否される', async () => {
    const victim = sodium.crypto_sign_keypair();
    // 鍵と署名が揃わない投稿は、送り出す前の build の段階で拒否される (ワイヤに載せる形が存在しない)
    await expect(roundTrip(identityWith(victim.publicKey, null))).rejects.toThrow(/trip/);
  });
});

describe('PacketBuilder 推奨 effort (A3)', () => {
  const build = (extra: object) => PacketBuilder.build({
    content: 'hello', key: sodium.randombytes_buf(32), identity: identityWith(null, null), cryptoEngine: new CryptoEngine(),
    powEngine, boardId: 'b', threadId: 't', ...extra,
  });

  it('推奨が無ければ最低 (1 セル = e=0)。onEffort に選んだ effort が渡る', async () => {
    await sodiumReady;
    let info: any = null;
    const p = await build({ onEffort: (i: any) => { info = i; } });
    expect(p.effort_exp).toBe(0);
    expect(info).toEqual({ effort: 1, cells: 1 });
  });

  it('1 セルあたりの推奨 × セル数を満たす最小の量子化値を使う', async () => {
    await sodiumReady;
    let info: any = null;
    const p = await build({ suggestedEffortPerCell: 16, onEffort: (i: any) => { info = i; } });
    expect(p.effort_exp).toBe(16); // 2^(16/4) = 16
    expect(info.effort).toBe(16);
    // 3 セル分の長い本文: 推奨 16 × 3 = 48 以上 (e=23 → 53)
    let big: any = null;
    const q = await PacketBuilder.build({
      content: 'あ'.repeat(680), key: sodium.randombytes_buf(32), identity: identityWith(null, null), cryptoEngine: new CryptoEngine(),
      powEngine, boardId: 'b', threadId: 't', suggestedEffortPerCell: 16, onEffort: (i: any) => { big = i; },
    });
    expect(big.cells).toBe(3);
    expect(big.effort).toBeGreaterThanOrEqual(48);
    expect(q.effort_exp).toBe(23);
  });

  it('推奨が最低より低ければ最低に従う', async () => {
    await sodiumReady;
    const p = await build({ suggestedEffortPerCell: 0.5 });
    expect(p.effort_exp).toBe(0);
  });
});
