import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { Identity } from '../../src/crypto/Identity';
import { memorySealedStore, captureLogSink, containsBytes } from '../helpers/cryptoStorageFixtures';

const data = new TextEncoder().encode('post body to sign');

let log: ReturnType<typeof captureLogSink>;

beforeAll(async () => {
  await sodiumReady;
});
beforeEach(() => {
  log = captureLogSink();
});
afterEach(() => {
  log.restore();
});

describe('Identity: セッション鍵 (タブごとの一時 ID)', () => {
  it('トリップ無しでは sign の trip 部は null で、セッション署名は検証できる', () => {
    const id = new Identity();
    expect(id.hasTrip).toBe(false);
    expect(id.tripDisplay).toBe('');
    const sig = id.sign(data);
    expect(sig.tripPubkey).toBeNull();
    expect(sig.tripSignature).toBeNull();
    expect(sig.sessionPubkey).toHaveLength(32);
    expect(Identity.verify(data, sig.sessionPubkey, sig.sessionSignature)).toBe(true);
  });

  it('インスタンスごとにセッション鍵が異なる', () => {
    const a = new Identity().sign(data);
    const b = new Identity().sign(data);
    expect(Array.from(a.sessionPubkey)).not.toEqual(Array.from(b.sessionPubkey));
  });

  it('sessionDisplay は SHA-512(pubkey) 先頭 4 バイトの Base64 (8 文字) で安定', () => {
    const id = new Identity();
    const pk = id.sign(data).sessionPubkey; // 文脈なし = 既定の文脈 (sessionDisplay と同じ)
    const want = Buffer.from(sodium.crypto_hash(pk).slice(0, 4)).toString('base64');
    expect(id.sessionDisplay).toBe(want);
    expect(id.sessionDisplay).toHaveLength(8);
    expect(id.sessionDisplay).toBe(id.sessionDisplay);
  });

  it('Identity.verify は改竄されたデータ・別の公開鍵・改竄された署名を拒否する', () => {
    const id = new Identity();
    const other = new Identity();
    const sig = id.sign(data);
    const tampered = Uint8Array.from(data); tampered[0] ^= 1;
    expect(Identity.verify(tampered, sig.sessionPubkey, sig.sessionSignature)).toBe(false);
    expect(Identity.verify(data, other.sign(data).sessionPubkey, sig.sessionSignature)).toBe(false);
    const badSig = Uint8Array.from(sig.sessionSignature); badSig[10] ^= 1;
    expect(Identity.verify(data, sig.sessionPubkey, badSig)).toBe(false);
  });
});

describe('Identity: トリップの生成と保存', () => {
  it('generateTrip は "◆" + Base64 のトリップを返し、署名にトリップが付く', async () => {
    const store = memorySealedStore();
    const id = new Identity();
    const display = await id.generateTrip(store);
    expect(display).toBe(id.tripDisplay);
    expect(display.startsWith('◆')).toBe(true);
    expect(id.hasTrip).toBe(true);

    const sig = id.sign(data);
    expect(sig.tripPubkey).toHaveLength(32);
    expect(Identity.verify(data, sig.tripPubkey!, sig.tripSignature!)).toBe(true);
    // セッション鍵とトリップ鍵は別物
    expect(Array.from(sig.tripPubkey!)).not.toEqual(Array.from(sig.sessionPubkey));
    expect(Identity.verify(data, sig.sessionPubkey, sig.tripSignature!)).toBe(false);

    const want = '◆' + Buffer.from(sodium.crypto_hash(sig.tripPubkey!).slice(0, 5)).toString('base64');
    expect(display).toBe(want);
  });

  it('store には sk||pk が渡る (暗号化は store の DEK の仕事。KDF はここでは走らせない)', async () => {
    const store = memorySealedStore();
    const id = new Identity();
    await id.generateTrip(store);
    const rec = store.slots.get('trip')!;
    const kp = (id as any).tripKeyPair;
    expect(rec.secret).toHaveLength(96);
    expect(containsBytes(rec.secret, kp.privateKey.subarray(0, 32))).toBe(true);
    expect(containsBytes(rec.secret, kp.publicKey)).toBe(true);
  });

  it('generateTrip を呼び直すと新しいトリップになる', async () => {
    const store = memorySealedStore();
    const id = new Identity();
    const a = await id.generateTrip(store);
    const b = await id.generateTrip(store);
    expect(a).not.toBe(b);
  });
});

describe('Identity.initTrip: 復元', () => {
  it('別のインスタンスで同じトリップに戻り、同じ鍵で署名する', async () => {
    const store = memorySealedStore();
    const original = new Identity();
    const display = await original.generateTrip(store);

    const restored = new Identity();
    expect(await restored.initTrip(store)).toBe(true);
    expect(restored.hasTrip).toBe(true);
    expect(restored.tripDisplay).toBe(display);
    const sig = restored.sign(data);
    expect(Array.from(sig.tripPubkey!)).toEqual(Array.from(original.sign(data).tripPubkey!));
    expect(Identity.verify(data, sig.tripPubkey!, sig.tripSignature!)).toBe(true);
  });

  it('長さの違う記録は読まず、名無しのまま (警告にも秘密は出ない)', async () => {
    const store = memorySealedStore();
    await new Identity().generateTrip(store);
    const good = store.slots.get('trip')!;
    for (const secret of [good.secret.slice(1), new Uint8Array(0), new Uint8Array(97)]) {
      store.slots.set('trip', { secret });
      const id = new Identity();
      expect(await id.initTrip(store)).toBe(false);
      expect(id.hasTrip).toBe(false);
    }
    expect(containsBytes(new TextEncoder().encode(log.text()), good.secret.subarray(0, 8))).toBe(false);
  });

  it('記録が無ければ false', async () => {
    expect(await new Identity().initTrip(memorySealedStore())).toBe(false);
  });
});

describe('Identity.deleteTrip', () => {
  it('メモリと保存先の両方から消す', async () => {
    const store = memorySealedStore();
    const id = new Identity();
    await id.generateTrip(store);
    await id.deleteTrip(store);
    expect(id.hasTrip).toBe(false);
    expect(id.tripDisplay).toBe('');
    expect(id.sign(data).tripPubkey).toBeNull();
    expect(store.slots.has('trip')).toBe(false);
    expect(await new Identity().initTrip(store)).toBe(false);
  });
});
