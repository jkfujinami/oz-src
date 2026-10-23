import { describe, it, expect } from 'vitest';
import { encode as msgpackEncode } from '@msgpack/msgpack';
import sodium from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { PACKET_FIXED_OVERHEAD, decodePacket, encodePacket } from '../../src/crypto/PacketCodec';
import {
  FLAG_PARENTS_SHIFT, FLAG_THREAD_META, FLAG_TRIP, SIGNER_BLOCK_BYTES, decodePostPlain, encodePostPlain, postSignedBytes,
  type PostFields, type PostSigner,
} from '../../src/crypto/PostCodec';
import { decodeExitItem, encodeExitItem } from '../../src/crypto/ExitItem';
import {
  OZ_EPOCH_MS, POW_POLICY, PACKET_VERSION, derivePacketId, headerPrefix, msToMinutes,
} from '../../src/crypto/PowPolicy';
import { PacketValidator } from '../../src/network/gossip/PacketValidator';
import { ByteReader, ByteWriter } from '../../src/common/ByteIO';
import { containsBytes } from '../helpers/cryptoStorageFixtures';
import { buildPost, makeIdentity, parentIds, fakePowEngine } from '../helpers/postFixtures';

const engine = new CryptoEngine();
const CTX = { kind: 'reply', boardId: 'vip', threadId: 'abcdefghij' } as const;

describe('ByteIO', () => {
  it('varint は最短形で往復し、非最短・過大・切り詰めは拒否する', () => {
    for (const v of [0, 1, 127, 128, 16383, 16384, 2 ** 32, Number.MAX_SAFE_INTEGER]) {
      const b = new ByteWriter().varint(v).finish();
      expect(new ByteReader(b).varint()).toBe(v);
    }
    expect(() => new ByteReader(Uint8Array.of(0x80, 0x00)).varint()).toThrow(); // 0 の非最短形
    expect(() => new ByteReader(Uint8Array.of(0x80)).varint()).toThrow(); // 切り詰め
    expect(() => new ByteReader(new Uint8Array(9).fill(0xff)).varint()).toThrow();
    expect(() => new ByteWriter().varint(-1)).toThrow();
  });
  it('u48 は往復する', () => {
    const t = 1_700_000_000_123;
    expect(new ByteReader(new ByteWriter().u48(t).finish()).u48()).toBe(t);
    expect(() => new ByteWriter().u48(2 ** 48)).toThrow();
  });
});

describe('PacketCodec: v5 のヘッダ (28 バイト) とペイロード', () => {
  it('バイト配置: version | time u24 | tag u16 | age | e | nonce u32 | 解 16 | payload (長さの前置きなし)', async () => {
    const now = Date.UTC(2026, 9, 14, 12, 34, 56);
    const { packet } = await buildPost({ content: 'こんにちは', trip: true, parents: 2, now });
    const bytes = encodePacket(packet);
    expect(PACKET_FIXED_OVERHEAD).toBe(28);
    expect(bytes.length).toBe(28 + packet.payload.length);
    expect(bytes[0]).toBe(PACKET_VERSION);
    const minutes = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    expect(minutes).toBe(msToMinutes(Date.UTC(2026, 9, 14, 12, 34)));
    expect(OZ_EPOCH_MS + minutes * 60_000).toBe(packet.timestamp);
    const tag = (bytes[4] << 8) | bytes[5];
    expect(tag).toBe(packet.tag);
    expect(tag).toBeLessThan(4096); // 上位 4 ビットは 0
    expect(bytes[6]).toBe(packet.age);
    expect(bytes[7]).toBe(packet.effort_exp);
    expect(new DataView(bytes.buffer, bytes.byteOffset + 8, 4).getUint32(0)).toBe(packet.pow_nonce);
    expect(Array.from(bytes.subarray(12, 28))).toEqual(Array.from(packet.pow_solution));
    expect(Array.from(bytes.subarray(28))).toEqual(Array.from(packet.payload));
    // ヘッダの先頭 7 バイトは SIV の AAD
    expect(Array.from(bytes.subarray(0, 7))).toEqual(Array.from(headerPrefix({
      version: PACKET_VERSION, time: minutes, tag, age: packet.age,
    })));
  });

  it('往復でき、packet_id (32 hex) は decode が導出する (ワイヤに載っていない)', async () => {
    const { packet } = await buildPost({ content: 'こんにちは', trip: true, parents: 2 });
    const bytes = encodePacket(packet);
    expect(packet.packet_id).toMatch(/^[0-9a-f]{32}$/);
    const idBytes = sodium.from_hex(packet.packet_id);
    expect(Buffer.from(bytes).includes(Buffer.from(idBytes))).toBe(false);

    const back = decodePacket(bytes)!;
    expect(back).not.toBeNull();
    expect(back.packet_id).toBe(packet.packet_id);
    expect(back.packet_id).toBe(derivePacketId({
      version: PACKET_VERSION, time: msToMinutes(back.timestamp), tag: back.tag, age: back.age, payload: back.payload,
    }));
    expect(back).toEqual(packet);
    expect(PacketValidator.check(back)).toEqual({ ok: true });
  });

  it('★どの 1 ビットを変えても受理されない (ヘッダ・effort・nonce・解・ペイロードのすべて)', async () => {
    const { packet, threadKey } = await buildPost({ content: 'bit flip', parents: 1 });
    const bytes = encodePacket(packet);
    expect(PacketValidator.check(decodePacket(bytes)!)).toEqual({ ok: true });
    let flips = 0, decodedFlips = 0;
    for (let i = 0; i < bytes.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const t = new Uint8Array(bytes);
        t[i] ^= 1 << bit;
        flips++;
        const d = decodePacket(t);
        if (!d) continue; // version の書き換え
        decodedFlips++;
        // 中継 (鍵なし): PoW / 範囲 / 時刻のどれかで落ちる。時刻の書き換えで未来・過去に飛ぶ場合も落ちる
        expect(PacketValidator.check(d, { allowStale: true }).ok, `validator byte ${i} bit ${bit}`).toBe(false);
        // 読み手 (鍵あり): ヘッダの先頭 7 バイトとペイロードは SIV が、tag / age は足切りが落とす。
        // (effort / nonce / 解は復号に関係しないので、PoW だけが守る)
        if (i < 7 || i >= 28) {
          expect(await PacketBuilder.verifyAndDecrypt(d, threadKey, CTX, engine), `reader byte ${i} bit ${bit}`).toBeNull();
        }
      }
    }
    expect(decodedFlips).toBe(flips - 8); // version の 8 ビットだけが decode で落ちる
  });

  it('切り詰め・未知の version・長さ違反は null (v1 の先頭 0x01 も落ちる)', async () => {
    const { packet } = await buildPost({ content: 'abc' });
    const bytes = encodePacket(packet);
    for (let n = 0; n <= PACKET_FIXED_OVERHEAD; n++) {
      expect(decodePacket(bytes.subarray(0, n)), `truncated to ${n}`).toBeNull();
    }
    for (const v of [0, 1, 3, 0x80]) {
      const t = new Uint8Array(bytes); t[0] = v;
      expect(decodePacket(t), `version ${v}`).toBeNull();
    }
    expect(decodePacket(Uint8Array.of(...bytes, ...new Uint8Array(POW_POLICY.MAX_PAYLOAD_SIZE)))).toBeNull(); // 上限超過
  });

  it('旧形式 (v1 コンパクト形式・msgpack の map・JSON) は網からも DB からも読めない', async () => {
    const { packet } = await buildPost({ content: 'abc' });
    const legacy = msgpackEncode({ packet_id: packet.packet_id, hop_count: 0, pow_nonce: packet.pow_nonce, payload: packet.payload });
    expect(decodePacket(legacy)).toBeNull();
    expect(decodePacket(new TextEncoder().encode('{"packet_id":"x"}'))).toBeNull();
    const v1 = new Uint8Array(200); v1[0] = 1;
    expect(decodePacket(v1)).toBeNull();
  });

  it('encode は範囲外の値を拒否する (解は 16 バイト、payload は上限以内、nonce は u32)', async () => {
    const { packet } = await buildPost({ content: 'abc' });
    expect(() => encodePacket({ ...packet, tag: 0x10000 })).toThrow();
    expect(() => encodePacket({ ...packet, payload: new Uint8Array(POW_POLICY.MAX_PAYLOAD_SIZE + 1) })).toThrow();
    expect(() => encodePacket({ ...packet, payload: new Uint8Array(0) })).toThrow();
    expect(() => encodePacket({ ...packet, pow_solution: new Uint8Array(15) })).toThrow();
    expect(() => encodePacket({ ...packet, pow_nonce: 2 ** 32 })).toThrow();
    expect(() => encodePacket({ ...packet, timestamp: OZ_EPOCH_MS - 1 })).toThrow();
  });
});

describe('PostCodec (暗号化層・署名層 v5)', () => {
  const fields = (over: Partial<PostFields> = {}): PostFields => ({
    postType: 0, boardId: 'vip', threadId: 'abcdefghij', parents: parentIds(2), content: '本文 body', ...over,
  });
  const signer = (trip: boolean): PostSigner => ({
    isTrip: trip, pubkey: new Uint8Array(32).fill(trip ? 3 : 1), signature: new Uint8Array(64).fill(trip ? 4 : 2),
  });
  const aad = headerPrefix({ version: PACKET_VERSION, time: 1234, tag: 0x0abc, age: 5 });

  it('レイアウト: flags | [thread_id] | 親 16 バイトずつ | 署名ブロック 96 | 本文 (残り全部)', () => {
    const reply = encodePostPlain(fields({ content: 'xyz' }), signer(false));
    expect(reply.length).toBe(1 + 2 * 16 + SIGNER_BLOCK_BYTES + 3);
    expect(reply[0]).toBe(2 << FLAG_PARENTS_SHIFT);
    expect(Array.from(reply.subarray(reply.length - 3))).toEqual(Array.from(new TextEncoder().encode('xyz')));
    const meta = encodePostPlain(fields({ postType: 1, parents: [], content: 'T' }), signer(true));
    expect(meta[0]).toBe(FLAG_THREAD_META | FLAG_TRIP);
    expect(meta[1]).toBe(10); // thread_id の長さ
    expect(new TextDecoder().decode(meta.subarray(2, 12))).toBe('abcdefghij');
    expect(meta.length).toBe(1 + 1 + 10 + SIGNER_BLOCK_BYTES + 1);
  });

  it('全フィールドが往復する (トリップ有無・親 0/1/2・スレ立て)', () => {
    for (const trip of [false, true]) {
      for (const f of [fields(), fields({ parents: parentIds(1) }), fields({ parents: [] }), fields({ postType: 1, parents: [] })]) {
        const d = decodePostPlain(encodePostPlain(f, signer(trip)))!;
        expect(d.postType).toBe(f.postType);
        expect(d.metaThreadId).toBe(f.postType === 1 ? f.threadId : null);
        expect(d.parents).toEqual(f.parents);
        expect(d.content).toBe(f.content);
        expect(d.signer.isTrip).toBe(trip);
        expect(Array.from(d.signer.pubkey)).toEqual(Array.from(signer(trip).pubkey));
        expect(Array.from(d.signer.signature)).toEqual(Array.from(signer(trip).signature));
      }
    }
  });

  it('flags の意味と予約ビット (bit4-7 は 0、親の数は最大 2)', () => {
    const b = encodePostPlain(fields({ postType: 1, parents: parentIds(1) }), signer(true));
    expect(b[0]).toBe(FLAG_THREAD_META | FLAG_TRIP | (1 << FLAG_PARENTS_SHIFT));
    for (const bit of [0x10, 0x20, 0x40, 0x80]) {
      const reserved = new Uint8Array(b); reserved[0] |= bit;
      expect(decodePostPlain(reserved), `bit ${bit}`).toBeNull();
    }
    const three = new Uint8Array(b); three[0] |= 3 << FLAG_PARENTS_SHIFT;
    expect(decodePostPlain(three)).toBeNull();
  });

  it('切り詰めは null (本文が空でも署名ブロックまで必要)。末尾の余りは本文になる', () => {
    const b = encodePostPlain(fields({ content: '' }), signer(true));
    for (let n = 0; n < b.length; n++) expect(decodePostPlain(b.subarray(0, n)), `n=${n}`).toBeNull();
    expect(decodePostPlain(b)!.content).toBe('');
    expect(decodePostPlain(Uint8Array.of(...b, 0x41))!.content).toBe('A');
  });

  it('過大なフィールド (thread_id 長・本文長・不正な UTF-8) は拒否する', () => {
    const meta = encodePostPlain(fields({ postType: 1, parents: [] }), signer(false));
    const longId = new Uint8Array(meta); longId[1] = 33;
    expect(decodePostPlain(longId)).toBeNull();
    expect(() => encodePostPlain(fields({ content: 'a'.repeat(2049) }), signer(false))).toThrow(RangeError);
    const body = encodePostPlain(fields({ parents: [], content: 'abc' }), signer(false));
    const bad = new Uint8Array(body); bad.set([0xff, 0xff, 0xff], body.length - 3);
    expect(decodePostPlain(bad)).toBeNull();
    const over = new Uint8Array(1 + SIGNER_BLOCK_BYTES + 2049);
    expect(decodePostPlain(over)).toBeNull();
    expect(decodePostPlain(new Uint8Array(1 + SIGNER_BLOCK_BYTES + 2048))).not.toBeNull();
  });

  it('署名対象は board_id・thread_id・AAD (time/tag/age)・flags (トリップ)・親・本文・スレ立ての thread_id の全てに依存する', () => {
    const a = postSignedBytes(fields(), aad, false);
    const differs = (b: Uint8Array) => expect(Array.from(b)).not.toEqual(Array.from(a));
    differs(postSignedBytes(fields({ boardId: 'news' }), aad, false));
    differs(postSignedBytes(fields({ threadId: 'abcdefghik' }), aad, false));
    differs(postSignedBytes(fields({ content: 'x' }), aad, false));
    differs(postSignedBytes(fields({ parents: parentIds(1) }), aad, false));
    differs(postSignedBytes(fields(), headerPrefix({ version: PACKET_VERSION, time: 1235, tag: 0x0abc, age: 5 }), false));
    differs(postSignedBytes(fields(), headerPrefix({ version: PACKET_VERSION, time: 1234, tag: 0x0abd, age: 5 }), false));
    differs(postSignedBytes(fields(), headerPrefix({ version: PACKET_VERSION, time: 1234, tag: 0x0abc, age: 6 }), false));
    differs(postSignedBytes(fields(), aad, true)); // トリップ有りの署名は、無しの署名として通らない
    differs(postSignedBytes(fields({ postType: 1, parents: [] }), aad, false));
    // 区切りの曖昧さ: board_id と thread_id の境界をずらしても同じにならない (長さ前置き)
    expect(Array.from(postSignedBytes(fields({ boardId: 'ab', threadId: 'cd' }), aad, false)))
      .not.toEqual(Array.from(postSignedBytes(fields({ boardId: 'a', threadId: 'bcd' }), aad, false)));
    // ドメイン
    expect(new TextDecoder().decode(a.subarray(0, 'OZ/v5/post'.length))).toBe('OZ/v5/post');
  });

  it('PacketBuilder: 往復・トリップ・親・ID の文脈', async () => {
    const { packet, threadKey } = await buildPost({ content: '日本語の本文', trip: true, parents: 2, postType: 0 });
    const post = (await PacketBuilder.verifyAndDecrypt(packet, threadKey, CTX, engine))!;
    expect(post).not.toBeNull();
    expect(post.content).toBe('日本語の本文');
    expect(post.board_id).toBe('vip');
    expect(post.thread_id).toBe('abcdefghij');
    expect(post.parents).toEqual(parentIds(2));
    expect(post.created_at).toBe(packet.timestamp);
    expect(post.post_type).toBe(0);
    expect(post.trip_pubkey).not.toBeNull();
    expect(post.session_pubkey).toBeNull();
    const post2 = await PacketBuilder.verifyAndDecrypt(decodePacket(encodePacket(packet))!, threadKey, CTX, engine);
    expect(post2!.content).toBe('日本語の本文');
  });

  it('★トリップ有りの投稿はセッション鍵を載せない (署名ブロックはトリップ鍵 + トリップ署名の 96 バイトだけ)', async () => {
    const session = sodium.crypto_sign_keypair();
    const trip = sodium.crypto_sign_keypair();
    const identity = {
      hasTrip: true,
      sign: (d: Uint8Array) => ({
        sessionPubkey: session.publicKey, sessionSignature: sodium.crypto_sign_detached(d, session.privateKey),
        tripPubkey: trip.publicKey, tripSignature: sodium.crypto_sign_detached(d, trip.privateKey),
      }),
    };
    const { packet, threadKey } = await buildPost({ content: 'trip post', identity, parents: 1 });
    const aadBytes = encodePacket(packet).subarray(0, 7);
    const plain = engine.decrypt(threadKey, packet.payload, aadBytes)!;
    expect(containsBytes(plain, trip.publicKey)).toBe(true);
    expect(containsBytes(plain, session.publicKey)).toBe(false);
    expect(containsBytes(packet.payload, session.publicKey)).toBe(false);
    expect(plain.length).toBe(1 + 16 + 96 + 'trip post'.length);
    const post = (await PacketBuilder.verifyAndDecrypt(packet, threadKey, CTX, engine))!;
    expect(post.session_pubkey).toBeNull();
    expect(Array.from(post.trip_pubkey!)).toEqual(Array.from(trip.publicKey));
  });

  it('署名は board_id / thread_id の文脈に束縛される (別のスレとして読むと、鍵が同じでも検証に落ちる)', async () => {
    const { packet, threadKey } = await buildPost({ content: 'x' });
    expect(await PacketBuilder.verifyAndDecrypt(packet, threadKey, { ...CTX, boardId: 'news' }, engine)).toBeNull();
    // 別のスレ ID でも (旧形式の ID なら tag は同じ日のものなので足切りは通る) 署名が落とす
    expect(await PacketBuilder.verifyAndDecrypt(packet, threadKey, { ...CTX, threadId: 'abcdefghik' }, engine)).toBeNull();
    expect(await PacketBuilder.verifyAndDecrypt(packet, threadKey, { kind: 'meta', boardId: 'vip' }, engine)).toBeNull();
  });

  it('署名は timestamp に束縛される (ヘッダの時刻だけ書き換えると検証に落ちる)', async () => {
    const { packet, threadKey } = await buildPost({ content: 'x' });
    expect(await PacketBuilder.verifyAndDecrypt({ ...packet, timestamp: packet.timestamp + 60_000 }, threadKey, CTX, engine)).toBeNull();
  });

  it('本文 2048 バイト (UTF-8) ちょうどは通り、2049 バイトは RangeError (日本語 682 文字 = 2046 / 683 文字 = 2049)', async () => {
    const ok = await buildPost({ content: 'あ'.repeat(682) + 'ab', pow: 'fake' });
    expect(ok.packet.payload.length).toBeLessThanOrEqual(POW_POLICY.MAX_PAYLOAD_SIZE);
    await expect(buildPost({ content: 'あ'.repeat(683), pow: 'fake' })).rejects.toThrow(RangeError);
    await expect(buildPost({ content: 'a'.repeat(2049), pow: 'fake' })).rejects.toThrow(/2049/);
    await expect(buildPost({ content: '😀'.repeat(513), pow: 'fake' })).rejects.toThrow(RangeError);
    await expect(buildPost({ content: '😀'.repeat(512), pow: 'fake' })).resolves.toBeDefined();
  });

  it('親は 2 つまで (3 つは例外)、スレ立ての ID は 32 バイトまで、親は 32 桁 hex のみ', async () => {
    await expect(buildPost({ content: 'x', parents: 3, pow: 'fake' })).rejects.toThrow(/parents/);
    await expect(buildPost({ content: 'x', boardId: 'b'.repeat(33), pow: 'fake' })).rejects.toThrow(/board_id/);
    await expect(buildPost({ content: 'x', threadId: 't'.repeat(33), pow: 'fake' })).rejects.toThrow(/thread_id/);
    const { threadKey } = await buildPost({ content: 'x', pow: 'fake' });
    for (const bad of ['not-hex', '1'.repeat(64), '1'.repeat(31)]) {
      await expect(PacketBuilder.build({
        content: 'x', key: threadKey, identity: makeIdentity(false), cryptoEngine: engine, powEngine: fakePowEngine,
        boardId: 'b', threadId: 't', parents: [bad],
      })).rejects.toThrow(/hex/);
    }
  });
});

describe('パケットの付帯バイト (本文 0 バイト)', () => {
  it('★返信 (親 2) の付帯は 28 + 16 + 1 + 32 + 96 = 173 バイト。トリップ有りでも同じ (旧: 約 234 / トリップ有り約 330)', async () => {
    for (const trip of [false, true]) {
      const { packet } = await buildPost({ content: '', trip, parents: 2, pow: 'fake' });
      expect(encodePacket(packet).length, `trip=${trip}`).toBe(28 + 16 + 1 + 32 + 96);
      expect(encodePacket(packet).length).toBe(173);
    }
  });

  it('親 1 つで 157、親なしで 141。スレ立ては thread_id (1 + 長さ) が加わる', async () => {
    expect(encodePacket((await buildPost({ content: '', parents: 1, pow: 'fake' })).packet).length).toBe(157);
    expect(encodePacket((await buildPost({ content: '', parents: 0, pow: 'fake' })).packet).length).toBe(141);
    const meta = await buildPost({ content: '', postType: 1, threadId: 'abcdefghij', pow: 'fake' });
    expect(encodePacket(meta.packet).length).toBe(141 + 1 + 10);
  });

  it('最大の投稿 (本文 2048・親 2・最長の thread_id のスレ立て) は MAX_PAYLOAD_SIZE にちょうど収まる', async () => {
    const meta = await buildPost({
      content: 'a'.repeat(2048), postType: 1, parents: 2, threadId: 't'.repeat(32), trip: true, pow: 'fake',
    });
    expect(meta.packet.payload.length).toBe(POW_POLICY.MAX_PAYLOAD_SIZE);
    const reply = await buildPost({ content: 'a'.repeat(2048), parents: 2, trip: true, pow: 'fake' });
    expect(reply.packet.payload.length).toBe(16 + 1 + 32 + 96 + 2048);
    // 保管・転送の上限 (decode) も通る
    expect(decodePacket(encodePacket(meta.packet))).not.toBeNull();
  });
});

describe('ExitItem (回路の中の 1 件)', () => {
  it('exit_fluff は往復し、パケットは item の最後に長さの前置きなしで載る (kind 1 バイトだけ付く)', async () => {
    const { packet } = await buildPost({ content: 'abc', trip: true, parents: 1, pow: 'fake' });
    const bytes = encodeExitItem({ type: 'exit_fluff', packet });
    expect(bytes[0]).toBe(1);
    expect(Array.from(bytes.subarray(1))).toEqual(Array.from(encodePacket(packet)));
    const a = decodeExitItem(bytes)!;
    expect(a.type).toBe('exit_fluff');
    expect(a.packet.packet_id).toBe(packet.packet_id);
    expect(a).not.toHaveProperty('slot');
  });

  it('未知の種別 (旧 hint = 2 を含む)・空・壊れた packet は null', () => {
    expect(decodeExitItem(Uint8Array.of(9, 0))).toBeNull();
    expect(decodeExitItem(Uint8Array.of(2, ...new Uint8Array(91)))).toBeNull();
    expect(decodeExitItem(new Uint8Array(0))).toBeNull();
    expect(decodeExitItem(Uint8Array.of(1, 0, 1, 2, 3))).toBeNull();
    expect(() => encodeExitItem({ type: 'exit_hint' } as any)).toThrow();
  });
});
