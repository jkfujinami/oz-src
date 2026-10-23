import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { WireType } from '../../src/network/wire/WireTypes';
import { NodeIdentity, NODE_ID_POW_FAST, joinMessage, trackerJoinMessage } from '../../src/crypto/NodeIdentity';
import {
  TRACKER_PROTOCOL_VERSION,
  TRACKER_MAX_FRAME_BYTES,
  TRACKER_MAX_PEERS,
  parseTrackerClientMessage,
  parseTrackerServerMessage,
} from '../../src/network/TrackerProtocol';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { OnionRouter, SEALED_EXIT_LAYER_SIZE } from '../../src/crypto/OnionRouter';
import {
  POW_POLICY, PACKET_VERSION, OZ_EPOCH_MS, POW_DOMAIN, ID_DOMAIN, powSeed, derivePacketId, verifyPow,
} from '../../src/crypto/PowPolicy';
import { metaTagAge } from '../../src/crypto/PacketTag';
import { PacketValidator } from '../../src/network/gossip/PacketValidator';
import { decodePacket, encodePacket } from '../../src/crypto/PacketCodec';
import { encodeExitItem, decodeExitItem, splitIntoFragments } from '../../src/crypto/ExitItem';
import { toBytes } from '../../src/crypto/PowPolicy';
import { Encoding } from '../../src/common/Encoding';
import {
  buildGoldenVectors,
  packetFromJson,
  seededKeyPair,
  toHex,
  fromHex,
  INPUTS,
  type GoldenVectors,
} from './goldenInputs';

/**
 * プロトコル適合テスト (golden vectors)。
 *
 * vectors/core_protocol_vectors.json は generateVectors.ts で一度だけ生成して
 * 固定したもの。ここでは
 *   (1) 保存済みのバイト列を今のコードで復号し、中身を確かめる
 *   (2) 同じ固定入力から今のコードで組み立て直し、保存済みのバイト列と完全一致を求める
 * の両方向で縛る。どちらかが落ちたら、既存ノードとのワイヤ互換性が壊れている。
 *
 * ★ 落ちたときにベクタを再生成して「直す」のは誤り。意図的な形式変更
 *   (ドメイン文字列の版を上げる等) のときだけ再生成すること。
 */

const VECTOR_PATH = join(__dirname, 'vectors/core_protocol_vectors.json');
let stored: GoldenVectors;
let fresh: GoldenVectors;

const enc = new TextEncoder();
const concatBytes = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

beforeAll(async () => {
  await sodiumReady;
  stored = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
  // オニオンのセルは封印に WASM 内部の乱数を使うので再現できない。
  // ONION_STEM フレームは保存済みのセルから組み立て直す。
  fresh = await buildGoldenVectors({ onionCell: fromHex(stored.onion.cell) });
});

function frame(name: string): Uint8Array {
  const f = stored.wire.frames[name];
  expect(f, `missing frame ${name}`).toBeDefined();
  return fromHex(f.hex);
}

// ───────────────────────── (2) 再符号化 ─────────────────────────

describe('固定入力から組み立て直した結果が保存済みベクタと 1 ビットも違わない', () => {
  it('定数表 (WireType 番号・内部タグ・セル長・PoW 方針・各ドメイン)', () => {
    expect(fresh.constants).toEqual(stored.constants);
  });

  it('KeyManager: thread key', () => {
    expect(fresh.keyManager).toEqual(stored.keyManager);
  });

  it('NodeIdentity: pubkey → peerId → position、NodeId PoW (Argon2id)', () => {
    expect(fresh.nodeIdentity).toEqual(stored.nodeIdentity);
  });

  it('JOIN v4: 正準メッセージと Ed25519 署名', () => {
    expect(fresh.join).toEqual(stored.join);
  });

  it('トラッカー登録 (v2): 署名対象と署名', () => {
    expect(fresh.tracker).toEqual(stored.tracker);
  });

  it('Gossip PoW (Equi-X): challenge の種 C / packet_id / 解', () => {
    expect(fresh.gossipPow).toEqual(stored.gossipPow);
  });

  it('CryptoEngine: SIV (決定的。乱数を使わない)', () => {
    expect(fresh.cryptoEngine).toEqual(stored.cryptoEngine);
  });

  it('PacketBuilder: 時刻・nonce・鍵を固定すると外側パケットが完全に再現される', () => {
    expect(fresh.packetBuilder).toEqual(stored.packetBuilder);
  });

  it('OnionRouter: 回路の鍵とパディング (封印部分を除く)', () => {
    const { cell: _freshCell, ...f } = fresh.onion;
    const { cell: _storedCell, ...s } = stored.onion;
    expect(f).toEqual(s);
  });

  it('全 WireType のフレームが保存済みのバイト列と一致する', () => {
    expect(Object.keys(fresh.wire.frames).sort()).toEqual(Object.keys(stored.wire.frames).sort());
    for (const [name, f] of Object.entries(stored.wire.frames)) {
      expect(fresh.wire.frames[name], name).toEqual(f);
    }
  });

  it('UNKNOWN を除く全 WireType がフレームベクタで網羅されている', () => {
    const covered = new Set(Object.values(stored.wire.frames).map(f => f.type));
    const all = Object.values(WireType).filter((v): v is number => typeof v === 'number' && v !== WireType.UNKNOWN);
    for (const t of all) expect(covered.has(t), `WireType 0x${t.toString(16)} のベクタが無い`).toBe(true);
  });
});

// ───────────────────────── 定数 (明示値) ─────────────────────────

describe('ワイヤに現れる定数 (明示値で固定)', () => {
  it('WireType の番号', () => {
    expect(stored.constants.wireTypes).toEqual({
      JOIN: 0x10, PING: 0x12, PONG: 0x13, HELLO: 0x17,
      PEX_REQUEST: 0x20, PEX_RESPONSE: 0x21,
      SDP_RELAY: 0x30, ICE_RELAY: 0x31,
      GOSSIP: 0x40, STEM: 0x41, ONION_STEM: 0x44,
      CATCHUP_REQ: 0x60, CATCHUP_DATA: 0x61, CATCHUP_END: 0x62,
      LEASESET: 0x70, LEASESET_SYNC_REQ: 0x71, LEASESET_SYNC: 0x72,
      TUNNEL_REGISTER: 0x80, TUNNEL_REGISTERED: 0x81, TUNNEL_SEND: 0x82, TUNNEL_FWD: 0x83, TUNNEL_DELIVER: 0x84,
      TUNNEL_REPLY: 0x85, TUNNEL_RET: 0x86, TUNNEL_RESULT: 0x87, TUNNEL_ERROR: 0x88,
      OZZY_REPLY: 0x90, OZZY_RESULT: 0x91, OZZY_WORKER_REQ: 0x92, OZZY_WORKER_ADS: 0x93, OZZY_UP: 0x94, OZZY_UP_FWD: 0x95,
      UNKNOWN: 0xff,
    });
  });

  it('オニオンのセル長・出口層長・マジック', () => {
    expect(OnionRouter.CELL_SIZE).toBe(1200);
    expect(OnionRouter.EXIT_LAYER_SIZE).toBe(1083);
    expect(SEALED_EXIT_LAYER_SIZE).toBe(1083 + 48);
    expect(OnionRouter.FRAG_DATA_MAX).toBe(1068);
    expect(stored.constants.onion.MAX_FRAGMENTS).toBe(3);
    expect(stored.constants.onion.FRAG_ID_BYTES).toBe(8);
    expect(stored.constants.onion.RELAY_LAYER_OVERHEAD).toBe(17);
    expect(stored.constants.onion.cellMagic).toBe('a55a');
  });

  it('Gossip PoW の方針値', () => {
    expect(POW_POLICY).toEqual({
      MAX_CONTENT_BYTES: 2048,
      MAX_PARENTS: 2,
      MAX_ID_BYTES: 32,
      PACKET_ID_BYTES: 16,
      HEADER_BYTES: 28,
      SIV_BYTES: 16,
      MIN_EFFORT_PER_CELL: 1,
      EFFORT_CELL_BYTES: 1000,
      MAX_EFFORT_EXP: 80,
      MAX_AGE_DAYS: 90,
      TAG_BITS: 12,
      MAX_TIME_DRIFT: 15 * 60 * 1000,
      // siv 16 + flags 1 + thread_id 33 + 親 2 * 16 + 署名ブロック 96 + 本文 2048
      MAX_PAYLOAD_SIZE: 2226,
    });
    expect(stored.constants.packetVersion).toBe(2);
    expect(stored.constants.epochMs).toBe(Date.parse('2025-01-01T00:00:00Z'));
  });

  it('ドメイン分離子と鍵導出のラベル (v5)', () => {
    expect(new TextDecoder().decode(POW_DOMAIN)).toBe('OZ/v5/pow');
    expect(new TextDecoder().decode(ID_DOMAIN)).toBe('OZ/v5/id');
    expect(stored.constants.postSignedDomain).toBe('OZ/v5/post');
    expect(stored.constants.sivLabels).toEqual({ enc: 'oz/v5/enc', mac: 'oz/v5/mac' });
    expect(stored.constants.tagLabels).toEqual({ board: 'oz/v5/board-tag', thread: 'oz/v5/thread-tag' });
  });

  it('NodeId PoW の既定パラメータ', () => {
    expect(stored.constants.nodeIdentity).toEqual({
      PEER_ID_BYTES: 16,
      CHALLENGE_BYTES: 32,
      NODE_ID_POW: { difficulty: 10, opsLimit: 1, memLimit: 1 << 20 },
      NODE_ID_POW_FAST: { difficulty: 4, opsLimit: 1, memLimit: 8192 },
    });
  });
});

// ───────────────────────── (1) 保存済みバイト列の復号 ─────────────────────────

describe('派生関数の定義そのもの (ドメイン文字列を独立に再計算)', () => {
  it('peerId = SHA256("OZ/v3/peerid" ‖ pubkey)[0..16]', () => {
    const pk = fromHex(stored.nodeIdentity.pubkey);
    expect(toHex(seededKeyPair(INPUTS.nodeSeedByte).publicKey)).toBe(stored.nodeIdentity.pubkey);
    const expected = toHex(sodium.crypto_hash_sha256(concatBytes(enc.encode('OZ/v3/peerid'), pk)).slice(0, 16));
    expect(stored.nodeIdentity.peerId).toBe(expected);
    expect(stored.nodeIdentity.peerId).toBe('a57c8bec330e5bd8771c3248ddb69236');
  });

  it('position = SHA256("OZ/v3/position" ‖ peerIdBytes)[0..8] / 2^64', () => {
    const h = sodium.crypto_hash_sha256(concatBytes(enc.encode('OZ/v3/position'), fromHex(stored.nodeIdentity.peerId)));
    const v = new DataView(h.buffer, h.byteOffset, 8).getBigUint64(0, false);
    expect(stored.nodeIdentity.position).toBe(Number(v) / 2 ** 64);
    expect(stored.nodeIdentity.position).toBeGreaterThanOrEqual(0);
    expect(stored.nodeIdentity.position).toBeLessThan(1);
  });

  it('NodeId PoW = Argon2id13(pubkey ‖ u64be(counter), salt="OZ/v3/nodeid-pow")', () => {
    const pk = fromHex(stored.nodeIdentity.pubkey);
    const { params, counter, hashAtSolvedCounter } = stored.nodeIdentity.nodeIdPowFast;
    const counterBytes = new Uint8Array(8);
    new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
    const h = sodium.crypto_pwhash(
      32, concatBytes(pk, counterBytes), enc.encode('OZ/v3/nodeid-pow'),
      params.opsLimit, params.memLimit, sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    expect(toHex(h)).toBe(hashAtSolvedCounter);
    // 先頭 4 ビットが 0 (difficulty 4)
    expect(h[0] & 0xf0).toBe(0);
    expect(NodeIdentity.verifyClaim({ peerId: stored.nodeIdentity.peerId, pubkey: pk, powCounter: counter }, NODE_ID_POW_FAST)).toBe(true);
  });

  it('JOIN v4 の正準メッセージ = "OZ/v4/join" ‖ challenge ‖ len16 で区切った 4 文字列', () => {
    const j = stored.join;
    const lp = (s: string) => {
      const b = enc.encode(s);
      return concatBytes(Uint8Array.of(b.length >> 8, b.length & 0xff), b);
    };
    const expected = concatBytes(
      enc.encode('OZ/v4/join'),
      fromHex(j.challenge),
      lp(j.binding.verifierId),
      lp(j.signerId),
      lp(j.binding.signerFingerprint),
      lp(j.binding.verifierFingerprint),
    );
    expect(j.message).toBe(toHex(expected));
    expect(toHex(joinMessage(fromHex(j.challenge), j.signerId, j.binding))).toBe(j.message);
    expect(sodium.crypto_sign_verify_detached(fromHex(j.signature), expected, fromHex(stored.nodeIdentity.pubkey))).toBe(true);
  });

  it('トラッカー登録の正準メッセージ = "OZ/v1/tracker-join" ‖ nonce(32) ‖ lp(peerId) ‖ lp(小文字の host)', () => {
    const t = stored.tracker;
    const lp = (str: string) => {
      const b = enc.encode(str);
      return concatBytes(Uint8Array.of(b.length >> 8, b.length & 0xff), b);
    };
    const expected = concatBytes(
      enc.encode('OZ/v1/tracker-join'),
      fromHex(t.nonce),
      lp(t.peerId),
      lp(t.host.toLowerCase()),
    );
    expect(t.domain).toBe('OZ/v1/tracker-join');
    expect(t.message).toBe(toHex(expected));
    // host の大文字小文字は署名に影響しない
    expect(toHex(trackerJoinMessage(fromHex(t.nonce), t.peerId, t.host.toLowerCase()))).toBe(t.message);
    expect(toHex(trackerJoinMessage(fromHex(t.nonce), t.peerId, t.host.toUpperCase()))).toBe(t.message);
    expect(() => trackerJoinMessage(new Uint8Array(31), t.peerId, t.host)).toThrow(RangeError);
  });

  it('トラッカー登録の署名が保存済みの鍵で検証でき、ドメインが JOIN (P2P) と分離されている', () => {
    const t = stored.tracker;
    const pubkey = fromHex(stored.nodeIdentity.pubkey);
    const claim = { peerId: t.peerId, pubkey, powCounter: t.powCounter };
    expect(sodium.crypto_sign_verify_detached(fromHex(t.signature), fromHex(t.message), pubkey)).toBe(true);
    expect(NodeIdentity.verifyTrackerJoin(claim, fromHex(t.nonce), t.host, fromHex(t.signature), NODE_ID_POW_FAST)).toBe(true);
    // 別のトラッカー・別の nonce 向けとしては通らない
    expect(NodeIdentity.verifyTrackerJoin(claim, fromHex(t.nonce), 'other.example.org:8443', fromHex(t.signature), NODE_ID_POW_FAST)).toBe(false);
    expect(NodeIdentity.verifyTrackerJoin(claim, new Uint8Array(32), t.host, fromHex(t.signature), NODE_ID_POW_FAST)).toBe(false);
    // P2P の JOIN 署名とは別物 (先頭のドメインが違う)
    expect(t.message.startsWith(toHex(enc.encode('OZ/v4/join')))).toBe(false);
  });

  it('トラッカープロトコルの定数', () => {
    expect(TRACKER_PROTOCOL_VERSION).toBe(3);
    expect(TRACKER_MAX_FRAME_BYTES).toBe(stored.tracker.maxFrameBytes);
    expect(TRACKER_MAX_PEERS).toBe(32);
    expect(stored.tracker.protocolVersion).toBe(3);
  });

  it('トラッカーのバイナリフレーム (v3) が保存済みのバイト列と一致し、読み戻せる', () => {
    const t = stored.tracker;
    expect(t.errorCodes).toEqual([
      'bad-message', 'unsupported-version', 'invalid-identity', 'bad-signature', 'bad-host',
      'rate-limited', 'capacity', 'not-joined', 'invalid-target', 'too-large', 'timeout',
    ]);
    const hello = parseTrackerServerMessage(fromHex(t.frames.hello));
    expect(hello).toMatchObject({ type: 'hello', v: 3 });
    expect(toHex((hello as any).nonce)).toBe(t.nonce);
    // join は [0x11][v][pubkey 32][powCounter u32][sig 64][lp8 host]。peerId は載らない
    const join = parseTrackerClientMessage(fromHex(t.frames.join)) as any;
    expect(join).toMatchObject({ type: 'join', v: 3, peerId: t.peerId, powCounter: t.powCounter, host: t.host.toLowerCase() });
    expect(toHex(join.sig)).toBe(t.signature);
    expect(NodeIdentity.verifyTrackerJoin(
      { peerId: join.peerId, pubkey: join.pubkey, powCounter: join.powCounter }, fromHex(t.nonce), join.host, join.sig, NODE_ID_POW_FAST,
    )).toBe(true);
    expect(fromHex(t.frames.join)[0]).toBe(0x11);
    expect(parseTrackerServerMessage(fromHex(t.frames.peers))).toMatchObject({ type: 'peers', peers: [{ peerId: t.peerId }, { peerId: '00112233445566778899aabbccddeeff' }] });
    expect(t.frames.error).toBe('0304');
    expect(parseTrackerServerMessage(fromHex(t.frames.error))).toEqual({ type: 'error', code: 'bad-signature' });
    expect(parseTrackerClientMessage(fromHex(t.frames.relaySdp))).toMatchObject({ type: 'relay', targetPeerId: t.peerId, payload: { sdp: { type: 'offer', sdp: 'v=0\r\n' } } });
    expect(parseTrackerServerMessage(fromHex(t.frames.relayIce))).toMatchObject({ type: 'relay', senderId: t.peerId });
  });

  it('thread key = HMAC-SHA512/256(boardKey, "thread:" ‖ threadId)', () => {
    const k = stored.keyManager;
    expect(toHex(sodium.crypto_auth(enc.encode(`thread:${k.threadId}`), fromHex(k.boardKey)))).toBe(k.threadKey);
  });

  it('Gossip PoW: C = BLAKE2b-256(domain ‖ version ‖ time ‖ tag ‖ age ‖ e ‖ SHA-256(payload))、packet_id = SHA-256(domain ‖ 先頭 7 バイト ‖ payload) の先頭 16 バイト', () => {
    const g = stored.gossipPow;
    const payload = fromHex(g.header.payload);
    const prefix = new Uint8Array(7);
    prefix[0] = g.header.version;
    prefix.set([(g.header.time >>> 16) & 0xff, (g.header.time >>> 8) & 0xff, g.header.time & 0xff], 1);
    prefix.set([(g.header.tag >>> 8) & 0xff, g.header.tag & 0xff], 4);
    prefix[6] = g.header.age;
    const seed = sodium.crypto_generichash(32, concatBytes(
      enc.encode('OZ/v5/pow'), prefix, Uint8Array.of(g.header.effort_exp), sodium.crypto_hash_sha256(payload),
    ), null);
    expect(toHex(seed)).toBe(g.seed);
    expect(g.packetId).toBe(toHex(sodium.crypto_hash_sha256(concatBytes(enc.encode('OZ/v5/id'), prefix, payload)).slice(0, 16)));
    expect(g.packetId).toHaveLength(32);
    const header = { ...g.header, payload };
    expect(toHex(powSeed(header))).toBe(g.seed);
    expect(derivePacketId(header)).toBe(g.packetId);
    expect(verifyPow(header, { nonce: g.solvedNonce, solution: fromHex(g.solution) })).toBe(true);
    // effort (e = 4 → 2) を高く名乗り直すと、同じ解は通らない
    expect(verifyPow({ ...header, effort_exp: 8 }, { nonce: g.solvedNonce, solution: fromHex(g.solution) })).toBe(false);
  });
});

describe('保存済みのバイト列を今のコードで復号できる', () => {
  it('CryptoEngine: 保存済みのペイロードが復号でき、長さは siv 16 + 平文。AAD が違えば復号できない', () => {
    const c = stored.cryptoEngine;
    const payload = fromHex(c.payload);
    expect(payload.length).toBe(fromHex(c.plaintext).length + 16);
    const pt = CryptoEngine.decrypt(fromHex(c.threadKey), payload, fromHex(c.aad));
    expect(pt && toHex(pt)).toBe(c.plaintext);
    const wrongAad = fromHex(c.aad); wrongAad[6] ^= 1;
    expect(CryptoEngine.decrypt(fromHex(c.threadKey), payload, wrongAad)).toBeNull();
  });

  it('PacketBuilder: 保存済みパケットがヘッダ検証・復号・署名検証を通る (トリップ有り / 無し / スレ立て)', async () => {
    const pb = stored.packetBuilder;
    const packet = packetFromJson(pb.packet);
    expect(PacketValidator.check(packet, { now: packet.timestamp })).toEqual({ ok: true });
    // ヘッダ時刻は分単位に丸められている
    expect(packet.timestamp).toBe(Math.floor(pb.nowMs / 60_000) * 60_000);
    expect(packet).not.toHaveProperty('hop_count');
    expect(packet).not.toHaveProperty('zone_id');
    // ワイヤ形式 (PacketCodec) のバイト列が固定されている。decode すると packet_id が導出される
    const wire = decodePacket(fromHex(pb.encodedPacket))!;
    expect(wire.packet_id).toBe(packet.packet_id);
    expect(toHex(encodePacket(packet))).toBe(pb.encodedPacket);
    expect(fromHex(pb.encodedPacket)[0]).toBe(PACKET_VERSION);
    expect(packet.effort_exp).toBe(0); // 1 セルに収まる最小
    // 返信は スレ立て日 (2026-10-12) から 2 日目
    expect(packet.age).toBe(2);
    const threadKey = fromHex(pb.threadKey);
    const ctx = { kind: 'reply', boardId: INPUTS.boardId, threadId: INPUTS.threadId } as const;

    const post = (await PacketBuilder.verifyAndDecrypt(packet, threadKey, ctx, new CryptoEngine()))!;
    expect(post).not.toBeNull();
    expect(post.content).toBe(INPUTS.post.content);
    expect(post.created_at).toBe(packet.timestamp);
    expect(post.board_id).toBe(INPUTS.boardId);
    expect(post.thread_id).toBe(INPUTS.threadId);
    expect(post.parents).toEqual(INPUTS.post.parents);
    expect(post.post_type).toBe(INPUTS.post.postType);
    // トリップ有りの投稿はセッション鍵を載せない
    expect(post.session_pubkey).toBeNull();
    expect(toHex(post.trip_pubkey!)).toBe(pb.tripPubkey);

    // トリップ無し: 署名ブロックはセッション鍵
    const sp = packetFromJson(pb.sessionPacket);
    expect(PacketValidator.check(sp, { now: sp.timestamp })).toEqual({ ok: true });
    expect(toHex(encodePacket(sp))).toBe(pb.encodedSessionPacket);
    const sessionPost = (await PacketBuilder.verifyAndDecrypt(sp, threadKey, ctx, new CryptoEngine()))!;
    expect(toHex(sessionPost.session_pubkey!)).toBe(pb.sessionPubkey);
    expect(sessionPost.trip_pubkey).toBeNull();
    // 付帯は同じ (署名ブロックは常に 96 バイト)
    expect(fromHex(pb.encodedSessionPacket).length).toBe(fromHex(pb.encodedPacket).length);

    // スレ立て: 板の鍵・tag は板の週ごとの値・age は投稿日 − その週の月曜 (0..6)
    const mp = packetFromJson(pb.metaPacket);
    expect(PacketValidator.check(mp, { now: mp.timestamp })).toEqual({ ok: true });
    expect({ tag: mp.tag, age: mp.age }).toEqual(metaTagAge(fromHex(pb.boardKey), mp.timestamp));
    expect(toHex(encodePacket(mp))).toBe(pb.encodedMetaPacket);
    const meta = (await PacketBuilder.verifyAndDecrypt(mp, fromHex(pb.boardKey), { kind: 'meta', boardId: INPUTS.boardId }, new CryptoEngine()))!;
    expect(meta.post_type).toBe(1);
    expect(meta.thread_id).toBe(INPUTS.threadId);
    expect(meta.content).toBe('ゴールデンなスレタイ');
  });

  it('PacketBuilder: 別のスレッド鍵では、tag の足切り / SIV の段階で弾かれる', async () => {
    const packet = packetFromJson(stored.packetBuilder.packet);
    const wrongKey = KeyManager.deriveThreadKey(fromHex(stored.keyManager.boardKey), 'other-thread');
    expect(await PacketBuilder.verifyAndDecrypt(
      packet, wrongKey, { kind: 'reply', boardId: INPUTS.boardId, threadId: INPUTS.threadId }, new CryptoEngine(),
    )).toBeNull();
  });

  it('Onion: 保存済みセルを Guard → Exit の順に剥がすと出口の指示が出てくる', () => {
    const o = stored.onion;
    const cell = fromHex(o.cell);
    expect(cell.length).toBe(OnionRouter.CELL_SIZE);
    expect(toHex(cell.subarray(0, 2))).toBe('a55a');
    expect(o.hops).toHaveLength(2);

    const [guard, exit] = o.hops.map(h => sodium.crypto_sign_seed_keypair(fromHex(h.seed)));
    const layer1 = OnionRouter.unwrap(cell, guard.publicKey, guard.privateKey);
    expect(layer1?.type).toBe('relay');
    if (layer1?.type !== 'relay') throw new Error('unreachable');
    expect(layer1.nextHop).toBe(o.hops[1].peerId);
    // Guard に見える内側は常に固定長の封印済み出口層
    expect(layer1.innerOnion.byteLength).toBe(SEALED_EXIT_LAYER_SIZE);
    // ★ 実データ長 (ヘッダの L) も中身に依らず固定: cover (drop) と同じ長さ
    const cover = OnionRouter.wrapCircuit({ type: 'drop' }, o.hops.map(h => ({ peerId: h.peerId, pubkey: fromHex(h.pubkey) })));
    expect(cellInnerLength(cell)).toBe(cellInnerLength(cover));

    const layer2 = OnionRouter.unwrap(OnionRouter.padCell(layer1.innerOnion), exit.publicKey, exit.privateKey);
    expect(layer2).toEqual({ type: 'frag', id: new Uint8Array(8).fill(0x9a), idx: 1, total: 3, data: fromHex(o.fragData) });

    // 出口の鍵で外殻は開けない (順序が逆)
    expect(OnionRouter.unwrap(cell, exit.publicKey, exit.privateKey)).toBeNull();
  });

  it('Onion: 決定的パディングの先頭はマジック + 長さ + 実データ', () => {
    expect(stored.onion.paddedCellPrefix).toBe(
      'a55a' + (19).toString(16).padStart(4, '0') + toHex(enc.encode('golden cell payload')),
    );
  });
});

/** セルの長さフィールドを返す (読みやすさのため) */
function cellInnerLength(cell: Uint8Array): number {
  return (cell[2] << 8) | cell[3];
}

describe('保存済みフレームを WireCodec.decode で読める', () => {
  it('全フレームの先頭バイトが WireType で、decode でき、種別が一致する', () => {
    for (const [name, f] of Object.entries(stored.wire.frames)) {
      const bytes = fromHex(f.hex);
      expect(bytes[0], name).toBe(f.type);
      expect(WireCodec.decode(bytes).type, name).toBe(f.type);
    }
  });

  it('HELLO: 型 1 バイト + challenge 32 バイト (固定レイアウト)', () => {
    const { payload } = WireCodec.decode(frame('hello'));
    expect(toHex(payload.challenge)).toBe(stored.join.challenge);
    expect(stored.wire.frames.hello.hex).toBe('17' + stored.join.challenge);
  });

  it('JOIN: pubkey 32 ‖ powCounter u32 ‖ 署名 64 の固定長。復元した claim が今の検証器で受理される', () => {
    const { type, payload } = WireCodec.decode(frame('join'));
    expect(type).toBe(WireType.JOIN);
    expect(fromHex(stored.wire.frames.join.hex).length).toBe(1 + 32 + 4 + 64);
    const claim = {
      peerId: NodeIdentity.derivePeerId(payload.pubkey),
      pubkey: payload.pubkey,
      powCounter: payload.powCounter,
      challenge: fromHex(stored.join.challenge),
      signature: payload.signature,
    };
    const binding = stored.join.binding;
    expect(NodeIdentity.verifySignedClaim(claim, fromHex(stored.join.challenge), binding, NODE_ID_POW_FAST)).toBe(true);
    // 束縛 (DTLS 指紋) が 1 文字でも違えば受理しない
    expect(NodeIdentity.verifySignedClaim(
      claim, fromHex(stored.join.challenge), { ...binding, verifierFingerprint: binding.signerFingerprint }, NODE_ID_POW_FAST,
    )).toBe(false);
  });

  it('PING / PONG: nonce u32 (時計ではない)', () => {
    expect(WireCodec.decode(frame('ping')).payload.nonce).toBe(0xdeadbeef);
    expect(WireCodec.decode(frame('pong')).payload.nonce).toBe(0xdeadbeef);
    expect(stored.wire.frames.ping.hex).toBe('12deadbeef');
  });

  it('PEX_RESPONSE: pubkey と powCounter だけ (peerId は pubkey から導出する)。position も zones も無い', () => {
    const { payload } = WireCodec.decode(frame('pexResponse'));
    expect(payload.peers).toHaveLength(1);
    expect(payload.peers[0]).not.toHaveProperty('position');
    expect(payload.peers[0]).not.toHaveProperty('zones');
    expect(toHex(payload.peers[0].pubkey)).toBe(stored.nodeIdentity.pubkey);
    expect(payload.peers[0].powCounter).toBe(stored.nodeIdentity.nodeIdPowFast.counter);
  });

  it('GOSSIP / STEM: 中継途中のパケットが検証器を通り、STEM にホップカウンタが無い', () => {
    const g = WireCodec.decode(frame('gossip')).payload.packet;
    expect(g.packet_id).toBe(stored.gossipPow.packetId);
    expect(g).not.toHaveProperty('hop_count');
    expect(PacketValidator.check(g, { now: g.timestamp })).toEqual({ ok: true });

    const s = WireCodec.decode(frame('stem')).payload;
    // Stem は { item: ExitItem } だけ。ホップ数・TTL は載せない (Fluff 地点までの距離が漏れる)
    expect(Object.keys(s).sort()).toEqual(['item']);
    expect(s.item.type).toBe('exit_fluff');
    expect(s.item.packet.tag).toBe(stored.gossipPow.header.tag);
    expect(s.item).not.toHaveProperty('stemTtl');
    expect(s.item).not.toHaveProperty('stem_ttl');
    expect(PacketValidator.check(s.item.packet, { now: s.item.packet.timestamp })).toEqual({ ok: true });
  });

  it('ONION_STEM: onionBytes が CELL_SIZE ちょうど', () => {
    const { payload } = WireCodec.decode(frame('onionStem'));
    expect(payload.onionBytes).toBeInstanceOf(Uint8Array);
    expect(payload.onionBytes.byteLength).toBe(OnionRouter.CELL_SIZE);
    expect(toHex(payload.onionBytes)).toBe(stored.onion.cell);
  });

  it('CATCHUP_REQ / DATA / END: 中身は同一で、DATA の各パケットは検証を通り (時刻は追いつきの上限まで)、元の packet_id に戻る', () => {
    const req = WireCodec.decode(frame('catchupReq')).payload;
    expect(req).toEqual({ since: INPUTS.catchupSince });
    const end = WireCodec.decode(frame('catchupEnd')).payload;
    expect(end).toEqual({ status: 1, nextSince: INPUTS.catchupNextSince });

    const { packets } = WireCodec.decode(frame('catchupData')).payload;
    expect(packets).toHaveLength(2);
    const now = OZ_EPOCH_MS + stored.gossipPow.header.time * 60_000;
    const p = decodePacket(packets[0])!;
    expect(p.packet_id).toBe(stored.gossipPow.packetId);
    expect(PacketValidator.check(p, { now: now + 72 * 3600_000, maxPastMs: 72 * 3600_000 + 15 * 60_000 })).toEqual({ ok: true });
    // 2 件目は途中で切れたパケット: decode できない (受け手が捨てる)
    expect(decodePacket(packets[1])).toBeNull();
  });

  it('SDP_RELAY / ICE_RELAY の中身', () => {
    const sdp = WireCodec.decode(frame('sdpRelay')).payload;
    expect(sdp.sdp).toEqual({ type: 'offer', sdp: 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n' });
    const ice = WireCodec.decode(frame('iceRelay')).payload;
    expect(ice.candidate.sdpMLineIndex).toBe(0);
  });
});

/**
 * フレーム長の予算。
 *
 * PeerManager は WireType ごとにフレーム長の上限を持ち (MAX_FRAME_BYTES, 非公開)、
 * ChunkedSender は 4096 バイトを超えるものを分割する。正規のメッセージが
 * これらに収まらないと、送った瞬間に相手に捨てられる / セルが分割されて
 * 固定長セルの意味が無くなる。値は src の定数を写したもの。
 */
/** 最大サイズのパケット (検証は通らないが、符号化の長さを測るには足りる) */
const maxPacket = () => ({
  packet_id: 'f'.repeat(32), timestamp: OZ_EPOCH_MS + 0xffffff * 60_000, tag: 0x0fff, age: 90, effort_exp: 80,
  pow_nonce: 0xffffffff, pow_solution: new Uint8Array(16), payload: new Uint8Array(POW_POLICY.MAX_PAYLOAD_SIZE),
});

describe('正規のフレームが上限に収まる', () => {
  const LIMITS = { HELLO: 256, JOIN: 1024, PING: 256, PONG: 256, ONION_STEM: 4096, GOSSIP: 8192, STEM: 8192, PEX_REQUEST: 256, PEX_RESPONSE: 4096, CATCHUP_REQ: 16, CATCHUP_DATA: 16 * 1024, CATCHUP_END: 16, LEASESET: 1 + 445, LEASESET_SYNC_REQ: 1, LEASESET_SYNC: 16 * 1024, TUNNEL_REGISTER: 9, TUNNEL_REGISTERED: 10, TUNNEL_SEND: 16 * 1024, TUNNEL_FWD: 16 * 1024, TUNNEL_DELIVER: 16 * 1024, TUNNEL_REPLY: 16 * 1024, TUNNEL_RET: 16 * 1024, TUNNEL_RESULT: 16 * 1024, TUNNEL_ERROR: 6 };
  const CHUNK_SIZE = 4096;

  it('ベクタの各フレームが WireType ごとの上限以下', () => {
    for (const [name, f] of Object.entries(stored.wire.frames)) {
      const typeName = Object.entries(stored.constants.wireTypes).find(([, v]) => v === f.type)![0];
      const limit = (LIMITS as Record<string, number>)[typeName];
      if (limit !== undefined) expect(f.hex.length / 2, name).toBeLessThanOrEqual(limit);
    }
  });

  it('★ONION_STEM は 1 フレームに収まり、分割されない (固定長セルの前提)', () => {
    const len = stored.wire.frames.onionStem.hex.length / 2;
    expect(len).toBeLessThanOrEqual(CHUNK_SIZE);
    // 中身に依らずフレーム長は一定 (セルが固定長なので)
    expect(len).toBe(WireCodec.encode(WireType.ONION_STEM, { onionBytes: new Uint8Array(OnionRouter.CELL_SIZE) }).length);
  });

  it('最大サイズの投稿 (payload MAX_PAYLOAD_SIZE) を載せた GOSSIP / STEM も上限以下', () => {
    const pkt = maxPacket();
    expect(WireCodec.encode(WireType.GOSSIP, { packet: pkt }).length).toBeLessThanOrEqual(LIMITS.GOSSIP);
    expect(WireCodec.encode(WireType.STEM, { item: { type: 'exit_fluff', packet: pkt } }).length).toBeLessThanOrEqual(LIMITS.STEM);
  });

  it('上限件数 (8 件) の PEX_RESPONSE も上限以下', () => {
    const peers = Array.from({ length: 8 }, () => ({ id: 'f'.repeat(32), pubkey: new Uint8Array(32), powCounter: 0xffffffff }));
    expect(WireCodec.encode(WireType.PEX_RESPONSE, { peers }).length).toBeLessThanOrEqual(LIMITS.PEX_RESPONSE);
  });

  it('最大の出口指示 (最大の投稿) は 3 枚の断片に収まり、それぞれ 1 枚のセルで回路が組める', () => {
    const kps = [0x61, 0x62].map(b => seededKeyPair(b));
    const hops = kps.map(kp => ({ peerId: NodeIdentity.derivePeerId(kp.publicKey), pubkey: kp.publicKey }));
    const pkt = maxPacket();
    const bytes = encodeExitItem({ type: 'exit_fluff', packet: pkt });
    const frags = splitIntoFragments(bytes, new Uint8Array(8))!;
    expect(frags).not.toBeNull();
    expect(frags.length).toBeLessThanOrEqual(3);
    for (const f of frags) {
      const cell = OnionRouter.wrapCircuit(f, hops);
      expect(cell.length).toBe(OnionRouter.CELL_SIZE);
      const outer = OnionRouter.unwrap(cell, kps[0].publicKey, kps[0].privateKey);
      expect(outer?.type).toBe('relay');
      const exit = OnionRouter.unwrap(OnionRouter.padCell((outer as any).innerOnion), kps[1].publicKey, kps[1].privateKey);
      expect(exit?.type).toBe('frag');
    }
  });
});

describe('ExitItem (回路の中の 1 件) のコンパクト形式', () => {
  it('保存済みのバイト列が decode でき、再符号化すると完全一致する', () => {
    const e = stored.exitItems;
    const item = decodeExitItem(fromHex(e.fluff));
    expect(item).not.toBeNull();
    expect(toHex(encodeExitItem(item!))).toBe(e.fluff);
    expect(item!.packet.packet_id).toBe(stored.gossipPow.packetId);
    expect(fromHex(e.fluff)[0]).toBe(1);
    // 旧 Slot / Hint の種別 (flags 付きの fluff・kind 2) は読めない
    expect(decodeExitItem(Uint8Array.of(2, ...new Uint8Array(91)))).toBeNull();
  });
});

describe('Base64URL (鍵の URL 表現)', () => {
  it('板鍵の Base64URL 表現が固定値 (パディング無し・URL 安全)', () => {
    const key = fromHex(stored.keyManager.boardKey);
    expect(KeyManager.toBase64(key)).toBe('QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI');
    expect(toHex(KeyManager.fromBase64('QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI'))).toBe(stored.keyManager.boardKey);
  });

  it('★回帰: 大きな入力 (1MB, 0x8000 区切りの境界を含む) でもスタックを使い切らずに往復する', () => {
    for (const n of [0x8000 - 1, 0x8000, 0x8000 + 1, 0x8000 * 3, 1024 * 1024 + 7]) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (i * 131 + (i >> 8)) & 0xff;
      const b64 = Encoding.toBase64(bytes);
      expect(b64.length, `n=${n}`).toBe(Math.ceil((n * 4) / 3));
      expect(b64).toMatch(/^[A-Za-z0-9_-]*$/);
      // 大きな配列の toEqual は遅いので Buffer で比べる
      expect(Buffer.from(Encoding.fromBase64(b64)).equals(Buffer.from(bytes)), `n=${n}`).toBe(true);
      // 区切って変換しても、標準の Base64 と同じ内容になる
      expect(b64).toBe(Buffer.from(bytes).toString('base64url'));
    }
  });
});
