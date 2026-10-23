import { describe, it, expect } from 'vitest';
import { encode as msgpackEncode } from '@msgpack/msgpack';
import { WireCodec, MAX_PEX_ENTRIES, MAX_SDP_BYTES, MAX_ICE_CANDIDATE_BYTES } from '../../src/network/wire/WireCodec';
import { WireType } from '../../src/network/wire/WireTypes';
import { MAX_FRAME_BYTES } from '../../src/network/PeerManager';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { encodePacket, decodePacket } from '../../src/crypto/PacketCodec';
import { signLeaseSet } from '../../src/network/storage/LeaseSet';
import { encodeExitItem } from '../../src/crypto/ExitItem';
import type { GossipPacket } from '../../src/types';

await sodiumReady;

/**
 * 往復できる GossipPacket。packet_id は decode が導出するので、いったん符号化して読み戻した値を使う
 * (パケット形式は PacketCodec の持ち物。ここは WireCodec が中身を不透明に運ぶことだけを見る)。
 */
function samplePacket(): GossipPacket {
  const raw = {
    packet_id: '', timestamp: 1_800_000_000_000, tag: 3, age: 0, effort_exp: 12, pow_nonce: 99,
    pow_solution: new Uint8Array(16).fill(5), payload: new Uint8Array(100).fill(9),
  } as GossipPacket;
  return decodePacket(encodePacket(raw))!;
}
const SAMPLE_PACKET = samplePacket();

const PUBKEY = new Uint8Array(32).fill(1);
const SAMPLE_LEASESET = signLeaseSet(
  {
    sid: PUBKEY,
    slots: [{ nonce: 7, solution: new Uint8Array(16).fill(4) }],
    gateway: 'ab'.repeat(16),
    tunnelId: new Uint8Array(8).fill(2),
    expiresMin: 123456,
  },
  () => new Uint8Array(64).fill(9),
);
const PEER_A = 'a'.repeat(32);
const PEER_B = '0123456789abcdef0123456789abcdef';
const ALL_TYPES = Object.values(WireType).filter(
  (v): v is WireType => typeof v === 'number' && v !== WireType.UNKNOWN,
);

/** 各 WireType の代表的なペイロード (実際の送信側と同じ形) */
const SAMPLE_PAYLOADS: Record<number, any> = {
  [WireType.HELLO]: { challenge: new Uint8Array(32).fill(7) },
  [WireType.JOIN]: { pubkey: PUBKEY, powCounter: 12345, signature: new Uint8Array(64).fill(3) },
  [WireType.PING]: { nonce: 4_000_000_000 },
  [WireType.PONG]: { nonce: 1 },
  [WireType.PEX_REQUEST]: {},
  [WireType.PEX_RESPONSE]: { peers: [{ id: NodeIdentity.derivePeerId(PUBKEY), pubkey: PUBKEY, powCounter: 0 }] },
  [WireType.SDP_RELAY]: { targetPeerId: PEER_A, senderId: PEER_B, sdp: { type: 'answer', sdp: 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n日本語' } },
  [WireType.ICE_RELAY]: {
    targetPeerId: PEER_A, senderId: PEER_B,
    candidate: { candidate: 'candidate:1 1 udp 2113937151 192.0.2.1 5000 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 'abcd' },
  },
  [WireType.GOSSIP]: { packet: SAMPLE_PACKET },
  [WireType.STEM]: { item: { type: 'exit_fluff', packet: SAMPLE_PACKET } },
  [WireType.ONION_STEM]: { onionBytes: new Uint8Array(1200).fill(0xa5) },
  [WireType.CATCHUP_REQ]: { since: 0xabcdef },
  [WireType.CATCHUP_DATA]: { packets: [encodePacket(SAMPLE_PACKET), new Uint8Array([1, 2, 3])] },
  [WireType.CATCHUP_END]: { status: 1, nextSince: 0x010203 },
  [WireType.LEASESET]: { leaseSet: SAMPLE_LEASESET },
  [WireType.LEASESET_SYNC_REQ]: {},
  [WireType.LEASESET_SYNC]: { leaseSets: [SAMPLE_LEASESET, SAMPLE_LEASESET] },
  [WireType.TUNNEL_REGISTER]: { tunnelId: new Uint8Array(8).fill(6) },
  [WireType.TUNNEL_REGISTERED]: { tunnelId: new Uint8Array(8).fill(6), ok: true },
  [WireType.TUNNEL_SEND]: { reqId: 0xfedcba98, gateway: PEER_A, tunnelId: new Uint8Array(8).fill(6), body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_FWD]: { returnTag: 0xfedcba98, tunnelId: new Uint8Array(8).fill(6), body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_DELIVER]: { returnTag: 0xfedcba98, fromHop: PEER_B, body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_REPLY]: { returnTag: 0xfedcba98, toHop: PEER_B, seq: 513, final: true, body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_RET]: { returnTag: 0xfedcba98, seq: 513, final: false, body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_RESULT]: { reqId: 0xfedcba98, seq: 513, final: true, body: new Uint8Array(100).fill(8) },
  [WireType.TUNNEL_ERROR]: { id: 0xfedcba98, code: 4 },
  [WireType.OZZY_REPLY]: { header: new Uint8Array(68).fill(5), seq: 513, final: true, body: new Uint8Array(100).fill(9) },
  [WireType.OZZY_RESULT]: { replyId: 0xfedcba98, seq: 513, final: false, body: new Uint8Array(100).fill(9) },
  [WireType.OZZY_UP]: { header: new Uint8Array(80).fill(6), seq: 514, final: false, body: new Uint8Array(100).fill(9) },
  [WireType.OZZY_UP_FWD]: { uploadId: new Uint8Array(16).fill(7), seq: 515, final: true, body: new Uint8Array(100).fill(9) },
  [WireType.OZZY_WORKER_REQ]: {},
  [WireType.OZZY_WORKER_ADS]: { ads: [{ pubkey: PUBKEY, powCounter: 7, expiresMin: 29_000_000, url: 'https://ozzy.a.workers.dev', signature: new Uint8Array(64).fill(4) }] },
};

const frame = (t: WireType, p = SAMPLE_PAYLOADS[t]) => WireCodec.encode(t, p);
const bad = { type: WireType.UNKNOWN, payload: null };

describe('WireType の表', () => {
  it('撤去した型 (RING_INFO / LOCAL_LINK_* / HINT / HINT_STEM / DHT_*) は無い', () => {
    const names = ALL_TYPES.map(t => WireType[t]);
    for (const dead of ['RING_INFO', 'LOCAL_LINK_REQ', 'LOCAL_LINK_ACK', 'LOCAL_LINK_REJ', 'HINT', 'HINT_STEM', 'DHT_PUT', 'DHT_GET', 'DHT_RES', 'DHT_PUT_STEM']) {
      expect(names).not.toContain(dead);
    }
    for (const b of [0x11, 0x14, 0x15, 0x16, 0x42, 0x43, 0x50, 0x51, 0x52, 0x53]) {
      expect(WireCodec.decode(Uint8Array.of(b, 0, 0, 0, 0)).type, `0x${b.toString(16)}`).toBe(WireType.UNKNOWN);
    }
  });
});

describe('WireCodec.encode: フレームの形 (固定レイアウト)', () => {
  it('HELLO = [0x17] + challenge 32 (33 バイト)', () => {
    const f = frame(WireType.HELLO);
    expect(f.length).toBe(33);
    expect(f[0]).toBe(0x17);
    expect(Array.from(f.subarray(1))).toEqual(Array(32).fill(7));
  });

  it('JOIN = [0x10] + pubkey 32 + powCounter u32 (BE) + 署名 64 (101 バイト)。peerId と challenge は載らない', () => {
    const f = frame(WireType.JOIN);
    expect(f.length).toBe(101);
    expect(Array.from(f.subarray(33, 37))).toEqual([0, 0, 0x30, 0x39]);
    expect(Array.from(f.subarray(37))).toEqual(Array(64).fill(3));
  });

  it('PING / PONG = 型 + u32 nonce (5 バイト)', () => {
    expect(Array.from(frame(WireType.PING))).toEqual([0x12, 0xee, 0x6b, 0x28, 0x00]);
    expect(frame(WireType.PONG).length).toBe(5);
  });

  it('PEX_REQUEST は型だけ (1 バイト)。PEX_RESPONSE は 2 + 36 × 件数', () => {
    expect(Array.from(frame(WireType.PEX_REQUEST))).toEqual([0x20]);
    expect(frame(WireType.PEX_RESPONSE).length).toBe(2 + 36);
  });

  it('GOSSIP / STEM / ONION_STEM の本体は中身のバイト列そのまま (ヘッダ 1 バイトだけ増える)', () => {
    expect(Array.from(frame(WireType.GOSSIP).subarray(1))).toEqual(Array.from(encodePacket(SAMPLE_PACKET)));
    const item = SAMPLE_PAYLOADS[WireType.STEM].item;
    expect(Array.from(frame(WireType.STEM).subarray(1))).toEqual(Array.from(encodeExitItem(item)));
    const f = frame(WireType.ONION_STEM);
    expect(f.length).toBe(1201);
    expect(f[1]).toBe(0xa5);
  });

  it('フレームは msgpack でも JSON でもない: フィールド名の文字列を含まない', () => {
    for (const t of ALL_TYPES) {
      const text = Buffer.from(frame(t)).toString('latin1');
      for (const name of ['type', 'challenge', 'pubkey', 'powCounter', 'signature', 'peerId', 'targetPeerId', 'packet', 'onionBytes']) {
        expect(text, `${WireType[t]} contains ${name}`).not.toContain(name);
      }
    }
  });

  it('CATCHUP_REQ = [0x60] + since u24 (4 バイト)。CATCHUP_END = [0x62] + status u8 + nextSince u24 (5 バイト)', () => {
    expect(Array.from(frame(WireType.CATCHUP_REQ))).toEqual([0x60, 0xab, 0xcd, 0xef]);
    expect(Array.from(frame(WireType.CATCHUP_END))).toEqual([0x62, 1, 0x01, 0x02, 0x03]);
  });

  it('CATCHUP_DATA = [0x61] + 件数 u16 + { 長さ u16 + パケット } × 件数', () => {
    const f = frame(WireType.CATCHUP_DATA);
    const p = encodePacket(SAMPLE_PACKET);
    expect(f.length).toBe(1 + 2 + (2 + p.length) + (2 + 3));
    expect(Array.from(f.subarray(1, 3))).toEqual([0, 2]);
    expect(Array.from(f.subarray(3, 5))).toEqual([p.length >> 8, p.length & 0xff]);
    expect(Array.from(f.subarray(5, 5 + p.length))).toEqual(Array.from(p));
  });

  it('LEASESET = [0x70] + leaseSet そのまま (1 枠で 146 バイト)。SYNC_REQ は型だけ。SYNC = [0x72] + 件数 u16 + { 長さ u16 + leaseSet } × 件数', () => {
    expect(SAMPLE_LEASESET.length).toBe(145);
    const f = frame(WireType.LEASESET);
    expect(f.length).toBe(146);
    expect(f[0]).toBe(0x70);
    expect(Array.from(f.subarray(1))).toEqual(Array.from(SAMPLE_LEASESET));
    expect(Array.from(frame(WireType.LEASESET_SYNC_REQ))).toEqual([0x71]);
    const s = frame(WireType.LEASESET_SYNC);
    expect(s.length).toBe(1 + 2 + 2 * (2 + 145));
    expect(Array.from(s.subarray(0, 5))).toEqual([0x72, 0, 2, 0, 145]);
  });

  it('LEASESET の長さ違反 (短い・長い・件数の余り) は decode で UNKNOWN、encode は RangeError', () => {
    expect(WireCodec.decode(Uint8Array.of(0x70, 1, 2, 3))).toEqual(bad);
    expect(WireCodec.decode(new Uint8Array(1 + 446).fill(1).map((v, i) => (i === 0 ? 0x70 : v)))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x71, 0))).toEqual(bad);
    const s = frame(WireType.LEASESET_SYNC);
    expect(WireCodec.decode(s.subarray(0, s.length - 1))).toEqual(bad);
    expect(WireCodec.decode(new Uint8Array([...s, 0]))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x72, 0, 1, 0, 3, 1, 2, 3))).toEqual(bad); // 中の leaseSet が短すぎる
    expect(() => WireCodec.encode(WireType.LEASESET, { leaseSet: new Uint8Array(10) })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.LEASESET_SYNC, { leaseSets: Array.from({ length: 120 }, () => SAMPLE_LEASESET) })).toThrow(RangeError);
  });

  it('TUNNEL_* のレイアウト: 固定部 + body。u32 / u16 はビッグエンディアン、flags の bit0 = final', () => {
    expect(Array.from(frame(WireType.TUNNEL_REGISTER))).toEqual([0x80, 6, 6, 6, 6, 6, 6, 6, 6]);
    expect(Array.from(frame(WireType.TUNNEL_REGISTERED))).toEqual([0x81, 6, 6, 6, 6, 6, 6, 6, 6, 1]);
    const send = frame(WireType.TUNNEL_SEND);
    expect(send.length).toBe(1 + 4 + 16 + 8 + 100);
    expect(Array.from(send.subarray(0, 5))).toEqual([0x82, 0xfe, 0xdc, 0xba, 0x98]);
    expect(Array.from(send.subarray(5, 21))).toEqual(Array(16).fill(0xaa)); // gateway は生の 16 バイト
    expect(frame(WireType.TUNNEL_FWD).length).toBe(1 + 4 + 8 + 100);
    expect(frame(WireType.TUNNEL_DELIVER).length).toBe(1 + 4 + 16 + 100);
    const reply = frame(WireType.TUNNEL_REPLY);
    expect(reply.length).toBe(1 + 4 + 16 + 2 + 1 + 100);
    expect(Array.from(reply.subarray(21, 24))).toEqual([0x02, 0x01, 0x01]); // seq 513, flags = final
    expect(Array.from(frame(WireType.TUNNEL_RET).subarray(5, 8))).toEqual([0x02, 0x01, 0x00]);
    expect(frame(WireType.TUNNEL_RESULT).length).toBe(1 + 4 + 2 + 1 + 100);
    expect(Array.from(frame(WireType.TUNNEL_ERROR))).toEqual([0x88, 0xfe, 0xdc, 0xba, 0x98, 4]);
    // peerId は 16 バイトの生で運ぶ (hex の 32 文字ではない)
    for (const f of [send, reply]) expect(Buffer.from(f).toString('latin1')).not.toContain('a'.repeat(32));
  });

  it('TUNNEL_* の範囲違反: 空の body・16KiB 超・予約ビット・id / code の不正は拒否する', () => {
    const body = (n: number) => new Uint8Array(n).fill(1);
    const reply = SAMPLE_PAYLOADS[WireType.TUNNEL_REPLY];
    expect(() => WireCodec.encode(WireType.TUNNEL_REPLY, { ...reply, body: new Uint8Array(0) })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.TUNNEL_REPLY, { ...reply, body: body(16 * 1024) })).toThrow(RangeError);
    const maxBody = 16 * 1024 - (1 + 4 + 16 + 2 + 1);
    expect(WireCodec.encode(WireType.TUNNEL_REPLY, { ...reply, body: body(maxBody) }).length).toBe(16 * 1024);
    expect(() => WireCodec.encode(WireType.TUNNEL_REPLY, { ...reply, seq: 0x10000 })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.TUNNEL_SEND, { ...SAMPLE_PAYLOADS[WireType.TUNNEL_SEND], reqId: 2 ** 32 })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.TUNNEL_SEND, { ...SAMPLE_PAYLOADS[WireType.TUNNEL_SEND], gateway: 'zz' })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.TUNNEL_ERROR, { id: 1, code: 0 })).toThrow(RangeError);
    // decode: 予約ビット・空の body・切り詰め・余りバイト・code 0 は UNKNOWN
    const r = frame(WireType.TUNNEL_REPLY).slice();
    r[23] = 0x03;
    expect(WireCodec.decode(r)).toEqual(bad);
    expect(WireCodec.decode(frame(WireType.TUNNEL_REPLY).subarray(0, 24))).toEqual(bad); // body が空
    expect(WireCodec.decode(frame(WireType.TUNNEL_SEND).subarray(0, 20))).toEqual(bad);
    expect(WireCodec.decode(new Uint8Array([...frame(WireType.TUNNEL_ERROR), 0]))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x88, 0, 0, 0, 1, 0))).toEqual(bad);
    expect(WireCodec.decode(new Uint8Array([...frame(WireType.TUNNEL_REGISTER), 0]))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x81, 1, 2, 3, 4, 5, 6, 7, 8, 2))).toEqual(bad);
    expect(WireCodec.decode(new Uint8Array(16 * 1024 + 1).map((_, i) => (i === 0 ? 0x86 : 1)))).toEqual(bad);
  });

  it('CATCHUP の範囲違反は encode が RangeError (u24 超え・未知の status・16KiB 超えのフレーム)', () => {
    expect(() => WireCodec.encode(WireType.CATCHUP_REQ, { since: 0x1000000 })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.CATCHUP_REQ, { since: -1 })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.CATCHUP_END, { status: 9, nextSince: 0 })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.CATCHUP_DATA, { packets: Array.from({ length: 9 }, () => new Uint8Array(2000)) })).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.CATCHUP_DATA, { packets: [new Uint8Array(0)] })).toThrow(RangeError);
  });

  it('呼び出し側のペイロードを書き換えない / 同じ入力からは同じバイト列', () => {
    for (const t of ALL_TYPES) {
      const payload = SAMPLE_PAYLOADS[t];
      const snapshot = JSON.stringify(payload, (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
      const a = WireCodec.encode(t, payload);
      expect(JSON.stringify(payload, (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v))).toBe(snapshot);
      expect(WireCodec.encode(t, payload)).toEqual(a);
    }
  });
});

describe('WireCodec.decode: 全 WireType の往復', () => {
  it('サンプルが全 WireType を網羅している', () => {
    for (const t of ALL_TYPES) expect(SAMPLE_PAYLOADS[t], `0x${t.toString(16)}`).toBeDefined();
  });

  for (const t of ALL_TYPES) {
    it(`0x${t.toString(16)} (${WireType[t]}) が型・中身ともに往復する`, () => {
      const decoded = WireCodec.decode(frame(t));
      expect(decoded.type).toBe(t);
      expect(decoded.payload).toEqual(SAMPLE_PAYLOADS[t]);
    });
  }

  it('JOIN: 余計なフィールド (peerId など) を渡しても載せない', () => {
    const f = WireCodec.encode(WireType.JOIN, { ...SAMPLE_PAYLOADS[WireType.JOIN], peerId: PEER_A, challenge: new Uint8Array(32) });
    expect(f.length).toBe(101);
    expect(WireCodec.decode(f).payload).toEqual(SAMPLE_PAYLOADS[WireType.JOIN]);
  });

  it('JOIN: powCounter は u32 の全域 (0 と 0xFFFFFFFF) が往復する。範囲外は符号化できない', () => {
    for (const powCounter of [0, 1, 0xffff, 0x10000, 0xffffffff]) {
      const p = { ...SAMPLE_PAYLOADS[WireType.JOIN], powCounter };
      expect(WireCodec.decode(WireCodec.encode(WireType.JOIN, p)).payload.powCounter).toBe(powCounter);
    }
    for (const powCounter of [-1, 0x100000000, 1.5, NaN, '1']) {
      expect(() => WireCodec.encode(WireType.JOIN, { ...SAMPLE_PAYLOADS[WireType.JOIN], powCounter })).toThrow(RangeError);
    }
  });

  it('PING / PONG: nonce は u32 の全域が往復する', () => {
    for (const t of [WireType.PING, WireType.PONG]) {
      for (const nonce of [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]) {
        expect(WireCodec.decode(WireCodec.encode(t, { nonce })).payload).toEqual({ nonce });
      }
      expect(() => WireCodec.encode(t, { nonce: -1 })).toThrow(RangeError);
      expect(() => WireCodec.encode(t, { nonce: 2 ** 32 })).toThrow(RangeError);
    }
  });

  it('バイト列フィールドは Uint8Array として戻り、入力フレームのバッファを共有しない (HELLO / JOIN)', () => {
    const f = frame(WireType.JOIN);
    const { payload } = WireCodec.decode(f);
    expect(payload.pubkey).toBeInstanceOf(Uint8Array);
    f.fill(0);
    expect(Array.from(payload.pubkey)).toEqual(Array(32).fill(1));
  });

  it('subarray (オフセット付きビュー) でも正しく読める', () => {
    const f = frame(WireType.PING);
    const big = new Uint8Array(f.length + 10);
    big.set(f, 5);
    expect(WireCodec.decode(big.subarray(5, 5 + f.length))).toEqual({ type: WireType.PING, payload: { nonce: 4_000_000_000 } });
  });

  it('PEX_RESPONSE: id は pubkey から導出される (申告ではない)。0 件と 8 件が往復する', () => {
    const mk = (n: number) => Array.from({ length: n }, (_, i) => {
      const pubkey = new Uint8Array(32).fill(i + 1);
      return { id: NodeIdentity.derivePeerId(pubkey), pubkey, powCounter: i * 1000 };
    });
    for (const n of [0, 1, MAX_PEX_ENTRIES]) {
      const peers = mk(n);
      const f = WireCodec.encode(WireType.PEX_RESPONSE, { peers });
      expect(f.length).toBe(2 + 36 * n);
      expect(WireCodec.decode(f).payload).toEqual({ peers });
    }
  });

  it('PEX_RESPONSE: 送信側が id だけで claim を持たない項目は運ばない', () => {
    const f = WireCodec.encode(WireType.PEX_RESPONSE, { peers: [{ id: PEER_A }, { id: PEER_B, pubkey: PUBKEY, powCounter: 5 }] });
    expect(WireCodec.decode(f).payload.peers).toHaveLength(1);
    expect(() => WireCodec.encode(WireType.PEX_RESPONSE, { peers: Array.from({ length: 9 }, () => ({ id: PEER_A, pubkey: PUBKEY, powCounter: 1 })) })).toThrow(RangeError);
  });

  it('SDP_RELAY: 4 種の sdp type と日本語を含む本文、空の本文 (rollback) が往復する', () => {
    for (const type of ['offer', 'answer', 'pranswer', 'rollback']) {
      const p = { targetPeerId: PEER_A, senderId: PEER_B, sdp: { type, sdp: type === 'rollback' ? '' : 'v=0\r\n♥' } };
      expect(WireCodec.decode(WireCodec.encode(WireType.SDP_RELAY, p)).payload).toEqual(p);
    }
    expect(() => WireCodec.encode(WireType.SDP_RELAY, { ...SAMPLE_PAYLOADS[WireType.SDP_RELAY], sdp: { type: 'evil', sdp: '' } })).toThrow(RangeError);
  });

  it('ICE_RELAY: null の sdpMid / sdpMLineIndex / usernameFragment が保たれる', () => {
    const p = { targetPeerId: PEER_A, senderId: PEER_B, candidate: { candidate: 'candidate:x', sdpMid: null, sdpMLineIndex: null, usernameFragment: null } };
    expect(WireCodec.decode(WireCodec.encode(WireType.ICE_RELAY, p)).payload).toEqual(p);
    const q = { ...p, candidate: { ...p.candidate, sdpMid: '', sdpMLineIndex: 65534, usernameFragment: 'x'.repeat(254) } };
    expect(WireCodec.decode(WireCodec.encode(WireType.ICE_RELAY, q)).payload).toEqual(q);
  });

  it('SDP / ICE の上限 (MAX_SDP_BYTES / MAX_ICE_CANDIDATE_BYTES) ちょうどは通り、超えると符号化できない', () => {
    const sdp = { ...SAMPLE_PAYLOADS[WireType.SDP_RELAY] };
    expect(WireCodec.decode(WireCodec.encode(WireType.SDP_RELAY, { ...sdp, sdp: { type: 'offer', sdp: 'x'.repeat(MAX_SDP_BYTES) } })).type).toBe(WireType.SDP_RELAY);
    expect(() => WireCodec.encode(WireType.SDP_RELAY, { ...sdp, sdp: { type: 'offer', sdp: 'x'.repeat(MAX_SDP_BYTES + 1) } })).toThrow(RangeError);
    const ice = SAMPLE_PAYLOADS[WireType.ICE_RELAY];
    const withCand = (c: string) => ({ ...ice, candidate: { ...ice.candidate, candidate: c } });
    expect(WireCodec.decode(WireCodec.encode(WireType.ICE_RELAY, withCand('x'.repeat(MAX_ICE_CANDIDATE_BYTES)))).type).toBe(WireType.ICE_RELAY);
    expect(() => WireCodec.encode(WireType.ICE_RELAY, withCand('x'.repeat(MAX_ICE_CANDIDATE_BYTES + 1)))).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.ICE_RELAY, withCand(''))).toThrow(RangeError);
  });

  it('SDP / ICE の宛先 (peerId) は 32 文字の小文字 hex でなければ符号化できない', () => {
    for (const id of ['', 'A'.repeat(32), 'a'.repeat(31), 'g'.repeat(32), undefined]) {
      expect(() => WireCodec.encode(WireType.SDP_RELAY, { ...SAMPLE_PAYLOADS[WireType.SDP_RELAY], targetPeerId: id })).toThrow(RangeError);
      expect(() => WireCodec.encode(WireType.ICE_RELAY, { ...SAMPLE_PAYLOADS[WireType.ICE_RELAY], senderId: id })).toThrow(RangeError);
    }
  });

  it('最大の SDP_RELAY / ICE_RELAY / PEX_RESPONSE も、PeerManager の MAX_FRAME_BYTES に収まる', () => {
    const maxSdp = WireCodec.encode(WireType.SDP_RELAY, { ...SAMPLE_PAYLOADS[WireType.SDP_RELAY], sdp: { type: 'offer', sdp: 'あ'.repeat(Math.floor(MAX_SDP_BYTES / 3)) } });
    expect(maxSdp.length).toBeLessThanOrEqual(MAX_FRAME_BYTES[WireType.SDP_RELAY]!);
    const maxIce = WireCodec.encode(WireType.ICE_RELAY, {
      targetPeerId: PEER_A, senderId: PEER_B,
      candidate: { candidate: 'x'.repeat(MAX_ICE_CANDIDATE_BYTES), sdpMid: 'm'.repeat(254), sdpMLineIndex: 1, usernameFragment: 'u'.repeat(254) },
    });
    expect(maxIce.length).toBeLessThanOrEqual(MAX_FRAME_BYTES[WireType.ICE_RELAY]!);
    const maxPex = WireCodec.encode(WireType.PEX_RESPONSE, { peers: Array.from({ length: 8 }, () => ({ id: PEER_A, pubkey: PUBKEY, powCounter: 1 })) });
    expect(maxPex.length).toBe(MAX_FRAME_BYTES[WireType.PEX_RESPONSE]);
  });

  it('固定長の型は MAX_FRAME_BYTES がちょうど正規の長さ (余りバイトのあるフレームは入口で落ちる)', () => {
    for (const t of [WireType.HELLO, WireType.JOIN, WireType.PING, WireType.PONG, WireType.PEX_REQUEST, WireType.ONION_STEM]) {
      expect(frame(t).length, WireType[t]).toBe(MAX_FRAME_BYTES[t]);
    }
  });
});

describe('GOSSIP / STEM フレーム', () => {
  it('壊れた中身 (packet / item) は null になり、ハンドラが拒否する (フレーム自体は成立)', () => {
    for (const body of [[], [1, 2, 3], [0xff, 0xff]]) {
      const g = WireCodec.decode(Uint8Array.of(WireType.GOSSIP, ...body));
      expect(g.type).toBe(WireType.GOSSIP);
      expect(g.payload.packet).toBeNull();
      const s = WireCodec.decode(Uint8Array.of(WireType.STEM, ...body));
      expect(s.type).toBe(WireType.STEM);
      expect(s.payload.item).toBeNull();
    }
  });

  it('旧形式 (msgpack の map) は受け付けない', () => {
    const legacy = new Uint8Array([WireType.GOSSIP, ...msgpackEncode({ type: 'gossip', packet: encodePacket(SAMPLE_PACKET) })]);
    expect(WireCodec.decode(legacy).payload.packet).toBeNull();
    const stemLegacy = new Uint8Array([WireType.STEM, ...msgpackEncode({ type: 'stem', item: { type: 'exit_fluff' } })]);
    expect(WireCodec.decode(stemLegacy).payload.item).toBeNull();
  });

  it('生のバイト列 (Uint8Array) をそのまま渡しても運べる', () => {
    const f = WireCodec.encode(WireType.GOSSIP, { packet: encodePacket(SAMPLE_PACKET) });
    expect(f).toEqual(frame(WireType.GOSSIP));
  });
});

describe('WireCodec.decode: 壊れたフレームの拒否 (例外を投げず UNKNOWN)', () => {
  it('空のフレーム・非 Uint8Array は UNKNOWN', () => {
    expect(WireCodec.decode(new Uint8Array(0))).toEqual(bad);
    expect(WireCodec.decode(null as any)).toEqual(bad);
    expect(WireCodec.decode('x' as any)).toEqual(bad);
  });

  it('固定レイアウトの型: ヘッダだけ・1 バイト足りない・1 バイト余る、はすべて UNKNOWN', () => {
    const fixed = [WireType.HELLO, WireType.JOIN, WireType.PING, WireType.PONG, WireType.PEX_REQUEST, WireType.PEX_RESPONSE, WireType.SDP_RELAY, WireType.ICE_RELAY];
    for (const t of fixed) {
      const f = frame(t);
      if (t !== WireType.PEX_REQUEST) expect(WireCodec.decode(Uint8Array.of(t)), `${WireType[t]} header only`).toEqual(bad);
      for (let cut = 1; cut < f.length; cut++) {
        expect(WireCodec.decode(f.subarray(0, cut)), `${WireType[t]} cut=${cut}`).toEqual(bad);
      }
      expect(WireCodec.decode(Uint8Array.from([...f, 0])), `${WireType[t]} +1`).toEqual(bad);
      expect(WireCodec.decode(Uint8Array.from([...f, ...new Uint8Array(100)])), `${WireType[t]} +100`).toEqual(bad);
    }
  });

  it('PEX_RESPONSE: 宣言件数 > 8、件数と実データの不一致は UNKNOWN', () => {
    const body = (count: number, entries: number) => Uint8Array.from([WireType.PEX_RESPONSE, count, ...new Uint8Array(36 * entries)]);
    expect(WireCodec.decode(body(9, 9))).toEqual(bad);
    expect(WireCodec.decode(body(255, 3))).toEqual(bad);
    expect(WireCodec.decode(body(2, 1))).toEqual(bad);
    expect(WireCodec.decode(body(1, 2))).toEqual(bad);
    expect(WireCodec.decode(body(0, 0)).payload).toEqual({ peers: [] });
  });

  it('SDP_RELAY: 未知の sdp type・宣言長が実データと食い違う・不正な UTF-8 は UNKNOWN', () => {
    const f = Uint8Array.from(frame(WireType.SDP_RELAY));
    const typeAt = 1 + 32;
    for (const t of [4, 5, 0xff]) {
      const g = Uint8Array.from(f);
      g[typeAt] = t;
      expect(WireCodec.decode(g), `sdpType ${t}`).toEqual(bad);
    }
    const longer = Uint8Array.from(f);
    longer[typeAt + 2] += 1; // 宣言長を 1 増やす
    expect(WireCodec.decode(longer)).toEqual(bad);
    const huge = Uint8Array.from(f);
    huge[typeAt + 1] = 0xff;
    huge[typeAt + 2] = 0xff; // 65535 > MAX_SDP_BYTES
    expect(WireCodec.decode(huge)).toEqual(bad);
    const badUtf8 = Uint8Array.from(f);
    badUtf8[typeAt + 3] = 0xff;
    expect(WireCodec.decode(badUtf8)).toEqual(bad);
  });

  it('ICE_RELAY: 空の candidate・上限超えの宣言長・不正な UTF-8 は UNKNOWN', () => {
    const header = (mid: number[], ufrag: number[], len: number[], cand: number[]) =>
      Uint8Array.from([WireType.ICE_RELAY, ...new Uint8Array(32), 0, 0, ...mid, ...ufrag, ...len, ...cand]);
    expect(WireCodec.decode(header([0xff], [0xff], [0, 1], [0x61])).type).toBe(WireType.ICE_RELAY);
    expect(WireCodec.decode(header([0xff], [0xff], [0, 0], []))).toEqual(bad);
    expect(WireCodec.decode(header([0xff], [0xff], [0xff, 0xff], [0x61]))).toEqual(bad);
    expect(WireCodec.decode(header([0xff], [0xff], [0, 1], [0xc3]))).toEqual(bad); // 切れた UTF-8
    expect(WireCodec.decode(header([5, 0x61], [0xff], [0, 1], [0x61]))).toEqual(bad); // sdpMid の宣言長が実データより長い
  });

  it('CATCHUP: 長さ違反・切り詰め・余りバイト・未知の status・空のパケットは UNKNOWN', () => {
    expect(WireCodec.decode(Uint8Array.of(0x60, 1, 2))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x60, 1, 2, 3, 4))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x62, 0, 0, 0))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x62, 7, 0, 0, 0))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x62, 0, 0, 0, 0, 0))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x61))).toEqual(bad);
    expect(WireCodec.decode(Uint8Array.of(0x61, 0, 1, 0, 5, 1, 2))).toEqual(bad); // 宣言長が実データより長い
    expect(WireCodec.decode(Uint8Array.of(0x61, 0, 1, 0, 0))).toEqual(bad); // 長さ 0
    expect(WireCodec.decode(Uint8Array.of(0x61, 0, 0, 9))).toEqual(bad); // 余り
    expect(WireCodec.decode(Uint8Array.of(0x61, 0, 0))).toEqual({ type: WireType.CATCHUP_DATA, payload: { packets: [] } });
    const f = frame(WireType.CATCHUP_DATA);
    expect(WireCodec.decode(f.subarray(0, f.length - 1))).toEqual(bad);
  });

  it('未知の先頭バイトは、続きがどんな形でも既知の型と誤認しない (撤去した型番号も含む)', () => {
    for (const b of [0x00, 0x01, 0x0f, 0x11, 0x14, 0x15, 0x16, 0x18, 0x1f, 0x22, 0x32, 0x43, 0x45, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x63, 0xf0, 0xfe, 0xff]) {
      expect(WireCodec.decode(Uint8Array.of(b, ...msgpackEncode({ type: 'ping', ts: 1 }))).type, `0x${b.toString(16)}`).toBe(WireType.UNKNOWN);
    }
  });

  it('JSON のフレーム (旧フォールバック形式) は受け付けない', () => {
    const json = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
    for (const tag of ['hello', 'join', 'ping', 'gossip', 'constructor', '__proto__']) {
      expect(WireCodec.decode(json({ type: tag, x: 1 })), tag).toEqual(bad);
    }
    // 先頭が既知の型番号と同じ文字 (0x20 = 空白 = PEX_REQUEST) の JSON も、JSON としては読まない
    expect(WireCodec.decode(new TextEncoder().encode(' {"type":"ping","ts":1}')).type).toBe(WireType.UNKNOWN);
  });

  it('旧 msgpack 形式のフレームは、固定レイアウトの型では受け付けない (互換なし)', () => {
    for (const [t, body] of [
      [WireType.HELLO, { type: 'hello', challenge: new Uint8Array(32) }],
      [WireType.JOIN, { type: 'join', peerId: PEER_A, pubkey: PUBKEY, powCounter: 1, challenge: new Uint8Array(32), signature: new Uint8Array(64) }],
      [WireType.PING, { type: 'ping', ts: 5 }],
      [WireType.PEX_RESPONSE, { type: 'pex-response', peers: [{ id: PEER_A }] }],
      [WireType.SDP_RELAY, { type: 'sdp-relay', targetPeerId: PEER_A, senderId: PEER_B, sdp: { type: 'offer', sdp: 'v=0' } }],
    ] as Array<[WireType, object]>) {
      expect(WireCodec.decode(Uint8Array.of(t, ...msgpackEncode(body))), WireType[t]).toEqual(bad);
    }
  });

  it('encode: 未知の型は例外 (呼び出し側のバグ)', () => {
    expect(() => WireCodec.encode(0x43 as any, {})).toThrow(RangeError);
    expect(() => WireCodec.encode(WireType.UNKNOWN, {})).toThrow(RangeError);
  });

  it('ランダムなバイト列を食わせても決して例外を投げない', () => {
    let seed = 12345;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) >>> 16) & 0xff;
    for (let i = 0; i < 3000; i++) {
      const len = rnd() % 200;
      const b = Uint8Array.from({ length: len }, rnd);
      if (len > 0 && i % 2 === 0) b[0] = ALL_TYPES[rnd() % ALL_TYPES.length];
      expect(() => WireCodec.decode(b)).not.toThrow();
    }
  });
});
