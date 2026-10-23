import { describe, it, expect, beforeAll } from 'vitest';
import { NodeIdentity, NODE_ID_POW_FAST } from '../../src/crypto/NodeIdentity';
import { Encoding } from '../../src/common/Encoding';
import {
  TRACKER_ERROR_CODES,
  TRACKER_FRAME_LIMITS,
  TRACKER_MAX_FRAME_BYTES,
  TRACKER_MAX_HOST_BYTES,
  TRACKER_MAX_PEERS,
  TRACKER_PROTOCOL_VERSION,
  encodeTrackerClientMessage,
  encodeTrackerServerMessage,
  parseTrackerClientMessage,
  parseTrackerServerMessage,
  type TrackerErrorCode,
  type TrackerJoin,
} from '../../src/network/TrackerProtocol';

let me: NodeIdentity;
beforeAll(async () => {
  me = await NodeIdentity.mine(NODE_ID_POW_FAST);
});

const PEER_A = 'a1'.repeat(16);
const PEER_B = '0f'.repeat(16);
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
const SDP = { sdp: { type: 'offer', sdp: 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\n' } };
const ICE = {
  candidate: { candidate: 'candidate:842163049 1 udp 1677729535 203.0.113.5 46154 typ srflx raddr 0.0.0.0 rport 0', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 'EsAw' },
};

function join(overrides: Partial<TrackerJoin> = {}, host = 'tracker.example.org'): TrackerJoin {
  return {
    type: 'join',
    v: TRACKER_PROTOCOL_VERSION,
    peerId: me.peerId,
    pubkey: me.pubkey,
    powCounter: me.powCounter,
    host,
    sig: me.signTrackerJoin(NONCE, host),
    ...overrides,
  };
}

describe('TrackerProtocol v3: 往復', () => {
  it('hello', () => {
    const f = encodeTrackerServerMessage({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: NONCE });
    expect(f.length).toBe(1 + 1 + 32);
    expect(parseTrackerServerMessage(f)).toEqual({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce: NONCE });
  });

  it('join (peerId は pubkey から導出され、ワイヤに載らない)', () => {
    const m = join({ powCounter: 0xffffffff });
    const f = encodeTrackerClientMessage(m);
    expect(f.length).toBe(1 + 1 + 32 + 4 + 64 + 1 + 'tracker.example.org'.length);
    expect(parseTrackerClientMessage(f)).toEqual(m);
    expect(Encoding.toHex(f)).not.toContain(me.peerId);
  });

  it('join: ポート付きホスト・IPv6 ホスト', () => {
    for (const host of ['tracker.example.org:8443', '127.0.0.1:3000', '[::1]:3000']) {
      const m = join({}, host);
      expect(parseTrackerClientMessage(encodeTrackerClientMessage(m))).toEqual(m);
    }
  });

  it('peers (0 件・最大件数)', () => {
    for (const n of [0, 1, TRACKER_MAX_PEERS]) {
      const peers = Array.from({ length: n }, (_, i) => ({ peerId: i.toString(16).padStart(2, '0').repeat(16) }));
      const f = encodeTrackerServerMessage({ type: 'peers', peers });
      expect(f.length).toBe(2 + 16 * n);
      expect(parseTrackerServerMessage(f)).toEqual({ type: 'peers', peers });
    }
  });

  it('error: 全コードが往復し、未知・0 は bad-message になる', () => {
    TRACKER_ERROR_CODES.forEach((code, i) => {
      const f = encodeTrackerServerMessage({ type: 'error', code });
      expect([...f]).toEqual([0x03, i + 1]);
      expect(parseTrackerServerMessage(f)).toEqual({ type: 'error', code });
    });
    expect(parseTrackerServerMessage(Uint8Array.of(0x03, 0))).toEqual({ type: 'error', code: 'bad-message' });
    expect(parseTrackerServerMessage(Uint8Array.of(0x03, 200))).toEqual({ type: 'error', code: 'bad-message' });
  });

  it('relay: SDP と ICE が両方向で往復する (null の項目も保たれる)', () => {
    const outS = encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: SDP });
    expect(parseTrackerClientMessage(outS)).toEqual({ type: 'relay', targetPeerId: PEER_A, payload: SDP });
    const inS = encodeTrackerServerMessage({ type: 'relay', senderId: PEER_B, payload: ICE });
    expect(parseTrackerServerMessage(inS)).toEqual({ type: 'relay', senderId: PEER_B, payload: ICE });
    const nulls = { candidate: { candidate: 'candidate:1 1 udp 1 192.0.2.1 9 typ host', sdpMid: null, sdpMLineIndex: null, usernameFragment: null } };
    expect(parseTrackerClientMessage(encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: nulls })))
      .toEqual({ type: 'relay', targetPeerId: PEER_A, payload: nulls });
  });

  it('relay: 宛先 (送信元) の 16 バイトは 1 つだけ載る', () => {
    const f = encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: SDP });
    expect(f.length).toBe(1 + 16 + 1 + 2 + SDP.sdp.sdp.length);
    expect(Encoding.toHex(f.subarray(1, 17))).toBe(PEER_A);
  });
});

describe('TrackerProtocol v3: 受信側は信用しない', () => {
  const clientFrames = (): Array<[string, Uint8Array]> => [
    ['join', encodeTrackerClientMessage(join())],
    ['relay-sdp', encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: SDP })],
    ['relay-ice', encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: ICE })],
  ];
  const serverFrames = (): Array<[string, Uint8Array]> => [
    ['hello', encodeTrackerServerMessage({ type: 'hello', v: 3, nonce: NONCE })],
    ['peers', encodeTrackerServerMessage({ type: 'peers', peers: [{ peerId: PEER_A }, { peerId: PEER_B }] })],
    ['error', encodeTrackerServerMessage({ type: 'error', code: 'capacity' })],
    ['relay-sdp', encodeTrackerServerMessage({ type: 'relay', senderId: PEER_A, payload: SDP })],
    ['relay-ice', encodeTrackerServerMessage({ type: 'relay', senderId: PEER_A, payload: ICE })],
  ];

  it('切り詰めはすべて null (どの長さでも例外を投げない)', () => {
    for (const [name, f] of clientFrames()) {
      for (let n = 0; n < f.length; n++) expect(parseTrackerClientMessage(f.subarray(0, n)), `${name}/${n}`).toBeNull();
    }
    for (const [name, f] of serverFrames()) {
      for (let n = 0; n < f.length; n++) {
        // error は 1 バイト短い (コード欠落) と null。peers の途中切り詰めも null
        expect(parseTrackerServerMessage(f.subarray(0, n)), `${name}/${n}`).toBeNull();
      }
    }
  });

  it('余りバイトはすべて null', () => {
    for (const [name, f] of clientFrames()) {
      expect(parseTrackerClientMessage(Uint8Array.of(...f, 0)), name).toBeNull();
    }
    for (const [name, f] of serverFrames()) {
      expect(parseTrackerServerMessage(Uint8Array.of(...f, 0)), name).toBeNull();
    }
  });

  it('方向違いの種別・未知の種別は null', () => {
    expect(parseTrackerClientMessage(encodeTrackerServerMessage({ type: 'hello', v: 3, nonce: NONCE }))).toBeNull();
    expect(parseTrackerClientMessage(encodeTrackerServerMessage({ type: 'error', code: 'timeout' }))).toBeNull();
    expect(parseTrackerServerMessage(encodeTrackerClientMessage(join()))).toBeNull();
    for (const t of [0x00, 0x06, 0x10, 0x12, 0x7b /* "{" */, 0xff]) {
      expect(parseTrackerClientMessage(Uint8Array.of(t, 0, 0, 0))).toBeNull();
      expect(parseTrackerServerMessage(Uint8Array.of(t, 0, 0, 0))).toBeNull();
    }
  });

  it('文字列 (テキストフレーム・旧 JSON)・空・型違いは null', () => {
    const json = JSON.stringify({ type: 'hello', v: 2, nonce: 'ab'.repeat(32) });
    expect(parseTrackerServerMessage(json)).toBeNull();
    expect(parseTrackerClientMessage(json)).toBeNull();
    expect(parseTrackerServerMessage(new TextEncoder().encode(json))).toBeNull();
    for (const bad of [new Uint8Array(0), null, undefined, 42, {}, [1, 2, 3]]) {
      expect(parseTrackerServerMessage(bad)).toBeNull();
      expect(parseTrackerClientMessage(bad)).toBeNull();
    }
  });

  it('ArrayBuffer (ブラウザの binaryType) も読める', () => {
    const f = encodeTrackerServerMessage({ type: 'peers', peers: [{ peerId: PEER_A }] });
    const ab = f.buffer.slice(f.byteOffset, f.byteOffset + f.byteLength) as ArrayBuffer;
    expect(parseTrackerServerMessage(ab)).toEqual({ type: 'peers', peers: [{ peerId: PEER_A }] });
  });

  it('種別ごとの上限: 超えたものは null (本体が正しくても)', () => {
    expect(TRACKER_MAX_FRAME_BYTES).toBe(TRACKER_FRAME_LIMITS.RELAY);
    expect(TRACKER_FRAME_LIMITS.HELLO).toBe(34);
    expect(TRACKER_FRAME_LIMITS.ERROR).toBe(2);
    const over = (type: number, n: number) => new Uint8Array(n + 1).fill(0).map((_, i) => (i === 0 ? type : 0));
    expect(parseTrackerClientMessage(over(0x11, TRACKER_FRAME_LIMITS.JOIN))).toBeNull();
    expect(parseTrackerClientMessage(over(0x04, TRACKER_FRAME_LIMITS.RELAY))).toBeNull();
    expect(parseTrackerServerMessage(over(0x02, TRACKER_FRAME_LIMITS.PEERS))).toBeNull();
    expect(parseTrackerServerMessage(over(0x01, TRACKER_FRAME_LIMITS.HELLO))).toBeNull();
    // peers の件数が上限超過 (フレーム長は合っている)
    const many = new Uint8Array(2 + 16 * (TRACKER_MAX_PEERS + 1));
    many[0] = 0x02;
    many[1] = TRACKER_MAX_PEERS + 1;
    expect(parseTrackerServerMessage(many)).toBeNull();
  });

  it('SDP は WireCodec と同じ上限で拒否される (最大長は通り、1 バイト超えは符号化できない)', () => {
    const max = 16 * 1024 - 64;
    const f = encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: { sdp: { type: 'offer', sdp: 'a'.repeat(max) } } });
    expect(f.length).toBeLessThanOrEqual(TRACKER_MAX_FRAME_BYTES);
    expect(parseTrackerClientMessage(f)).not.toBeNull();
    expect(() => encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: { sdp: { type: 'offer', sdp: 'a'.repeat(max + 1) } } })).toThrow(RangeError);
  });

  it('壊れた中身 (SDP 種別・UTF-8・長さ) は null', () => {
    const f = encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: SDP });
    const badType = f.slice(); badType[17] = 9;
    const badUtf8 = f.slice(); badUtf8[badUtf8.length - 1] = 0xff;
    const badLen = f.slice(); badLen[18] = 0xff;
    for (const b of [badType, badUtf8, badLen]) expect(parseTrackerClientMessage(b)).toBeNull();
  });

  it('join: 不正なホスト (空・大文字・空白・不正な UTF-8・長さ不一致) は null', () => {
    const f = encodeTrackerClientMessage(join());
    const hostAt = f.length - 'tracker.example.org'.length;
    const mut = (fn: (g: Uint8Array) => void) => { const g = f.slice(); fn(g); return g; };
    expect(parseTrackerClientMessage(mut((g) => { g[hostAt] = 0x54; }))).toBeNull(); // 'T'
    expect(parseTrackerClientMessage(mut((g) => { g[hostAt] = 0x20; }))).toBeNull();
    expect(parseTrackerClientMessage(mut((g) => { g[hostAt] = 0xff; }))).toBeNull();
    expect(parseTrackerClientMessage(mut((g) => { g[hostAt - 1] += 1; }))).toBeNull();
    expect(parseTrackerClientMessage(mut((g) => { g[hostAt - 1] = 0; g[0] = 0x11; }).subarray(0, hostAt))).toBeNull(); // host 空
  });

  it('符号化は範囲違反を RangeError にする (呼び出し側のバグ)', () => {
    expect(() => encodeTrackerClientMessage(join({ powCounter: 0x1_0000_0000 }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ powCounter: -1 }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ powCounter: 1.5 }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ sig: new Uint8Array(63) }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ pubkey: new Uint8Array(31) }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ host: 'a b' }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage(join({ host: 'a'.repeat(TRACKER_MAX_HOST_BYTES + 1) }))).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage({ type: 'relay', targetPeerId: 'zz', payload: SDP })).toThrow(RangeError);
    expect(() => encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: {} })).toThrow(RangeError);
    expect(() => encodeTrackerServerMessage({ type: 'error', code: 'nope' as TrackerErrorCode })).toThrow(RangeError);
    expect(() => encodeTrackerServerMessage({ type: 'hello', v: 3, nonce: new Uint8Array(31) })).toThrow(RangeError);
  });
});

describe('TrackerProtocol v3: join の署名は nonce・ホスト・鍵に束縛されたまま', () => {
  const verify = (m: TrackerJoin, nonce: Uint8Array) =>
    NodeIdentity.verifyTrackerJoin({ peerId: m.peerId, pubkey: m.pubkey, powCounter: m.powCounter }, nonce, m.host, m.sig, NODE_ID_POW_FAST);

  it('往復したあとも検証を通る', () => {
    const m = parseTrackerClientMessage(encodeTrackerClientMessage(join())) as TrackerJoin;
    expect(verify(m, NONCE)).toBe(true);
  });

  it('★別の nonce では通らない', () => {
    const m = parseTrackerClientMessage(encodeTrackerClientMessage(join())) as TrackerJoin;
    const other = NONCE.slice(); other[0] ^= 1;
    expect(verify(m, other)).toBe(false);
  });

  it('★ホストのバイトを 1 つ変える・別のホストにすり替えると通らない', () => {
    const f = encodeTrackerClientMessage(join());
    const g = f.slice(); g[g.length - 1] = 'h'.charCodeAt(0); // ...org → ...orh
    expect(verify(parseTrackerClientMessage(g) as TrackerJoin, NONCE)).toBe(false);
    const evil = parseTrackerClientMessage(encodeTrackerClientMessage(join({}, 'tracker.example.org'))) as TrackerJoin;
    expect(verify({ ...evil, host: 'evil.example.org' }, NONCE)).toBe(false);
  });

  it('★pubkey・署名のビットを反転すると通らない (peerId も pubkey から導出し直される)', () => {
    const f = encodeTrackerClientMessage(join());
    const pk = f.slice(); pk[2] ^= 1;
    const m1 = parseTrackerClientMessage(pk) as TrackerJoin;
    expect(m1.peerId).not.toBe(me.peerId);
    expect(verify(m1, NONCE)).toBe(false);
    const sg = f.slice(); sg[2 + 32 + 4] ^= 1;
    expect(verify(parseTrackerClientMessage(sg) as TrackerJoin, NONCE)).toBe(false);
  });

  it('powCounter を書き換えると Bound Identity (PoW) の検証が落ちる', () => {
    const m = parseTrackerClientMessage(encodeTrackerClientMessage(join())) as TrackerJoin;
    let c = m.powCounter + 1;
    while (NodeIdentity.verifyClaim({ peerId: m.peerId, pubkey: m.pubkey, powCounter: c }, NODE_ID_POW_FAST)) c++;
    expect(verify({ ...m, powCounter: c }, NONCE)).toBe(false);
  });
});

describe('TrackerProtocol v3: サイズ表 (v2 の JSON との比較)', () => {
  // v2 の JSON をそのまま再現して測る (旧実装の形: 余計な空白なしの JSON.stringify)
  const hex = (b: Uint8Array) => Encoding.toHex(b);
  const json = (o: unknown) => new TextEncoder().encode(JSON.stringify(o)).length;

  it('実運用に近い内容で測り、すべて小さくなっている', () => {
    const host = 'tracker.example.org';
    const j = join({}, host);
    const sdpText = 'v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:EsAw\r\na=ice-pwd:by4GZGG1lw+040DWA6hXM5Bz\r\na=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\na=setup:actpass\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n';
    const sdp = { sdp: { type: 'offer', sdp: sdpText } };
    const rows: Array<[string, number, number]> = [
      ['hello', json({ type: 'hello', v: 2, nonce: hex(NONCE) }), encodeTrackerServerMessage({ type: 'hello', v: 3, nonce: NONCE }).length],
      ['join', json({ type: 'join', v: 2, peerId: j.peerId, pubkey: hex(j.pubkey), powCounter: j.powCounter, host, sig: hex(j.sig) }), encodeTrackerClientMessage(j).length],
      ['peers (8 件)', json({ type: 'peers', peers: Array.from({ length: 8 }, (_, i) => ({ peerId: i.toString(16).repeat(32).slice(0, 32) })) }),
        encodeTrackerServerMessage({ type: 'peers', peers: Array.from({ length: 8 }, (_, i) => ({ peerId: i.toString(16).repeat(32).slice(0, 32) })) }).length],
      ['error', json({ type: 'error', code: 'bad-signature' }), encodeTrackerServerMessage({ type: 'error', code: 'bad-signature' }).length],
      ['relay SDP (offer)', json({ type: 'relay', targetPeerId: PEER_A, payload: { type: 'sdp-relay', targetPeerId: PEER_A, senderId: PEER_B, ...sdp } }),
        encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: sdp }).length],
      ['relay ICE', json({ type: 'relay', targetPeerId: PEER_A, payload: { type: 'ice-relay', targetPeerId: PEER_A, senderId: PEER_B, ...ICE } }),
        encodeTrackerClientMessage({ type: 'relay', targetPeerId: PEER_A, payload: ICE }).length],
    ];
    const lines = rows.map(([n, a, b]) => `${n.padEnd(18)} ${String(a).padStart(5)} -> ${String(b).padStart(5)} bytes (${((1 - b / a) * 100).toFixed(0)}% 減)`);
    console.log(`\n[tracker frame sizes]\n${lines.join('\n')}`);
    for (const [name, before, after] of rows) expect(after, name).toBeLessThan(before);
    // join は固定部 102 バイト + ホスト
    expect(rows[1][2]).toBe(1 + 1 + 32 + 4 + 64 + 1 + host.length);
  });
});

