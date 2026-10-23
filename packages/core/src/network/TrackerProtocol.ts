/**
 * トラッカー (シグナリングサーバ) とノードの間のプロトコル (v3: バイナリフレーム)。
 *
 * ★ クライアント (SignalingClient) とサーバ (@oz/tracker) の両方がこのファイルの
 *   型・符号化・検証関数を使う。片方だけ形式を変えて食い違う、ということが起きないようにするため。
 *
 * ★ v2 までは JSON (フィールド名・hex 文字列) だった。join だけで約 440 バイト、SDP/ICE の中継も
 *   JSON の入れ子だった。いまは WebSocket のバイナリメッセージで、型ごとの固定レイアウト
 *   (フィールド名なし・hex なし)。ID・鍵・署名・nonce は生のバイトで運ぶ。
 *
 *   フレーム = [type u8][本体]
 *
 *   サーバ → ノード
 *     HELLO   0x01  v u8 ‖ nonce 32
 *     PEERS   0x02  count u8 (≤ 32) ‖ peerId 16 × count
 *     ERROR   0x03  code u8 (1 始まり。0 と未知の値は bad-message 扱い)
 *     RELAY_SDP 0x04 / RELAY_ICE 0x05   sender 16 ‖ (WireCodec の SDP_RELAY / ICE_RELAY の target・sender より後ろ)
 *   ノード → サーバ
 *     JOIN    0x11  v u8 ‖ pubkey 32 ‖ powCounter u32 ‖ sig 64 ‖ lp8(host)   (peerId は pubkey から導出する)
 *     RELAY_SDP 0x04 / RELAY_ICE 0x05   target 16 ‖ (同上)
 *
 *   SDP の本体 = sdpType u8 ‖ len u16 ‖ sdp (UTF-8)
 *   ICE の本体 = mLineIndex u16 ‖ lp8(sdpMid) ‖ lp8(ufrag) ‖ len u16 ‖ candidate (UTF-8)
 *
 * ★ SDP/ICE の本体は P2P の SDP_RELAY / ICE_RELAY と同じ。WireCodec をそのまま通して
 *   (target ‖ sender の 32 バイトを 16 バイトに畳んで) 使うので、検証 (長さ上限・UTF-8・余りバイト)
 *   も 1 か所のまま。中継の宛先と送信元は同時に載らないので、片方を省ける。
 *
 * 流れ:
 *   1. 接続直後、サーバが HELLO { nonce } を送る (接続ごとに新しい乱数)。
 *   2. ノードが JOIN を送る。
 *        sig = Ed25519(trackerJoinMessage(nonce, peerId, host))   ← v2 と同じ (peerId は pubkey から導出した値)
 *      サーバは Bound Identity (peerId = hash(pubkey) + NodeId PoW) と署名を検証する。
 *      host は「ノードが接続したつもりのトラッカー」で、サーバは自分のホスト名と照合する。
 *   3. サーバが PEERS を返す。以後 RELAY で SDP/ICE を中継する。
 *
 * v1 (署名なしの join) と v2 (JSON) は受け付けない。peerId・pubkey・powCounter は P2P の JOIN で
 * 全隣人に渡る公開情報なので、署名が無いと誰でも他人の ID で登録できた。
 *
 * ★ 受信側は信用しない。種別違い・切り詰め・余りバイト・フレーム上限超過・文字列 (テキストフレーム) は
 *   すべて null (例外は外へ出さない)。
 */
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import { CHALLENGE_BYTES, NODE_ID_POW_COUNTER_MAX, NodeIdentity, PEER_ID_BYTES } from '../crypto/NodeIdentity';
import { WireCodec } from './wire/WireCodec';
import { WireType } from './wire/WireTypes';

export const TRACKER_PROTOCOL_VERSION = 3;

/** peers で返す最大件数 */
export const TRACKER_MAX_PEERS = 32;

const PUBKEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
/** lp8 で運ぶホストの最大バイト数 (HOST_RE の最長は 259 だが、現実のホスト名は 254 を超えない) */
export const TRACKER_MAX_HOST_BYTES = 254;
/** SDP の本文の最大 (WireCodec と同じ) + 種別・長さ。ICE の上限も含む */
const RELAY_BODY_MAX = 1 + 2 + (16 * 1024 - 64);

/** ホスト名 (小文字)・IPv4・[IPv6]、任意でポート */
const HOST_RE = /^(?:[a-z0-9.-]{1,253}|\[[0-9a-f:.]{2,45}\])(?::\d{1,5})?$/;
const PEER_ID_RE = /^[0-9a-f]{32}$/;

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** フレームの種別。方向ごとに受け付ける集合が違う */
const T = {
  HELLO: 0x01,
  PEERS: 0x02,
  ERROR: 0x03,
  RELAY_SDP: 0x04,
  RELAY_ICE: 0x05,
  JOIN: 0x11,
} as const;

/** ★ 添字 + 1 が ERROR のコード。並べ替えると互換が切れる (ゴールデンテストで固定) */
export const TRACKER_ERROR_CODES = [
  'bad-message',
  'unsupported-version',
  'invalid-identity',
  'bad-signature',
  'bad-host',
  'rate-limited',
  'capacity',
  'not-joined',
  'invalid-target',
  'too-large',
  'timeout',
] as const;
export type TrackerErrorCode = (typeof TRACKER_ERROR_CODES)[number];

/**
 * 種別ごとのフレーム上限 (種別 1 バイトを含む)。
 * ★ v2 は一律 64 KiB だった。HELLO や ERROR は数十バイトなので、種別ごとに絞る。
 */
export const TRACKER_FRAME_LIMITS = {
  HELLO: 1 + 1 + CHALLENGE_BYTES,
  PEERS: 1 + 1 + PEER_ID_BYTES * TRACKER_MAX_PEERS,
  ERROR: 1 + 1,
  JOIN: 1 + 1 + PUBKEY_BYTES + 4 + SIGNATURE_BYTES + 1 + TRACKER_MAX_HOST_BYTES,
  /** SDP / ICE の中継 (どちらの方向も)。ICE は SDP より小さいので SDP の上限で足りる */
  RELAY: 1 + PEER_ID_BYTES + RELAY_BODY_MAX,
} as const;

/** 1 フレームの上限 (サーバ・クライアント共通。WebSocket の maxPayload に使う) */
export const TRACKER_MAX_FRAME_BYTES = TRACKER_FRAME_LIMITS.RELAY;

// ── サーバ → ノード ──

export interface TrackerHello { type: 'hello'; v: number; nonce: Uint8Array }
export interface TrackerPeers { type: 'peers'; peers: Array<{ peerId: string }> }
/** payload は { sdp } か { candidate } (PeerManager が P2P 経由の中継で受け取る形から id を除いたもの) */
export interface TrackerRelayIn { type: 'relay'; senderId: string; payload: Record<string, unknown> }
export interface TrackerError { type: 'error'; code: TrackerErrorCode }
export type TrackerServerMessage = TrackerHello | TrackerPeers | TrackerRelayIn | TrackerError;

// ── ノード → サーバ ──

export interface TrackerJoin {
  type: 'join';
  v: number;
  /** pubkey から導出した値 (ワイヤには載らない) */
  peerId: string;
  pubkey: Uint8Array;
  powCounter: number;
  /** ノードが接続したつもりのトラッカーのホスト (小文字、既定以外のポートを含む) */
  host: string;
  /** Ed25519 署名 (64 バイト) */
  sig: Uint8Array;
}
export interface TrackerRelayOut { type: 'relay'; targetPeerId: string; payload: Record<string, unknown> }
export type TrackerClientMessage = TrackerJoin | TrackerRelayOut;

export function isPeerId(v: unknown): v is string {
  return typeof v === 'string' && PEER_ID_RE.test(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** WebSocket のバイナリメッセージ (ArrayBuffer / Uint8Array / Buffer) をバイト列にする。文字列は不可 */
function toBytes(raw: unknown, maxBytes: number): Uint8Array | null {
  let b: Uint8Array;
  if (raw instanceof Uint8Array) b = raw;
  else if (raw instanceof ArrayBuffer) b = new Uint8Array(raw);
  else return null;
  if (b.length < 1 || b.length > maxBytes) return null;
  return b;
}

function writeU32(w: ByteWriter, v: number): void {
  if (!Number.isInteger(v) || v < 0 || v > NODE_ID_POW_COUNTER_MAX) throw new RangeError('powCounter: not a u32');
  w.u16(Math.floor(v / 0x10000)).u16(v % 0x10000);
}

function readU32(r: ByteReader): number {
  return r.u16() * 0x10000 + r.u16();
}

function fixed(v: unknown, len: number, what: string): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== len) throw new RangeError(`${what}: must be ${len} bytes`);
  return v;
}

function peerBytes(id: unknown, what: string): Uint8Array {
  if (!isPeerId(id)) throw new RangeError(`${what}: bad peerId`);
  return Encoding.fromHex(id);
}

// ── 中継 (WireCodec の SDP_RELAY / ICE_RELAY を 16 バイト 1 つの ID に畳む) ──

const WIRE_ID_PAIR = PEER_ID_BYTES * 2;

function encodeRelay(peerId: unknown, payload: unknown): Uint8Array {
  if (!isPlainObject(payload)) throw new RangeError('relay: bad payload');
  const kind = payload.sdp !== undefined ? 'sdp' : payload.candidate !== undefined ? 'ice' : null;
  if (!kind) throw new RangeError('relay: neither sdp nor candidate');
  peerBytes(peerId, 'relay.peer'); // 検証 (WireCodec にも同じ検査がある)
  // ★ WireCodec には同じ ID を target / sender の両方に入れて通し、後半 16 バイトを落とす
  const wire = WireCodec.encode(kind === 'sdp' ? WireType.SDP_RELAY : WireType.ICE_RELAY, {
    targetPeerId: peerId,
    senderId: peerId,
    ...(kind === 'sdp' ? { sdp: payload.sdp } : { candidate: payload.candidate }),
  });
  const out = new Uint8Array(1 + wire.length - 1 - PEER_ID_BYTES);
  out[0] = kind === 'sdp' ? T.RELAY_SDP : T.RELAY_ICE;
  out.set(wire.subarray(1, 1 + PEER_ID_BYTES), 1);
  out.set(wire.subarray(1 + WIRE_ID_PAIR), 1 + PEER_ID_BYTES);
  if (out.length > TRACKER_FRAME_LIMITS.RELAY) throw new RangeError('relay: too large');
  return out;
}

function decodeRelay(b: Uint8Array): { peerId: string; payload: Record<string, unknown> } | null {
  if (b.length < 1 + PEER_ID_BYTES) return null;
  const kind = b[0] === T.RELAY_SDP ? WireType.SDP_RELAY : WireType.ICE_RELAY;
  const id = b.subarray(1, 1 + PEER_ID_BYTES);
  const rest = b.subarray(1 + PEER_ID_BYTES);
  const wire = new Uint8Array(1 + WIRE_ID_PAIR + rest.length);
  wire[0] = kind;
  wire.set(id, 1);
  wire.set(id, 1 + PEER_ID_BYTES);
  wire.set(rest, 1 + WIRE_ID_PAIR);
  const m = WireCodec.decode(wire);
  if (m.type !== kind || !isPlainObject(m.payload)) return null;
  const p = m.payload;
  const payload = kind === WireType.SDP_RELAY ? { sdp: p.sdp } : { candidate: p.candidate };
  return { peerId: p.targetPeerId as string, payload };
}

// ── 符号化 (範囲違反は RangeError。呼び出し側のバグなので握りつぶさない) ──

export function encodeTrackerServerMessage(msg: TrackerServerMessage): Uint8Array {
  switch (msg.type) {
    case 'hello':
      return new ByteWriter().u8(T.HELLO).u8(msg.v).raw(fixed(msg.nonce, CHALLENGE_BYTES, 'hello.nonce')).finish();
    case 'peers': {
      const peers = msg.peers.slice(0, TRACKER_MAX_PEERS);
      const w = new ByteWriter().u8(T.PEERS).u8(peers.length);
      for (const p of peers) w.raw(peerBytes(p.peerId, 'peers.peerId'));
      return w.finish();
    }
    case 'error': {
      const i = TRACKER_ERROR_CODES.indexOf(msg.code);
      if (i < 0) throw new RangeError('error: unknown code');
      return Uint8Array.of(T.ERROR, i + 1);
    }
    case 'relay':
      return encodeRelay(msg.senderId, msg.payload);
  }
}

export function encodeTrackerClientMessage(msg: TrackerClientMessage): Uint8Array {
  if (msg.type === 'relay') return encodeRelay(msg.targetPeerId, msg.payload);
  if (!HOST_RE.test(msg.host)) throw new RangeError('join.host: bad host');
  const host = utf8.encode(msg.host);
  if (host.length > TRACKER_MAX_HOST_BYTES) throw new RangeError('join.host: too long');
  const w = new ByteWriter().u8(T.JOIN).u8(msg.v).raw(fixed(msg.pubkey, PUBKEY_BYTES, 'join.pubkey'));
  writeU32(w, msg.powCounter);
  return w.raw(fixed(msg.sig, SIGNATURE_BYTES, 'join.sig')).u8(host.length).raw(host).finish();
}

// ── 検証 (復号) ──

/** サーバ側: ノードからのメッセージを検証する。不正なら null (例外は投げない) */
export function parseTrackerClientMessage(raw: unknown): TrackerClientMessage | null {
  const b = toBytes(raw, TRACKER_FRAME_LIMITS.RELAY);
  if (!b) return null;
  try {
    switch (b[0]) {
      case T.JOIN: {
        if (b.length > TRACKER_FRAME_LIMITS.JOIN) return null;
        const r = new ByteReader(b.subarray(1));
        const v = r.u8();
        const pubkey = r.bytes(PUBKEY_BYTES).slice();
        const powCounter = readU32(r);
        const sig = r.bytes(SIGNATURE_BYTES).slice();
        const host = utf8Strict.decode(r.bytes(r.u8()));
        r.end();
        if (!HOST_RE.test(host)) return null;
        return { type: 'join', v, peerId: NodeIdentity.derivePeerId(pubkey), pubkey, powCounter, host, sig };
      }
      case T.RELAY_SDP:
      case T.RELAY_ICE: {
        const m = decodeRelay(b);
        return m ? { type: 'relay', targetPeerId: m.peerId, payload: m.payload } : null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** ノード側: トラッカーからのメッセージを検証する。不正なら null (例外は投げない) */
export function parseTrackerServerMessage(raw: unknown): TrackerServerMessage | null {
  const b = toBytes(raw, TRACKER_FRAME_LIMITS.RELAY);
  if (!b) return null;
  try {
    switch (b[0]) {
      case T.HELLO: {
        if (b.length > TRACKER_FRAME_LIMITS.HELLO) return null;
        const r = new ByteReader(b.subarray(1));
        const v = r.u8();
        const nonce = r.bytes(CHALLENGE_BYTES).slice();
        r.end();
        return { type: 'hello', v, nonce };
      }
      case T.PEERS: {
        if (b.length > TRACKER_FRAME_LIMITS.PEERS) return null;
        const r = new ByteReader(b.subarray(1));
        const n = r.u8();
        if (n > TRACKER_MAX_PEERS) return null;
        const peers: Array<{ peerId: string }> = [];
        for (let i = 0; i < n; i++) peers.push({ peerId: Encoding.toHex(r.bytes(PEER_ID_BYTES)) });
        r.end();
        return { type: 'peers', peers };
      }
      case T.ERROR: {
        if (b.length !== TRACKER_FRAME_LIMITS.ERROR) return null;
        return { type: 'error', code: TRACKER_ERROR_CODES[b[1] - 1] ?? 'bad-message' };
      }
      case T.RELAY_SDP:
      case T.RELAY_ICE: {
        const m = decodeRelay(b);
        return m ? { type: 'relay', senderId: m.peerId, payload: m.payload } : null;
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** WebSocket の URL から、署名に含めるホストを取り出す (URL の正規化に従う) */
export function trackerHostOf(url: string): string {
  return new URL(url).host.toLowerCase();
}

/** HTTP の Host ヘッダの値を、署名のホストと同じ形に揃える */
export function normalizeHostHeader(host: string | undefined): string | null {
  if (typeof host !== 'string') return null;
  const h = host.trim().toLowerCase();
  if (!HOST_RE.test(h)) return null;
  // 既定のポートは URL の正規化で消えるので、Host ヘッダ側も消して揃える
  return h.replace(/:(80|443)$/, '');
}
