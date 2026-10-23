import { WireType } from './WireTypes';
import { ByteReader, ByteWriter } from '../../common/ByteIO';
import { Encoding } from '../../common/Encoding';
import { decodePacket, encodePacket } from '../../crypto/PacketCodec';
import { decodeExitItem, encodeExitItem } from '../../crypto/ExitItem';
import { LEASESET_MAX_BYTES, LEASESET_MIN_BYTES } from '../storage/LeaseSet';
import { CHALLENGE_BYTES, NODE_ID_POW_COUNTER_MAX, NodeIdentity, PEER_ID_BYTES } from '../../crypto/NodeIdentity';

export interface DecodedWireMessage {
  type: WireType;
  payload: any;
}

/**
 * WireCodec — P2P フレームの符号化。
 *
 *   フレーム = [WireType u8][本体]
 *
 * ★ 本体は型ごとの固定レイアウト (フィールド名なし・msgpack なし)。
 *   旧実装は全フレームを msgpack の map にして、さらに Rust ピア用に "type": "..." の文字列を
 *   毎回注入していた (Rust ピアは放棄済み)。JOIN は peerId と echo した challenge を再送していた。
 *   ここで削った分は、ハンドシェイクと PEX・シグナリングの毎回の帯域に効く。
 *
 *   HELLO         challenge 32
 *   JOIN          pubkey 32 ‖ powCounter u32 ‖ signature 64   (peerId は pubkey から導出する。challenge は載せない)
 *   PING / PONG   nonce u32
 *   PEX_REQUEST   (空)
 *   PEX_RESPONSE  count u8 (≤ 8) ‖ { pubkey 32 ‖ powCounter u32 } × count   (peerId は pubkey から導出する)
 *   SDP_RELAY     target 16 ‖ sender 16 ‖ sdpType u8 ‖ len u16 ‖ sdp (UTF-8)
 *   ICE_RELAY     target 16 ‖ sender 16 ‖ mLineIndex u16 ‖ lp8(sdpMid) ‖ lp8(ufrag) ‖ len u16 ‖ candidate (UTF-8)
 *   GOSSIP        PacketCodec のバイト列そのまま
 *   STEM          ExitItem のバイト列そのまま
 *   ONION_STEM    1,200 バイトのセルそのまま
 *   CATCHUP_REQ   since u24 (OZ_EPOCH からの分)
 *   CATCHUP_DATA  count u16 ‖ { len u16 ‖ パケット (PacketCodec) } × count   (フレーム全体で ≤ MAX_CATCHUP_FRAME_BYTES)
 *   CATCHUP_END   status u8 ‖ nextSince u24
 *   LEASESET      leaseSet のバイト列そのまま (network/storage/LeaseSet。145〜445 バイト)
 *   LEASESET_SYNC_REQ  (空)
 *   LEASESET_SYNC count u16 ‖ { len u16 ‖ leaseSet } × count   (フレーム全体で ≤ MAX_LEASESET_FRAME_BYTES)
 *   TUNNEL_REGISTER   tunnelId 8
 *   TUNNEL_REGISTERED tunnelId 8 ‖ ok u8 (0 / 1)
 *   TUNNEL_SEND       reqId u32 ‖ gateway 16 (peerId の生) ‖ tunnelId 8 ‖ body   (フレーム全体で ≤ MAX_TUNNEL_FRAME_BYTES)
 *   TUNNEL_FWD        returnTag u32 ‖ tunnelId 8 ‖ body
 *   TUNNEL_DELIVER    returnTag u32 ‖ fromHop 16 ‖ body
 *   TUNNEL_REPLY      returnTag u32 ‖ toHop 16 ‖ seq u16 ‖ flags u8 (bit0 = final。他は 0) ‖ body
 *   TUNNEL_RET        returnTag u32 ‖ seq u16 ‖ flags u8 ‖ body
 *   TUNNEL_RESULT     reqId u32 ‖ seq u16 ‖ flags u8 ‖ body
 *   TUNNEL_ERROR      id u32 ‖ code u8 (TUNNEL_ERROR_CODE)
 *   OZZY_REPLY        replyHeader 68 ‖ seq u16 ‖ flags u8 (bit0 = final。他は 0) ‖ body (フレーム全体で ≤ MAX_OZZY_FRAME_BYTES)
 *   OZZY_RESULT       replyId u32 ‖ seq u16 ‖ flags u8 ‖ body (フレーム全体で ≤ MAX_OZZY_FRAME_BYTES)
 *   OZZY_UP           upHeader 80 ‖ seq u16 ‖ flags u8 ‖ body (フレーム全体で ≤ MAX_OZZY_FRAME_BYTES)
 *   OZZY_UP_FWD       uploadId 16 ‖ seq u16 ‖ flags u8 ‖ body (フレーム全体で ≤ MAX_OZZY_FRAME_BYTES)
 *   OZZY_WORKER_REQ   (空)
 *   OZZY_WORKER_ADS   count u8 (≤ MAX_OZZY_WORKER_ADS) ‖ { pubkey 32 ‖ powCounter u32 ‖ expiresMin u32 ‖ lp8(url) ‖ sig 64 } × count
 *
 * ★ 受信側は信用しない。長さの違反・切り詰め・余りバイト・未知の種別は、すべて
 *   { type: UNKNOWN, payload: null } を返す (例外は外へ出さない)。GOSSIP / STEM は中身 (packet / item) が
 *   読めなくてもフレーム自体は成立させ、null を渡してハンドラに拒否させる (従来の挙動)。
 */

/** 実在する WireType の集合。decode の判定に使う。 */
const KNOWN_WIRE_TYPES: ReadonlySet<number> = new Set(
  Object.values(WireType).filter((v): v is number => typeof v === 'number' && v !== WireType.UNKNOWN),
);

/** 1 回の PEX_RESPONSE で運ぶ最大件数 */
export const MAX_PEX_ENTRIES = 8;
/** SDP / ICE の本文の最大バイト数 (UTF-8)。フレームの上限 (PeerManager.MAX_FRAME_BYTES) と合わせる */
export const MAX_SDP_BYTES = 16 * 1024 - 64;
export const MAX_ICE_CANDIDATE_BYTES = 1024;
/**
 * CATCHUP_DATA 1 フレームの上限 (type 1 バイトを含む)。WebRTC DataChannel で安全に送れる 16KiB に合わせる
 * (SDP_RELAY と同じ)。パケットは最大 約 2.3KB なので、1 フレームに数件〜数十件入る。
 */
export const MAX_CATCHUP_FRAME_BYTES = 16 * 1024;
/** LEASESET_SYNC 1 フレームの上限 (type 1 バイトを含む)。CATCHUP_DATA と同じ 16KiB */
export const MAX_LEASESET_FRAME_BYTES = 16 * 1024;
/** TUNNEL_* 1 フレームの上限 (type 1 バイトを含む)。WebRTC DataChannel で安全に送れる 16KiB */
export const MAX_TUNNEL_FRAME_BYTES = 16 * 1024;
/** TUNNEL_ERROR の code */
export const TUNNEL_ERROR_CODE = {
  /** 受け口 (gateway) に届かない (接続できない・タイムアウト) */
  NO_ROUTE: 1,
  /** どこかの段の制限 (要求数・帯域・同時数) に当たった */
  BUSY: 2,
  /** 応答が止まった (保持者が黙った・状態が期限切れ) */
  TIMEOUT: 3,
  /** その tunnelId は登録されていない (保持者が切れた・未登録) */
  NO_TUNNEL: 4,
  /** 要求が壊れている・復号できない */
  BAD_REQUEST: 5,
} as const;
export const TUNNEL_FLAG_FINAL = 1;

/**
 * OZZY_REPLY / OZZY_RESULT 1 フレームの上限 (type 1 バイトを含む)。★ 4KiB 以下にして DataChannel の 1 メッセージで送る
 * (ChunkedSender の分割・再組み立てに乗せない。再組み立ての同時数の上限で捨てられないように)。
 */
export const MAX_OZZY_FRAME_BYTES = 4096;
/** OZZY_REPLY の返送先 (Guard の X25519 鍵への sealed box: 読み手の peerId 16 ‖ replyId u32) */
export const OZZY_REPLY_HEADER_BYTES = 48 + 16 + 4;
/** OZZY_REPLY の body を除く固定部 (type 1 バイトを含む) */
export const OZZY_REPLY_FIXED_BYTES = 1 + OZZY_REPLY_HEADER_BYTES + 2 + 1;
export const OZZY_FLAG_FINAL = 1;
/** OZZY_UP の宛先 (Guard の X25519 鍵への sealed box: M1 の peerId 16 ‖ uploadId 16) */
export const OZZY_UP_HEADER_BYTES = 48 + 16 + 16;
/** OZZY_UP の body を除く固定部 (type 1 バイトを含む) */
export const OZZY_UP_FIXED_BYTES = 1 + OZZY_UP_HEADER_BYTES + 2 + 1;
export const OZZY_UPLOAD_ID_BYTES = 16;
/** OZZY_WORKER_ADS 1 回に載せる広告の数と、フレームの上限 (type 1 バイトを含む。URL は 200 バイトまで) */
export const MAX_OZZY_WORKER_ADS = 16;
export const MAX_OZZY_WORKER_FRAME_BYTES = 2 + MAX_OZZY_WORKER_ADS * (32 + 4 + 4 + 1 + 200 + 64);

/** body を除く固定部 (type 1 バイトを含む) */
export const TUNNEL_HEADER_BYTES = {
  SEND: 1 + 4 + 16 + 8,
  FWD: 1 + 4 + 8,
  DELIVER: 1 + 4 + 16,
  REPLY: 1 + 4 + 16 + 2 + 1,
  RET: 1 + 4 + 2 + 1,
  RESULT: 1 + 4 + 2 + 1,
} as const;
/** CATCHUP_END の status */
export const CATCHUP_STATUS = {
  /** 要求の範囲をすべて送った */
  OK: 0,
  /** since がバッファの範囲より古かった。持っている分は全部送ったが、その前の分は無い (保管担当へ) */
  PARTIAL: 1,
  /** 同じ相手の追いつきが進行中、または間隔が短すぎる。送っていない */
  BUSY: 2,
} as const;
const MAX_U24 = 0xffffff;

/** u8 の長さ前置きで「null」を表す値 / u16 の mLineIndex で「null」を表す値 */
const NULL_LEN8 = 0xff;
const NULL_U16 = 0xffff;
const PUBKEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const PEER_ID_RE = /^[0-9a-f]{32}$/;
const SDP_TYPES = ['offer', 'answer', 'pranswer', 'rollback'] as const;
const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** 各種別の固定長 (ヘッダの 1 バイトを含まない本体の長さ)。テストと MAX_FRAME_BYTES が参照する */
export const WIRE_BODY_BYTES = {
  HELLO: CHALLENGE_BYTES,
  JOIN: PUBKEY_BYTES + 4 + SIGNATURE_BYTES,
  PING: 4,
  PONG: 4,
  PEX_ENTRY: PUBKEY_BYTES + 4,
  CATCHUP_REQ: 3,
  CATCHUP_END: 1 + 3,
  TUNNEL_REGISTER: 8,
  TUNNEL_REGISTERED: 8 + 1,
  TUNNEL_ERROR: 4 + 1,
} as const;
const TUNNEL_ID_BYTES = 8;

function peerIdBytes(id: unknown, what: string): Uint8Array {
  if (typeof id !== 'string' || !PEER_ID_RE.test(id)) throw new RangeError(`${what}: bad peerId`);
  return Encoding.fromHex(id);
}

function u32Of(v: unknown, what: string): number {
  if (!Number.isInteger(v) || (v as number) < 0 || (v as number) > NODE_ID_POW_COUNTER_MAX) throw new RangeError(`${what}: not a u32`);
  return v as number;
}

function bytesOf(v: unknown, len: number, what: string): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== len) throw new RangeError(`${what}: must be ${len} bytes`);
  return v;
}

function writeU32(w: ByteWriter, v: number): void {
  w.u16(Math.floor(v / 0x10000)).u16(v % 0x10000);
}

function readU32(r: ByteReader): number {
  return r.u16() * 0x10000 + r.u16();
}

/** u8 長 + UTF-8。null は 0xFF (本文は最大 254 バイト) */
function writeLp8(w: ByteWriter, s: string | null | undefined): void {
  if (s === null || s === undefined) {
    w.u8(NULL_LEN8);
    return;
  }
  const b = utf8.encode(s);
  if (b.length >= NULL_LEN8) throw new RangeError('lp8 too long');
  w.u8(b.length).raw(b);
}

function readLp8(r: ByteReader): string | null {
  const n = r.u8();
  if (n === NULL_LEN8) return null;
  return utf8Strict.decode(r.bytes(n));
}

function writeLp16(w: ByteWriter, s: string, max: number): void {
  const b = utf8.encode(s);
  if (b.length > max) throw new RangeError('text too long');
  w.u16(b.length).raw(b);
}

function readLp16(r: ByteReader, max: number): string {
  const n = r.u16();
  if (n > max) throw new RangeError('text too long');
  return utf8Strict.decode(r.bytes(n));
}

function writeU24(w: ByteWriter, v: number, what: string): void {
  if (!Number.isInteger(v) || v < 0 || v > MAX_U24) throw new RangeError(`${what}: not a u24`);
  w.u8(v >>> 16).u8((v >>> 8) & 0xff).u8(v & 0xff);
}

function readU24(r: ByteReader): number {
  return (r.u8() << 16) | (r.u8() << 8) | r.u8();
}

function withType(type: WireType, body: Uint8Array): Uint8Array {
  const frame = new Uint8Array(1 + body.length);
  frame[0] = type;
  frame.set(body, 1);
  return frame;
}

/** 固定部 (w) に body を足して 1 フレームにする。body は 1 バイト以上、フレーム全体で 16KiB 以内 */
function tunnelFrame(type: WireType, w: ByteWriter, body: unknown): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length === 0) throw new RangeError('TUNNEL: body must be non-empty bytes');
  const frame = withType(type, w.raw(body).finish());
  if (frame.length > MAX_TUNNEL_FRAME_BYTES) throw new RangeError('TUNNEL: frame too large');
  return frame;
}

export class WireCodec {
  /**
   * payload は上位の層が扱う形 (decode の戻りと同じ形)。
   * 範囲違反は RangeError (呼び出し側のバグなので握りつぶさない)。
   */
  static encode(type: WireType, payload: any): Uint8Array {
    switch (type) {
      case WireType.HELLO:
        return withType(type, bytesOf(payload?.challenge, CHALLENGE_BYTES, 'HELLO.challenge'));

      case WireType.JOIN: {
        const w = new ByteWriter().raw(bytesOf(payload?.pubkey, PUBKEY_BYTES, 'JOIN.pubkey'));
        writeU32(w, u32Of(payload?.powCounter, 'JOIN.powCounter'));
        return withType(type, w.raw(bytesOf(payload?.signature, SIGNATURE_BYTES, 'JOIN.signature')).finish());
      }

      case WireType.PING:
      case WireType.PONG: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.nonce, 'PING/PONG.nonce'));
        return withType(type, w.finish());
      }

      case WireType.PEX_REQUEST:
        return withType(type, new Uint8Array(0));

      case WireType.PEX_RESPONSE: {
        // 検証用の claim (pubkey + powCounter) を持たない項目は運べない (受け手が検証できない)
        const peers: any[] = Array.isArray(payload?.peers) ? payload.peers : [];
        const entries = peers.filter(p => p?.pubkey instanceof Uint8Array && typeof p?.powCounter === 'number');
        if (entries.length > MAX_PEX_ENTRIES) throw new RangeError('PEX_RESPONSE: too many entries');
        const w = new ByteWriter().u8(entries.length);
        for (const p of entries) {
          w.raw(bytesOf(p.pubkey, PUBKEY_BYTES, 'PEX.pubkey'));
          writeU32(w, u32Of(p.powCounter, 'PEX.powCounter'));
        }
        return withType(type, w.finish());
      }

      case WireType.SDP_RELAY: {
        const idx = SDP_TYPES.indexOf(payload?.sdp?.type);
        if (idx < 0) throw new RangeError('SDP_RELAY: bad sdp type');
        const w = new ByteWriter()
          .raw(peerIdBytes(payload.targetPeerId, 'SDP_RELAY.target'))
          .raw(peerIdBytes(payload.senderId, 'SDP_RELAY.sender'))
          .u8(idx);
        writeLp16(w, typeof payload.sdp.sdp === 'string' ? payload.sdp.sdp : '', MAX_SDP_BYTES);
        return withType(type, w.finish());
      }

      case WireType.ICE_RELAY: {
        const c = payload?.candidate;
        if (typeof c?.candidate !== 'string' || c.candidate.length === 0) throw new RangeError('ICE_RELAY: bad candidate');
        const w = new ByteWriter()
          .raw(peerIdBytes(payload.targetPeerId, 'ICE_RELAY.target'))
          .raw(peerIdBytes(payload.senderId, 'ICE_RELAY.sender'));
        const m = c.sdpMLineIndex;
        if (m === null || m === undefined) w.u16(NULL_U16);
        else if (Number.isInteger(m) && m >= 0 && m < NULL_U16) w.u16(m);
        else throw new RangeError('ICE_RELAY: bad sdpMLineIndex');
        writeLp8(w, c.sdpMid);
        writeLp8(w, c.usernameFragment);
        writeLp16(w, c.candidate, MAX_ICE_CANDIDATE_BYTES);
        return withType(type, w.finish());
      }

      // ★ GOSSIP / STEM は PacketCodec / ExitItem のバイト列をそのまま本体にする。
      //   ハンドラには decode 側が元のオブジェクトを返すので、上位の層は形式を意識しない。
      case WireType.GOSSIP: {
        const p = payload?.packet;
        return withType(type, p instanceof Uint8Array ? p : encodePacket(p));
      }
      case WireType.STEM: {
        const item = payload?.item;
        return withType(type, item instanceof Uint8Array ? item : encodeExitItem(item));
      }
      case WireType.ONION_STEM: {
        const cell = payload?.onionBytes;
        if (!(cell instanceof Uint8Array)) throw new RangeError('ONION_STEM: onionBytes must be bytes');
        return withType(type, cell);
      }

      case WireType.CATCHUP_REQ: {
        const w = new ByteWriter();
        writeU24(w, payload?.since, 'CATCHUP_REQ.since');
        return withType(type, w.finish());
      }

      case WireType.CATCHUP_DATA: {
        // パケットは encodePacket 済みのバイト列で運ぶ (サーバはバッファの中身をそのまま送る)
        const packets: unknown = payload?.packets;
        if (!Array.isArray(packets)) throw new RangeError('CATCHUP_DATA: packets must be an array');
        const w = new ByteWriter().u16(packets.length);
        for (const p of packets) {
          if (!(p instanceof Uint8Array) || p.length === 0 || p.length > 0xffff) throw new RangeError('CATCHUP_DATA: bad packet bytes');
          w.u16(p.length).raw(p);
        }
        const frame = withType(type, w.finish());
        if (frame.length > MAX_CATCHUP_FRAME_BYTES) throw new RangeError('CATCHUP_DATA: frame too large');
        return frame;
      }

      case WireType.CATCHUP_END: {
        const status = payload?.status;
        if (status !== CATCHUP_STATUS.OK && status !== CATCHUP_STATUS.PARTIAL && status !== CATCHUP_STATUS.BUSY) {
          throw new RangeError('CATCHUP_END: bad status');
        }
        const w = new ByteWriter().u8(status);
        writeU24(w, payload?.nextSince, 'CATCHUP_END.nextSince');
        return withType(type, w.finish());
      }

      case WireType.LEASESET: {
        const b = payload?.leaseSet;
        if (!(b instanceof Uint8Array) || b.length < LEASESET_MIN_BYTES || b.length > LEASESET_MAX_BYTES) {
          throw new RangeError('LEASESET: bad leaseSet bytes');
        }
        return withType(type, b);
      }

      case WireType.LEASESET_SYNC_REQ:
        return withType(type, new Uint8Array(0));

      case WireType.LEASESET_SYNC: {
        const sets: unknown = payload?.leaseSets;
        if (!Array.isArray(sets)) throw new RangeError('LEASESET_SYNC: leaseSets must be an array');
        const w = new ByteWriter().u16(sets.length);
        for (const b of sets) {
          if (!(b instanceof Uint8Array) || b.length < LEASESET_MIN_BYTES || b.length > LEASESET_MAX_BYTES) {
            throw new RangeError('LEASESET_SYNC: bad leaseSet bytes');
          }
          w.u16(b.length).raw(b);
        }
        const frame = withType(type, w.finish());
        if (frame.length > MAX_LEASESET_FRAME_BYTES) throw new RangeError('LEASESET_SYNC: frame too large');
        return frame;
      }

      case WireType.TUNNEL_REGISTER:
        return withType(type, bytesOf(payload?.tunnelId, TUNNEL_ID_BYTES, 'TUNNEL_REGISTER.tunnelId'));

      case WireType.TUNNEL_REGISTERED:
        return withType(type, new ByteWriter().raw(bytesOf(payload?.tunnelId, TUNNEL_ID_BYTES, 'TUNNEL_REGISTERED.tunnelId')).u8(payload?.ok ? 1 : 0).finish());

      case WireType.TUNNEL_SEND: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.reqId, 'TUNNEL_SEND.reqId'));
        w.raw(peerIdBytes(payload?.gateway, 'TUNNEL_SEND.gateway')).raw(bytesOf(payload?.tunnelId, TUNNEL_ID_BYTES, 'TUNNEL_SEND.tunnelId'));
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_FWD: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.returnTag, 'TUNNEL_FWD.returnTag'));
        w.raw(bytesOf(payload?.tunnelId, TUNNEL_ID_BYTES, 'TUNNEL_FWD.tunnelId'));
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_DELIVER: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.returnTag, 'TUNNEL_DELIVER.returnTag'));
        w.raw(peerIdBytes(payload?.fromHop, 'TUNNEL_DELIVER.fromHop'));
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_REPLY: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.returnTag, 'TUNNEL_REPLY.returnTag'));
        w.raw(peerIdBytes(payload?.toHop, 'TUNNEL_REPLY.toHop')).u16(payload?.seq).u8(payload?.final ? TUNNEL_FLAG_FINAL : 0);
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_RET: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.returnTag, 'TUNNEL_RET.returnTag'));
        w.u16(payload?.seq).u8(payload?.final ? TUNNEL_FLAG_FINAL : 0);
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_RESULT: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.reqId, 'TUNNEL_RESULT.reqId'));
        w.u16(payload?.seq).u8(payload?.final ? TUNNEL_FLAG_FINAL : 0);
        return tunnelFrame(type, w, payload?.body);
      }

      case WireType.TUNNEL_ERROR: {
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.id, 'TUNNEL_ERROR.id'));
        const code = payload?.code;
        if (!Number.isInteger(code) || code < 1 || code > 0xff) throw new RangeError('TUNNEL_ERROR: bad code');
        return withType(type, w.u8(code).finish());
      }

      case WireType.OZZY_REPLY: {
        const header = payload?.header;
        const body = payload?.body;
        if (!(header instanceof Uint8Array) || header.length !== OZZY_REPLY_HEADER_BYTES) throw new TypeError('OZZY_REPLY: bad header');
        if (!(body instanceof Uint8Array) || body.length === 0) throw new TypeError('OZZY_REPLY: body missing');
        if (OZZY_REPLY_FIXED_BYTES + body.length > MAX_OZZY_FRAME_BYTES) throw new RangeError('OZZY_REPLY: too large');
        const seq = payload?.seq;
        if (!Number.isInteger(seq) || seq < 0 || seq > 0xffff) throw new RangeError('OZZY_REPLY: bad seq');
        return withType(type, new ByteWriter().raw(header).u16(seq).u8(payload?.final ? OZZY_FLAG_FINAL : 0).raw(body).finish());
      }

      case WireType.OZZY_UP: {
        const header = payload?.header;
        const body = payload?.body;
        if (!(header instanceof Uint8Array) || header.length !== OZZY_UP_HEADER_BYTES) throw new TypeError('OZZY_UP: bad header');
        if (!(body instanceof Uint8Array) || body.length === 0) throw new TypeError('OZZY_UP: body missing');
        if (OZZY_UP_FIXED_BYTES + body.length > MAX_OZZY_FRAME_BYTES) throw new RangeError('OZZY_UP: too large');
        const seq = payload?.seq;
        if (!Number.isInteger(seq) || seq < 0 || seq > 0xffff) throw new RangeError('OZZY_UP: bad seq');
        return withType(type, new ByteWriter().raw(header).u16(seq).u8(payload?.final ? OZZY_FLAG_FINAL : 0).raw(body).finish());
      }

      case WireType.OZZY_UP_FWD: {
        const uploadId = payload?.uploadId;
        const body = payload?.body;
        if (!(uploadId instanceof Uint8Array) || uploadId.length !== OZZY_UPLOAD_ID_BYTES) throw new TypeError('OZZY_UP_FWD: bad uploadId');
        if (!(body instanceof Uint8Array) || body.length === 0) throw new TypeError('OZZY_UP_FWD: body missing');
        if (1 + OZZY_UPLOAD_ID_BYTES + 3 + body.length > MAX_OZZY_FRAME_BYTES) throw new RangeError('OZZY_UP_FWD: too large');
        const seq = payload?.seq;
        if (!Number.isInteger(seq) || seq < 0 || seq > 0xffff) throw new RangeError('OZZY_UP_FWD: bad seq');
        return withType(type, new ByteWriter().raw(uploadId).u16(seq).u8(payload?.final ? OZZY_FLAG_FINAL : 0).raw(body).finish());
      }

      case WireType.OZZY_WORKER_REQ:
        return withType(type, new Uint8Array(0));

      case WireType.OZZY_WORKER_ADS: {
        const ads: unknown = payload?.ads;
        if (!Array.isArray(ads) || ads.length === 0 || ads.length > MAX_OZZY_WORKER_ADS) throw new RangeError('OZZY_WORKER_ADS: bad count');
        const w = new ByteWriter().u8(ads.length);
        for (const ad of ads) {
          const url = utf8.encode(String(ad?.url ?? ''));
          if (!(ad?.pubkey instanceof Uint8Array) || ad.pubkey.length !== PUBKEY_BYTES) throw new TypeError('OZZY_WORKER_ADS: bad pubkey');
          if (!(ad.signature instanceof Uint8Array) || ad.signature.length !== SIGNATURE_BYTES) throw new TypeError('OZZY_WORKER_ADS: bad signature');
          if (url.length < 1 || url.length > 200) throw new RangeError('OZZY_WORKER_ADS: bad url');
          w.raw(ad.pubkey);
          writeU32(w, u32Of(ad.powCounter, 'OZZY_WORKER_ADS.powCounter'));
          writeU32(w, u32Of(ad.expiresMin, 'OZZY_WORKER_ADS.expiresMin'));
          w.u8(url.length).raw(url).raw(ad.signature);
        }
        return withType(type, w.finish());
      }

      case WireType.OZZY_RESULT: {
        const body = payload?.body;
        if (!(body instanceof Uint8Array) || body.length === 0) throw new TypeError('OZZY_RESULT: body missing');
        if (1 + 4 + 2 + 1 + body.length > MAX_OZZY_FRAME_BYTES) throw new RangeError('OZZY_RESULT: too large');
        const seq = payload?.seq;
        if (!Number.isInteger(seq) || seq < 0 || seq > 0xffff) throw new RangeError('OZZY_RESULT: bad seq');
        const w = new ByteWriter();
        writeU32(w, u32Of(payload?.replyId, 'OZZY_RESULT.replyId'));
        return withType(type, w.u16(seq).u8(payload?.final ? OZZY_FLAG_FINAL : 0).raw(body).finish());
      }

      default:
        throw new RangeError(`WireCodec.encode: unknown type 0x${Number(type).toString(16)}`);
    }
  }

  /**
   * 失敗 (未知の種別・長さ違反・余りバイト・不正な UTF-8 …) は { UNKNOWN, null }。例外は投げない。
   * 旧実装の JSON フォールバックは廃止した (網の外から来る平文 JSON を受け付ける理由がない)。
   */
  static decode(data: Uint8Array): DecodedWireMessage {
    const bad: DecodedWireMessage = { type: WireType.UNKNOWN, payload: null };
    if (!(data instanceof Uint8Array) || data.length < 1) return bad;
    const typeByte = data[0];
    // ★ 範囲のハードコードはしない (WireType を足したときに無言で落ちるのを防ぐ)。既知の集合そのもので判定する。
    if (!KNOWN_WIRE_TYPES.has(typeByte)) return bad;
    const type = typeByte as WireType;
    const body = data.subarray(1);

    try {
      const r = new ByteReader(body);
      switch (type) {
        case WireType.HELLO: {
          const challenge = r.bytes(CHALLENGE_BYTES).slice();
          r.end();
          return { type, payload: { challenge } };
        }

        case WireType.JOIN: {
          const pubkey = r.bytes(PUBKEY_BYTES).slice();
          const powCounter = readU32(r);
          const signature = r.bytes(SIGNATURE_BYTES).slice();
          r.end();
          return { type, payload: { pubkey, powCounter, signature } };
        }

        case WireType.PING:
        case WireType.PONG: {
          const nonce = readU32(r);
          r.end();
          return { type, payload: { nonce } };
        }

        case WireType.PEX_REQUEST:
          r.end();
          return { type, payload: {} };

        case WireType.PEX_RESPONSE: {
          const count = r.u8();
          if (count > MAX_PEX_ENTRIES) return bad;
          const peers: Array<{ id: string; pubkey: Uint8Array; powCounter: number }> = [];
          for (let i = 0; i < count; i++) {
            const pubkey = r.bytes(PUBKEY_BYTES).slice();
            const powCounter = readU32(r);
            // ★ id は pubkey から導出する (申告させない)。束縛の検証は受け手 (verifyClaim) が行う
            peers.push({ id: NodeIdentity.derivePeerId(pubkey), pubkey, powCounter });
          }
          r.end();
          return { type, payload: { peers } };
        }

        case WireType.SDP_RELAY: {
          const targetPeerId = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const senderId = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const sdpType = SDP_TYPES[r.u8()];
          if (!sdpType) return bad;
          const sdp = readLp16(r, MAX_SDP_BYTES);
          r.end();
          return { type, payload: { targetPeerId, senderId, sdp: { type: sdpType, sdp } } };
        }

        case WireType.ICE_RELAY: {
          const targetPeerId = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const senderId = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const m = r.u16();
          const sdpMid = readLp8(r);
          const usernameFragment = readLp8(r);
          const candidate = readLp16(r, MAX_ICE_CANDIDATE_BYTES);
          r.end();
          if (candidate.length === 0) return bad;
          return {
            type,
            payload: {
              targetPeerId,
              senderId,
              candidate: { candidate, sdpMid, sdpMLineIndex: m === NULL_U16 ? null : m, usernameFragment },
            },
          };
        }

        // 中身が読めなければ null (ハンドラが拒否する)。形式違反をここで接続断にはしない
        case WireType.GOSSIP:
          return { type, payload: { packet: decodePacket(body) } };
        case WireType.STEM:
          return { type, payload: { item: decodeExitItem(body) } };
        // 長さの検査 (CELL_SIZE) は受け手 (OnionCircuit.handleCell) が行う
        case WireType.ONION_STEM:
          return { type, payload: { onionBytes: body.slice() } };

        case WireType.CATCHUP_REQ: {
          const since = readU24(r);
          r.end();
          return { type, payload: { since } };
        }

        case WireType.CATCHUP_DATA: {
          const count = r.u16();
          const packets: Uint8Array[] = [];
          for (let i = 0; i < count; i++) {
            const len = r.u16();
            if (len === 0) return bad;
            packets.push(r.bytes(len).slice());
          }
          r.end();
          return { type, payload: { packets } };
        }

        case WireType.CATCHUP_END: {
          const status = r.u8();
          if (status !== CATCHUP_STATUS.OK && status !== CATCHUP_STATUS.PARTIAL && status !== CATCHUP_STATUS.BUSY) return bad;
          const nextSince = readU24(r);
          r.end();
          return { type, payload: { status, nextSince } };
        }

        // 構造 (署名・PoW・期限) の検証は受け手 (LeaseSetRouter) が行う。ここは長さだけ
        case WireType.LEASESET: {
          if (body.length < LEASESET_MIN_BYTES || body.length > LEASESET_MAX_BYTES) return bad;
          return { type, payload: { leaseSet: body.slice() } };
        }

        case WireType.LEASESET_SYNC_REQ:
          r.end();
          return { type, payload: {} };

        case WireType.LEASESET_SYNC: {
          const count = r.u16();
          const leaseSets: Uint8Array[] = [];
          for (let i = 0; i < count; i++) {
            const len = r.u16();
            if (len < LEASESET_MIN_BYTES || len > LEASESET_MAX_BYTES) return bad;
            leaseSets.push(r.bytes(len).slice());
          }
          r.end();
          return { type, payload: { leaseSets } };
        }

        case WireType.TUNNEL_REGISTER: {
          const tunnelId = r.bytes(TUNNEL_ID_BYTES).slice();
          r.end();
          return { type, payload: { tunnelId } };
        }

        case WireType.TUNNEL_REGISTERED: {
          const tunnelId = r.bytes(TUNNEL_ID_BYTES).slice();
          const ok = r.u8();
          if (ok > 1) return bad;
          r.end();
          return { type, payload: { tunnelId, ok: ok === 1 } };
        }

        case WireType.TUNNEL_SEND: {
          if (data.length > MAX_TUNNEL_FRAME_BYTES) return bad;
          const reqId = readU32(r);
          const gateway = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const tunnelId = r.bytes(TUNNEL_ID_BYTES).slice();
          const b = r.rest();
          if (b.length === 0) return bad;
          return { type, payload: { reqId, gateway, tunnelId, body: b.slice() } };
        }

        case WireType.TUNNEL_FWD: {
          if (data.length > MAX_TUNNEL_FRAME_BYTES) return bad;
          const returnTag = readU32(r);
          const tunnelId = r.bytes(TUNNEL_ID_BYTES).slice();
          const b = r.rest();
          if (b.length === 0) return bad;
          return { type, payload: { returnTag, tunnelId, body: b.slice() } };
        }

        case WireType.TUNNEL_DELIVER: {
          if (data.length > MAX_TUNNEL_FRAME_BYTES) return bad;
          const returnTag = readU32(r);
          const fromHop = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const b = r.rest();
          if (b.length === 0) return bad;
          return { type, payload: { returnTag, fromHop, body: b.slice() } };
        }

        case WireType.TUNNEL_REPLY: {
          if (data.length > MAX_TUNNEL_FRAME_BYTES) return bad;
          const returnTag = readU32(r);
          const toHop = Encoding.toHex(r.bytes(PEER_ID_BYTES));
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~TUNNEL_FLAG_FINAL) !== 0) return bad;
          const b = r.rest();
          if (b.length === 0) return bad;
          return { type, payload: { returnTag, toHop, seq, final: (flags & TUNNEL_FLAG_FINAL) !== 0, body: b.slice() } };
        }

        case WireType.TUNNEL_RET:
        case WireType.TUNNEL_RESULT: {
          if (data.length > MAX_TUNNEL_FRAME_BYTES) return bad;
          const id = readU32(r);
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~TUNNEL_FLAG_FINAL) !== 0) return bad;
          const b = r.rest();
          if (b.length === 0) return bad;
          const final = (flags & TUNNEL_FLAG_FINAL) !== 0;
          return type === WireType.TUNNEL_RET
            ? { type, payload: { returnTag: id, seq, final, body: b.slice() } }
            : { type, payload: { reqId: id, seq, final, body: b.slice() } };
        }

        case WireType.TUNNEL_ERROR: {
          const id = readU32(r);
          const code = r.u8();
          r.end();
          if (code === 0) return bad;
          return { type, payload: { id, code } };
        }


        case WireType.OZZY_REPLY: {
          if (data.length > MAX_OZZY_FRAME_BYTES) return bad;
          const header = r.bytes(OZZY_REPLY_HEADER_BYTES).slice();
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~OZZY_FLAG_FINAL) !== 0) return bad;
          const body = r.rest().slice();
          if (body.length === 0) return bad;
          return { type, payload: { header, seq, final: (flags & OZZY_FLAG_FINAL) !== 0, body } };
        }

        case WireType.OZZY_UP: {
          if (data.length > MAX_OZZY_FRAME_BYTES) return bad;
          const header = r.bytes(OZZY_UP_HEADER_BYTES).slice();
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~OZZY_FLAG_FINAL) !== 0) return bad;
          const body = r.rest().slice();
          if (body.length === 0) return bad;
          return { type, payload: { header, seq, final: (flags & OZZY_FLAG_FINAL) !== 0, body } };
        }

        case WireType.OZZY_UP_FWD: {
          if (data.length > MAX_OZZY_FRAME_BYTES) return bad;
          const uploadId = r.bytes(OZZY_UPLOAD_ID_BYTES).slice();
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~OZZY_FLAG_FINAL) !== 0) return bad;
          const body = r.rest().slice();
          if (body.length === 0) return bad;
          return { type, payload: { uploadId, seq, final: (flags & OZZY_FLAG_FINAL) !== 0, body } };
        }

        case WireType.OZZY_WORKER_REQ:
          r.end();
          return { type, payload: {} };

        case WireType.OZZY_WORKER_ADS: {
          if (data.length > MAX_OZZY_WORKER_FRAME_BYTES) return bad;
          const count = r.u8();
          if (count < 1 || count > MAX_OZZY_WORKER_ADS) return bad;
          const ads = [];
          for (let i = 0; i < count; i++) {
            const pubkey = r.bytes(PUBKEY_BYTES).slice();
            const powCounter = readU32(r);
            const expiresMin = readU32(r);
            const urlLen = r.u8();
            if (urlLen < 1 || urlLen > 200) return bad;
            const url = utf8Strict.decode(r.bytes(urlLen));
            const signature = r.bytes(SIGNATURE_BYTES).slice();
            ads.push({ pubkey, powCounter, expiresMin, url, signature });
          }
          r.end();
          return { type, payload: { ads } };
        }

        case WireType.OZZY_RESULT: {
          if (data.length > MAX_OZZY_FRAME_BYTES) return bad;
          const replyId = readU32(r);
          const seq = r.u16();
          const flags = r.u8();
          if ((flags & ~OZZY_FLAG_FINAL) !== 0) return bad;
          const body = r.rest().slice();
          if (body.length === 0) return bad;
          return { type, payload: { replyId, seq, final: (flags & OZZY_FLAG_FINAL) !== 0, body } };
        }
      }
    } catch {
      // 切り詰め・不正な UTF-8 など
    }
    return bad;
  }
}
