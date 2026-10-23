import { ByteReader, ByteWriter } from '../common/ByteIO';
import type { GossipPacket } from '../types';
import { EQUIX_SOLUTION_BYTES } from './equix/EquiX';
import {
  PACKET_VERSION, POW_POLICY, derivePacketId, minutesToMs, msToMinutes, toBytes,
} from './PowPolicy';

/**
 * PacketCodec — GossipPacket のワイヤ形式 v5 (外側のパケット。経路上の全員に見える)。
 *
 *   offset  size  field
 *   0       1     version (= 2)
 *   1       3     time: u24。OZ_EPOCH (2025-01-01T00:00:00Z) からの分
 *   4       2     tag: u16。下位 12 ビットだけ使う (上位 4 ビットは 0)
 *   6       1     age: u8。スレ立てからの日数 (0..90。90 超は中継が拒否)
 *   7       1     effort の指数 e: effort = floor(2^(e/4)) (e=0 → 1, e ≤ 80)
 *   8       4     pow nonce: u32
 *   12      16    Equi-X の解
 *   28      …     payload (SIV 暗号文。残り全部。長さの前置きは無い)
 *   固定部 = 28 バイト
 *
 * ★ payload に長さを前置きしない。どの入れ物も、パケットを最後に置くか (ExitItem / SlotBlob)、
 *   外側が長さを持つ (ストレージ / WireCodec のフレーム) ので、2 バイト浮く。
 * ★ time は分単位。ミリ秒精度だと端末の時計のずれが指紋になる (PacketBuilder が分に丸める)。
 * ★ tag / age の意味は PacketTag を参照。中継が見るのは tag < 4096 と age ≤ 90 だけ。
 * ★ packet_id は載せない。ヘッダ (effort / nonce / 解を除く) とペイロードの SHA-256 の先頭 16 バイトを
 *   decode のときに導出する。だから「申告された packet_id が偽」という状態がワイヤ上に存在しない。
 *   effort / nonce / 解を id に入れないのは、解き直しても同じ投稿が同じ id になるように (重複排除のため)。
 * ★ 未知の version は拒否する (fail-closed)。v1 (先頭 0x01) は先頭バイトで落ちるので、旧形式の
 *   パケットは網からも端末の DB からも読めない (公開前なので互換は持たない)。
 */
export const PACKET_FIXED_OVERHEAD = POW_POLICY.HEADER_BYTES;

export function encodePacket(packet: GossipPacket): Uint8Array {
  const payload = toBytes(packet.payload);
  const solution = toBytes(packet.pow_solution);
  if (solution.length !== EQUIX_SOLUTION_BYTES) throw new RangeError('encodePacket: bad solution size');
  if (payload.length === 0 || payload.length > POW_POLICY.MAX_PAYLOAD_SIZE) {
    throw new RangeError(`encodePacket: payload size ${payload.length} out of range`);
  }
  if (!Number.isInteger(packet.pow_nonce) || packet.pow_nonce < 0 || packet.pow_nonce > 0xffffffff) {
    throw new RangeError('encodePacket: bad pow_nonce');
  }
  const time = msToMinutes(packet.timestamp);
  const w = new ByteWriter()
    .u8(PACKET_VERSION)
    .u8(time >>> 16).u8((time >>> 8) & 0xff).u8(time & 0xff)
    .u16(packet.tag)
    .u8(packet.age)
    .u8(packet.effort_exp);
  const nonce = new Uint8Array(4);
  new DataView(nonce.buffer).setUint32(0, packet.pow_nonce, false);
  return w.raw(nonce).raw(solution).raw(payload).finish();
}

/** 失敗 (version 違い・切り詰め) は null。packet_id はここで導出する。tag / age / effort の範囲は PacketValidator が見る */
export function decodePacket(bytes: Uint8Array): GossipPacket | null {
  try {
    const r = new ByteReader(bytes);
    const version = r.u8();
    if (version !== PACKET_VERSION) return null;
    const time = (r.u8() << 16) | (r.u8() << 8) | r.u8();
    const tag = r.u16();
    const age = r.u8();
    const effort_exp = r.u8();
    const nb = r.bytes(4);
    const pow_nonce = new DataView(nb.buffer, nb.byteOffset, 4).getUint32(0, false);
    const pow_solution = r.bytes(EQUIX_SOLUTION_BYTES).slice();
    const payload = r.rest().slice();
    if (payload.length === 0 || payload.length > POW_POLICY.MAX_PAYLOAD_SIZE) return null;
    return {
      packet_id: derivePacketId({ version, time, tag, age, payload }),
      timestamp: minutesToMs(time),
      tag,
      age,
      effort_exp,
      pow_nonce,
      pow_solution,
      payload,
    };
  } catch {
    return null;
  }
}
