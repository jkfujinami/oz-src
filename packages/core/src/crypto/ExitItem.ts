import { ByteReader, ByteWriter } from '../common/ByteIO';
import type { GossipPacket } from '../types';
import { decodePacket, encodePacket } from './PacketCodec';
import { FRAG_ID_BYTES, MAX_FRAGMENTS, OnionRouter, type ExitPayload } from './OnionRouter';

/**
 * ExitItem — 作者が網へ出す「1 件」(M1 に届き、Stem を歩き、Fluff される単位)。
 *
 * ★ 回路の中では断片 (frag) に分けて運ぶ (OnionRouter.ExitPayload)。ここはその前後の符号化。
 *
 *   exit_fluff : Gossip を Fluff する
 *
 * 形式 (位置固定のバイナリ。Stem フレームの item もこれ):
 *   kind u8 (1 = fluff) ‖ packet (PacketCodec。残り全部)
 *
 * ★ 旧形式にあった Schrödinger の Slot / Hint (kind 2、flags、topicHash) は撤去した (history v2)。
 *   過去ログのための「保管の依頼」は作者の発信に載せない: 投稿は flood で全員に届くので、
 *   保管担当は自分の受け持ちを受け取った投稿から保存するだけでよい (docs/design/history-v2.md §4)。
 *   kind を 1 バイト残してあるのは、将来別の種別を足すときに fail-closed で古い版が拒否できるように。
 */
export type ExitItem = {
  type: 'exit_fluff';
  packet: GossipPacket;
};

const KIND_FLUFF = 1;

export function encodeExitItem(item: ExitItem): Uint8Array {
  if (item.type !== 'exit_fluff') throw new RangeError('encodeExitItem: unknown item type');
  return new ByteWriter().u8(KIND_FLUFF).raw(encodePacket(item.packet)).finish();
}

/** 失敗 (形式違反・未知の種別・packet の不正) は null。packet_id は導出される */
export function decodeExitItem(bytes: Uint8Array): ExitItem | null {
  try {
    const r = new ByteReader(bytes);
    if (r.u8() !== KIND_FLUFF) return null;
    const packet = decodePacket(r.rest());
    if (!packet) return null;
    return { type: 'exit_fluff', packet };
  } catch {
    return null;
  }
}

/** 断片の枚数を数える (切り上げ)。0 バイトは 1 枚 */
export function fragmentCount(byteLength: number): number {
  return Math.max(1, Math.ceil(byteLength / OnionRouter.FRAG_DATA_MAX));
}

/**
 * item を断片に分ける。MAX_FRAGMENTS を超えるなら null (呼び出し側が拒否する)。
 * 断片 id は item ごとの乱数 (M1 が送り主 (Guard) と組にして再構成する)。
 */
export function splitIntoFragments(bytes: Uint8Array, id: Uint8Array): Array<Extract<ExitPayload, { type: 'frag' }>> | null {
  if (id.length !== FRAG_ID_BYTES) throw new RangeError('splitIntoFragments: bad id length');
  const total = fragmentCount(bytes.length);
  if (total > MAX_FRAGMENTS) return null;
  const out: Array<Extract<ExitPayload, { type: 'frag' }>> = [];
  for (let idx = 0; idx < total; idx++) {
    const data = bytes.slice(idx * OnionRouter.FRAG_DATA_MAX, (idx + 1) * OnionRouter.FRAG_DATA_MAX);
    out.push({ type: 'frag', id, idx, total, data });
  }
  return out;
}
