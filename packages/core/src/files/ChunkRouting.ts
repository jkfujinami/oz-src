import type { PeerId } from '../types';
import { chunkPositions } from './FileCodec';
import { CHUNK_DUTY_SLOTS, CHUNK_READ_SLOTS, R_FILE } from '../network/storage/ChunkProtocol';
import type { Duty } from '../network/storage/Duty';
import type { LeaseSetStore } from '../network/storage/LeaseSetStore';

/** チャンクを預ける・取りに行く先の保持者 1 台 (leaseSet から) */
export interface HolderRoute {
  sid: string;
  sidBytes: Uint8Array;
  gateway: PeerId;
  tunnelId: Uint8Array;
}

export interface RoutingParts {
  duty: Pick<Duty, 'closestSlotsAt'>;
  leaseSets: Pick<LeaseSetStore, 'get'>;
  /** 自分の SID (hex)。自分自身には預けず、自分からは取らない (上げた端末は自分ではチャンクを配らない: 設計 §3) */
  ownSid: () => string | null;
}

/** 位置に近い順の保持者 (SID で重複を除く)。leaseSet が手元に無い枠は飛ばす (受け口が分からない) */
function holdersNear(parts: RoutingParts, position: bigint, slots: number): HolderRoute[] {
  const own = parts.ownSid();
  const seen = new Set<string>();
  const out: HolderRoute[] = [];
  for (const slot of parts.duty.closestSlotsAt(position, slots)) {
    if (slot.sid === own || seen.has(slot.sid)) continue;
    seen.add(slot.sid);
    const ls = parts.leaseSets.get(slot.sid);
    if (!ls) continue;
    out.push({ sid: slot.sid, sidBytes: ls.sid, gateway: ls.gateway, tunnelId: ls.tunnelId });
  }
  return out;
}

/**
 * 預け先の候補。複製 j の位置に**近い 3 枠** (CHUNK_DUTY_SLOTS) の保持者を、近い順に。
 * ★ 保持者の受け入れ条件 (Duty.shouldStoreChunk) と同じ範囲に限る: それより遠くへ送っても NOT_DUTY で断られる。
 *   戻り値の j 番目が複製 j の位置の候補 (位置が衝突して 1 つにまとまった分は短くなる)。
 */
export function placementCandidates(parts: RoutingParts, chunkId: Uint8Array, replicas: number = R_FILE): HolderRoute[][] {
  return chunkPositions(chunkId, replicas).map(pos => holdersNear(parts, pos, CHUNK_DUTY_SLOTS));
}

/**
 * 取りに行く先の候補を、近さの順位ごとの束にする。各複製の位置の近くから CHUNK_READ_SLOTS (6) 枠までを見て、
 * 束 r = 「全複製の r 番目に近い保持者」 (同じ保持者は最初に出た束だけ)。先頭の束 = 全複製の最も近い保持者。
 * ★ 速さの記録で、同じ束の中を並べ替えるのは呼び出し側 (ChunkReader)。束をまたいでは並べ替えない
 *   (遠い保持者は、置き先がずれたときの予備)。
 */
export function readTiers(parts: RoutingParts, chunkId: Uint8Array, replicas: number = R_FILE): HolderRoute[][] {
  const perPos = chunkPositions(chunkId, replicas).map(pos => holdersNear(parts, pos, CHUNK_READ_SLOTS));
  const seen = new Set<string>();
  const tiers: HolderRoute[][] = [];
  const depth = Math.max(0, ...perPos.map(l => l.length));
  for (let r = 0; r < depth; r++) {
    const tier: HolderRoute[] = [];
    for (const list of perPos) {
      const h = list[r];
      if (h && !seen.has(h.sid)) {
        seen.add(h.sid);
        tier.push(h);
      }
    }
    if (tier.length > 0) tiers.push(tier);
  }
  return tiers;
}
