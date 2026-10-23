import type { GossipPacket } from '../../types';
import {
  PACKET_VERSION, POW_POLICY, derivePacketId, effortFromExp, minEffortFor, msToMinutes, toBytes, verifyPow,
} from '../../crypto/PowPolicy';
import { EQUIX_SOLUTION_BYTES } from '../../crypto/equix/EquiX';
import { createLogger } from '../../common/Logger';

const log = createLogger('net.validator');

/**
 * 互換用エイリアス。値は {@link POW_POLICY} を単一の出所とする。
 */
export const GOSSIP_RULES = {
  MAX_PAYLOAD_SIZE: POW_POLICY.MAX_PAYLOAD_SIZE,
  MAX_TIME_DRIFT: POW_POLICY.MAX_TIME_DRIFT,
  MIN_EFFORT_PER_CELL: POW_POLICY.MIN_EFFORT_PER_CELL,
} as const;

/** 拒否理由。ログとテストの両方で使う */
export type RejectReason =
  | 'malformed'
  | 'bad-packet-id-type'
  | 'bad-timestamp'
  | 'bad-payload-size'
  | 'bad-tag'
  | 'bad-age'
  | 'bad-effort'
  | 'bad-solution'
  | 'bad-pow-nonce'
  | 'time-drift'
  | 'packet-id-mismatch'
  | 'insufficient-effort'
  | 'insufficient-pow';

export type ValidationResult =
  | { ok: true }
  | { ok: false; reason: RejectReason };

export interface ValidateOptions {
  /** テスト用に現在時刻を差し替えるためのフック */
  now?: number;
  /**
   * 過去方向のドリフト検査を省く。
   *
   * 保管 (過去ログ: 追いつき・保管担当) は「過去ログの保管庫」なので、そこに入っているパケットは
   * 15 分どころか何日も前のものが正当にあり得る。ライブのゴシップと同じ
   * 検査を掛けると過去ログ同期が丸ごと壊れる。
   *
   * 未来方向のドリフトは省かない (未来日付での順序操作を防ぐため)。
   * PoW と packet_id は変わらず全件に掛かるので、偽造は依然として不可能。
   */
  allowStale?: boolean;
  /**
   * 過去方向のドリフトの上限 (ms)。省略時は MAX_TIME_DRIFT (15 分)。
   *
   * ★ Guard からの追いつき (CatchupClient) 専用: 72 時間 + 15 分 ({@link CATCHUP_MAX_PAST_MS}) まで。
   *   allowStale (無制限) より狭い。追いつきで届くのは Guard のバッファの中身だけなので、
   *   それより古いものは正当にあり得ず、受け付けない (古い投稿の水増しを許さない)。
   *   未来方向は変わらない。PoW と packet_id も全件に掛かる。
   */
  maxPastMs?: number;
}

const OK: ValidationResult = { ok: true };
const fail = (reason: RejectReason): ValidationResult => ({ ok: false, reason });

/** 最小のペイロード: siv 16 + flags 1 + 署名ブロック 96 (本文 0 バイト) */
const MIN_PAYLOAD_SIZE = POW_POLICY.SIV_BYTES + 1 + 96;

/**
 * PacketValidator — 鍵を持たない中継ノードでも実行できる検証。
 *
 * 旧実装の致命的欠陥:
 *   受信パケットが *自己申告* した難易度をそのまま使っていたため、
 *   `pow_difficulty: 0` と書くだけで PoW を一切計算せずに全ノードに受理された。
 *
 * 現在は次を鍵なしで見る:
 *   1. 形式 — tag < 4096・age ≤ 90・effort の指数 ≤ 80・サイズ・時刻。
 *   2. packet_id — ヘッダ (effort / nonce / 解を除く) とペイロードの SHA-256。
 *      1 ビットでも書き換えれば必ず落ちる。
 *   3. 最低 effort — 申告ではなく **パケットの長さ**から中継が計算する (長い投稿は枚数分だけ払う)。
 *   4. PoW — Equi-X の解と effort。effort は challenge に入るので、解を使い回して高い effort を名乗れない。
 *
 * ★ 全体が同期関数。Equi-X の検証は約 20µs なので、受信のホットパスで直接呼んでよい
 *   (Worker 越しにすると、ゴミパケットで Worker を詰まらせる head-of-line blocking が起きる)。
 *   事前に `await equixReady` しておくこと (読み込み前は例外)。
 * ★ 中継が見る tag / age の検査は「範囲」だけ。板 / スレに合うかは鍵を持つ読み手が見る。
 */
export class PacketValidator {
  public static check(packet: GossipPacket, opts: ValidateOptions = {}): ValidationResult {
    const now = opts.now ?? Date.now();
    if (!packet || typeof packet !== 'object') return fail('malformed');
    if (typeof packet.packet_id !== 'string' || packet.packet_id.length !== 2 * POW_POLICY.PACKET_ID_BYTES) {
      return fail('bad-packet-id-type');
    }
    if (typeof packet.timestamp !== 'number' || !Number.isSafeInteger(packet.timestamp) || packet.timestamp < 0) {
      return fail('bad-timestamp');
    }
    let time: number;
    try {
      time = msToMinutes(packet.timestamp);
    } catch {
      return fail('bad-timestamp');
    }

    // 1. サイズ・範囲
    const payload = toBytes(packet.payload);
    if (payload.length < MIN_PAYLOAD_SIZE || payload.length > POW_POLICY.MAX_PAYLOAD_SIZE) {
      return fail('bad-payload-size');
    }
    if (!Number.isInteger(packet.tag) || packet.tag < 0 || packet.tag >= 1 << POW_POLICY.TAG_BITS) return fail('bad-tag');
    if (!Number.isInteger(packet.age) || packet.age < 0 || packet.age > POW_POLICY.MAX_AGE_DAYS) return fail('bad-age');
    if (!Number.isInteger(packet.effort_exp) || packet.effort_exp < 0 || packet.effort_exp > POW_POLICY.MAX_EFFORT_EXP) {
      return fail('bad-effort');
    }
    const solution = toBytes(packet.pow_solution);
    if (solution.length !== EQUIX_SOLUTION_BYTES) return fail('bad-solution');
    if (!Number.isInteger(packet.pow_nonce) || packet.pow_nonce < 0 || packet.pow_nonce > 0xffffffff) {
      return fail('bad-pow-nonce');
    }

    // 2. 時刻制約 (SeenCache TTL との二重防御)
    //    15分以内の再送は LRU が、それ以前は時刻検査が弾く。
    if (packet.timestamp - now > POW_POLICY.MAX_TIME_DRIFT) {
      return fail('time-drift'); // 未来日付は常に拒否
    }
    if (!opts.allowStale && now - packet.timestamp > (opts.maxPastMs ?? POW_POLICY.MAX_TIME_DRIFT)) {
      return fail('time-drift');
    }

    // 3. packet_id は、ヘッダとペイロードのハッシュでなければならない
    const committed = {
      version: PACKET_VERSION, time, tag: packet.tag, age: packet.age, effort_exp: packet.effort_exp, payload,
    };
    if (derivePacketId(committed) !== packet.packet_id) return fail('packet-id-mismatch');

    // 4. 最低 effort。長さから中継が計算する (申告を信用しない)
    if (effortFromExp(packet.effort_exp) < minEffortFor(POW_POLICY.HEADER_BYTES + payload.length)) {
      return fail('insufficient-effort');
    }

    // 5. PoW (一番高いので最後)
    if (!verifyPow(committed, { nonce: packet.pow_nonce, solution })) return fail('insufficient-pow');

    return OK;
  }

  /** boolean だけ欲しい呼び出し側向け。理由はログに出す。 */
  public static validate(packet: GossipPacket, opts: ValidateOptions = {}): boolean {
    const result = PacketValidator.check(packet, opts);
    if (!result.ok) {
      const id = typeof packet?.packet_id === 'string' ? packet.packet_id.substring(0, 8) : '????????';
      log.warn(`Dropped ${id} (${result.reason})`);
    }
    return result.ok;
  }
}
