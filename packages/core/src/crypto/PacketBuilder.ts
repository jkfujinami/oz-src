import type { ICryptoEngine, IIdentity, IPoWEngine, GossipPacket } from '../types';
import { Identity } from './Identity';
import {
  PACKET_VERSION, POW_POLICY, cellsFor, derivePacketId, effortFor, headerPrefix, msToMinutes, minutesToMs, toBytes,
  type PowCommitted,
} from './PowPolicy';
import {
  assertPostLimits, decodePostPlain, encodePostPlain, postSignedBytes, type PostFields,
} from './PostCodec';
import { metaTagAge, replyTagAge, threadTag, dayOf, birthDayOfThread } from './PacketTag';
import { createLogger } from '../common/Logger';
import sodium from './sodium';

const log = createLogger('crypto.packet');

/** 読み手が「どの板 / スレとして読んでいるか」。署名はこの文脈に縛られる */
export type ReadContext =
  | { kind: 'meta'; boardId: string }
  | { kind: 'reply'; boardId: string; threadId: string };

/** verifyAndDecrypt が返す、検証済みの投稿 */
export interface VerifiedPost {
  content: string;
  /** ms (ヘッダの時刻。分に丸めてある) */
  created_at: number;
  board_id: string;
  thread_id: string;
  post_type: number;
  parents: string[];
  /** トリップ無しのときだけ。トリップ有りの投稿はセッション鍵を載せない */
  session_pubkey: Uint8Array | null;
  trip_pubkey: Uint8Array | null;
}

export class PacketBuilder {
  /**
   * 投稿内容を署名 → SIV 暗号 → PoW でパケットにする。形式は PacketCodec / PostCodec / PowPolicy を参照。
   *
   * @param opts.key 板の鍵 (スレ立て) またはスレの鍵 (返信)
   * @param opts.postType 0 = 返信, 1 = スレ立て
   * @param opts.parents 親の packet_id (hex 32 文字)。最大 POW_POLICY.MAX_PARENTS 個。超えると例外
   * @param opts.suggestedEffortPerCell 1 セルあたりの推奨 effort (任意。EffortAdvisor の値)。セル数を掛けた値が
   *   最低値より高ければ従う
   * @param opts.onEffort PoW の探索の直前に、選んだ effort を知らせる (UI が「時間がかかります」を出すため)
   * @param opts.now ms (テスト用。分に丸める)
   * @throws RangeError 本文が 2048 バイト (UTF-8) を超える・親が多すぎる・ID が長すぎる・スレ立てから 90 日超、など
   */
  static async build(opts: {
    content: string;
    key: Uint8Array;
    identity: IIdentity;
    cryptoEngine: ICryptoEngine;
    powEngine: IPoWEngine;
    boardId: string;
    threadId: string;
    postType?: number;
    parents?: string[];
    suggestedEffortPerCell?: number;
    onEffort?: (info: { effort: number; cells: number }) => void;
    now?: number;
  }): Promise<GossipPacket> {
    await sodium.ready;
    const fields: PostFields = {
      postType: opts.postType ?? 0,
      boardId: opts.boardId,
      threadId: opts.threadId,
      parents: opts.parents ?? [],
      content: opts.content,
    };
    // ★ 網に出す前に、上限 (本文 2048 バイト・親 2 つ・ID 長) を必ず検査する。
    //   超えたものを黙って切り詰めると利用者の意図と違う投稿になり、通すと固定長セル (3 枚) に収まらない。
    assertPostLimits(fields);

    // ★ 分単位に切り捨てる。ヘッダの時刻は網の全員に見える。ミリ秒精度だと端末の時計の
    //   ずれ (クロックスキュー) が指紋になり、送信の瞬間とも結び付けやすくなる。
    //   時刻は PoW・SIV の AAD・署名のすべてに入るので、探索の *前に* 一度だけ確定させる。
    const timeMin = msToMinutes(opts.now ?? Date.now());
    const timeMs = minutesToMs(timeMin);
    const { tag, age } = fields.postType === 1
      ? metaTagAge(opts.key, timeMs)
      : replyTagAge(opts.key, opts.threadId, timeMs);
    const aad = headerPrefix({ version: PACKET_VERSION, time: timeMin, tag, age });

    // Step 1: 署名。トリップ有りならトリップの署名だけを載せる (セッション鍵は載せない)。
    //   署名対象に trip フラグが入るので、トリップの有無は署名の前に決めておく (identity.hasTrip)。
    const isTrip = opts.identity.hasTrip;
    const sig = opts.identity.sign(
      postSignedBytes(fields, aad, isTrip),
      // ★ セッション鍵は (板, スレ, 日) ごとに別。スレ立てでは fields.threadId が新しいスレの id なので、
      //   作者の最初の ID はその日の返信と同じになる。
      { boardId: fields.boardId, threadId: fields.threadId, day: dayOf(timeMs) },
    );
    if (isTrip && (sig.tripPubkey === null || sig.tripSignature === null)) throw new Error('identity claims a trip but did not sign with it');

    // Step 2: SIV 暗号
    const signer = isTrip
      ? { isTrip: true, pubkey: sig.tripPubkey!, signature: sig.tripSignature! }
      : { isTrip: false, pubkey: sig.sessionPubkey, signature: sig.sessionSignature };
    const plain = encodePostPlain(fields, signer);
    const payload = opts.cryptoEngine.encrypt(opts.key, plain, aad);

    // Step 3: PoW。最低 effort (長さに応じた下限) と推奨 (1 セルあたり × セル数) を満たす最小の量子化値
    const bytes = POW_POLICY.HEADER_BYTES + payload.length;
    const cells = cellsFor(bytes);
    const suggested = opts.suggestedEffortPerCell === undefined
      ? undefined
      : Math.ceil(opts.suggestedEffortPerCell * cells - 1e-9);
    const { exp, effort } = effortFor(bytes, suggested);
    opts.onEffort?.({ effort, cells });
    const committed: PowCommitted = {
      version: PACKET_VERSION, time: timeMin, tag, age, effort_exp: exp, payload,
    };
    const sol = await opts.powEngine.compute(committed);

    return {
      packet_id: derivePacketId(committed),
      timestamp: timeMs,
      tag,
      age,
      effort_exp: exp,
      pow_nonce: sol.nonce,
      pow_solution: sol.solution,
      payload,
    };
  }

  /**
   * 受信パケットを、鍵と文脈で読む。
   *
   *   0. tag / age が、この板 / スレとして期待される値か (HMAC 1 回。違えば他人のパケットなので復号しない)
   *   1. SIV の復号 (鍵違い・ヘッダの書き換え・改竄はここで落ちる)
   *   2. 平文のデコード
   *   3. 署名 (トリップ有りならトリップの署名)。文脈 (board_id / thread_id) に縛られる
   *
   * @returns 失敗は null。PoW と packet_id は PacketValidator の仕事 (鍵なしで済む) なのでここでは見ない
   */
  static async verifyAndDecrypt(
    packet: GossipPacket,
    key: Uint8Array,
    ctx: ReadContext,
    cryptoEngine: ICryptoEngine,
  ): Promise<VerifiedPost | null> {
    await sodium.ready;
    const payload = toBytes(packet?.payload);
    if (!Number.isSafeInteger(packet?.timestamp) || packet.timestamp < 0) return null;
    let timeMin: number;
    try { timeMin = msToMinutes(packet.timestamp); } catch { return null; }

    // 0. tag / age (復号の前の足切り)
    if (!PacketBuilder.tagAgeMatches(packet, key, ctx)) {
      log.trace(`tag/age mismatch for packet ${packet.packet_id}`);
      return null;
    }

    // 1. SIV 復号
    const aad = headerPrefix({ version: PACKET_VERSION, time: timeMin, tag: packet.tag, age: packet.age });
    const plain = cryptoEngine.decrypt(key, payload, aad);
    if (!plain) {
      log.trace(`SIV decryption failed (not a target packet or invalid key) for packet ${packet.packet_id}`);
      return null;
    }

    // 2. 平文のデコード (形式違反・切り詰めは捨てる)
    const decoded = decodePostPlain(plain);
    if (!decoded) {
      log.debug(`Post body decode failed for packet ${packet.packet_id}`);
      return null;
    }
    // 板のメタとして読むならスレ立て、スレとして読むなら返信でなければならない
    if ((ctx.kind === 'meta') !== (decoded.postType === 1)) return null;

    const threadId = ctx.kind === 'meta' ? decoded.metaThreadId! : ctx.threadId;
    const fields: PostFields = {
      postType: decoded.postType, boardId: ctx.boardId, threadId, parents: decoded.parents, content: decoded.content,
    };

    // 3. 署名。トリップ有りならトリップ鍵の署名 (セッション鍵は無い)
    let ok = false;
    try {
      ok = Identity.verify(
        postSignedBytes(fields, aad, decoded.signer.isTrip), decoded.signer.pubkey, decoded.signer.signature,
      );
    } catch (e: any) {
      log.error(`Ed25519 signature verification crashed for packet ${packet.packet_id}:`, e);
      return null;
    }
    if (!ok) {
      log.warn(`Signature Verification Failed for packet: ${packet.packet_id}`);
      return null;
    }

    return {
      content: decoded.content,
      created_at: packet.timestamp,
      board_id: ctx.boardId,
      thread_id: threadId,
      post_type: decoded.postType,
      parents: decoded.parents,
      session_pubkey: decoded.signer.isTrip ? null : decoded.signer.pubkey,
      trip_pubkey: decoded.signer.isTrip ? decoded.signer.pubkey : null,
    };
  }

  /**
   * ヘッダの tag / age が、この板 / スレとして期待される値か。
   * 板のメタ: 週の月曜で決まる tag と、投稿日 - 月曜 (PacketTag.metaTagAge)。返信: スレ立て日で決まる tag と、投稿日 - スレ立て日。
   */
  static tagAgeMatches(packet: Pick<GossipPacket, 'timestamp' | 'tag' | 'age'>, key: Uint8Array, ctx: ReadContext): boolean {
    const day = dayOf(packet.timestamp);
    if (ctx.kind === 'meta') {
      const expected = metaTagAge(key, packet.timestamp);
      return packet.age === expected.age && packet.tag === expected.tag;
    }
    const birth = birthDayOfThread(ctx.threadId) ?? day;
    return packet.age === Math.max(0, day - birth) && packet.tag === threadTag(key, birth);
  }
}
