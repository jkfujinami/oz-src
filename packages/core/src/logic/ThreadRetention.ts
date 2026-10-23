import type { IndexedDBStore, PostEntry } from '../storage/IndexedDBStore';
import type { ICryptoEngine } from '../types';
import { PacketBuilder } from '../crypto/PacketBuilder';
import { decodePacket } from '../crypto/PacketCodec';
import { BOARD_META_THREAD_ID } from './types';
import { THREAD_LIMITS, threadExpiresAt, threadBirthFromId } from './ThreadLimits';
import { createLogger } from '../common/Logger';

const log = createLogger('logic.retention');

export interface PruneResult {
  /** 全て消したスレ (寿命の上限を過ぎた) */
  deletedThreadIds: string[];
  /** レスのキャッシュと閲覧由来の統計だけを消したスレ (過疎。タイトルは残る) */
  prunedReplyThreadIds: string[];
}

/** 実行間隔 */
const RETENTION_INTERVAL_MS = 60 * 60 * 1000;

const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v > 0;

/**
 * 端末に保存したスレッドのうち、期限を過ぎたものを消す。
 *
 * ★ 押収・解析で「この端末で何が読まれたか」が分かるデータは、要らなくなったら残さない。
 *
 * ★ 2 段階に分ける。
 *   1. 寿命の上限 (スレ立てから 90 日) は確実なので、そのスレのものを全て消す
 *      (レス・板メタ・統計)。
 *   2. 過疎 (最後の書き込みから 30 日) は端末の知識に基づく推定。活動を知っているのは、
 *      この端末が開いたスレだけで、しかもその知識は古いかもしれない (スレは今も生きているかもしれない)。
 *      だからレスのキャッシュと、レス由来の統計 (max_pow / last_post_at) だけを消し、
 *      板メタ (タイトル) は寿命の上限まで残す。前者は「この端末がどのスレを読んだか」の痕跡で、
 *      フォレンジックで意味があるのはこちら。タイトル一覧は板の全員が同じものを持つので、
 *      残っても端末固有の情報にならない。生きているスレは、開き直せば同期し直される。
 *   3. 活動を知らない (last_post_at が無い) スレには、寿命の上限だけを適用する。
 */
export async function pruneExpiredThreads(opts: {
  db: IndexedDBStore;
  cryptoEng: ICryptoEngine;
  now?: number;
}): Promise<PruneResult> {
  const { db, cryptoEng } = opts;
  const now = opts.now ?? Date.now();
  const result: PruneResult = { deletedThreadIds: [], prunedReplyThreadIds: [] };

  for (const board of await db.listBoards()) {
    const boardId = board.boardId;
    const stats = await db.getThreads(boardId);
    const metaEntries = await db.getPosts(boardId, BOARD_META_THREAD_ID);

    // ★ 復号は全て先に済ませる。IndexedDB のトランザクションは、IDB 以外の Promise を待つと
    //   自動で閉じてしまうので、削除のトランザクションの中では復号しない。
    const metas = new Map<string, { ids: number[]; createdAt: number | null }>();
    for (const entry of metaEntries) {
      if (entry.id === undefined) continue;
      const known = entry.metaFor;
      // metaFor が控えてあるものは復号しない。起点は統計行の birth_at で足りる
      const decoded = known === undefined ? await readMeta(entry, boardId, board.key, cryptoEng) : null;
      const threadId = known ?? decoded?.threadId;
      if (threadId === undefined) continue; // 読めないものには触らない
      const m = metas.get(threadId) ?? { ids: [], createdAt: null };
      m.ids.push(entry.id);
      if (decoded && isTime(decoded.createdAt)) m.createdAt = Math.min(m.createdAt ?? Infinity, decoded.createdAt);
      metas.set(threadId, m);
    }

    const statsById = new Map<string, any>(stats.map((s: any) => [s.threadId, s]));
    const threadIds = new Set<string>([...statsById.keys(), ...metas.keys()]);

    for (const threadId of threadIds) {
      const s = statsById.get(threadId);
      const m = metas.get(threadId);

      // 起点は ID に埋め込んだスレ立て日。旧形式の ID だけ統計行・板メタから推定する
      let birth: number | null = threadBirthFromId(threadId)
        ?? (isTime(s?.birth_at) ? s.birth_at : isTime(s?.created_at) ? s.created_at : null);
      if (birth === null && m) {
        // 統計行が無い (古いデータ): 控えのある板メタでも、起点が要るときだけ復号する
        birth = m.createdAt;
        if (birth === null) {
          for (const entry of metaEntries) {
            if (!m.ids.includes(entry.id as number)) continue;
            const d = await readMeta(entry, boardId, board.key, cryptoEng);
            if (d && isTime(d.createdAt)) birth = Math.min(birth ?? Infinity, d.createdAt);
          }
        }
      }
      if (birth === null) continue; // 起点が分からないものは消さない

      if (now > birth + THREAD_LIMITS.MAX_LIFETIME_MS) {
        await db.deleteThreadPosts(boardId, threadId);
        if (m) await db.deletePostEntries(m.ids);
        await db.deleteThreadStats(threadId);
        result.deletedThreadIds.push(threadId);
        continue;
      }

      if (isTime(s?.last_post_at) && now > threadExpiresAt(birth, s.last_post_at)) {
        await db.deleteThreadPosts(boardId, threadId);
        await db.resetThreadActivity(boardId, threadId);
        result.prunedReplyThreadIds.push(threadId);
      }
    }
  }

  if (result.deletedThreadIds.length + result.prunedReplyThreadIds.length > 0) {
    log.info(() => `retention: deleted ${result.deletedThreadIds.length} thread(s), pruned replies of ${result.prunedReplyThreadIds.length}`);
  }
  return result;
}

/** 保存された板メタを板の鍵で復号して、スレ ID と作成時刻を取り出す。読めなければ null */
async function readMeta(
  entry: PostEntry,
  boardId: string,
  boardKey: Uint8Array,
  cryptoEng: ICryptoEngine,
): Promise<{ threadId: string; createdAt: number } | null> {
  try {
    // 旧形式 (v1・JSON) は decodePacket が null を返す (読めないものには触らない)
    const packet = decodePacket(entry.payload);
    const meta = packet ? await PacketBuilder.verifyAndDecrypt(packet, boardKey, { kind: 'meta', boardId }, cryptoEng) : null;
    if (!meta || typeof meta.thread_id !== 'string') return null;
    return { threadId: meta.thread_id, createdAt: Number(meta.created_at) };
  } catch {
    return null;
  }
}

/**
 * 起動時に 1 回、その後は 1 時間ごとに {@link pruneExpiredThreads} を走らせる。
 * 消したスレは onPruned (通常は BoardOrchestrator.forgetThreads) で画面の一覧からも外す。
 *
 * @returns stop() でタイマーを止める。止めた後に終わった実行の結果は通知しない
 */
export function startThreadRetention(opts: {
  db: IndexedDBStore;
  cryptoEng: ICryptoEngine;
  onPruned?: (result: PruneResult) => void;
  intervalMs?: number;
}): { stop: () => void; runNow: () => Promise<PruneResult | null> } {
  let stopped = false;
  let running: Promise<PruneResult | null> | null = null;

  const runNow = (): Promise<PruneResult | null> => {
    if (stopped) return Promise.resolve(null);
    // 重なって走らせない (遅い端末で前の実行が終わる前に次が来ても二重にならない)
    if (running) return running;
    running = (async () => {
      try {
        if (!opts.db.isUnlocked) return null;
        const r = await pruneExpiredThreads({ db: opts.db, cryptoEng: opts.cryptoEng });
        if (!stopped && (r.deletedThreadIds.length > 0 || r.prunedReplyThreadIds.length > 0)) opts.onPruned?.(r);
        return r;
      } catch (e) {
        log.warn(() => `retention run failed: ${(e as any)?.message ?? e}`);
        return null;
      } finally {
        running = null;
      }
    })();
    return running;
  };

  void runNow();
  const timer = setInterval(() => void runNow(), opts.intervalMs ?? RETENTION_INTERVAL_MS);
  (timer as any).unref?.();

  return {
    runNow,
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
