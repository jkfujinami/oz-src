import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { Identity } from '../../src/crypto/Identity';
import { BoardOrchestrator } from '../../src/logic/BoardOrchestrator';
import { BOARD_META_THREAD_ID } from '../../src/logic/types';
import { THREAD_LIMITS } from '../../src/logic/ThreadLimits';
import { pruneExpiredThreads, startThreadRetention } from '../../src/logic/ThreadRetention';
import { encodePacket } from '../../src/crypto/PacketCodec';
import type { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import {
  FakePeerManager, FakeRouter, syncPow,
  unlockedStore, buildThreadMetaPacket,
} from '../helpers/logicHarness';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 9, 14);
const cryptoEng = new CryptoEngine();

let db: IndexedDBStore;
let key: Uint8Array;
let otherKey: Uint8Array;
let signer: Identity;

/** 板メタ + (任意で) レスを保存する。birth は birth_at として統計行に入る */
async function seedThread(
  boardId: string, boardKey: Uint8Array, threadId: string, birth: number,
  opts: { withMetaFor?: boolean; replies?: number; lastPostAt?: number } = {},
) {
  const packet = await buildThreadMetaPacket(boardKey, boardId, threadId, `title-${threadId}`, signer);
  await db.save({
    boardId, threadId: BOARD_META_THREAD_ID, payload: encodePacket(packet),
    ...(opts.withMetaFor === false ? {} : { metaFor: threadId }),
    dag: { parents: [], cumulative_pow: 5, thread_root: threadId, created_at: birth },
  });
  for (let i = 0; i < (opts.replies ?? 0); i++) {
    await db.save({
      boardId, threadId, payload: new Uint8Array([1, 2, 3, i]),
      dag: { parents: [], cumulative_pow: 7, thread_root: threadId, created_at: birth + 1000 },
    });
  }
  if (opts.lastPostAt !== undefined) await db.touchThread(boardId, threadId, opts.lastPostAt);
}

const stats = async (boardId: string, threadId: string) =>
  (await db.getThreads(boardId)).find((s: any) => s.threadId === threadId);

describe('ThreadRetention', () => {
  beforeAll(async () => { await sodiumReady; });
  beforeEach(async () => {
    db = await unlockedStore();
    key = sodium.randombytes_buf(32);
    otherKey = sodium.randombytes_buf(32);
    signer = new Identity();
    await db.saveBoard('b1', key);
    await db.saveBoard('b2', otherKey);
  });

  it('寿命の上限を過ぎたスレだけ、板メタ・レス・統計が全て消える', async () => {
    const old = NOW - 91 * DAY;
    await seedThread('b1', key, 'old', old, { replies: 2 });
    await seedThread('b1', key, 'young', NOW - 10 * DAY, { replies: 2 });
    await seedThread('b2', otherKey, 'old2', NOW - 5 * DAY, { replies: 1 });

    const r = await pruneExpiredThreads({ db, cryptoEng, now: NOW });

    expect(r.deletedThreadIds).toEqual(['old']);
    expect(await db.getPosts('b1', 'old')).toHaveLength(0);
    expect(await stats('b1', 'old')).toBeUndefined();
    const metas = await db.getPosts('b1', BOARD_META_THREAD_ID);
    expect(metas.map(m => m.metaFor)).toEqual(['young']);
    expect(await db.getPosts('b1', 'young')).toHaveLength(2);
    expect(await stats('b1', 'young')).toBeDefined();
    expect(await db.getPosts('b2', 'old2')).toHaveLength(1);
    expect(await db.getPosts('b2', BOARD_META_THREAD_ID)).toHaveLength(1);
  });

  it('過疎のスレはレスと統計だけ消え、板メタと birth_at は残る', async () => {
    const birth = NOW - 60 * DAY;
    await seedThread('b1', key, 'idle', birth, { replies: 3, lastPostAt: NOW - 31 * DAY });
    await seedThread('b1', key, 'active', birth, { replies: 3, lastPostAt: NOW - 2 * DAY });
    expect((await stats('b1', 'idle')).max_pow).toBe(7);

    const r = await pruneExpiredThreads({ db, cryptoEng, now: NOW });

    expect(r.deletedThreadIds).toEqual([]);
    expect(r.prunedReplyThreadIds).toEqual(['idle']);
    expect(await db.getPosts('b1', 'idle')).toHaveLength(0);
    const s = await stats('b1', 'idle');
    expect(s.max_pow).toBe(0);
    expect(s.last_post_at).toBeUndefined();
    expect(s.birth_at).toBe(birth);
    expect(s.boardId).toBe('b1');
    expect(Object.keys(s).sort()).toEqual(['birth_at', 'boardId', 'created_at', 'max_pow', 'threadId']);
    expect((await db.getPosts('b1', BOARD_META_THREAD_ID)).map(m => m.metaFor).sort()).toEqual(['active', 'idle']);
    expect(await db.getPosts('b1', 'active')).toHaveLength(3);

    // 2 回目は何もしない (リセット済みは「活動不明」扱い)
    const again = await pruneExpiredThreads({ db, cryptoEng, now: NOW });
    expect(again.prunedReplyThreadIds).toEqual([]);
  });

  it('活動が不明なスレは、90 日までは残り、過ぎたら消える', async () => {
    await seedThread('b1', key, 'unknown', NOW - 80 * DAY, { replies: 1 });
    let r = await pruneExpiredThreads({ db, cryptoEng, now: NOW });
    expect(r).toEqual({ deletedThreadIds: [], prunedReplyThreadIds: [] });
    expect(await db.getPosts('b1', 'unknown')).toHaveLength(1);

    r = await pruneExpiredThreads({ db, cryptoEng, now: NOW + 11 * DAY });
    expect(r.deletedThreadIds).toEqual(['unknown']);
    expect(await db.getPosts('b1', 'unknown')).toHaveLength(0);
  });

  it('metaFor が無い (旧データの) 板メタは、復号してスレ ID を調べて消す', async () => {
    // パケットの作成時刻は実時刻 (復号して初めて分かる)。統計行も無い旧データを再現する
    await seedThread('b1', key, 'legacyA', NOW, { withMetaFor: false });
    await seedThread('b1', key, 'legacyB', NOW, { withMetaFor: false });
    await db.deleteThreadStats('legacyA');
    await db.deleteThreadStats('legacyB');
    await db.save({ boardId: 'b1', threadId: 'legacyA', payload: new Uint8Array([5]) });
    const created = Date.now();

    let r = await pruneExpiredThreads({ db, cryptoEng, now: created + 10 * DAY });
    expect(r.deletedThreadIds).toEqual([]);
    expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(2);

    r = await pruneExpiredThreads({ db, cryptoEng, now: created + 100 * DAY });
    expect(r.deletedThreadIds.sort()).toEqual(['legacyA', 'legacyB']);
    expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(0);
    expect(await db.getPosts('b1', 'legacyA')).toHaveLength(0);
  });

  it('復号できない板メタには触らない', async () => {
    await db.save({ boardId: 'b1', threadId: BOARD_META_THREAD_ID, payload: new Uint8Array([9, 9, 9]) });
    const r = await pruneExpiredThreads({ db, cryptoEng, now: NOW + 365 * DAY });
    expect(r.deletedThreadIds).toEqual([]);
    expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(1);
  });

  it('save() の統計の更新で birth_at / last_post_at が落ちない', async () => {
    const birth = NOW - 20 * DAY;
    await seedThread('b1', key, 't', birth, { lastPostAt: NOW - DAY });
    await db.save({
      boardId: 'b1', threadId: 't', payload: new Uint8Array([1]),
      dag: { parents: [], cumulative_pow: 99, thread_root: 't', created_at: NOW },
    });
    // 後から (別の) 板メタが来ても、起点は早い方のまま
    await db.save({
      boardId: 'b1', threadId: BOARD_META_THREAD_ID, payload: new Uint8Array([1]),
      dag: { parents: [], cumulative_pow: 1, thread_root: 't', created_at: NOW },
    });
    const s = await stats('b1', 't');
    expect(s.birth_at).toBe(birth);
    expect(s.last_post_at).toBe(NOW - DAY);
    expect(s.max_pow).toBe(99);
  });

  describe('BoardOrchestrator', () => {
    let board: BoardOrchestrator;
    beforeEach(() => {
      board = new BoardOrchestrator(
        new FakePeerManager() as any, db, new FakeRouter() as any, cryptoEng, syncPow, signer,
      );
    });
    afterEach(() => { board.clear(); vi.useRealTimers(); });

    it('寿命を過ぎた板メタは一覧に載せず、保存もしない', async () => {
      const real = Date.now();
      const packet = await buildThreadMetaPacket(key, 'b1', 'x', 'title', signer);
      // 作成時刻 (packet.timestamp) から 90 日 + 1 日後に届いたことにする
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(real + THREAD_LIMITS.MAX_LIFETIME_MS + DAY);
      await board.handlePacketObject('b1', key, packet, false, encodePacket(packet));
      expect(board.getThreads()).toHaveLength(0);
      expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(0);

      // 期限内なら載る (保存時には metaFor も控える)
      vi.setSystemTime(real + DAY);
      const p2 = await buildThreadMetaPacket(key, 'b1', 'y', 'title', signer);
      await board.handlePacketObject('b1', key, p2, false, encodePacket(p2));
      expect(board.getThreads().map(t => t.thread_id)).toEqual(['y']);
      expect((await db.getPosts('b1', BOARD_META_THREAD_ID))[0].metaFor).toBe('y');
    });

    it('forgetThreads で一覧から外れ、購読者に通知される', async () => {
      const p = await buildThreadMetaPacket(key, 'b1', 'x', 'title', signer);
      await board.handlePacketObject('b1', key, p, true);
      expect(board.getThreads()).toHaveLength(1);
      const l = vi.fn();
      board.subscribe(l);
      board.forgetThreads(['x', 'nothing']);
      expect(board.getThreads()).toHaveLength(0);
      expect(l).toHaveBeenCalledTimes(1);
      board.forgetThreads(['x']);
      expect(l).toHaveBeenCalledTimes(1);
    });
  });

  describe('startThreadRetention', () => {
    afterEach(() => vi.useRealTimers());

    it('起動時に 1 回走り、間隔ごとに繰り返し、stop() で止まる', async () => {
      await seedThread('b1', key, 'old', Date.now() - 91 * DAY);
      const onPruned = vi.fn();
      const h = startThreadRetention({ db, cryptoEng, onPruned, intervalMs: 20 });
      await h.runNow();
      expect(onPruned).toHaveBeenCalledTimes(1);
      expect(onPruned.mock.calls[0][0].deletedThreadIds).toEqual(['old']);

      const spy = vi.spyOn(db, 'listBoards');
      await new Promise(r => setTimeout(r, 100));
      expect(spy.mock.calls.length).toBeGreaterThanOrEqual(2);

      h.stop();
      await new Promise(r => setTimeout(r, 30));
      const n = spy.mock.calls.length;
      await new Promise(r => setTimeout(r, 100));
      expect(spy.mock.calls.length).toBe(n);
      expect(await h.runNow()).toBeNull();
    });
  });
});
