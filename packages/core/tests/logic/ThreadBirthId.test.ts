import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { Identity } from '../../src/crypto/Identity';
import { BoardOrchestrator } from '../../src/logic/BoardOrchestrator';
import { POW_POLICY } from '../../src/crypto/PowPolicy';
import {
  THREAD_LIMITS, THREAD_ID_RANDOM_CHARS, makeThreadId, threadBirthFromId, isThreadMetaTimeConsistent,
} from '../../src/logic/ThreadLimits';
import { pruneExpiredThreads } from '../../src/logic/ThreadRetention';
import { BOARD_META_THREAD_ID } from '../../src/logic/types';
import { encodePacket } from '../../src/crypto/PacketCodec';
import type { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import {
  FakePeerManager, FakeRouter, syncPow,
  unlockedStore, buildThreadMetaPacket,
} from '../helpers/logicHarness';

const DAY = 24 * 60 * 60 * 1000;
const DRIFT = POW_POLICY.MAX_TIME_DRIFT;

describe('スレ立て日を埋め込んだスレッド ID', () => {
  it('作った日の 0 時 (UTC) が取り出せる。乱数部はそのまま残る', () => {
    const now = Date.UTC(2026, 9, 14, 23, 59, 30);
    const id = makeThreadId(now, 'k3j9x0a1b2');
    expect(id).toHaveLength(4 + THREAD_ID_RANDOM_CHARS);
    expect(id.endsWith('k3j9x0a1b2')).toBe(true);
    expect(threadBirthFromId(id)).toBe(Date.UTC(2026, 9, 14));
  });

  it('旧形式 (乱数だけの 10 文字) や不正な文字は null', () => {
    expect(threadBirthFromId('abcdefghij')).toBeNull();
    expect(threadBirthFromId('ABCDabcdefghij')).toBeNull();
    expect(threadBirthFromId('g0k-abcdefghij')).toBeNull();
    expect(threadBirthFromId('')).toBeNull();
  });

  it('スレ立ての時刻は、ID の日付 (前後に時刻のずれ分の余裕) に収まらなければならない', () => {
    const birth = Date.UTC(2026, 9, 14);
    const id = makeThreadId(birth + 5 * 60 * 60 * 1000, 'abcdefghij');
    expect(isThreadMetaTimeConsistent(id, birth)).toBe(true);
    expect(isThreadMetaTimeConsistent(id, birth + DAY - 1)).toBe(true);
    expect(isThreadMetaTimeConsistent(id, birth - DRIFT)).toBe(true);
    expect(isThreadMetaTimeConsistent(id, birth - DRIFT - 1)).toBe(false);
    expect(isThreadMetaTimeConsistent(id, birth + DAY + DRIFT)).toBe(false);
    // 遡った偽のスレ立て (寿命を縮める) も、今日の偽のスレ立て (寿命を延ばす) も合わない
    expect(isThreadMetaTimeConsistent(id, birth - 80 * DAY)).toBe(false);
    expect(isThreadMetaTimeConsistent(id, birth + 30 * DAY)).toBe(false);
    // 旧形式の ID は検査できない
    expect(isThreadMetaTimeConsistent('abcdefghij', 0)).toBe(true);
  });
});

describe('偽のスレ立てで寿命の起点を動かせない', () => {
  const cryptoEng = new CryptoEngine();
  let db: IndexedDBStore;
  let key: Uint8Array;
  let board: BoardOrchestrator;
  let signer: Identity;
  const real = Date.now();

  beforeAll(async () => { await sodiumReady; });
  beforeEach(async () => {
    db = await unlockedStore();
    key = sodium.randombytes_buf(32);
    signer = new Identity();
    await db.saveBoard('b1', key);
    board = new BoardOrchestrator(
      new FakePeerManager() as any, db, new FakeRouter() as any, cryptoEng, syncPow, signer,
    );
    vi.useFakeTimers({ toFake: ['Date'] });
  });
  afterEach(() => { board.clear(); vi.useRealTimers(); });

  it('ID の日付と合わないスレ立ては一覧にも端末にも入らない (同じ ID の本物は入る)', async () => {
    vi.setSystemTime(real);
    const id = makeThreadId(real, 'abcdefghij');

    // 80 日前の日付で作った偽物 (起点を遡らせて早死にさせる狙い)
    vi.setSystemTime(real - 80 * DAY);
    const forged = await buildThreadMetaPacket(key, 'b1', id, '偽のタイトル', new Identity());
    vi.setSystemTime(real);
    await board.handlePacketObject('b1', key, forged, false, encodePacket(forged));
    expect(board.getThreads()).toHaveLength(0);
    expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(0);

    const genuine = await buildThreadMetaPacket(key, 'b1', id, '本物', signer);
    await board.handlePacketObject('b1', key, genuine, false, encodePacket(genuine));
    expect(board.getThreads().map(t => t.content)).toEqual(['本物']);
  });

  it('端末の掃除も ID の日付を起点にする (統計行の birth_at が遡っていても消さない)', async () => {
    vi.setSystemTime(real);
    const id = makeThreadId(real, 'abcdefghij');
    const genuine = await buildThreadMetaPacket(key, 'b1', id, '本物', signer);
    // 旧い版の端末が遡った birth_at を書いてしまった状況
    await db.save({
      boardId: 'b1', threadId: BOARD_META_THREAD_ID, payload: encodePacket(genuine), metaFor: id,
      dag: { parents: [], cumulative_pow: 5, thread_root: id, created_at: real - 89 * DAY },
    });
    const r = await pruneExpiredThreads({ db, cryptoEng, now: real + 2 * DAY });
    expect(r.deletedThreadIds).toEqual([]);
    expect(await db.getPosts('b1', BOARD_META_THREAD_ID)).toHaveLength(1);

    // ID の日付から 90 日を過ぎたら消える
    const birth = threadBirthFromId(id)!;
    const r2 = await pruneExpiredThreads({ db, cryptoEng, now: birth + THREAD_LIMITS.MAX_LIFETIME_MS + 1 });
    expect(r2.deletedThreadIds).toEqual([id]);
  });
});
