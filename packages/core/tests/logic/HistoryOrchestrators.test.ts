import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { ThreadOrchestrator } from '../../src/logic/ThreadOrchestrator';
import { BoardOrchestrator } from '../../src/logic/BoardOrchestrator';
import { makeThreadId } from '../../src/logic/ThreadLimits';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { Identity } from '../../src/crypto/Identity';
import { KeyManager } from '../../src/crypto/KeyManager';
import { DAY_MS, MINUTE_MS, msToMinutes } from '../../src/crypto/PowPolicy';
import { boardTag, dayOf, mondayOf, threadTag } from '../../src/crypto/PacketTag';
import type { HistoryFetcher } from '../../src/network/history/HistoryClient';
import { FakePeerManager, FakeRouter, keyMgr, syncPow, unlockedStore, customSigner, buildReplyPacket, buildThreadMetaPacket, waitFor } from '../helpers/logicHarness';
import { realPowEngine } from '../helpers/postFixtures';
import { createSimNode, link, stopAll, sleep } from '../helpers/onionNet';
import { stopStorage } from '../helpers/storageNet';
import { attachTunnel, attachBehind, stopTunnel, until } from '../helpers/tunnelNet';

/** 窓口の代役: 呼ばれた引数を記録し、テストが完了を制御する */
function fakeHistory() {
  const calls: Array<{ birthDay: number; tag: number; since: number; resolve: () => void; progress: (n: number) => void; signal?: AbortSignal }> = [];
  const readyCbs = new Set<() => void>();
  let running = 0, peak = 0;
  const history: HistoryFetcher = {
    onReady: (cb) => { readyCbs.add(cb); return () => { readyCbs.delete(cb); }; },
    fetchBucket: (birthDay, tag, opts = {}) => new Promise((resolve) => {
      running++; peak = Math.max(peak, running);
      calls.push({
        birthDay, tag, since: opts.since ?? 0, signal: opts.signal, progress: (n) => opts.onProgress?.(n),
        resolve: () => { running--; resolve({ completed: true, packets: 0, attempts: 1, reason: 'ok' }); },
      });
    }),
  };
  return { history, calls, fireReady: () => readyCbs.forEach(cb => cb()), peak: () => peak, readyCount: () => readyCbs.size };
}

const BOARD = 'news';

describe('ThreadOrchestrator: 開いたとき保管担当から過去ログを取る', () => {
  let boardKey: Uint8Array;
  beforeAll(async () => { await sodiumReady; });
  let thread: ThreadOrchestrator;
  afterEach(() => thread?.clear());

  async function make(f: ReturnType<typeof fakeHistory>, db?: any) {
    const pm = new FakePeerManager();
    pm.degreeOverride = 1;
    const router = new FakeRouter();
    const store = db ?? await unlockedStore();
    thread = new ThreadOrchestrator(pm as any, store, router as any, new CryptoEngine(), syncPow, new Identity(), keyMgr, null, f.history);
    return { pm, router, store };
  }

  it('★スレ立て日 (ID に埋め込み) とスレ鍵の tag で、手元に 1 件も無ければ since = 0。「過去ログを取得中」と件数を出し、終われば消える。UI は待たない', async () => {
    boardKey = sodium.randombytes_buf(32);
    const threadId = makeThreadId(Date.now() - 6 * DAY_MS, '0123456789');
    const f = fakeHistory();
    await make(f);
    await thread.activate(BOARD, threadId, boardKey); // 取得は終わっていないのに activate は返る
    expect(f.calls).toHaveLength(1);
    const key = KeyManager.deriveThreadKey(boardKey, threadId);
    const birth = dayOf(Date.now() - 6 * DAY_MS);
    expect(f.calls[0]).toMatchObject({ birthDay: birth, tag: threadTag(key, birth), since: 0 });
    expect(thread.getStatus()).toMatchObject({ phase: 'syncing', message: '過去ログを取得中...' });
    f.calls[0].progress(3);
    expect(thread.getStatus().message).toBe('過去ログを取得中... (3件)');
    f.calls[0].resolve();
    await waitFor(() => !thread.getStatus().message.includes('過去ログを取得中'));
  });

  it('★手元に投稿があれば since = 手元の最新の投稿の時刻 − 5 分。旧形式のスレ ID (スレ立て日なし) は取らない', async () => {
    boardKey = sodium.randombytes_buf(32);
    const threadId = makeThreadId(Date.now() - 6 * DAY_MS, 'abcdefghij');
    const key = KeyManager.deriveThreadKey(boardKey, threadId);
    const f = fakeHistory();
    const { router } = await make(f);
    const when = Math.floor((Date.now() - 2 * DAY_MS) / MINUTE_MS) * MINUTE_MS;
    router.recent = [await buildReplyPacket(key, BOARD, threadId, '手元にある', customSigner(), { now: when })];
    await thread.activate(BOARD, threadId, boardKey);
    expect(f.calls[0].since).toBe(msToMinutes(when - 5 * MINUTE_MS));
    thread.clear();
    const legacy = fakeHistory();
    await make(legacy);
    await thread.activate(BOARD, 'abcdefghij', boardKey);
    expect(legacy.calls).toHaveLength(0);
  });

  it('★開いたとき 1 回だけ。取得中の再接続は重ねず、終わったあとの再接続で取り直す。画面を閉じたら中止して購読も外す', async () => {
    boardKey = sodium.randombytes_buf(32);
    const threadId = makeThreadId(Date.now() - 3 * DAY_MS, 'zzzzzzzzzz');
    const f = fakeHistory();
    await make(f);
    await thread.activate(BOARD, threadId, boardKey);
    await thread.activate(BOARD, threadId, boardKey); // 同じスレを開き直しても重ねない
    f.fireReady(); // 取得中の再接続
    expect(f.calls).toHaveLength(1);
    f.calls[0].resolve();
    await waitFor(() => !thread.getStatus().message.includes('過去ログ'));
    f.fireReady(); // 終わったあとの再接続
    expect(f.calls).toHaveLength(2);
    const sig = f.calls[1].signal!;
    thread.clear();
    expect(sig.aborted).toBe(true);
    expect(f.readyCount()).toBe(0);
    f.fireReady();
    expect(f.calls).toHaveLength(2);
  });
});

describe('BoardOrchestrator: 板を開いたとき直近 13 週のスレ立てを取る', () => {
  beforeAll(async () => { await sodiumReady; });
  let board: BoardOrchestrator;
  afterEach(() => board?.clear());

  it('★新しい週から順に 13 本、同時 3 本まで。バケット = (週の月曜の日番号, 板の鍵の tag)。手元のスレ立てがある週は since がその最新 − 5 分', async () => {
    const boardKey = sodium.randombytes_buf(32);
    const f = fakeHistory();
    const pm = new FakePeerManager();
    pm.degreeOverride = 1;
    const router = new FakeRouter();
    const db = await unlockedStore();
    // 手元に 2 週間前のスレ立てがある
    const when = Math.floor((Date.now() - 14 * DAY_MS) / MINUTE_MS) * MINUTE_MS;
    router.recent = [await buildThreadMetaPacket(boardKey, BOARD, makeThreadId(when, 'abcdefghij'), '手元のスレ', customSigner(), 0, { now: when })];
    board = new BoardOrchestrator(pm as any, db, router as any, new CryptoEngine(), syncPow, new Identity(), null, f.history);
    await board.activate(BOARD, boardKey);
    await waitFor(() => f.calls.length >= 3);
    expect(f.calls).toHaveLength(3); // 同時 3 本
    const thisMonday = mondayOf(dayOf(Date.now()));
    expect(f.calls.map(c => c.birthDay)).toEqual([thisMonday, thisMonday - 7, thisMonday - 14]);
    expect(f.calls.every(c => c.tag === boardTag(boardKey, c.birthDay))).toBe(true);
    expect(board.getStatus().message).toMatch(/^過去ログを取得中\.\.\. \(1\/13/);
    // 1 本終わると次が始まる。全部で 13 本
    for (let i = 0; i < 13; i++) {
      await waitFor(() => f.calls.length > i);
      f.calls[i].resolve();
    }
    await waitFor(() => f.calls.length === 13);
    expect(f.peak()).toBeLessThanOrEqual(3);
    expect(f.calls.map(c => c.birthDay)).toEqual(Array.from({ length: 13 }, (_, i) => thisMonday - 7 * i));
    const myWeek = mondayOf(dayOf(when));
    const call = f.calls.find(c => c.birthDay === myWeek)!;
    expect(call.since).toBe(msToMinutes(when - 5 * MINUTE_MS));
    expect(f.calls.filter(c => c.birthDay !== myWeek).every(c => c.since === 0)).toBe(true);
    // 開いたとき 1 回だけ
    f.fireReady();
    expect(f.calls).toHaveLength(13);
    void sleep;
  });
});

describe('端から端まで: 新しい端末で古いスレを開くと、保持者から取ってきた過去ログが画面に出る', () => {
  beforeAll(async () => { await sodiumReady; });

  it('★72 時間より古い投稿を、別の端末 (保持者) からトンネル経由で取り、ThreadOrchestrator に表示される。DB にも保存される', async () => {
    const guardIds = new Set<string>();
    const g = await attachTunnel(await createSimNode('g'), { storage: { slots: 1, wait: false }, relay: { role: 'guard', isBackbone: (id) => guardIds.has(id) } });
    guardIds.add(g.identity.peerId);
    const h = await attachTunnel(await createSimNode('h'), { storage: { slots: 1 } });
    const r = await attachTunnel(await createSimNode('r'), { storage: { slots: 1, wait: false } });
    const all = [g, h, r];
    try {
      attachBehind(h, g);
      attachBehind(r, g);
      // 5 日前のスレに 3 件の投稿 (本物の暗号化・PoW)
      const boardKey = sodium.randombytes_buf(32);
      const birthMs = Date.now() - 5 * DAY_MS;
      const threadId = makeThreadId(birthMs, '9876543210');
      const key = KeyManager.deriveThreadKey(boardKey, threadId);
      const base = Math.floor(birthMs / DAY_MS) * DAY_MS + 10 * 3600_000;
      const texts = ['古い投稿 1', '古い投稿 2', '古い投稿 3'];
      for (let i = 0; i < texts.length; i++) {
        const p = await buildReplyPacket(key, BOARD, threadId, texts[i], customSigner(), { pow: 'real', now: base + i * 5 * MINUTE_MS });
        await h.storage.holder!.put(p);
      }
      h.storage.router.publish();
      await until(() => h.storage.tunnel!.registered && r.storage.leaseSets.size === 1, 5000, 'ready');

      const db = await unlockedStore();
      const thread = new ThreadOrchestrator(r.peerManager as any, db, r.gossip, new CryptoEngine(), syncPow, new Identity(), keyMgr, null, r.history);
      try {
        await thread.activate(BOARD, threadId, boardKey);
        await waitFor(() => thread.getPosts().length === 3, 8000);
        expect(thread.getPosts().map(p => p.content).sort()).toEqual([...texts].sort());
        await waitFor(() => !thread.getStatus().message.includes('過去ログを取得中'), 3000);
        expect((await db.getPosts(BOARD, threadId)).length).toBe(3);
      } finally {
        thread.clear();
      }
    } finally {
      stopTunnel(all);
      await stopStorage(all);
      stopAll(all);
    }
    void link;
  }, 30_000);
});
