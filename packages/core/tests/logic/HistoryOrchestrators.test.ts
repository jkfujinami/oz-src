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
  const calls: Array<{ birthDay: number; tag: number; since: number; resolve: (completed?: boolean) => void; progress: (n: number) => void; signal?: AbortSignal }> = [];
  const readyCbs = new Set<() => void>();
  let running = 0, peak = 0;
  const history: HistoryFetcher = {
    onReady: (cb) => { readyCbs.add(cb); return () => { readyCbs.delete(cb); }; },
    fetchBucket: (birthDay, tag, opts = {}) => new Promise((resolve) => {
      running++; peak = Math.max(peak, running);
      calls.push({
        birthDay, tag, since: opts.since ?? 0, signal: opts.signal, progress: (n) => opts.onProgress?.(n),
        resolve: (completed = true) => { running--; resolve({ completed, packets: 0, attempts: 1, reason: completed ? 'ok' : 'exhausted' } as any); },
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
    expect(thread.getStatus()).toMatchObject({ phase: 'syncing', code: 'history-fetching', message: '過去ログを取得中...' });
    f.calls[0].progress(3);
    expect(thread.getStatus().message).toBe('過去ログを取得中... (3件)');
    expect(thread.getStatus()).toMatchObject({ code: 'history-fetching', params: { count: 3 } });
    f.calls[0].resolve();
    await waitFor(() => !thread.getStatus().message.includes('過去ログを取得中'));
  });

  it('★手元に最新のレスがあっても (追いつきで先に届いただけかもしれない)、取り切った記録が無ければ since = 0。取り切ったあと開き直すと since = 取り切った時刻 − 5 分。取り切れなければ記録は進まない。旧形式のスレ ID は取らない', async () => {
    // 実網で、追いつきで届いた最新のレスを基準に since を決め、それより前のレスを取りに行かずに抜けていた
    boardKey = sodium.randombytes_buf(32);
    const threadId = makeThreadId(Date.now() - 6 * DAY_MS, 'abcdefghij');
    const key = KeyManager.deriveThreadKey(boardKey, threadId);
    const f = fakeHistory();
    const { router, store } = await make(f);
    const when = Math.floor((Date.now() - 2 * DAY_MS) / MINUTE_MS) * MINUTE_MS;
    router.recent = [await buildReplyPacket(key, BOARD, threadId, '追いつきで届いた最新のレス', customSigner(), { now: when })];
    await thread.activate(BOARD, threadId, boardKey);
    expect(f.calls[0].since).toBe(0);
    f.calls[0].resolve(false); // どの保持者からも取り切れなかった
    await waitFor(() => !thread.getStatus().message.includes('過去ログ'));
    thread.clear();

    const g = fakeHistory();
    await make(g, store);
    await thread.activate(BOARD, threadId, boardKey);
    expect(g.calls[0].since).toBe(0); // 記録は進んでいない
    const t0 = Date.now();
    g.calls[0].resolve();
    await waitFor(() => !thread.getStatus().message.includes('過去ログ'));
    thread.clear();

    const h = fakeHistory();
    await make(h, store);
    await thread.activate(BOARD, threadId, boardKey);
    expect(Math.abs(h.calls[0].since - (msToMinutes(t0) - 5))).toBeLessThanOrEqual(1);
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

  it('★13 週を一度に (新しい週から)。バケット = (週の月曜の日番号, 板の鍵の tag)。手元にスレ立てがあっても since は 0、取り切った週は次に開いたとき その時刻 − 5 分', async () => {
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
    // 実網の実測で、スレの無い週が枠待ちで後ろに並び、全体で 9 秒かかっていた。全週を一度に出す
    await waitFor(() => f.calls.length >= 13);
    expect(f.calls).toHaveLength(13);
    expect(f.peak()).toBe(13);
    const thisMonday = mondayOf(dayOf(Date.now()));
    expect(f.calls.map(c => c.birthDay)).toEqual(Array.from({ length: 13 }, (_, i) => thisMonday - 7 * i));
    expect(f.calls.every(c => c.tag === boardTag(boardKey, c.birthDay))).toBe(true);
    expect(board.getStatus().message).toMatch(/^過去ログを取得中\.\.\. \(1\/13/);
    expect(board.getStatus()).toMatchObject({ code: 'history-fetching', params: { done: 1, total: 13 } });
    for (const c of f.calls) c.resolve();
    // 手元のスレ立て (追いつきで届いたかもしれない) は基準にしない: 全週 since = 0
    expect(f.calls.every(c => c.since === 0)).toBe(true);
    // 開いたとき 1 回だけ
    f.fireReady();
    expect(f.calls).toHaveLength(13);
    await waitFor(() => !board.getStatus().message.includes('過去ログ'));
    board.clear();

    // 開き直すと、取り切った週は その時刻 − 5 分から
    const g = fakeHistory();
    board = new BoardOrchestrator(pm as any, db, router as any, new CryptoEngine(), syncPow, new Identity(), null, g.history);
    await board.activate(BOARD, boardKey);
    await waitFor(() => g.calls.length >= 1);
    const expected = msToMinutes(Date.now()) - 5;
    expect(Math.abs(g.calls[0].since - expected)).toBeLessThanOrEqual(2);
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
