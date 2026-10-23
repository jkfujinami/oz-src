import { threadBirthFromId } from '../../src/logic/ThreadLimits';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { BoardOrchestrator } from '../../src/logic/BoardOrchestrator';
import { BOARD_META_THREAD_ID } from '../../src/logic/types';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { Identity } from '../../src/crypto/Identity';
import { KeyManager } from '../../src/crypto/KeyManager';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { realPowEngine } from '../helpers/postFixtures';
import { metaTagAge } from '../../src/crypto/PacketTag';
import { PacketValidator } from '../../src/network/gossip/PacketValidator';
import type { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import {
  FakePeerManager, FakeRouter, FakeCatchup, syncPow,
  unlockedStore, customSigner, buildThreadMetaPacket, buildReplyPacket, encodeBody,
  waitFor, flush, LOGIC_FAKE_TIMERS, PASS,
} from '../helpers/logicHarness';

const BOARD = 'news';
const OTHER_BOARD = 'other';

interface H {
  board: BoardOrchestrator;
  pm: FakePeerManager;
  router: FakeRouter;
  catchup: FakeCatchup;
  db: IndexedDBStore;
  identity: Identity;
}

async function make(db?: IndexedDBStore, identity?: Identity, deps: { pm?: any; router?: any; pow?: any } = {}): Promise<H> {
  const pm = deps.pm ?? new FakePeerManager();
  const router = deps.router ?? new FakeRouter();
  const catchup = new FakeCatchup();
  const store = db ?? await unlockedStore();
  const id = identity ?? new Identity();
  const board = new BoardOrchestrator(
    pm as any, store, router as any, new CryptoEngine(), deps.pow ?? syncPow, id, catchup,
  );
  return { board, pm, router, catchup, db: store, identity: id };
}

describe('BoardOrchestrator', () => {
  let boardKey: Uint8Array;
  let otherKey: Uint8Array;
  let h: H;

  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(async () => {
    boardKey = sodium.randombytes_buf(32);
    otherKey = sodium.randombytes_buf(32);
    h = await make();
  });

  afterEach(() => {
    h.board.clear();
    vi.useRealTimers();
  });

  describe('スレッドの作成', () => {
    it('スレッドを立てると即座に一覧へ載り、オニオン回路経由で送信される', async () => {
      await h.board.activate(BOARD, boardKey);
      const notified = vi.fn();
      h.board.subscribe(notified);

      const threadId = await h.board.submitThread(BOARD, boardKey, '最初のスレッド');

      // 先頭 4 文字がスレ立て日 (寿命の起点)、残り 10 文字が乱数
      expect(threadId).toMatch(/^[0-9a-z]{14}$/);
      expect(threadBirthFromId(threadId!)).toBe(Math.floor(Date.now() / 86_400_000) * 86_400_000);
      const threads = h.board.getThreads();
      expect(threads).toHaveLength(1);
      expect(threads[0]).toMatchObject({ thread_id: threadId, content: '最初のスレッド', max_pow: 0 });
      expect(notified).toHaveBeenCalled();
      expect(h.board.getStatus()).toMatchObject({ phase: 'idle', isSubmitting: false });

      // 送出はオニオン回路 (router.broadcast) だけ。保管・索引の依頼は無い
      expect(h.router.broadcast).toHaveBeenCalledTimes(1);
      const [packet, ...rest] = h.router.broadcast.mock.calls[0];
      expect(rest).toEqual([]);
      expect(threads[0].packet_id).toBe(packet.packet_id);
      expect(h.pm.sendMessage).not.toHaveBeenCalled();
    });

    it('送出されるパケットは網の検証 (packet_id + Equi-X) を通り、板の鍵でだけ開ける', async () => {
      const real = await make(h.db, undefined, { pow: realPowEngine });
      h.board.clear();
      h = real;
      const threadId = await h.board.submitThread(BOARD, boardKey, 'タイトル');
      const packet = h.router.broadcast.mock.calls[0][0];

      expect(PacketValidator.check(packet)).toEqual({ ok: true });
      expect(packet.effort_exp).toBe(0); // 1 セルに収まる最小の effort
      expect(packet.age).toBe(metaTagAge(boardKey, packet.timestamp).age); // スレ立ては「投稿日 − 週の月曜」
      // 網に出す時刻は分単位に丸める (A5)
      expect(packet.timestamp % 60_000).toBe(0);
      expect(h.board.getThreads()[0].created_at).toBe(packet.timestamp);

      const ctx = { kind: 'meta', boardId: BOARD } as const;
      const meta = await PacketBuilder.verifyAndDecrypt(packet, boardKey, ctx, new CryptoEngine());
      expect(meta).toMatchObject({ post_type: 1, content: 'タイトル', thread_id: threadId, board_id: BOARD });
      expect(await PacketBuilder.verifyAndDecrypt(packet, otherKey, ctx, new CryptoEngine())).toBeNull();
      // スレッド鍵 (板の鍵からの派生) でも開けない: 板のメタは板の鍵でしか読めない
      expect(await PacketBuilder.verifyAndDecrypt(packet, KeyManager.deriveThreadKey(boardKey, threadId!), ctx, new CryptoEngine())).toBeNull();
    });

    it('立てたスレッドは暗号化 DB に保存され、スレッド統計も更新される', async () => {
      const threadId = await h.board.submitThread(BOARD, boardKey, '保存されるスレッド');

      const rows = await h.db.getPosts(BOARD, BOARD_META_THREAD_ID);
      expect(rows).toHaveLength(1);
      const stats = await h.db.getThreads(BOARD);
      expect(stats).toEqual([expect.objectContaining({ threadId, boardId: BOARD, max_pow: 0 })]);
      expect(await h.db.getThreads(OTHER_BOARD)).toEqual([]);
    });

    it('回路で届かなかったら、平文に落とさずエラー表示にする', async () => {
      h.router.broadcast.mockResolvedValueOnce(false);
      const threadId = await h.board.submitThread(BOARD, boardKey, '届かないスレッド');
      expect(threadId).toBeTruthy();

      await waitFor(() => h.board.getStatus().phase === 'error');
      expect(h.board.getStatus().message).toContain('平文での送信は行っていません');
      expect(h.pm.sendMessage).not.toHaveBeenCalled();
    });

    it('空のタイトルでは何もしない', async () => {
      expect(await h.board.submitThread(BOARD, boardKey, '')).toBeNull();
      expect(h.router.broadcast).not.toHaveBeenCalled();
      expect(h.board.getThreads()).toHaveLength(0);
    });

    it('PoW の計算に失敗したらエラー表示にして null を返す', async () => {
      const failing = new BoardOrchestrator(
        h.pm as any, h.db, h.router as any, new CryptoEngine(),
        { compute: async () => { throw new Error('pow failed'); } }, h.identity,
      );
      expect(await failing.submitThread(BOARD, boardKey, 'x')).toBeNull();
      expect(failing.getStatus()).toMatchObject({ phase: 'error', isSubmitting: false });
      expect(h.router.broadcast).not.toHaveBeenCalled();
    });

    it('連続して立てたスレッドの ID は重複しない', async () => {
      const ids = new Set<string>();
      for (let i = 0; i < 5; i++) ids.add((await h.board.submitThread(BOARD, boardKey, `t${i}`))!);
      expect(ids.size).toBe(5);
      expect(h.board.getThreads()).toHaveLength(5);
    });
  });

  describe('網からの受信と板の鍵', () => {
    beforeEach(async () => {
      await h.board.activate(BOARD, boardKey);
    });

    it('板の鍵で開けるスレッド作成パケットは一覧に載り、DB に保存される', async () => {
      const pkt = await buildThreadMetaPacket(boardKey, BOARD, 'remote0001', '他人のスレ', customSigner());
      await h.router.deliver(pkt);

      expect(h.board.getThreads().map(t => t.content)).toEqual(['他人のスレ']);
      expect(h.board.getThreads()[0].packet_id).toBe(pkt.packet_id);
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(1);
    });

    it('別の板の鍵で暗号化されたパケットは無視し、保存もしない', async () => {
      const notified = vi.fn();
      h.board.subscribe(notified);
      const pkt = await buildThreadMetaPacket(otherKey, OTHER_BOARD, 'foreign001', 'よその板', customSigner());
      await h.router.deliver(pkt);

      expect(h.board.getThreads()).toHaveLength(0);
      expect(notified).not.toHaveBeenCalled();
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(0);
      expect(await h.db.getPosts(OTHER_BOARD, BOARD_META_THREAD_ID)).toHaveLength(0);
    });

    it('板の鍵で暗号化されていても、レス (post_type=0) はスレッド一覧に載せない', async () => {
      const pkt = await buildReplyPacket(boardKey, BOARD, 'thread0001', 'レス', customSigner());
      await h.router.deliver(pkt);
      expect(h.board.getThreads()).toHaveLength(0);
    });

    it('同じパケットが何度届いても通知は 1 回', async () => {
      const notified = vi.fn();
      h.board.subscribe(notified);
      const pkt = await buildThreadMetaPacket(boardKey, BOARD, 'dup0000001', '重複', customSigner());
      await h.router.deliver(pkt);
      await h.router.deliver(pkt);
      await h.router.deliver({ ...pkt });
      expect(notified).toHaveBeenCalledTimes(1);
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(1);
    });

    it('購読解除した listener には通知しない', async () => {
      const notified = vi.fn();
      const unsubscribe = h.board.subscribe(notified);
      unsubscribe();
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'unsub00001', 'x', customSigner()));
      expect(notified).not.toHaveBeenCalled();
    });

    it('getThreads は変更が無い限り同じ参照を返す (useSyncExternalStore の契約)', async () => {
      const before = h.board.getThreads();
      expect(h.board.getThreads()).toBe(before);
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'snap000001', 's', customSigner()));
      const after = h.board.getThreads();
      expect(after).not.toBe(before);
      expect(h.board.getThreads()).toBe(after);
    });

    it('同じスレッドの別パケット (別の分に作られたスレ立て) が届いても一覧は 1 件のまま、作成時刻は最初のものを保つ', async () => {
      const first = await buildThreadMetaPacket(boardKey, BOARD, 'merge00001', 'merge', customSigner());
      await h.router.deliver(first);
      const createdAt = h.board.getThreads()[0].created_at;

      const later = await buildThreadMetaPacket(boardKey, BOARD, 'merge00001', 'merge', customSigner(), 0, { now: Date.now() + 120_000 });
      expect(later.packet_id).not.toBe(first.packet_id);
      await h.router.deliver(later);

      const t = h.board.getThreads();
      expect(t).toHaveLength(1);
      expect(t[0].created_at).toBe(createdAt);
    });

    it('直近に見た投稿 (追いつきで先に届いた分) は、板を開いたときに流し込まれて保存される', async () => {
      h.board.clear();
      const pkt = await buildThreadMetaPacket(boardKey, BOARD, 'recent0001', '先に届いていた', customSigner());
      const foreign = await buildThreadMetaPacket(otherKey, OTHER_BOARD, 'recent0002', 'よその板', customSigner());
      h.router.recent = [foreign, pkt];
      await h.board.activate(BOARD, boardKey);
      expect(h.board.getThreads().map(t => t.content)).toEqual(['先に届いていた']);
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(1);
    });

    it('追いつきの受信中は「見つかりませんでした」と言わず、終わってから猶予を過ぎていれば言う', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 1;
      h.catchup.active = true;
      await h.board.activate(BOARD, boardKey);
      await vi.advanceTimersByTimeAsync(20_000);
      expect(h.board.getStatus()).toMatchObject({ phase: 'syncing', message: '過去ログを取得中...' });
      h.catchup.set(false);
      expect(h.board.getStatus().message).toContain('見つかりませんでした');
    });

    it('板を切り替えると一覧は空になり、前の板のパケットは取り込まない', async () => {
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'before0001', '前の板', customSigner()));
      expect(h.board.getThreads()).toHaveLength(1);

      await h.board.activate(OTHER_BOARD, otherKey);
      expect(h.board.getThreads()).toHaveLength(0);
      // リスナーは張り替えられ、重複登録されない
      expect(h.router.listeners.size).toBe(1);
      expect(h.pm.listenerCount('peer:connect')).toBe(1);

      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'before0002', '前の板 2', customSigner()));
      expect(h.board.getThreads()).toHaveLength(0);
      await h.router.deliver(await buildThreadMetaPacket(otherKey, OTHER_BOARD, 'after00001', '新しい板', customSigner()));
      expect(h.board.getThreads().map(t => t.content)).toEqual(['新しい板']);
    });

    it('同じ板で activate し直しても一覧は消えず、リスナーも増えない', async () => {
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'again00001', 'x', customSigner()));
      await h.board.activate(BOARD, boardKey);
      expect(h.board.getThreads()).toHaveLength(1);
      expect(h.router.listeners.size).toBe(1);
      expect(h.pm.listenerCount('peer:connect')).toBe(1);
    });
  });

  describe('本文の上限と旧形式の保存データ', () => {
    it('2049 バイトのスレッドタイトルは送信前に RangeError で拒否する', async () => {
      await expect(h.board.submitThread(BOARD, boardKey, 'a'.repeat(2049))).rejects.toThrow(RangeError);
      expect(h.router.broadcast).not.toHaveBeenCalled();
    });

    it('★旧形式 (v1 のコンパクト形式・JSON) で保存されていたスレッドは読めず、黙って飛ばされる。書き戻されない', async () => {
      await h.board.activate(BOARD, boardKey);
      const v1 = new Uint8Array(200).fill(7); v1[0] = 1;
      const json = new TextEncoder().encode('{"packet_id":"x","payload":{"_type":"Uint8Array","data":"AAAA"}}');
      for (const payload of [v1, json]) {
        await h.db.save({ boardId: BOARD, threadId: BOARD_META_THREAD_ID, payload, dag: { parents: [], cumulative_pow: 12, thread_root: 'old0000001', created_at: Date.now() } });
      }
      h.board.clear();
      const again = await make(h.db);
      await again.board.activate(BOARD, boardKey);
      expect(again.board.getThreads()).toEqual([]);
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(2);
      again.board.clear();
    });

    it('新しく立てたスレッドは v5 の形式 (PacketCodec) で保存される', async () => {
      await h.board.activate(BOARD, boardKey);
      await h.board.submitThread(BOARD, boardKey, '保存形式');
      const [entry] = await h.db.getPosts(BOARD, BOARD_META_THREAD_ID);
      expect(entry.payload[0]).toBe(2); // version
    });
  });

  describe('トリップ署名', () => {
    beforeEach(async () => {
      await h.board.activate(BOARD, boardKey);
    });

    it('正しいトリップ署名付きのスレッドは、トリップ公開鍵つきで載る', async () => {
      const author = new Identity();
      await author.generateTrip(h.db);
      const expected = author.sign(new Uint8Array([1])).tripPubkey!;

      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'trip000001', 'トリップ付き', author));
      const t = h.board.getThreads();
      expect(t).toHaveLength(1);
      expect(Array.from(t[0].trip_pubkey)).toEqual(Array.from(expected));
    });

    it('トリップ無しのスレッドは trip_pubkey=null で載る', async () => {
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'notrip0001', '名無し', customSigner()));
      expect(h.board.getThreads()[0].trip_pubkey).toBeNull();
    });

    it('他人のトリップ公開鍵を偽の署名で名乗ったスレッドは載せない', async () => {
      const victim = sodium.crypto_sign_keypair();
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'forge00001', '偽トリップ', customSigner({ trip: victim, forgeTripSig: true })));
      await expect(buildThreadMetaPacket(boardKey, BOARD, 'forge00002', '署名無しトリップ', customSigner({ tripPubkeyOnly: victim.publicKey }))).rejects.toThrow(/trip/);
      expect(h.board.getThreads()).toHaveLength(0);
      expect(await h.db.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(0);
    });

    it('自分がトリップ付きで立てたスレッドは、他のノードでもトリップ付きで検証される', async () => {
      const me = new Identity();
      await me.generateTrip(h.db);
      const mine = await make(h.db, me);
      await mine.board.submitThread(BOARD, boardKey, '自分のトリップ');
      const packet = mine.router.broadcast.mock.calls[0][0];

      await h.router.deliver(packet);
      const t = h.board.getThreads().find(x => x.content === '自分のトリップ')!;
      expect(Array.from(t.trip_pubkey)).toEqual(Array.from(me.sign(new Uint8Array()).tripPubkey!));
      mine.board.clear();
    });
  });

  describe('暗号化 DB による永続化', () => {
    it('別インスタンスでパスワードを解除し直しても、板を開けば保存済みのスレッドが復元される', async () => {
      const name = `board_persist_${Date.now()}`;
      const db1 = await unlockedStore(name);
      const first = await make(db1);
      await first.board.activate(BOARD, boardKey);
      await first.board.submitThread(BOARD, boardKey, '自分のスレ');
      await first.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'persist001', '受信したスレ', customSigner()));
      await first.router.deliver(await buildThreadMetaPacket(otherKey, OTHER_BOARD, 'persist002', 'よその板', customSigner()));
      first.board.clear();
      db1.lock();

      const db2 = await unlockedStore(name);
      const second = await make(db2);
      await second.board.activate(BOARD, boardKey);
      expect(second.board.getThreads().map(t => t.content).sort()).toEqual(['受信したスレ', '自分のスレ']);
      // DB から読んだ分は書き戻さない
      expect(await db2.getPosts(BOARD, BOARD_META_THREAD_ID)).toHaveLength(2);
      second.board.clear();
    });

    it('DB に保存済みでも、違う板の鍵で開くと何も復元されない', async () => {
      await h.board.activate(BOARD, boardKey);
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'wrongkey01', 'x', customSigner()));
      h.board.clear();

      const again = await make(h.db);
      await again.board.activate(BOARD, otherKey);
      expect(again.board.getThreads()).toHaveLength(0);
      again.board.clear();
    });

    it('ロックされた DB では復元も保存もできないが、例外で止まらない', async () => {
      h.db.lock();
      await expect(h.board.activate(BOARD, boardKey)).resolves.toBeUndefined();
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'locked0001', 'ロック中', customSigner()));
      expect(h.board.getThreads()).toHaveLength(0);
    });
  });

  describe('状態表示とタイマー', () => {
    it('隣人が居なければ「接続中」', async () => {
      await h.board.activate(BOARD, boardKey);
      expect(h.board.getStatus().phase).toBe('loading');
    });

    it('隣人が居てスレッドが無ければ、8 秒の猶予の後で初めて「見つかりませんでした」と出す', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 2;
      await h.board.activate(BOARD, boardKey);
      expect(h.board.getStatus()).toMatchObject({ phase: 'syncing' });

      await vi.advanceTimersByTimeAsync(7999);
      expect(h.board.getStatus().phase).toBe('syncing');
      await vi.advanceTimersByTimeAsync(1);
      expect(h.board.getStatus()).toMatchObject({ phase: 'idle' });
      expect(h.board.getStatus().message).toContain('見つかりませんでした');
    });

    it('猶予中にスレッドが届けば「無い」とは出さない', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 1;
      await h.board.activate(BOARD, boardKey);
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'grace00001', '間に合った', customSigner()));
      expect(h.board.getStatus()).toMatchObject({ phase: 'idle', message: '' });
      await vi.advanceTimersByTimeAsync(20_000);
      expect(h.board.getStatus().message).toBe('');
    });

    it('新しい隣人が来ると猶予を引き直し、同期はデバウンスして 1 本に畳む', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      await h.board.activate(BOARD, boardKey);
      const sync = vi.spyOn(h.board, 'fullSync');

      h.pm.addPeer();
      await vi.advanceTimersByTimeAsync(300);
      h.pm.addPeer();
      await vi.advanceTimersByTimeAsync(300);
      h.pm.addPeer();
      expect(sync).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(500);
      expect(sync).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(7000);
      expect(h.board.getStatus().phase).toBe('syncing');
      await vi.advanceTimersByTimeAsync(1100);
      expect(h.board.getStatus().message).toContain('見つかりませんでした');
    });

    it('DB のスレッド統計 (max_pow) は 5 秒ごとに一覧へ反映される', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 1;
      await h.board.activate(BOARD, boardKey);
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, 'stats00001', 'stats', customSigner()));
      expect(h.board.getThreads()[0].max_pow).toBe(0);

      // 同じスレッドへのレスが重い累積 PoW で保存された (ThreadOrchestrator 相当)
      await h.db.save({
        boardId: BOARD, threadId: 'stats00001', payload: new Uint8Array([1]),
        dag: { parents: [], cumulative_pow: 999, thread_root: 'stats00001', created_at: Date.now() },
      });
      await vi.advanceTimersByTimeAsync(5000);
      await waitFor(() => h.board.getThreads()[0].max_pow === 999);
    });

    it('clear() で全タイマーとリスナーが外れる', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 1;
      await h.board.activate(BOARD, boardKey);
      h.pm.addPeer(); // デバウンスタイマーも仕掛ける
      expect(vi.getTimerCount()).toBeGreaterThan(0);

      h.board.clear();
      expect(vi.getTimerCount()).toBe(0);
      expect(h.router.listeners.size).toBe(0);
      expect(h.pm.listenerCount('peer:connect')).toBe(0);
      expect(h.board.getThreads()).toEqual([]);
    });
  });
});

describe('BoardOrchestrator: 発信するパケット', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('スレッド作成パケットはゾーン番号を載せない。tag は板の鍵の日替わり tag', async () => {
    const h = await make();
    const key = sodium.randombytes_buf(32);
    await h.board.submitThread(BOARD, key, 'tag');
    const packet = h.router.broadcast.mock.calls[0][0];
    expect(packet).not.toHaveProperty('zone_id');
    expect(packet.tag).toBe(metaTagAge(key, packet.timestamp).tag);
    expect(packet.tag).toBeLessThan(4096);
    h.board.clear();
  });

  it('自分が立てたスレッドは、別ノードの開いている板に届く (本物の検証を通る)', async () => {
    const key = sodium.randombytes_buf(32);
    const author = await make(undefined, undefined, { pow: realPowEngine });
    await author.board.submitThread(BOARD, key, '作者のスレ');
    const packet = author.router.broadcast.mock.calls[0][0];
    expect(PacketValidator.check(packet)).toEqual({ ok: true });

    const reader = await make();
    await reader.board.activate(BOARD, key);
    await reader.router.deliver(packet);
    expect(reader.board.getThreads()).toHaveLength(1);
    author.board.clear();
    reader.board.clear();
  });
});

describe('BoardOrchestrator: 状態通知', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('同じ状態への更新では status listener を呼ばない', async () => {
    const h = await make();
    const statusCb = vi.fn();
    h.board.subscribeStatus(statusCb);
    const key = sodium.randombytes_buf(32);
    await h.board.activate(BOARD, key); // loading
    const calls = statusCb.mock.calls.length;
    await h.board.fullSync(BOARD, key); // 同じ loading
    expect(statusCb.mock.calls.length).toBe(calls);
    await flush();
    h.board.clear();
  });
});
