import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { ThreadOrchestrator } from '../../src/logic/ThreadOrchestrator';
import { ThreadClosedError } from '../../src/logic/ThreadClosedError';
import { THREAD_LIMITS, makeThreadId } from '../../src/logic/ThreadLimits';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { Identity } from '../../src/crypto/Identity';
import { KeyManager } from '../../src/crypto/KeyManager';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { realPowEngine } from '../helpers/postFixtures';
import { threadTag, dayOf } from '../../src/crypto/PacketTag';
import { PacketValidator } from '../../src/network/gossip/PacketValidator';
import type { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import {
  FakePeerManager, FakeRouter, FakeCatchup, keyMgr, syncPow,
  unlockedStore, customSigner, buildReplyPacket, buildThreadMetaPacket,
  waitFor, LOGIC_FAKE_TIMERS,
} from '../helpers/logicHarness';

import { decodePacket } from '../../src/crypto/PacketCodec';

const BOARD = 'news';
const THREAD = 'thr0000001';
const OTHER_THREAD = 'thr0000002';
const REPLY = { kind: 'reply', boardId: BOARD, threadId: THREAD } as const;

interface H {
  thread: ThreadOrchestrator;
  pm: FakePeerManager;
  router: FakeRouter;
  catchup: FakeCatchup;
  db: IndexedDBStore;
}

async function make(db?: IndexedDBStore, identity: Identity = new Identity(), deps: { pm?: any; router?: any; pow?: any } = {}): Promise<H> {
  const pm = deps.pm ?? new FakePeerManager();
  if (!deps.pm) pm.degreeOverride = 1; // 既定では隣人が居る (初回同期の 10 秒待ちを避ける)
  const router = deps.router ?? new FakeRouter();
  const catchup = new FakeCatchup();
  const store = db ?? await unlockedStore();
  const thread = new ThreadOrchestrator(
    pm as any, store, router as any, new CryptoEngine(), deps.pow ?? syncPow, identity, keyMgr, catchup,
  );
  return { thread, pm, router, catchup, db: store };
}

const contents = (h: H) => h.thread.getPosts().map(p => p.content);

describe('ThreadOrchestrator', () => {
  let boardKey: Uint8Array;
  let threadKey: Uint8Array;
  let h: H;

  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(async () => {
    boardKey = sodium.randombytes_buf(32);
    threadKey = KeyManager.deriveThreadKey(boardKey, THREAD);
    h = await make();
  });

  afterEach(() => {
    h.thread.clear();
    vi.useRealTimers();
  });

  describe('返信の投稿', () => {
    beforeEach(async () => {
      await h.thread.activate(BOARD, THREAD, boardKey);
    });

    it('直近に見た投稿 (追いつきで先に届いた分) は、スレを開いたときに流し込まれて保存される。他のスレの分は無視', async () => {
      h.thread.clear();
      const mine = await buildReplyPacket(threadKey, BOARD, THREAD, '先に届いていた', customSigner());
      const otherKey = KeyManager.deriveThreadKey(boardKey, OTHER_THREAD);
      const foreign = await buildReplyPacket(otherKey, BOARD, OTHER_THREAD, '別のスレ', customSigner());
      h.router.recent = [foreign, mine];
      await h.thread.activate(BOARD, THREAD, boardKey);
      expect(contents(h)).toEqual(['先に届いていた']);
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(1);
    });

    it('返信は即座に DAG に載り、スレッド鍵で暗号化された正当なパケットとして回路へ送られる', async () => {
      const real = await make(h.db, undefined, { pow: realPowEngine });
      h.thread.clear();
      h = real;
      await h.thread.activate(BOARD, THREAD, boardKey);
      await h.thread.submitReply('こんにちは');

      const posts = h.thread.getPosts();
      expect(posts).toHaveLength(1);
      expect(posts[0]).toMatchObject({ content: 'こんにちは', parents: [], thread_id: THREAD, board_id: BOARD });

      expect(h.router.broadcast).toHaveBeenCalledTimes(1);
      const [packet, ...rest] = h.router.broadcast.mock.calls[0];
      expect(posts[0].packet_id).toBe(packet.packet_id);
      expect(rest).toEqual([]); // 保管・索引の依頼は付かない
      expect(PacketValidator.check(packet)).toEqual({ ok: true });
      expect(packet.timestamp % 60_000).toBe(0);

      const decoded = await PacketBuilder.verifyAndDecrypt(packet, threadKey, REPLY, new CryptoEngine());
      expect(decoded).toMatchObject({ post_type: 0, content: 'こんにちは', thread_id: THREAD });
      expect(decoded).not.toHaveProperty('post_number');
      expect(decoded).not.toHaveProperty('cumulative_pow');
      expect(await PacketBuilder.verifyAndDecrypt(packet, boardKey, REPLY, new CryptoEngine())).toBeNull();

      expect(h.pm.sendMessage).not.toHaveBeenCalled();
    });

    it('続く返信は直前の先端を親に持つ。累積 PoW も post_number もワイヤに載らない (閲覧状況を漏らさない)', async () => {
      await h.thread.submitReply('1');
      await h.thread.submitReply('2');
      await h.thread.submitReply('3');

      const posts = h.thread.getPosts();
      expect(posts.map(p => p.content)).toEqual(['1', '2', '3']);
      expect(posts[1].parents).toEqual([posts[0].packet_id]);
      expect(posts[2].parents).toEqual([posts[1].packet_id]);

      const third = h.router.broadcast.mock.calls[2][0];
      const decoded = await PacketBuilder.verifyAndDecrypt(third, threadKey, REPLY, new CryptoEngine());
      expect(decoded!.parents).toEqual([posts[1].packet_id]);
      expect(decoded).not.toHaveProperty('post_number');
    });

    it('返信は暗号化 DB にスレッド単位で保存される', async () => {
      await h.thread.submitReply('保存');
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(1);
      expect(await h.db.getPosts(BOARD, OTHER_THREAD)).toHaveLength(0);
      const stats = await h.db.getThreads(BOARD);
      // ★ DB の熱量は手元で数えた祖先の数 n(p) (最初の返信は 1)
      expect(stats).toEqual([expect.objectContaining({ threadId: THREAD, max_pow: 1 })]);
    });

    it('回路で届かなかったら平文に落とさずエラー表示にする', async () => {
      h.router.broadcast.mockResolvedValueOnce(false);
      await h.thread.submitReply('届かない');
      await waitFor(() => h.thread.getStatus().phase === 'error');
      expect(h.thread.getStatus().message).toContain('平文での送信は行っていません');
    });

    it('投稿後の表示は 3 秒で通常に戻る', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      await h.thread.submitReply('x');
      expect(h.thread.getStatus()).toMatchObject({ phase: 'idle', isSubmitting: false });
      expect(h.thread.getStatus().message).not.toBe('');
      await vi.advanceTimersByTimeAsync(3000);
      expect(h.thread.getStatus()).toMatchObject({ phase: 'idle', message: '' });
    });

    it('空文字の返信は何もしない', async () => {
      await h.thread.submitReply('');
      expect(h.router.broadcast).not.toHaveBeenCalled();
      expect(h.thread.getPosts()).toHaveLength(0);
    });
  });

  it('スレッドを開く前の返信は何もしない', async () => {
    await h.thread.submitReply('早すぎる');
    expect(h.router.broadcast).not.toHaveBeenCalled();
  });

  describe('網からの受信', () => {
    beforeEach(async () => {
      await h.thread.activate(BOARD, THREAD, boardKey);
    });

    it('このスレッドの鍵で開ける返信は DAG に載り、DB に保存される', async () => {
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '他人のレス', customSigner()));
      expect(contents(h)).toEqual(['他人のレス']);
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(1);
    });

    it('同じ板の別スレッドの返信は (鍵が違うので) 取り込まない', async () => {
      const otherKey = KeyManager.deriveThreadKey(boardKey, OTHER_THREAD);
      await h.router.deliver(await buildReplyPacket(otherKey, BOARD, OTHER_THREAD, '別スレ', customSigner()));
      expect(h.thread.getPosts()).toHaveLength(0);
      expect(await h.db.getPosts(BOARD, OTHER_THREAD)).toHaveLength(0);
    });

    it('スレッド鍵で開けても、中の thread_id が違う返信は取り込まない', async () => {
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, OTHER_THREAD, '偽のスレッド ID', customSigner()));
      expect(h.thread.getPosts()).toHaveLength(0);
    });

    it('スレッド鍵で開けても、スレッド作成 (post_type=1) は返信として取り込まない', async () => {
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, 'メタ', customSigner(), { postType: 1 }));
      expect(h.thread.getPosts()).toHaveLength(0);
    });

    it('板の鍵で暗号化された板メタは、スレッドには現れない', async () => {
      await h.router.deliver(await buildThreadMetaPacket(boardKey, BOARD, THREAD, 'スレタイ', customSigner()));
      expect(h.thread.getPosts()).toHaveLength(0);
    });

    it('同じパケットが何度届いても通知は 1 回', async () => {
      const notified = vi.fn();
      h.thread.subscribe(notified);
      const pkt = await buildReplyPacket(threadKey, BOARD, THREAD, '重複', customSigner());
      await h.router.deliver(pkt);
      await h.router.deliver(pkt);
      expect(notified).toHaveBeenCalledTimes(1);
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(1);
    });

    it('子が親より先に届いても、表示は親が先', async () => {
      const parent = await buildReplyPacket(threadKey, BOARD, THREAD, '親', customSigner());
      const child = await buildReplyPacket(threadKey, BOARD, THREAD, '子', customSigner(), { parents: [parent.packet_id] });
      await h.router.deliver(child);
      expect(contents(h)).toEqual(['子']);
      await h.router.deliver(parent);
      expect(contents(h)).toEqual(['親', '子']);
    });

    it('並行して書かれた返信が両方届くと、次の自分の返信はその両方を親にする (祖先の多い方が先)', async () => {
      const a = await buildReplyPacket(threadKey, BOARD, THREAD, 'A', customSigner());
      const root = await buildReplyPacket(threadKey, BOARD, THREAD, 'R', customSigner());
      const b = await buildReplyPacket(threadKey, BOARD, THREAD, 'B', customSigner(), { parents: [root.packet_id] });
      await h.router.deliver(a);
      await h.router.deliver(root);
      await h.router.deliver(b);

      await h.thread.submitReply('合流');
      const mine = h.thread.getPosts().find(p => p.content === '合流')!;
      // 先端は A (n=1) と B (n=2)。n(p) の大きい B が先 (累積 PoW の申告ではなく手元で数えた値)
      expect(mine.parents).toEqual([b.packet_id, a.packet_id]);
      expect(h.thread.getPosts().at(-1)!.content).toBe('合流');
    });

    it('スレッドを切り替えると DAG は空になり、前のスレッドの返信は取り込まない', async () => {
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '前', customSigner()));
      await h.thread.activate(BOARD, OTHER_THREAD, boardKey);
      expect(h.thread.getPosts()).toHaveLength(0);
      expect(h.router.listeners.size).toBe(1);

      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '前 2', customSigner()));
      expect(h.thread.getPosts()).toHaveLength(0);
      const otherKey = KeyManager.deriveThreadKey(boardKey, OTHER_THREAD);
      await h.router.deliver(await buildReplyPacket(otherKey, BOARD, OTHER_THREAD, '新', customSigner()));
      expect(contents(h)).toEqual(['新']);
    });
  });

  describe('板の鍵の扱い', () => {
    it('違う板の鍵でスレッドを開くと、正しい板のスレッドの返信は読めない', async () => {
      const wrongBoardKey = sodium.randombytes_buf(32);
      await h.thread.activate(BOARD, THREAD, wrongBoardKey);
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '読めないはず', customSigner()));
      expect(h.thread.getPosts()).toHaveLength(0);
    });

    it('スレッド鍵は板の鍵とスレッド ID の両方に依存する', () => {
      expect(KeyManager.deriveThreadKey(boardKey, THREAD)).toEqual(threadKey);
      expect(KeyManager.deriveThreadKey(boardKey, OTHER_THREAD)).not.toEqual(threadKey);
      expect(KeyManager.deriveThreadKey(sodium.randombytes_buf(32), THREAD)).not.toEqual(threadKey);
    });
  });

  describe('トリップ署名', () => {
    beforeEach(async () => {
      await h.thread.activate(BOARD, THREAD, boardKey);
    });

    it('正しいトリップ署名付きの返信はトリップ公開鍵つきで載る', async () => {
      const author = new Identity();
      await author.generateTrip(h.db);
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, 'トリップ', author));
      const p = h.thread.getPosts()[0];
      expect(Array.from(p.trip_pubkey!)).toEqual(Array.from(author.sign(new Uint8Array()).tripPubkey!));
    });

    it('他人のトリップを偽った返信 (不正な署名 / 署名無し) は載せない', async () => {
      const victim = sodium.crypto_sign_keypair();
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '偽 1', customSigner({ trip: victim, forgeTripSig: true })));
      // 鍵だけで署名の無いトリップは、そもそも build が作らせない
      await expect(buildReplyPacket(threadKey, BOARD, THREAD, '偽 2', customSigner({ tripPubkeyOnly: victim.publicKey }))).rejects.toThrow(/trip/);
      expect(h.thread.getPosts()).toHaveLength(0);
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(0);
    });

    it('別人のトリップ鍵で署名したものを自分のトリップ公開鍵と偽っても通らない', async () => {
      const victim = sodium.crypto_sign_keypair();
      const attacker = sodium.crypto_sign_keypair();
      const session = sodium.crypto_sign_keypair();
      const signer = {
        hasTrip: true,
        sign: (data: Uint8Array) => ({
          sessionPubkey: session.publicKey,
          sessionSignature: sodium.crypto_sign_detached(data, session.privateKey),
          tripPubkey: victim.publicKey,
          tripSignature: sodium.crypto_sign_detached(data, attacker.privateKey),
        }),
      };
      await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, '乗っ取り', signer));
      expect(h.thread.getPosts()).toHaveLength(0);
    });
  });

  describe('暗号化 DB による永続化', () => {
    it('パスワードを解除し直した別インスタンスで、返信が DAG の順序どおりに復元される', async () => {
      const name = `thread_persist_${Date.now()}`;
      const db1 = await unlockedStore(name);
      const first = await make(db1);
      await first.thread.activate(BOARD, THREAD, boardKey);
      await first.thread.submitReply('一');
      const remote = await buildReplyPacket(threadKey, BOARD, THREAD, '二', customSigner(), {
        parents: [first.thread.getPosts()[0].packet_id],
      });
      await first.router.deliver(remote);
      await first.thread.submitReply('三');
      const expectedOrder = first.thread.getPosts().map(p => p.packet_id);
      first.thread.clear();
      db1.lock();

      const db2 = await unlockedStore(name);
      const second = await make(db2);
      await second.thread.activate(BOARD, THREAD, boardKey);
      expect(second.thread.getPosts().map(p => p.packet_id)).toEqual(expectedOrder);
      expect(contents(second)).toEqual(['一', '二', '三']);
      // DB から読んだ分は書き戻さない
      expect(await db2.getPosts(BOARD, THREAD)).toHaveLength(3);
      second.thread.clear();
    });

    it('別スレッドを開いても、保存済みの他スレッドの返信は混ざらない', async () => {
      await h.thread.activate(BOARD, THREAD, boardKey);
      await h.thread.submitReply('このスレ');
      h.thread.clear();

      const again = await make(h.db);
      await again.thread.activate(BOARD, OTHER_THREAD, boardKey);
      expect(again.thread.getPosts()).toHaveLength(0);
      again.thread.clear();
    });
  });

  describe('本文の上限 (2048 バイト) と保存形式', () => {
    beforeEach(async () => {
      await h.thread.activate(BOARD, THREAD, boardKey);
    });

    it('2049 バイトの本文は、PoW も送信もせずに RangeError で拒否する', async () => {
      await expect(h.thread.submitReply('a'.repeat(2049))).rejects.toThrow(RangeError);
      await expect(h.thread.submitReply('あ'.repeat(683))).rejects.toThrow(/2049/);
      expect(h.router.broadcast).not.toHaveBeenCalled();
      expect(h.thread.getPosts()).toHaveLength(0);
    });

    it('2048 バイトちょうど (日本語 682 文字 + 2 バイト) は通る', async () => {
      await h.thread.submitReply('あ'.repeat(682) + 'ab');
      expect(h.thread.getPosts()).toHaveLength(1);
      expect(h.router.broadcast).toHaveBeenCalledTimes(1);
    });

    it('先端が多くても親は 2 つまでで、そのパケットは検証を通る', async () => {
      // 同時書き込みで先端が 5 本になった状態を作る
      for (let i = 0; i < 5; i++) {
        await h.router.deliver(await buildReplyPacket(threadKey, BOARD, THREAD, `枝${i}`, customSigner()));
      }
      expect(h.thread.getPosts()).toHaveLength(5);
      await h.thread.submitReply('合流');
      const sent = h.router.broadcast.mock.calls.at(-1)![0];
      const decoded = await PacketBuilder.verifyAndDecrypt(sent, threadKey, REPLY, new CryptoEngine());
      expect(decoded!.parents).toHaveLength(2);
    });

    it('保存は v5 の形式 (PacketCodec のバイト列) で、再起動後に読み戻せる', async () => {
      await h.thread.submitReply('保存形式');
      const [entry] = await h.db.getPosts(BOARD, THREAD);
      expect(entry.payload[0]).toBe(2); // PACKET_VERSION。JSON の '{' (0x7b) ではない
      expect(decodePacket(entry.payload)?.packet_id).toBe(h.thread.getPosts()[0].packet_id);
      h.thread.clear();
      const again = await make(h.db);
      await again.thread.activate(BOARD, THREAD, boardKey);
      expect(contents(again)).toEqual(['保存形式']);
      again.thread.clear();
    });

    it('★旧形式 (v1 のコンパクト形式・JSON) で端末に保存されていた返信は読めず、黙って飛ばされる。書き戻されない', async () => {
      const v1 = new Uint8Array(200).fill(7); v1[0] = 1;
      const json = new TextEncoder().encode('{"packet_id":"x","payload":{"_type":"Uint8Array","data":"AAAA"}}');
      for (const payload of [v1, json]) {
        await h.db.save({ boardId: BOARD, threadId: THREAD, payload, dag: { parents: [], cumulative_pow: 12, thread_root: THREAD, created_at: Date.now() } });
      }
      h.thread.clear();
      const again = await make(h.db);
      await again.thread.activate(BOARD, THREAD, boardKey);
      expect(contents(again)).toEqual([]);
      expect(await h.db.getPosts(BOARD, THREAD)).toHaveLength(2);
      // 新しい返信は書ける
      await again.thread.submitReply('今の返信');
      expect(contents(again)).toEqual(['今の返信']);
      again.thread.clear();
    });

    it('★旧形式のオブジェクトが網から (GOSSIP として) 届いても取り込まない', async () => {
      const v1Like = { packet_id: 'a'.repeat(64), hop_count: 0, pow_nonce: 1, pow_difficulty: 12, timestamp: Date.now(), zone_id: 0, nonce: new Uint8Array(12), payload: new Uint8Array(200) };
      await h.router.deliver(v1Like);
      expect(h.thread.getPosts()).toHaveLength(0);
    });
  });

  describe('初回同期と状態表示', () => {
    it('隣人が居なければ最大 10 秒だけ待ち、来なければ「待機中」と表示する', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = 0;
      let done = false;
      const p = h.thread.activate(BOARD, THREAD, boardKey).then(() => { done = true; });
      await waitFor(() => h.thread.getStatus().message === '隣人を探しています...');
      expect(h.thread.getStatus().phase).toBe('loading');

      await vi.advanceTimersByTimeAsync(9_999);
      expect(done).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await p;
      expect(h.thread.getStatus()).toMatchObject({ phase: 'idle' });
      expect(h.thread.getStatus().message).toContain('ネット接続待機中');
    });

    it('待っている間に隣人が来れば即座に同期へ進み、8 秒の猶予の後で「1 件も無い」と出す', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.pm.degreeOverride = null; // 実際の隣人数
      const p = h.thread.activate(BOARD, THREAD, boardKey);
      await waitFor(() => h.thread.getStatus().phase === 'loading' && h.pm.listenerCount('peer:connect') === 2);
      h.pm.addPeer();
      await p;
      expect(h.thread.getStatus().phase).toBe('syncing');
      // 待機用の一時リスナーは外れている
      expect(h.pm.listenerCount('peer:connect')).toBe(1);

      await vi.advanceTimersByTimeAsync(8000);
      expect(h.thread.getStatus().message).toContain('レスが1件もありませんでした');
    });

    it('追いつきの受信中は「1 件も無い」と言わず、終わってから猶予を過ぎていれば言う', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      h.catchup.active = true;
      await h.thread.activate(BOARD, THREAD, boardKey);
      await vi.advanceTimersByTimeAsync(20_000);
      expect(h.thread.getStatus()).toMatchObject({ phase: 'syncing', message: '過去ログを取得中...' });
      h.catchup.set(false);
      expect(h.thread.getStatus().message).toContain('レスが1件もありませんでした');
    });

    it('clear() で全タイマーとリスナーが外れる', async () => {
      vi.useFakeTimers(LOGIC_FAKE_TIMERS);
      await h.thread.activate(BOARD, THREAD, boardKey);
      h.pm.addPeer(); // デバウンス
      expect(vi.getTimerCount()).toBeGreaterThan(0);
      h.thread.clear();
      expect(vi.getTimerCount()).toBe(0);
      expect(h.router.listeners.size).toBe(0);
      expect(h.pm.listenerCount('peer:connect')).toBe(0);
      expect(h.thread.getPosts()).toEqual([]);
    });
  });
});

describe('ThreadOrchestrator: 発信するパケットの tag / age', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  it('返信パケットはゾーン番号を載せない。tag はスレ立て日で決まるスレッドの tag', async () => {
    for (const depth of [0, 5, 12]) {
      const h = await make();
      const boardKey = sodium.randombytes_buf(32);
      await h.thread.activate(BOARD, THREAD, boardKey);
      await h.thread.submitReply(`depth ${depth}`);
      const packet = h.router.broadcast.mock.calls[0][0];
      expect(packet).not.toHaveProperty('zone_id');
      // 旧形式 (10 文字) の ID なので、birthDay = 投稿日・age 0
      expect(packet.age).toBe(0);
      expect(packet.tag).toBe(threadTag(KeyManager.deriveThreadKey(boardKey, THREAD), dayOf(packet.timestamp)));
      h.thread.clear();
    }
  });

  it('新形式 (スレ立て日入り) の ID の返信は、tag がスレ立て日で決まり、age は投稿日 - スレ立て日', async () => {
    const h = await make();
    const boardKey = sodium.randombytes_buf(32);
    const born = Date.now() - 3 * 24 * 3600_000;
    const tid = makeThreadId(born, 'abcdefghij');
    await h.thread.activate(BOARD, tid, boardKey);
    await h.thread.submitReply('3 日目');
    const packet = h.router.broadcast.mock.calls[0][0];
    expect(packet.age).toBe(3);
    expect(packet.tag).toBe(threadTag(KeyManager.deriveThreadKey(boardKey, tid), dayOf(born)));
    h.thread.clear();
  });
});


describe('ThreadOrchestrator: スレッドの上限と寿命', () => {
  let boardKey: Uint8Array;
  let threadKey: Uint8Array;
  let h: H;
  const MIN = 60_000;

  /** 暗号処理を通さず、DAG に 1000 レスの鎖を直接入れる (埋まったスレを作る) */
  function fill(count: number, startAt: number) {
    const dag = (h.thread as any).dag;
    const hex = (i: number) => i.toString(16).padStart(32, '0');
    for (let i = 0; i < count; i++) {
      dag.addPost({
        packet_id: hex(i + 1), content: 'x', post_number: 0, created_at: startAt + i * MIN,
        board_id: BOARD, thread_id: THREAD, parents: i === 0 ? [] : [hex(i)],
      });
    }
    (h.thread as any).notify();
  }

  beforeAll(async () => { await sodiumReady; });
  beforeEach(async () => {
    boardKey = sodium.randombytes_buf(32);
    threadKey = KeyManager.deriveThreadKey(boardKey, THREAD);
    h = await make();
  });
  afterEach(() => { h.thread.clear(); vi.restoreAllMocks(); });

  it('埋まったスレへの返信は ThreadClosedError で断り、PoW も送信もしない', async () => {
    await h.thread.activate(BOARD, THREAD, boardKey);
    fill(THREAD_LIMITS.MAX_POSTS, Date.now() - 2000 * MIN);
    expect(h.thread.getThreadState()).toMatchObject({ closed: true, closeReason: 'posts', visibleCount: THREAD_LIMITS.MAX_POSTS });

    const pow = vi.spyOn(syncPow, 'compute');
    await expect(h.thread.submitReply('もう書けない')).rejects.toBeInstanceOf(ThreadClosedError);
    await expect(h.thread.submitReply('もう書けない')).rejects.toMatchObject({ reason: 'closed' });
    expect(pow).not.toHaveBeenCalled();
    expect(h.router.broadcast).not.toHaveBeenCalled();
    expect(h.thread.getPosts()).toHaveLength(THREAD_LIMITS.MAX_POSTS);
  });

  it('容量を超える書き込みも、PoW の前に断る (full-bytes)', async () => {
    await h.thread.activate(BOARD, THREAD, boardKey);
    const dag = (h.thread as any).dag;
    dag.addPost({
      packet_id: 'big', content: 'a'.repeat(THREAD_LIMITS.MAX_CONTENT_BYTES - 100), post_number: 0, created_at: Date.now() - MIN,
      board_id: BOARD, thread_id: THREAD, parents: [],
    });
    (h.thread as any).notify();
    await expect(h.thread.submitReply('a'.repeat(101))).rejects.toMatchObject({ reason: 'full-bytes' });
    expect(h.router.broadcast).not.toHaveBeenCalled();
  });

  it('touchThread には、表示される投稿の最後の時刻だけを渡す (隠れる投稿では呼ばない)', async () => {
    await h.thread.activate(BOARD, THREAD, boardKey);
    const touch = vi.spyOn(h.db, 'touchThread');

    await h.thread.submitReply('自分');
    const own = h.thread.getPosts()[0];
    expect(touch).toHaveBeenCalledTimes(1);
    expect(touch).toHaveBeenLastCalledWith(BOARD, THREAD, own.created_at);

    // 埋める。以降の返信は上限を超えて隠れる
    fill(THREAD_LIMITS.MAX_POSTS, Date.now() - 3000 * MIN);
    touch.mockClear();
    const tail = h.thread.getPosts().at(-1)!;
    const hidden = await buildReplyPacket(threadKey, BOARD, THREAD, '隠れる', customSigner(), {
      parents: [tail.packet_id],
    });
    await h.router.deliver(hidden);
    expect(h.thread.getThreadState().hiddenCount).toBeGreaterThan(0);
    expect(h.thread.getPosts().map(p => p.content)).not.toContain('隠れる');
    expect(touch).not.toHaveBeenCalled();
    // 状態のスナップショットは変わらない限り同じ参照
    expect(h.thread.getThreadState()).toBe(h.thread.getThreadState());
  });

  it('寿命の起点は板のメタの birth_at (created_at ではない)', async () => {
    const birth = Date.now() - 5 * 24 * 60 * MIN;
    vi.spyOn(h.db, 'getThreads').mockResolvedValue([
      { threadId: OTHER_THREAD, birth_at: 1 },
      { threadId: THREAD, birth_at: birth, created_at: Date.now() },
    ] as any);
    await h.thread.activate(BOARD, THREAD, boardKey);
    expect(h.thread.getThreadState().birthAt).toBe(birth);
    expect(h.thread.getThreadState().expiresAt).toBe(birth + THREAD_LIMITS.IDLE_EXPIRY_MS);
  });

  it('ID にスレ立て日があれば、それが寿命の起点 (統計行の birth_at より優先。偽のスレ立てで動かせない)', async () => {
    const day = 24 * 60 * MIN;
    const idBirth = Math.floor((Date.now() - 3 * day) / day) * day;
    const tid = makeThreadId(idBirth, 'abcdefghij');
    vi.spyOn(h.db, 'getThreads').mockResolvedValue([{ threadId: tid, birth_at: Date.now() - 80 * day }] as any);
    await h.thread.activate(BOARD, tid, boardKey);
    expect(h.thread.getThreadState().birthAt).toBe(idBirth);
    expect(h.thread.getThreadState().expiresAt).toBe(idBirth + THREAD_LIMITS.IDLE_EXPIRY_MS);
  });

  it('落ちる時刻に再通知し、開いたままでも expired が切り替わる。clear でタイマーも消える', async () => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    try {
      const birth = Date.now() - 29 * 24 * 60 * MIN;
      vi.spyOn(h.db, 'getThreads').mockResolvedValue([{ threadId: THREAD, birth_at: birth }] as any);
      await h.thread.activate(BOARD, THREAD, boardKey);
      expect(h.thread.getThreadState().expired).toBe(false);
      const listener = vi.fn();
      h.thread.subscribe(listener);
      await vi.advanceTimersByTimeAsync(2 * 24 * 60 * MIN);
      expect(listener).toHaveBeenCalled();
      expect(h.thread.getThreadState().expired).toBe(true);
      await expect(h.thread.submitReply('落ちた')).rejects.toMatchObject({ reason: 'expired' });
    } finally {
      h.thread.clear();
      expect(vi.getTimerCount()).toBe(0);
      vi.useRealTimers();
    }
  });

  it('resolveAnchor は DAG に委ねる', async () => {
    await h.thread.activate(BOARD, THREAD, boardKey);
    await h.thread.submitReply('1');
    await h.thread.submitReply('2');
    const [a, b] = h.thread.getPosts();
    expect(h.thread.resolveAnchor(b.packet_id, 1)).toBe(a.packet_id);
    expect(h.thread.resolveAnchor('nope', 1)).toBeNull();
  });
});
