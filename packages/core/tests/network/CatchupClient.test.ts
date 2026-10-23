import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { CATCHUP_STATUS } from '../../src/network/wire/WireCodec';
import { GossipRouter } from '../../src/network/gossip/GossipRouter';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import { RecentBuffer, CATCHUP_MAX_PAST_MS } from '../../src/network/history/RecentBuffer';
import { CatchupClient, CATCHUP_LAST_SEEN_KEY, CATCHUP_OVERLAP_MS } from '../../src/network/history/CatchupClient';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { msToMinutes } from '../../src/crypto/PowPolicy';
import { makePacket } from '../helpers/onionNet';
import { FakePeerManager } from '../helpers/logicHarness';
import type { GossipPacket } from '../../src/types';

const MIN = 60_000;
const H = 3600_000;
const G = 'a'.repeat(32);
const G2 = 'b'.repeat(32);
const OTHER = 'c'.repeat(32);
const PUB = new Uint8Array(32).fill(1);

class MemStore {
  public data = new Map<string, unknown>();
  get = async (k: string) => this.data.get(k);
  set = async (k: string, v: unknown) => { this.data.set(k, v); };
}

const t0 = Date.UTC(2026, 9, 14, 12, 0, 0);
const minute = (ms: number) => msToMinutes(ms);

interface Rig {
  pm: FakePeerManager;
  dispatcher: MessageDispatcher;
  dandelion: DandelionRouter;
  router: GossipRouter;
  buffer: RecentBuffer;
  client: CatchupClient;
  store: MemStore;
  delivered: GossipPacket[];
  circuit: any;
  reqs: () => number[];
  data: (from: string, packets: GossipPacket[]) => void;
  end: (from: string, status: number, nextSince: number) => void;
  verify: (id: string) => void;
}

async function rig(store = new MemStore(), { init = true } = {}): Promise<Rig> {
  const pm = new FakePeerManager();
  const dispatcher = new MessageDispatcher();
  const dandelion = new DandelionRouter(pm as any);
  const circuit: any = { onExit: vi.fn(), send: vi.fn().mockResolvedValue(true) };
  const buffer = new RecentBuffer({ windowMs: H, maxBytes: 1 << 24, now: Date.now });
  const router = new GossipRouter(pm as any, dispatcher, dandelion, circuit, buffer);
  const delivered: GossipPacket[] = [];
  router.onMessage(p => delivered.push(p));
  const client = new CatchupClient(pm as any, dispatcher, dandelion, router, store);
  if (init) await client.init();
  return {
    pm, dispatcher, dandelion, router, buffer, client, store, delivered, circuit,
    reqs: () => pm.sendMessage.mock.calls.filter((c: any[]) => c[1] === WireType.CATCHUP_REQ).map((c: any[]) => c[2].since),
    data: (from, packets) => dispatcher.dispatch(from, WireType.CATCHUP_DATA, { packets: packets.map(encodePacket) }),
    end: (from, status, nextSince) => dispatcher.dispatch(from, WireType.CATCHUP_END, { status, nextSince }),
    verify: (id) => {
      const peer = pm.peers.get(id);
      peer.isVerified = true;
      pm.emit('peer:verified', peer);
    },
  };
}

/** 握手前の隣人として足し、その隣人を 1 ホップ目 (固定した Guard) にする */
function pinGuard(r: Rig, id: string, verified = false) {
  r.pm.peers.set(id, { peerId: id, isConnected: true, isVerified: verified, position: 0.1 });
  r.dandelion.getPinnedGuard([{ peerId: id, pubkey: PUB }]);
}

describe('CatchupClient', () => {
  let r: Rig;

  beforeAll(async () => { await sodiumReady; });
  beforeEach(() => { vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] }); vi.setSystemTime(t0); });
  afterEach(() => {
    r?.client.destroy();
    r?.router.destroy();
    vi.useRealTimers();
  });

  describe('いつ頼むか (peer:connect ではなく、握手 (HELLO / JOIN) が済んでから)', () => {
    it('★固定した Guard が検証済みになるまでは頼まない。検証済みになった瞬間に 1 回だけ頼む', async () => {
      r = await rig();
      pinGuard(r, G, false);
      r.pm.emit('peer:connect', r.pm.peers.get(G)); // 握手の前に出る
      expect(r.reqs()).toEqual([]);
      r.verify(G);
      expect(r.reqs()).toHaveLength(1);
      r.pm.emit('peer:verified', r.pm.peers.get(G)); // 重ねて出ても 1 本だけ
      expect(r.reqs()).toHaveLength(1);
      expect(r.client.active).toBe(true);
    });

    it('Guard が固定されていない間・Guard 以外の隣人が検証済みになっても頼まない', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      r.pm.emit('peer:verified', r.pm.peers.get(OTHER));
      expect(r.reqs()).toEqual([]);
      pinGuard(r, G, true); // 検証済みの Guard を固定した → すぐ頼む
      expect(r.reqs()).toHaveLength(1);
      r.pm.emit('peer:verified', r.pm.peers.get(OTHER));
      expect(r.reqs()).toHaveLength(1);
    });

    it('最後に見た投稿が無い端末 (初回) は since = 0 (Guard が持っている分を全部)', async () => {
      r = await rig();
      pinGuard(r, G, true);
      expect(r.reqs()).toEqual([0]);
    });

    it('★since = lastSeen − 5 分 (遅れて届いた分の取りこぼしを防ぐ重なり)', async () => {
      const store = new MemStore();
      const last = minute(t0 - 2 * H);
      store.data.set(CATCHUP_LAST_SEEN_KEY, last);
      r = await rig(store);
      pinGuard(r, G, true);
      expect(r.reqs()).toEqual([last - CATCHUP_OVERLAP_MS / MIN]);
      expect(CATCHUP_OVERLAP_MS).toBe(5 * MIN);
    });

    it('Guard が替わったらもう一度頼む。前の Guard への要求は捨てる', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.pm.peers.set(G2, { peerId: G2, isConnected: true, isVerified: true });
      r.dandelion.resetPinnedGuard();
      r.dandelion.getPinnedGuard([{ peerId: G2, pubkey: PUB }]);
      const sent = r.pm.sendMessage.mock.calls.filter((c: any[]) => c[1] === WireType.CATCHUP_REQ).map((c: any[]) => c[0]);
      expect(sent).toEqual([G, G2]);
      // 前の Guard からの DATA はもう受け取らない
      const p = makePacket([1], t0 - MIN);
      r.data(G, [p]);
      expect(r.delivered).toHaveLength(0);
      r.data(G2, [p]);
      expect(r.delivered).toHaveLength(1);
    });

    it('完了した Guard には、つなぎ直すまで頼み直さない。切れて、つなぎ直したら頼む', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.end(G, CATCHUP_STATUS.OK, minute(t0));
      expect(r.client.active).toBe(false);
      r.pm.emit('peer:verified', r.pm.peers.get(G));
      expect(r.reqs()).toHaveLength(1);

      r.pm.peers.delete(G);
      r.pm.emit('peer:disconnect', G);
      r.pm.peers.set(G, { peerId: G, isConnected: true, isVerified: false });
      r.verify(G);
      expect(r.reqs()).toHaveLength(2);
    });

    it('init が終わるまでは頼まない (保存済みの lastSeen を読む前に since = 0 で頼んで全部取り直さない)', async () => {
      r = await rig(new MemStore(), { init: false });
      pinGuard(r, G, true);
      expect(r.reqs()).toEqual([]);
      await r.client.init();
      expect(r.reqs()).toHaveLength(1);
    });
  });

  describe('届いた投稿の扱い', () => {
    it('★古い順に手元へ配り、flood しない (誰にも GOSSIP を送らず、回路にも載せない)', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      pinGuard(r, G, true);
      const ps = [3, 2, 1].map(i => makePacket([i], t0 - i * 10 * MIN)).reverse(); // 古い順
      r.data(G, ps);
      expect(r.delivered.map(p => p.packet_id)).toEqual(ps.map(p => p.packet_id));
      expect(r.pm.sendMessage.mock.calls.filter((c: any[]) => c[1] === WireType.GOSSIP)).toEqual([]);
      expect(r.circuit.send).not.toHaveBeenCalled();
      // 入れ物には入る (板を開いたときの流し込み・次の隣人への追いつき用)
      expect(r.buffer.size).toBe(3);
    });

    it('保管候補のフックに source = catchup で渡る (保管担当の保存用)', async () => {
      r = await rig();
      pinGuard(r, G, true);
      const seen: Array<[string, string]> = [];
      r.router.onStoredCandidate((p, src) => seen.push([p.packet_id, src]));
      const p = makePacket([1], t0 - MIN);
      r.data(G, [p]);
      expect(seen).toEqual([[p.packet_id, 'catchup']]);
    });

    it('★live と同じ検証: PoW の不正・中身の改竄 (packet_id が変わるので PoW が合わない)・壊れたバイト・72 時間 + 15 分より古い・未来の投稿は捨てる', async () => {
      r = await rig();
      pinGuard(r, G, true);
      const good = makePacket([1], t0 - 71 * H);
      const badPow = { ...makePacket([2], t0 - H), pow_nonce: 12345 };
      const tampered = encodePacket(makePacket([3], t0 - H));
      tampered[tampered.length - 1] ^= 0xff;
      const tooOld = makePacket([4], t0 - CATCHUP_MAX_PAST_MS - 2 * MIN);
      const future = makePacket([5], t0 + 16 * MIN);
      const justInside = makePacket([6], t0 - CATCHUP_MAX_PAST_MS + 2 * MIN);
      r.dispatcher.dispatch(G, WireType.CATCHUP_DATA, {
        packets: [encodePacket(good), encodePacket(badPow), tampered, encodePacket(tooOld), encodePacket(future),
          new Uint8Array([9, 9, 9]), encodePacket(justInside)],
      });
      expect(r.delivered.map(p => p.packet_id)).toEqual([good.packet_id, justInside.packet_id]);
    });

    it('live の検証 (15 分) は変わらない: 72 時間前の投稿は live の GOSSIP としては受け付けない', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: makePacket([1], t0 - 3 * H) });
      expect(r.delivered).toHaveLength(0);
    });

    it('既に持っている投稿 (live で受け取った分) は二重に配らない', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      pinGuard(r, G, true);
      const p = makePacket([1], t0 - 2 * MIN);
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: p });
      r.data(G, [p]);
      r.data(G, [p]);
      expect(r.delivered).toHaveLength(1);
    });

    it('頼んでいない相手・要求していないときの DATA / END は無視する', async () => {
      r = await rig();
      const p = makePacket([1], t0 - MIN);
      r.data(G, [p]); // まだ何も頼んでいない
      expect(r.delivered).toHaveLength(0);
      pinGuard(r, G, true);
      r.data(OTHER, [p]); // 頼んだのは G
      r.end(OTHER, CATCHUP_STATUS.OK, minute(t0));
      expect(r.delivered).toHaveLength(0);
      expect(r.client.active).toBe(true);
    });
  });

  describe('lastSeen (最後に見た投稿の時刻。分単位)', () => {
    it('追いつきで届いた投稿の時刻 (分単位) まで進む。丸めない', async () => {
      r = await rig();
      pinGuard(r, G, true);
      const p = makePacket([1], t0 - 37 * MIN);
      r.data(G, [p]);
      expect(r.client.lastSeen).toBe(minute(p.timestamp));
      expect(r.client.lastSeen).toBe(minute(t0 - 37 * MIN));
    });

    it('★END (OK) で nextSince まで進み、完了後の live の投稿でも進む', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      pinGuard(r, G, true);
      r.data(G, [makePacket([1], t0 - 30 * MIN)]);
      r.end(G, CATCHUP_STATUS.PARTIAL, minute(t0 - 5 * MIN));
      expect(r.client.lastSeen).toBe(minute(t0 - 5 * MIN));
      vi.setSystemTime(t0 + 10 * MIN);
      const live = makePacket([2], t0 + 10 * MIN);
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: live });
      expect(r.client.lastSeen).toBe(minute(live.timestamp));
    });

    it('★追いつきが済んでいない間の live の投稿では進めない (その間の取り逃しを永久に失わないため)', async () => {
      const store = new MemStore();
      const last = minute(t0 - 2 * H);
      store.data.set(CATCHUP_LAST_SEEN_KEY, last);
      r = await rig(store);
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });

      // Guard にまだつながっていない。先に一般の隣人から live の投稿が届く
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: makePacket([1], t0) });
      expect(r.delivered).toHaveLength(1);
      expect(r.client.lastSeen).toBe(last);

      // Guard につながって追いつきが始まる。その最中の live の投稿でも進めない
      pinGuard(r, G, true);
      expect(r.reqs()).toEqual([last - 5]);
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: makePacket([2], t0) });
      expect(r.client.lastSeen).toBe(last);

      // 途中で切れたら、追いつきの進み具合 (古い順に届いた分) までしか進んでいない
      r.data(G, [makePacket([3], t0 - 100 * MIN)]);
      expect(r.client.lastSeen).toBe(minute(t0 - 100 * MIN));
      r.pm.peers.delete(G);
      r.pm.emit('peer:disconnect', G);
      expect(r.client.lastSeen).toBe(minute(t0 - 100 * MIN));
      expect(r.client.active).toBe(false);
    });

    it('追いつきの最中に届いた live の投稿は、完了 (END) の時点で反映する', async () => {
      r = await rig();
      r.pm.peers.set(OTHER, { peerId: OTHER, isConnected: true, isVerified: true });
      pinGuard(r, G, true);
      const live = makePacket([1], t0);
      r.dispatcher.dispatch(OTHER, WireType.GOSSIP, { packet: live });
      expect(r.client.lastSeen).toBeNull();
      r.end(G, CATCHUP_STATUS.OK, minute(t0 - 20 * MIN));
      expect(r.client.lastSeen).toBe(minute(live.timestamp));
    });

    it('自分の時計より先へは進めない (未来側のドリフト 15 分以内の投稿・偽の nextSince で飛ばされない)', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.data(G, [makePacket([1], t0 + 10 * MIN)]);
      expect(r.client.lastSeen).toBe(minute(t0));
      r.end(G, CATCHUP_STATUS.OK, minute(t0 + 5 * H));
      expect(r.client.lastSeen).toBe(minute(t0));
    });

    it('戻らない (古い投稿が後から届いても下がらない)', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.data(G, [makePacket([1], t0 - 10 * MIN)]);
      r.data(G, [makePacket([2], t0 - 50 * MIN)]);
      expect(r.client.lastSeen).toBe(minute(t0 - 10 * MIN));
    });

    it('★暗号化 DB (kv) に保存され、再起動しても残る。保存は間引く (投稿ごとには書かない)', async () => {
      const store = new MemStore();
      const setSpy = vi.spyOn(store, 'set');
      r = await rig(store);
      pinGuard(r, G, true);
      for (let i = 1; i <= 5; i++) r.data(G, [makePacket([i], t0 - (50 - i) * MIN)]);
      expect(setSpy).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(11_000);
      expect(setSpy).toHaveBeenCalledTimes(1);
      const saved = store.data.get(CATCHUP_LAST_SEEN_KEY);
      expect(saved).toBe(minute(t0 - 45 * MIN));

      // 再起動 (新しいクライアント・同じ保存先)
      r.client.destroy();
      r.router.destroy();
      const again = await rig(store);
      r = again;
      expect(again.client.lastSeen).toBe(saved);
      pinGuard(again, G, true);
      expect(again.reqs()).toEqual([(saved as number) - 5]);
    });

    it('flush は保存待ちを今すぐ書く (停止の前に呼ぶ)。変化が無ければ書かない', async () => {
      const store = new MemStore();
      r = await rig(store);
      pinGuard(r, G, true);
      r.data(G, [makePacket([1], t0 - MIN)]);
      await r.client.flush();
      expect(store.data.get(CATCHUP_LAST_SEEN_KEY)).toBe(minute(t0 - MIN));
      const setSpy = vi.spyOn(store, 'set');
      await r.client.flush();
      expect(setSpy).not.toHaveBeenCalled();
    });

    it('壊れた保存値は無視する (全部取り直すだけ)', async () => {
      const store = new MemStore();
      store.data.set(CATCHUP_LAST_SEEN_KEY, 'garbage');
      r = await rig(store);
      expect(r.client.lastSeen).toBeNull();
    });
  });

  describe('BUSY・無反応・状態通知', () => {
    it('BUSY なら、間をあけてもう一度頼む。完了すれば止まる', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.end(G, CATCHUP_STATUS.BUSY, minute(t0));
      expect(r.client.active).toBe(false);
      expect(r.reqs()).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(16_000);
      expect(r.reqs()).toHaveLength(2);
      r.end(G, CATCHUP_STATUS.OK, minute(t0));
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      expect(r.reqs()).toHaveLength(2);
    });

    it('60 秒なにも届かなければこの回は諦め、あとで頼み直す', async () => {
      r = await rig();
      pinGuard(r, G, true);
      await vi.advanceTimersByTimeAsync(61_000);
      expect(r.client.active).toBe(false);
      await vi.advanceTimersByTimeAsync(16_000);
      expect(r.reqs()).toHaveLength(2);
    });

    it('受信中 (active) の変化を購読できる (オーケストレータが「過去ログを取得中」を出す)', async () => {
      r = await rig();
      const changes: boolean[] = [];
      const off = r.client.onChange(() => changes.push(r.client.active));
      pinGuard(r, G, true);
      r.end(G, CATCHUP_STATUS.OK, minute(t0));
      expect(changes).toEqual([true, false]);
      off();
    });

    it('destroy 後はタイマーが残らず、何も頼まない', async () => {
      r = await rig();
      pinGuard(r, G, true);
      r.client.destroy();
      expect(vi.getTimerCount()).toBe(0);
      r.end(G, CATCHUP_STATUS.BUSY, 0);
      expect(vi.getTimerCount()).toBe(0);
    });
  });
});
