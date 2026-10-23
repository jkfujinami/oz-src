import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import type { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { sodiumReady } from '../../src/crypto/sodium';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import {
  GuardManager,
  FALLBACK_GRACE_MS,
  MIN_OPEN_CANDIDATES,
  OPEN_SELECTION_DELAY_MS,
  type GuardStatus,
} from '../../src/trust/GuardManager';
import { FAST, NOW, MemoryStore, makeList, makeMaintainer, mineIdentities, type Maintainer } from '../helpers/guardFixtures';

/**
 * Guard 選択の方針 (GuardManager + DandelionRouter)。
 * 時計は注入して進める (実時間は待たない)。
 */
describe('Guard 選択: 信頼リストの優先・起動直後の選択待ち', () => {
  let m: Maintainer;
  let trusted: NodeIdentity[];
  let strangers: NodeIdentity[];

  beforeAll(async () => {
    await sodiumReady;
    m = await makeMaintainer();
    trusted = await mineIdentities(4);
    strangers = await mineIdentities(6);
  });

  const hop = (i: NodeIdentity) => ({ peerId: i.peerId, pubkey: i.exportSecret().pubkey });

  let clock: { t: number };
  let peers: Map<string, any>;
  let hops: Array<{ peerId: string; pubkey: Uint8Array }>;
  let changes: Array<string | null>;

  function connect(i: NodeIdentity, direction: 'inbound' | 'outbound' = 'inbound') {
    peers.set(i.peerId, { peerId: i.peerId, isConnected: true, isVerified: true, direction, verifiedAt: clock.t });
    hops.push(hop(i));
  }
  function disconnect(i: NodeIdentity) {
    peers.delete(i.peerId);
    hops = hops.filter(h => h.peerId !== i.peerId);
  }

  beforeEach(() => {
    clock = { t: NOW };
    peers = new Map();
    hops = [];
    changes = [];
  });

  async function setup(withList: boolean, over: Partial<ConstructorParameters<typeof GuardManager>[0]> = {}) {
    const gm = new GuardManager({
      keyset: withList ? m.keyset : undefined,
      guardList: withList ? makeList(m, trusted) : undefined,
      store: new MemoryStore(),
      powParams: FAST,
      now: () => clock.t,
      randomIndex: () => 0,
      ...over,
    });
    await gm.init();
    const pm: any = { peers, myPeerId: 'f'.repeat(32), myPosition: 0, degree: 0, sendMessage: vi.fn(), on: vi.fn(), off: vi.fn() };
    const router = new DandelionRouter(pm, gm);
    router.onGuardChange(g => changes.push(g));
    const pick = () => router.getPinnedGuard(hops);
    const statuses: GuardStatus[] = [];
    gm.onStatus(s => statuses.push(s));
    return { gm, router, pick, statuses };
  }

  describe('リストがあるとき', () => {
    it('先に接続した信頼できない隣人は、唯一の候補でも選ばない (猶予の間は送信を止める)', async () => {
      const { pick, router, gm } = await setup(true);
      connect(strangers[0], 'outbound');

      for (let i = 0; i < 5; i++) {
        expect(pick()).toBeNull();
        clock.t += 5_000;
      }
      expect(clock.t - NOW).toBeLessThan(FALLBACK_GRACE_MS);
      expect(router.getPinnedGuardId()).toBeNull();
      expect(changes).toEqual([]);
      expect(gm.status).toMatchObject({ mode: 'none', guardId: null, reason: 'waiting-for-trusted-guard' });
    });

    it('猶予の間に信頼 Guard がつながれば、それを選ぶ', async () => {
      const { pick, gm, router } = await setup(true);
      connect(strangers[0]);
      expect(pick()).toBeNull();
      clock.t += 10_000;
      connect(trusted[2]);
      expect(pick()?.peerId).toBe(trusted[2].peerId);
      expect(router.getPinnedGuardId()).toBe(trusted[2].peerId);
      expect(gm.status).toMatchObject({ mode: 'trusted', guardId: trusted[2].peerId });
      expect(changes).toEqual([trusted[2].peerId]);
    });

    it('猶予を過ぎても信頼 Guard がいなければ fallback: 4 人以上の普通の隣人から選ぶ', async () => {
      const { pick, gm } = await setup(true);
      connect(strangers[0]);
      expect(pick()).toBeNull();

      clock.t += FALLBACK_GRACE_MS + 1;
      // 猶予を過ぎても、候補が 1 人だけなら選ばない (最初の 1 人が Guard になる穴を塞ぐ)
      expect(pick()).toBeNull();
      expect(gm.status.mode).toBe('none');
      expect(gm.status.reason).toBe('waiting-for-candidates');

      for (const s of strangers.slice(1, MIN_OPEN_CANDIDATES)) connect(s);
      const g = pick();
      expect(g).not.toBeNull();
      expect(strangers.slice(0, MIN_OPEN_CANDIDATES).map(s => s.peerId)).toContain(g!.peerId);
      expect(gm.status).toMatchObject({ mode: 'fallback', guardId: g!.peerId, reason: 'no-trusted-guard-connected' });
    });

    it('fallback で固定した後に信頼 Guard がつながったら、すぐ乗り換えて onGuardChange が発火する', async () => {
      const { pick, gm, router } = await setup(true);
      for (const s of strangers.slice(0, 4)) connect(s);
      pick();
      clock.t += FALLBACK_GRACE_MS + 1;
      const fb = pick()!;
      expect(gm.status.mode).toBe('fallback');
      expect(changes).toEqual([fb.peerId]);

      connect(trusted[1]);
      const g = pick()!;
      expect(g.peerId).toBe(trusted[1].peerId);
      expect(router.getPinnedGuardId()).toBe(trusted[1].peerId);
      expect(gm.status).toMatchObject({ mode: 'trusted', guardId: trusted[1].peerId });
      expect(changes).toEqual([fb.peerId, trusted[1].peerId]);
    });

    it('固定中のサンプルの Guard は、優先順が上の Guard やサンプル外の Guard が現れても替えない', async () => {
      const { pick, gm } = await setup(true);
      const order = gm.wantedGuardIds();
      const byId = new Map(trusted.map(t => [t.peerId, t]));
      connect(byId.get(order[2])!);
      expect(pick()?.peerId).toBe(order[2]);
      connect(byId.get(order[0])!); // 優先順では先
      connect(trusted.find(t => !order.includes(t.peerId))!); // サンプル外
      for (let i = 0; i < 5; i++) expect(pick()?.peerId).toBe(order[2]);
      expect(changes).toEqual([order[2]]);
      expect(gm.status.mode).toBe('trusted');
    });

    it('最初に選ぶときは、サンプルの順 (優先順) に従う', async () => {
      const { pick, gm } = await setup(true);
      const order = gm.wantedGuardIds();
      expect(order.length).toBe(3);
      // 優先順の 3 番目と、サンプル外の Guard だけがつながっている
      const byId = new Map(trusted.map(t => [t.peerId, t]));
      const outside = trusted.find(t => !order.includes(t.peerId))!;
      connect(outside);
      connect(byId.get(order[2])!);
      expect(pick()?.peerId).toBe(order[2]);
    });

    it('固定中の信頼 Guard が切れたら固定を外し、別の信頼 Guard を選ぶ', async () => {
      const { pick, router } = await setup(true);
      connect(trusted[0]);
      connect(trusted[1]);
      const first = pick()!;
      const firstId = trusted.find(t => t.peerId === first.peerId)!;
      disconnect(firstId);
      const second = pick()!;
      expect(second.peerId).not.toBe(first.peerId);
      expect(router.getPinnedGuardId()).toBe(second.peerId);
      expect(changes).toEqual([first.peerId, second.peerId]);
    });

    it('信頼 Guard が全部切れたら、切れてから猶予 (30 秒) の間は待ち、それを過ぎてから普通の隣人で fallback する', async () => {
      const { pick, gm } = await setup(true);
      connect(trusted[0]);
      pick();
      for (const s of strangers.slice(0, 4)) connect(s);
      // 起動から十分経っていても、信頼 Guard を失った直後は即座に乗り換えない
      // (接続を一度切らせるだけで、攻撃者かもしれない隣人を Guard にさせられないように)
      clock.t += 5 * 60_000;
      pick();
      disconnect(trusted[0]);
      expect(pick()).toBeNull();
      expect(gm.status.reason).toBe('waiting-for-trusted-guard');
      clock.t += FALLBACK_GRACE_MS - 1;
      expect(pick()).toBeNull();

      clock.t += 2;
      const g = pick();
      expect(g).not.toBeNull();
      expect(strangers.map(s => s.peerId)).toContain(g!.peerId);
      expect(gm.status.mode).toBe('fallback');
    });

    it('サンプル外の信頼 Guard しかいないときは、猶予の間サンプルの Guard を待ち、過ぎたら使う', async () => {
      const { pick, gm } = await setup(true);
      const order = gm.wantedGuardIds();
      const outside = trusted.find(t => !order.includes(t.peerId))!;
      connect(outside);
      expect(pick()).toBeNull();
      expect(gm.status.reason).toBe('waiting-for-trusted-guard');

      clock.t += FALLBACK_GRACE_MS;
      expect(pick()?.peerId).toBe(outside.peerId);
      expect(gm.status.mode).toBe('trusted');
    });

    it('サンプル外の信頼 Guard を使っている間にサンプルの Guard がつながったら、サンプルへ乗り換える', async () => {
      const { pick, gm } = await setup(true);
      const order = gm.wantedGuardIds();
      const byId = new Map(trusted.map(t => [t.peerId, t]));
      const outside = trusted.find(t => !order.includes(t.peerId))!;
      connect(outside);
      expect(pick()).toBeNull(); // 猶予の間はサンプルの Guard を待つ
      clock.t += FALLBACK_GRACE_MS;
      expect(pick()?.peerId).toBe(outside.peerId);

      connect(byId.get(order[1])!);
      expect(pick()?.peerId).toBe(order[1]);
      expect(changes).toEqual([outside.peerId, order[1]]);
    });

    it('普通の隣人で fallback 中にサンプル外の信頼 Guard が現れたら、猶予を待たずに乗り換える', async () => {
      const { pick, gm } = await setup(true);
      const order = gm.wantedGuardIds();
      for (const s of strangers.slice(0, 4)) connect(s);
      expect(pick()).toBeNull(); // 起動 (最初の select) と最初の隣人の時刻を記録させる
      clock.t += FALLBACK_GRACE_MS + OPEN_SELECTION_DELAY_MS;
      const fb = pick();
      expect(fb).not.toBeNull();
      expect(gm.status.mode).toBe('fallback');

      const outside = trusted.find(t => !order.includes(t.peerId))!;
      connect(outside);
      expect(pick()?.peerId).toBe(outside.peerId);
      expect(gm.status.mode).toBe('trusted');
      expect(changes).toEqual([fb!.peerId, outside.peerId]);
    });

    it('失効された Guard は、fallback の候補にも数えない', async () => {
      const { pick, gm } = await setup(true);
      const res = await gm.importList(makeList(m, trusted, { version: 2, revoked: [trusted[0]] }));
      expect(res.ok).toBe(true);
      // 失効した Guard + 普通の隣人 3 人。失効した Guard を数えれば 4 人で選べてしまう
      connect(trusted[0], 'outbound');
      for (const s of strangers.slice(0, MIN_OPEN_CANDIDATES - 1)) connect(s);
      expect(pick()).toBeNull(); // 起動と最初の隣人の時刻を記録させる (足りないのは人数だけにする)
      clock.t += FALLBACK_GRACE_MS + OPEN_SELECTION_DELAY_MS;
      expect(pick()).toBeNull();
      expect(gm.status.reason).toBe('waiting-for-candidates');
    });

    it('peerId が信頼 Guard でも、公開鍵が違う (なりすまし) 隣人は信頼 Guard として扱わない', async () => {
      const { pick, gm } = await setup(true);
      peers.set(trusted[0].peerId, { peerId: trusted[0].peerId, isConnected: true, isVerified: true, direction: 'outbound', verifiedAt: clock.t });
      hops.push({ peerId: trusted[0].peerId, pubkey: strangers[0].exportSecret().pubkey });
      expect(pick()).toBeNull();
      expect(gm.status.mode).toBe('none');
    });

    it('リストで失効された Guard を固定していたら外す', async () => {
      const { pick, gm, router } = await setup(true);
      connect(trusted[0]);
      expect(pick()?.peerId).toBe(trusted[0].peerId);

      const res = await gm.importList(makeList(m, trusted, { version: 2, revoked: [trusted[0]] }));
      expect(res.ok).toBe(true);
      // 他に候補が無いので固定は外れ、送信は止まる (すでに猶予を過ぎていても候補が足りない)
      clock.t += FALLBACK_GRACE_MS + 1;
      expect(pick()).toBeNull();
      expect(router.getPinnedGuardId()).toBeNull();
    });

    it('リストが失効したら普通の隣人の規則 (open) に戻り、理由に失効が出る', async () => {
      const gm0 = await setup(true, { guardList: makeList(m, trusted, { validityMs: 60_000 }) });
      connect(trusted[0]);
      expect(gm0.pick()?.peerId).toBe(trusted[0].peerId);
      for (const s of strangers.slice(0, 4)) connect(s);
      clock.t += 2 * 60_000;
      const g = gm0.pick();
      expect(g).not.toBeNull(); // 固定していた Guard は引き続き使える (つながっている限り替えない)
      expect(gm0.gm.status.mode).toBe('open');
      expect(gm0.gm.status.reason).toBe('list-expired');
    });
  });

  describe('リストが無いとき (open)', () => {
    it('検証済みの隣人が 4 人揃い、かつ最初の隣人から 20 秒経つまで選ばない', async () => {
      const { pick, gm } = await setup(false);
      expect(MIN_OPEN_CANDIDATES).toBe(4);
      expect(OPEN_SELECTION_DELAY_MS).toBe(20_000);

      connect(strangers[0], 'outbound');
      expect(pick()).toBeNull();

      // 時間だけ経っても、人数が足りなければ選ばない
      clock.t += 60_000;
      expect(pick()).toBeNull();

      connect(strangers[1]);
      connect(strangers[2]);
      expect(pick()).toBeNull();
      connect(strangers[3]);
      const g = pick();
      expect(g).not.toBeNull();
      expect(gm.status).toMatchObject({ mode: 'open', reason: 'no-list' });
    });

    it('人数が揃っても、最初の隣人から 20 秒が経つまでは選ばない', async () => {
      const { pick, gm } = await setup(false);
      connect(strangers[0]);
      expect(pick()).toBeNull(); // ここが「最初の検証済み隣人が現れた」時刻
      clock.t += 1_000;
      for (const s of strangers.slice(1, 5)) connect(s);
      expect(pick()).toBeNull();
      clock.t += OPEN_SELECTION_DELAY_MS - 2_000;
      expect(pick()).toBeNull();
      expect(gm.status).toMatchObject({ mode: 'none', reason: 'waiting-for-candidates' });
      clock.t += 1_001;
      expect(pick()).not.toBeNull();
    });

    it('選んだ後は、つながっている限り替えない (隣人が増えても)', async () => {
      const { pick } = await setup(false);
      for (const s of strangers.slice(0, 4)) connect(s);
      pick();
      clock.t += OPEN_SELECTION_DELAY_MS + 1;
      const first = pick()!;
      for (const s of strangers.slice(4)) connect(s);
      for (let i = 0; i < 10; i++) expect(pick()!.peerId).toBe(first.peerId);
      expect(changes).toEqual([first.peerId]);
    });

    it('open で固定した後に、リストを取り込んで信頼 Guard がつながれば乗り換える', async () => {
      const { pick, gm } = await setup(false, { keyset: m.keyset });
      for (const s of strangers.slice(0, 4)) connect(s);
      pick();
      clock.t += OPEN_SELECTION_DELAY_MS + 1;
      const first = pick()!;
      expect(gm.status.mode).toBe('open');

      expect((await gm.importList(makeList(m, trusted))).ok).toBe(true);
      expect(pick()!.peerId).toBe(first.peerId); // 信頼 Guard がつながるまでは据え置き
      expect(gm.status.mode).toBe('fallback');
      connect(trusted[0]);
      expect(pick()!.peerId).toBe(trusted[0].peerId);
      expect(changes).toEqual([first.peerId, trusted[0].peerId]);
    });
  });

  it('方針なしの DandelionRouter は従来どおり (最初の隣人を即座に固定する)', () => {
    const pm: any = { peers, myPeerId: 'f'.repeat(32), myPosition: 0, degree: 0, sendMessage: vi.fn(), on: vi.fn(), off: vi.fn() };
    const router = new DandelionRouter(pm);
    connect(strangers[0]);
    expect(router.getPinnedGuard(hops)?.peerId).toBe(strangers[0].peerId);
  });
});
