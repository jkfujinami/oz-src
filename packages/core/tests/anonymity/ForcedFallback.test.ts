import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';
import { DandelionRouter } from '../../src/network/gossip/DandelionRouter';
import { GuardManager, FALLBACK_GRACE_MS } from '../../src/trust/GuardManager';
import type { WebRTCPeer } from '../../src/network/WebRTCPeer';
import type { ISignalingClient } from '../../src/types';
import { SignalingHub, HubSignalingClient } from '../helpers/fakes';
import { installFakeWebRTC, resetFakeWebRTC } from '../helpers/webrtc';
import { flush, LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';
import { FAST, makeList, makeMaintainer, mineIdentities, type Maintainer } from '../helpers/guardFixtures';

/**
 * 強制フォールバック攻撃: 攻撃者は、利用者が信頼 Guard につながるのを邪魔できるか。
 *
 * 旧 PeerManager は握手が済んでいない接続を node 全体で同時に 8 本までしか持たず、満杯なら新着を拒否し、
 * つながらない試行は 15 秒で捨てていた。攻撃者は ICE を完了させないまま、でたらめな送り手 ID の offer を
 * 15 秒ごとに 8 通送るだけで、Guard の「握手待ち枠」を常に埋めておけた。
 * 正直な利用者の offer は枠が無いので黙って捨てられ、30 秒の猶予のあと Guard の方針は
 * 普通の隣人 (Sybil かもしれない) へ落ちた。
 *
 * 対策 (PeerManager.admitPending): 出所ごとの上限、Guard 役は枠 64、満杯なら進捗のない最古の inbound を
 * 追い出す、繋がらない試行は 8 秒で捨てる。このテストの攻撃者は「出所の上限」を回避するため、
 * 毎回別のトラッカー ID (= 無限に ID を持つ最強の想定) を使う。それでも追い出しで守れることを見る。
 *
 * 本番の PeerManager / WebRTCPeer / GuardManager / DandelionRouter を使い、WebRTC と
 * トラッカーだけを偽物にしている。攻撃者の offer は「相手の RTCPeerConnection が存在しない」
 * SDP なので、偽 WebRTC では ICE が永久に完了しない (= 攻撃者は握手を終えない)。
 * 時間は偽タイマーで進める (実時間は待たない)。決定的に動き、乱数は使わない。
 */

const MAX_PENDING = 64; // PeerManager.MAX_PENDING_PEERS_GUARD (非公開定数) と同じ値。変わったら pending のピーク測定が落ちる
/** 攻撃者の送信周期。つながらない試行の寿命 (PENDING_CONNECT_TIMEOUT_MS = 8 秒) より 0.1 秒だけ長くする = 枠が空くのは周期あたり 0.1 秒 */
const ATTACK_PERIOD_MS = 8_100;
const STEP_MS = 100;
const LOOSE = Object.fromEntries(Object.keys(RATE_LIMITS).map(k => [k, { ratePerSec: 1e6, burst: 1e6 }]));

/** isConnected を持つ偽トラッカー (本物の SignalingClient と同じく、接続中だけ true) */
class TrackerLikeSignaling extends HubSignalingClient implements ISignalingClient {
  public isConnected = false;
  override async connect(options: any): Promise<void> {
    await super.connect(options);
    this.isConnected = true;
  }
  override disconnect(): void {
    this.isConnected = false;
  }
}

let m: Maintainer;
let ids: NodeIdentity[]; // [guard, client, s1..s4, offline1, offline2]
let hub: SignalingHub;
let pms: PeerManager[] = [];
let fakeSeq = 0;

function makeNode(identity: NodeIdentity, opts: ConstructorParameters<typeof PeerManager>[3] = {}) {
  const sig = new TrackerLikeSignaling(hub, identity.peerId);
  const pm = new PeerManager(identity, new MessageDispatcher(), sig, {
    powParams: FAST,
    rateLimiter: new RateLimiter(LOOSE),
    ...opts,
  });
  pms.push(pm);
  return pm;
}

/** ICE を完了させない offer (相手の RTCPeerConnection が無い SDP)。送り手 ID は毎回でたらめ */
function attackOffer(guardId: string) {
  const fakeSender = (++fakeSeq).toString(16).padStart(8, '0').padEnd(32, 'a');
  hub.route(fakeSender, guardId, {
    type: 'sdp-relay',
    targetPeerId: guardId,
    sdp: { type: 'offer', sdp: `v=0\r\no=- pc${900000 + fakeSeq} 2 IN IP4 203.0.113.1\r\ns=-\r\nt=0 0\r\n` },
  });
}

const pendingOf = (pm: PeerManager): number => (pm as any).pendingCount;

interface Scenario {
  guardPm: PeerManager;
  clientPm: PeerManager;
  router: DandelionRouter;
  gm: GuardManager;
  /** 攻撃が送った offer の総数 */
  offersSent: () => number;
  /** 仮想時間 ms だけ進める。攻撃は attackFrom 以降 attackMsgs 通/周期で続く */
  run: (ms: number) => Promise<void>;
  now: () => number;
  stats: {
    stepsFull: number;
    steps: number;
    peakPending: number;
    guardConnectedAt: number | null;
    modeAt: Array<{ t: number; mode: string; guardId: string | null }>;
  };
}

/**
 * 守る側 = Guard (G)。利用者 (C) は G を含む 3 件の信頼リストを持ち、G 以外の信頼 Guard は不在。
 * C のそばには普通の隣人 4 人 (正直) がいる (fallback の候補になる)。
 */
async function buildScenario(opts: { attackMsgs: number; attackFromMs: number; clientStartMs: number }): Promise<Scenario> {
  const [gId, cId, s1, s2, s3, s4, off1, off2] = ids;
  const guardPm = makeNode(gId, { maxDegree: 256, keepTrackerAttached: true });
  const strangers = [s1, s2, s3, s4].map(s => makeNode(s));
  const clientPm = makeNode(cId);

  const gm = new GuardManager({
    keyset: m.keyset,
    guardList: makeList(m, [gId, off1, off2], { now: Date.now() }),
    powParams: FAST,
    now: () => Date.now(),
  });
  await gm.init();
  clientPm.setGuardSource(gm);
  const router = new DandelionRouter(clientPm, gm);

  const t0 = Date.now();
  const stats: Scenario['stats'] = { stepsFull: 0, steps: 0, peakPending: 0, guardConnectedAt: null, modeAt: [] };
  let offers = 0;
  let nextAttack = opts.attackFromMs;
  let clientStarted = false;
  let lastModeKey = '';

  const sample = () => {
    const t = Date.now() - t0;
    const pend = pendingOf(guardPm);
    stats.steps++;
    if (t >= opts.attackFromMs + 1000) {
      // 攻撃が定常に入ってからの「握手待ち枠が満杯 = 新規の offer を受け付けられない」割合
      if (pend >= MAX_PENDING) stats.stepsFull++;
    }
    stats.peakPending = Math.max(stats.peakPending, pend);
    const gp = clientPm.peers.get(gId.peerId) as WebRTCPeer | undefined;
    if (stats.guardConnectedAt === null && gp?.isVerified) stats.guardConnectedAt = t;
    // 方針の状態 (OnionCircuit が送信のたびに引くのと同じ呼び方) を 1 秒ごとに見る
    if (clientStarted && t % 1000 === 0) {
      router.getPinnedGuard(clientPm.verifiedPeersWithKeys);
      const key = `${gm.status.mode}:${gm.status.guardId}`;
      if (key !== lastModeKey) {
        lastModeKey = key;
        stats.modeAt.push({ t, mode: gm.status.mode, guardId: gm.status.guardId });
      }
    }
  };

  await guardPm.start();
  for (const s of strangers) await s.start();

  const run = async (ms: number) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const t = Date.now() - t0;
      if (opts.attackMsgs > 0 && t >= nextAttack) {
        for (let i = 0; i < opts.attackMsgs; i++) { attackOffer(gId.peerId); offers++; }
        nextAttack += ATTACK_PERIOD_MS;
      }
      if (!clientStarted && t >= opts.clientStartMs) {
        clientStarted = true;
        await clientPm.start(); // 起動時に待ち受け Guard (G) へ outbound で接続しに行く
        for (const s of strangers) clientPm.connect(s.myPeerId, true);
      }
      await vi.advanceTimersByTimeAsync(STEP_MS);
      await flush(2);
      sample();
    }
  };

  return { guardPm, clientPm, router, gm, offersSent: () => offers, run, now: () => Date.now() - t0, stats };
}

describe('強制フォールバック: Guard の握手待ち枠を埋めて、利用者を信頼 Guard から遠ざけられるか', () => {
  beforeAll(async () => {
    await sodiumReady;
    installFakeWebRTC();
    m = await makeMaintainer();
    ids = await mineIdentities(8);
  });

  beforeEach(() => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    resetFakeWebRTC();
    hub = new SignalingHub();
    pms = [];
    fakeSeq = 0;
  });

  afterEach(() => {
    for (const pm of pms) pm.stop();
    vi.useRealTimers();
  });

  it('(対照) 攻撃が無ければ、利用者は数秒で信頼 Guard につながり、方針は trusted になる', async () => {
    const sc = await buildScenario({ attackMsgs: 0, attackFromMs: 0, clientStartMs: 0 });
    await sc.run(20_000);
    console.log(`[対照: 攻撃なし] Guard 接続 = ${sc.stats.guardConnectedAt} ms, 方針 = ${sc.gm.status.mode}`);
    expect(sc.stats.guardConnectedAt).not.toBeNull();
    expect(sc.stats.guardConnectedAt!).toBeLessThan(5_000);
    expect(sc.gm.status).toMatchObject({ mode: 'trusted', guardId: ids[0].peerId });
  });

  it('(対照) 握手待ち枠 8 のうち 7 本までを埋められても、利用者は Guard につながれる (枠の上限が効いている条件の確認)', async () => {
    const sc = await buildScenario({ attackMsgs: MAX_PENDING - 1, attackFromMs: 0, clientStartMs: 5_000 });
    await sc.run(25_000);
    console.log(`[対照: 攻撃 ${MAX_PENDING - 1} 通/周期] Guard 接続 = ${sc.stats.guardConnectedAt} ms, pending ピーク = ${sc.stats.peakPending}`);
    expect(sc.stats.guardConnectedAt).not.toBeNull();
    expect(sc.stats.peakPending).toBeGreaterThanOrEqual(MAX_PENDING - 1);
  });

  it('測定: 攻撃者は周期あたり 64 通 (約 8 通/秒) の offer で Guard の握手待ち枠を満杯にできる (満杯でも次のテストの通り、正直な利用者は入れる)', async () => {
    const DURATION = 600_000;
    const sc = await buildScenario({ attackMsgs: MAX_PENDING, attackFromMs: 0, clientStartMs: 20_000 });
    await sc.run(DURATION);

    const ratio = sc.stats.stepsFull / (sc.stats.steps - 10);
    const perSec = sc.offersSent() / (DURATION / 1000);
    const fb = sc.stats.modeAt.map(x => `${(x.t / 1000).toFixed(0)}s:${x.mode}`).join(' → ');
    console.log(
      `[強制フォールバック測定] 攻撃 ${MAX_PENDING} 通 / ${ATTACK_PERIOD_MS / 1000}s, 仮想 ${DURATION / 1000}s\n` +
      `  - 攻撃者の送信数 = ${sc.offersSent()} 通 (${perSec.toFixed(2)} 通/秒, 1 通あたり数百バイト)\n` +
      `  - Guard の握手待ち枠が満杯だった時間 = ${(ratio * 100).toFixed(1)}% (pending ピーク ${sc.stats.peakPending})\n` +
      `  - 利用者が Guard につながった時刻 = ${sc.stats.guardConnectedAt === null ? '一度もなし' : sc.stats.guardConnectedAt + ' ms'}\n` +
      `  - 利用者の Guard 方針の推移 = ${fb}`,
    );

    // 攻撃のコスト: 周期あたり 8 通だけ
    expect(sc.offersSent()).toBe(MAX_PENDING * Math.ceil(DURATION / ATTACK_PERIOD_MS));
    // 枠の上限が働いている (これを超えて RTCPeerConnection は増えない)
    expect(sc.stats.peakPending).toBe(MAX_PENDING);
    // 猶予 (30 秒) の間は、普通の隣人を Guard にしない (fail-closed)。利用者の起動は 20 秒時点。
    // fallback に落ちた場合 (現状はそうなる) は、起動から猶予以上あとであること
    const fallback = sc.stats.modeAt.find(x => x.mode === 'fallback');
    if (fallback) expect(fallback.t - 20_000).toBeGreaterThanOrEqual(FALLBACK_GRACE_MS);
  }, 120_000);

  // ★ 既知の脆弱性 (修正済み): 握手待ち枠の占有による強制フォールバック。
  //   以前は枠が満杯の間に届いた offer が黙って捨てられ、攻撃が続く限り利用者はつながれなかった。
  //   PeerManager.admitPending が、満杯なら「進捗のない最古の inbound」を追い出して正直な offer を入れ、
  //   Guard 役の枠を 64 に広げ、繋がらない試行を 8 秒で捨てるようにした (出所ごとの上限は別の経路で効く)。
  // 性質: 攻撃が続いていても、正直な利用者は信頼 Guard につながれ、方針は trusted になる。
  it('攻撃が 10 分続いても、正直な利用者は信頼 Guard につながれ、方針は trusted になる', async () => {
    const sc = await buildScenario({ attackMsgs: MAX_PENDING, attackFromMs: 0, clientStartMs: 20_000 });
    await sc.run(600_000);
    expect(sc.stats.guardConnectedAt).not.toBeNull();
    expect(sc.gm.status.mode).toBe('trusted');
  }, 120_000);

  it('枠の 3 倍の offer を周期ごとに撃ち込まれて常に満杯でも、利用者は信頼 Guard につながり trusted になる', async () => {
    const sc = await buildScenario({ attackMsgs: MAX_PENDING * 3, attackFromMs: 0, clientStartMs: 20_000 });
    await sc.run(120_000);
    expect(sc.stats.guardConnectedAt).not.toBeNull();
    expect(sc.gm.status.mode).toBe('trusted');
  }, 120_000);
});
