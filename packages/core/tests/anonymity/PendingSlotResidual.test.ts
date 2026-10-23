import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { PeerManager } from '../../src/network/PeerManager';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { RateLimiter, RATE_LIMITS } from '../../src/network/RateLimiter';
import { SignalingHub, HubSignalingClient } from '../helpers/fakes';
import { installFakeWebRTC, resetFakeWebRTC } from '../helpers/webrtc';
import { LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';
import { FAST } from '../helpers/guardFixtures';

/**
 * 握手待ち枠の「残る弱点」の測定 (対策後)。
 *
 * ForcedFallback.test.ts は、攻撃者が毎回別のトラッカー ID を使っても (出所の上限を回避しても)
 * 正直な利用者が入れることを見ている。ここでは、より強い攻撃者 = 多数のトラッカー ID
 * (それぞれ NodeId PoW を払い、トラッカーに認証される) が、1 秒に 1 通ずつ offer を送り続ける場合に、
 * 「正直な利用者の試行を追い出す」のに何個の ID と毎秒何通が要るかを測る。
 *
 * 仕組み: 追い出しが起きるのは一般枠 (Guard 役 64) が攻撃者の試行で満杯になったときだけ。
 * 同じ ID の再 offer は自分の古い試行を置き換えるだけなので、ID が 64 個以下なら枠は溢れず、
 * 追い出し (= 新着の受理) は定常で起きない。ID が 65 個以上あると、追い出された ID がすぐ再 offer して
 * 別の ID を追い出す循環になり、新着がメッセージ数と同じ速さで生まれる。最古優先なので正直な試行は
 * 最も新しく、追い出されるのは、その握手が終わる (繋がる) までの間に 64 件の新着が来たとき。
 * ICE が繋がった後は 5 秒保護される (PENDING_EVICT_CONNECTED_AFTER_MS) ので、狙えるのは
 * 「繋がるまで」の 1〜3 秒だけ。
 * これは「文書化された残存リスク」であり、assert で消すものではない: 数値を出力して、
 * ID が枠より少ない攻撃者には追い出しが起きないことと、ID が多いほど新着が増えることだけを確かめる。
 */

const POOL = 64; // PeerManager.MAX_PENDING_PEERS_GUARD
const PER_SOURCE = 2; // MAX_PENDING_PER_SOURCE
const CONNECT_TIMEOUT_S = 8; // PENDING_CONNECT_TIMEOUT_MS
const STEP_MS = 1000; // 各 ID は 1 秒に 1 通
const LOOSE = Object.fromEntries(Object.keys(RATE_LIMITS).map(k => [k, { ratePerSec: 1e6, burst: 1e6 }]));

let hub: SignalingHub;
let pm: PeerManager | null = null;
let ident: NodeIdentity;

beforeAll(async () => {
  await sodiumReady;
  installFakeWebRTC();
  ident = await NodeIdentity.mine(FAST);
});

beforeEach(() => {
  vi.useFakeTimers(LOGIC_FAKE_TIMERS);
  resetFakeWebRTC();
  hub = new SignalingHub();
});

afterEach(() => {
  pm?.stop();
  pm = null;
  vi.useRealTimers();
});

/** N 個の ID が、1 秒に 1 通ずつ offer を撃つ。定常で「新しく受理された試行」が毎秒いくつ生まれるかを返す */
async function arrivalsPerSec(identities: number, seconds = 30): Promise<{ perSec: number; sentPerSec: number }> {
  resetFakeWebRTC();
  hub = new SignalingHub();
  pm?.stop();
  const sig = new HubSignalingClient(hub, ident.peerId);
  pm = new PeerManager(ident, new MessageDispatcher(), sig, {
    powParams: FAST, rateLimiter: new RateLimiter(LOOSE), maxDegree: 256, keepTrackerAttached: true,
  });
  await pm.start();

  const hex = (n: number) => n.toString(16).padStart(8, '0').padEnd(32, 'b');
  let seq = 0;
  let arrivals = 0;
  const warmup = 12; // 枠が満たされ、最初の試行が寿命 (8 秒) を迎えるまで
  for (let t = 0; t < seconds * 1000; t += STEP_MS) {
    for (let i = 0; i < identities; i++) {
      const sender = hex(i + 1);
      const had = pm.peers.has(sender);
      hub.route(sender, ident.peerId, {
        type: 'sdp-relay',
        targetPeerId: ident.peerId,
        sdp: { type: 'offer', sdp: `v=0\r\no=- pc${800000 + ++seq} 2 IN IP4 203.0.113.1\r\ns=-\r\nt=0 0\r\n` },
      });
      if (!had && pm.peers.has(sender) && t >= warmup * 1000) arrivals++;
    }
    await vi.advanceTimersByTimeAsync(STEP_MS);
  }
  return { perSec: arrivals / (seconds - warmup), sentPerSec: identities };
}

describe('握手待ち枠: 多数のトラッカー ID を持つ攻撃者 (残存リスクの測定)', () => {
  it('ID が枠より少なければ追い出しは起きず、多ければ新着が増える。追い出すのに要る ID 数と毎秒の通数を出力する', async () => {
    const rows: string[] = [];
    const rate = new Map<number, number>();
    for (const n of [32, 62, 128, 256]) {
      const r = await arrivalsPerSec(n);
      rate.set(n, r.perSec);
      rows.push(`  - ID ${String(n).padStart(3)} 個 (毎秒 ${r.sentPerSec} 通): 新着の受理 ${r.perSec.toFixed(1)} 件/秒`);
    }

    console.log(
      `[握手待ち枠の残存リスク] Guard 役の一般枠 ${POOL}, 出所上限 ${PER_SOURCE}, 繋がらない試行の寿命 ${CONNECT_TIMEOUT_S}s\n` +
      rows.join('\n') + '\n' +
      [1, 2, 3].map(w =>
        `  - 正直な握手が ${w}s かかる場合: 追い出すのに要るのは ${POOL + 1} 個以上のトラッカー ID (各々が NodeId PoW を払う) と 毎秒 約 ${Math.ceil(POOL / w)} 通 (枠 ${POOL} 件が ${w}s の間に入れ替わる量)`,
      ).join('\n'),
    );

    // ID が枠より少ない攻撃者は、新着の受理を (定常で) 作れない = 正直な試行を追い出せない
    expect(rate.get(32)).toBe(0);
    expect(rate.get(62)).toBe(0);
    // 枠を超える ID を持てば追い出しの循環が起き、ID が多いほど速い (これが残存リスク)
    expect(rate.get(128)!).toBeGreaterThan(0);
    expect(rate.get(256)!).toBeGreaterThan(rate.get(128)!);
  }, 120_000);
});
