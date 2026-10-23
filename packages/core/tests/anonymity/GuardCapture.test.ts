import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import type { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { DandelionRouter, guardWeight } from '../../src/network/gossip/DandelionRouter';
import {
  GuardManager,
  FALLBACK_GRACE_MS,
  OPEN_SELECTION_DELAY_MS,
  MIN_OPEN_CANDIDATES,
} from '../../src/trust/GuardManager';
import { FAST, NOW, makeList, makeMaintainer, mineIdentities, type Maintainer } from '../helpers/guardFixtures';

/**
 * Guard 捕捉率の測定: 監視ノード (Sybil) は、誰かの Guard (= その人の IP を見る 1 ホップ目) になれるか。
 *
 * 本番の DandelionRouter + GuardManager (方針) をそのまま動かし、候補の集合と接続の順序だけを模擬する。
 * 攻撃者の成功率はコードが実際に選んだ結果から数える (決め打ちしない)。
 *
 * ── トラッカーの模擬 ──
 *   Sybil は常駐し、正直なノードは登録から 15 秒しか残らない。そのため新参の最初の隣人に占める
 *   Sybil の割合 (share) は高い。Sybil は握手が速いので、正直なノードより先に検証済みになる。
 *
 * ── 乱数と偽陽性 ──
 *   接続のタイミングは固定シードの PRNG。Guard の重みづけ選択だけは本番が CSPRNG を直接使うので
 *   (注入できない)、試行回数 N=1500 で測り、期待値 (本番の guardWeight から計算) との差の許容を 0.08 にしている。
 *   N=1500 での標準偏差は最大 sqrt(.25/1500)=0.0129 なので、0.08 は 6.2σ。
 *   正規近似で片側 3e-10、両側でも 1e-9 未満 (< 1e-6) であり、テストが偶然落ちることはない。
 */

const N = 1500;
const TOL = 0.08;
const K_OUT = 10; // トラッカーが最初に渡す隣人の数 (自分から張る = outbound)
const SIM_END_MS = 120_000;
const STEP_MS = 1_000;

type Role = 'sybil' | 'honest' | 'trusted';
type Mode = 'old' | 'open' | 'trusted-reachable' | 'trusted-unreachable';

interface SimPeer {
  peerId: string;
  pubkey: Uint8Array;
  role: Role;
  direction: 'outbound' | 'inbound';
  verifyAtMs: number;
}

/** 固定シードの PRNG (接続順序の再現用) */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

let m: Maintainer;
let trustedIds: NodeIdentity[];
let listText: string;

const randHex = (rnd: () => number) =>
  Array.from({ length: 32 }, () => Math.floor(rnd() * 16).toString(16)).join('');

interface TrialResult {
  role: Role | null; // null = 期間内に Guard が決まらなかった
  at: number | null;
  /** 選んだ時点の候補に対する、本番の重みでの Sybil 選択確率 (期待値) */
  expectedSybil: number | null;
}

interface CellResult {
  sybilRate: number;
  none: number;
  expected: number;
  earliestMs: number;
  trusted: number;
  honest: number;
}

/**
 * 1 人の新参ノードの Guard 選択を最後まで走らせる。
 * @param firstCallAtMs 方針なし (旧実装) のときに最初に送信 (= getPinnedGuard) する時刻。
 *   方針ありでは OnionCircuit が送信のたびに 1 秒ごとに引き直す想定で、決まるまで繰り返す。
 */
async function runTrial(
  mode: Mode,
  share: number,
  seed: number,
  opts: { extraInboundSybils?: number; firstCallAtMs?: 'first-peer' | number } = {},
): Promise<TrialResult> {
  const rnd = mulberry32(seed);
  const peers: SimPeer[] = [];
  const nSybil = Math.round(share * K_OUT);

  for (let i = 0; i < nSybil; i++) {
    peers.push({
      peerId: randHex(rnd), pubkey: new Uint8Array(32).fill(1 + i), role: 'sybil', direction: 'outbound',
      verifyAtMs: 200 + rnd() * 1000, // Sybil は握手が最も速い
    });
  }
  for (let i = 0; i < K_OUT - nSybil; i++) {
    peers.push({
      peerId: randHex(rnd), pubkey: new Uint8Array(32).fill(100 + i), role: 'honest', direction: 'outbound',
      verifyAtMs: 1000 + rnd() * 5000,
    });
  }
  for (let i = 0; i < (opts.extraInboundSybils ?? 0); i++) {
    peers.push({
      peerId: randHex(rnd), pubkey: new Uint8Array(32).fill(200 + i), role: 'sybil', direction: 'inbound',
      verifyAtMs: 200 + rnd() * 1000,
    });
  }
  if (mode === 'trusted-reachable') {
    // 信頼 Guard が 1 台だけつながる。サンプルに入っているかは試行ごとに変わる。猶予 (30 秒) の内側で現れる
    const g = trustedIds[Math.floor(rnd() * trustedIds.length)];
    peers.push({
      peerId: g.peerId, pubkey: g.exportSecret().pubkey, role: 'trusted', direction: 'outbound',
      verifyAtMs: 2000 + rnd() * 23_000,
    });
  }

  const base = NOW;
  vi.setSystemTime(base);
  const clock = () => Date.now();

  const live = new Map<string, any>();
  let hops: Array<{ peerId: string; pubkey: Uint8Array }> = [];
  const pm: any = { peers: live, myPeerId: 'f'.repeat(32), myPosition: 0, degree: 0, sendMessage: vi.fn(), on: vi.fn(), off: vi.fn() };

  let policy: GuardManager | null = null;
  if (mode !== 'old') {
    const withList = mode !== 'open';
    policy = new GuardManager({
      keyset: withList ? m.keyset : undefined,
      guardList: withList ? listText : undefined,
      powParams: FAST,
      now: clock,
      randomIndex: n => Math.floor(rnd() * n),
    });
    await policy.init();
  }
  const router = new DandelionRouter(pm, policy);

  const arrive = (p: SimPeer) => {
    live.set(p.peerId, {
      peerId: p.peerId, isConnected: true, isVerified: true, direction: p.direction,
      verifiedAt: Date.now(), pubkey: p.pubkey,
    });
    hops.push({ peerId: p.peerId, pubkey: p.pubkey });
  };

  const byTime = [...peers].sort((a, b) => a.verifyAtMs - b.verifyAtMs);
  let next = 0;
  const firstPeerAt = byTime[0].verifyAtMs;
  const roleOf = new Map(peers.map(p => [p.peerId, p.role]));

  const pick = (): TrialResult | null => {
    const g = router.getPinnedGuard(hops);
    if (!g) return null;
    const now = Date.now();
    const w = hops.map(h => ({ role: roleOf.get(h.peerId)!, w: guardWeight(live, h.peerId, now) }));
    const total = w.reduce((a, x) => a + x.w, 0);
    const expectedSybil = w.filter(x => x.role === 'sybil').reduce((a, x) => a + x.w, 0) / total;
    return { role: roleOf.get(g.peerId)!, at: now - base, expectedSybil };
  };

  for (let t = 0; t <= SIM_END_MS; t += STEP_MS) {
    vi.setSystemTime(base + t);
    while (next < byTime.length && byTime[next].verifyAtMs <= t) arrive(byTime[next++]);
    if (hops.length === 0) continue;

    if (mode === 'old') {
      // 方針なしは「最初の getPinnedGuard」で即座に固定される。いつ最初に送るかで結果が変わる
      const when = opts.firstCallAtMs ?? 'first-peer';
      if (when === 'first-peer') {
        // 最初の隣人が現れた直後 (= 隣人が 1 人しかいない) に送る。ステップより細かく扱うため、その時点の候補だけにする
        const early = byTime.filter(p => p.verifyAtMs <= Math.max(t, firstPeerAt) && p.verifyAtMs <= firstPeerAt + 1e-9);
        hops = early.map(p => ({ peerId: p.peerId, pubkey: p.pubkey }));
        for (const p of early) live.set(p.peerId, { peerId: p.peerId, isConnected: true, isVerified: true, direction: p.direction, verifiedAt: base + p.verifyAtMs, pubkey: p.pubkey });
        const r = pick();
        if (r) return r;
      } else if (t >= when) {
        const r = pick();
        if (r) return r;
      }
      continue;
    }
    const r = pick();
    if (r) return r;
  }
  return { role: null, at: null, expectedSybil: null };
}

async function runCell(
  mode: Mode, share: number, opts: Parameters<typeof runTrial>[3] = {},
): Promise<CellResult> {
  let sybil = 0, none = 0, trusted = 0, honest = 0, expSum = 0, expN = 0, earliest = Infinity;
  for (let i = 0; i < N; i++) {
    const r = await runTrial(mode, share, 1000 + i, opts);
    if (r.role === null) { none++; continue; }
    if (r.role === 'sybil') sybil++;
    else if (r.role === 'trusted') trusted++;
    else honest++;
    expSum += r.expectedSybil!; expN++;
    earliest = Math.min(earliest, r.at!);
  }
  const decided = N - none;
  return {
    sybilRate: decided ? sybil / decided : 0,
    none, expected: expN ? expSum / expN : 0, earliestMs: earliest, trusted, honest,
  };
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`.padStart(6);

describe('Guard 捕捉率: 監視ノード (Sybil) は新参の Guard になれるか', () => {
  beforeAll(async () => {
    await sodiumReady;
    vi.useFakeTimers({ toFake: ['Date'] });
    m = await makeMaintainer();
    trustedIds = await mineIdentities(4);
    listText = makeList(m, trustedIds);
  });
  afterAll(() => vi.useRealTimers());

  const results = new Map<string, CellResult>();
  const key = (mode: string, share: number, extra = '') => `${mode}@${share}${extra}`;

  for (const share of [0.5, 0.9]) {
    describe(`最初に渡される隣人の Sybil 率 = ${pct(share).trim()} (outbound ${K_OUT} 人)`, () => {
      it('(i) 旧実装 (方針なし): 最初の隣人が現れた直後に送ると、Sybil が先に握手を終えるので Guard の座をほぼ確実に取る', async () => {
        const r = await runCell('old', share, { firstCallAtMs: 'first-peer' });
        results.set(key('old-first', share), r);
        // Sybil は握手が最速なので、最初の隣人が Sybil である確率はほぼ 1
        expect(r.none).toBe(0);
        expect(r.sybilRate).toBeGreaterThan(0.95);
      }, 120_000);

      it('(i) 旧実装 (方針なし): 全員そろってから送っても、Sybil 率にほぼ比例して Guard を取られる', async () => {
        const r = await runCell('old', share, { firstCallAtMs: 20_000 });
        results.set(key('old-all', share), r);
        expect(r.none).toBe(0);
        // 重みづけは接続の向きと経過時間にしか依存しない。Sybil は少し古いので期待値は share をわずかに上回る
        expect(Math.abs(r.sybilRate - r.expected)).toBeLessThan(TOL);
        expect(r.sybilRate).toBeGreaterThan(share - TOL);
      }, 120_000);

      it('(ii) リスト無し (open): 4 人 / 20 秒待ってから重みづけで選ぶ。待っても Sybil 率はほぼ変わらない', async () => {
        const r = await runCell('open', share);
        results.set(key('open', share), r);
        expect(r.none).toBe(0);
        // 本番の 4 人 / 20 秒の待ちより早くは決まらない
        expect(r.earliestMs).toBeGreaterThanOrEqual(OPEN_SELECTION_DELAY_MS);
        // 選択は guardWeight に比例する。期待値との一致だけを主張する
        expect(Math.abs(r.sybilRate - r.expected)).toBeLessThan(TOL);
      }, 120_000);

      it('(iii) 信頼リストがあり、信頼 Guard につながれる: Sybil が Guard になることは一度もない', async () => {
        const r = await runCell('trusted-reachable', share);
        results.set(key('trusted', share), r);
        // 厳密に 0。確率ではなく、信頼 Guard 以外を選ばないという規則の帰結
        expect(r.sybilRate).toBe(0);
        expect(r.honest).toBe(0);
        expect(r.none).toBe(0);
        expect(r.trusted).toBe(N);
      }, 120_000);

      it('(iv) 信頼リストがあるが信頼 Guard につながれない: 猶予 30 秒後に普通の隣人へ落ちる (捕捉率は open と同程度)', async () => {
        const r = await runCell('trusted-unreachable', share);
        results.set(key('fallback', share), r);
        expect(r.none).toBe(0);
        // 猶予の間は送信を止める
        expect(r.earliestMs).toBeGreaterThanOrEqual(FALLBACK_GRACE_MS);
        expect(Math.abs(r.sybilRate - r.expected)).toBeLessThan(TOL);
      }, 120_000);
    });
  }

  it('Sybil が outbound ではなく inbound を大量に送り込んでも、open の重みづけ (outbound ×3) で頭打ちになる', async () => {
    // 正直 5 人 (outbound) + Sybil 5 人 (outbound) + Sybil inbound 10 人
    const r = await runCell('open', 0.5, { extraInboundSybils: 10 });
    results.set(key('open', 0.5, '+10inbound'), r);
    // 数の上では Sybil は 15/20 = 75%。重み (outbound=3, inbound=1) を掛けると Sybil 5*3+10*1=25、正直 5*3=15 で 25/40 = 62.5%
    expect(r.none).toBe(0);
    expect(Math.abs(r.sybilRate - r.expected)).toBeLessThan(TOL);
    expect(r.expected).toBeLessThan(0.75);
  }, 120_000);

  it('信頼 Guard の peerId を名乗っても、公開鍵が違う Sybil は信頼 Guard として扱われない (Bound Identity)', async () => {
    const gm = new GuardManager({ keyset: m.keyset, guardList: listText, powParams: FAST, now: () => Date.now() });
    await gm.init();
    vi.setSystemTime(NOW);
    const fake = { peerId: trustedIds[0].peerId, pubkey: sodium.randombytes_buf(32) };
    const peers = new Map<string, any>([[fake.peerId, { isConnected: true, isVerified: true, direction: 'outbound', verifiedAt: NOW }]]);
    const router = new DandelionRouter({ peers } as any, gm);
    // 猶予の外まで進めても、唯一の候補は「信頼 Guard」にならない
    for (const t of [0, 10_000, FALLBACK_GRACE_MS + 1, FALLBACK_GRACE_MS + 60_000]) {
      vi.setSystemTime(NOW + t);
      const g = router.getPinnedGuard([fake]);
      expect(gm.status.mode).not.toBe('trusted');
      // 候補が 1 人 (< MIN_OPEN_CANDIDATES) なので fallback でも選ばれない
      expect(g).toBeNull();
    }
    expect(MIN_OPEN_CANDIDATES).toBeGreaterThan(1);
  });

  it('結果の一覧', () => {
    const rows = [
      ['(i)  旧実装・最初の隣人で固定', 'old-first'],
      ['(i)  旧実装・全員そろってから', 'old-all'],
      ['(ii) リスト無し (open)', 'open'],
      ['(iii)信頼 Guard あり', 'trusted'],
      ['(iv) 信頼 Guard に届かず fallback', 'fallback'],
    ] as const;
    const lines: string[] = [];
    lines.push(`[Guard 捕捉率] 試行数=${N}/セル, 最初の隣人 ${K_OUT} 人 (Sybil は握手が速く常駐)`);
    lines.push('  方式                              share=50%         share=90%');
    lines.push('                                   捕捉率 (期待値)   捕捉率 (期待値)  未決定');
    for (const [label, k] of rows) {
      const a = results.get(key(k, 0.5));
      const b = results.get(key(k, 0.9));
      const f = (r?: CellResult) => (r ? `${pct(r.sybilRate)} (${k === 'trusted' ? '   --' : pct(r.expected)})` : '   n/a        ');
      lines.push(`  ${label.padEnd(30)}  ${f(a)}   ${f(b)}   ${(a?.none ?? 0) + (b?.none ?? 0)}`);
    }
    const inb = results.get(key('open', 0.5, '+10inbound'));
    if (inb) lines.push(`  (ii) open, Sybil inbound +10 人 (share=50%): ${pct(inb.sybilRate)} (重み期待値 ${pct(inb.expected)})`);
    lines.push(`  最速の決定時刻: open=${((results.get(key('open', 0.5))?.earliestMs ?? 0) / 1000).toFixed(0)}s, fallback=${((results.get(key('fallback', 0.5))?.earliestMs ?? 0) / 1000).toFixed(0)}s`);
    console.log(lines.join('\n'));
    expect(results.size).toBeGreaterThan(0);
  });
});
