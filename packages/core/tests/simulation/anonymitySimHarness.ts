import { vi } from 'vitest';
import { OnionRouter } from '../../src/crypto/OnionRouter';
import { WireType } from '../../src/network/wire/WireTypes';
import { GuardManager } from '../../src/trust/GuardManager';
import { makeCheapPacket } from '../helpers/cheapPow';
import { makeList, makeMaintainer } from '../helpers/guardFixtures';
import { createSimNode, FAST_POW, sleep, stopAll, type SimNode } from '../helpers/onionNet';

/**
 * 匿名性シミュレーション (D1) の道具立て。
 *
 * ★ 実コードをそのまま動かす (OnionCircuit / DandelionRouter / GossipRouter / GuardManager)。
 *   網は onionNet の SimNode をメモリ内でつないだもので、本物の cover traffic・3 スロット回路・
 *   Stem の歩き・Fluff を実時間のタイマーで回す。数理モデルは使わない。
 *
 * ★ 時間の縮尺 (scale)
 *   実時間で 0.5 秒間隔の cover を 60 ノードぶん回すと暗号が間に合わない。cover 間隔・中継遅延・
 *   リンク遅延をすべて 1/scale に縮めて回し、報告では (実測 ms × scale) = 「モデル時間」に直す。
 *   縮尺をかけても「相対的な並び」(cover 間隔 : 中継遅延 : リンク遅延) は保たれるので、
 *   タイミング相関の議論は変わらない。ただし CPU の遅れ (イベントループの詰まり) は縮尺が大きいほど
 *   混ざる。cpuLagMs で確認できる。
 *
 * ★ 攻撃者 (監視ノード) の能力
 *   - 自分に届いたフレームの (時刻, 送り主, 種別) を全部ログに取る。
 *   - 自分宛ての onion セルは、自分の鍵で 1 枚剥がせる (relay → 次ホップ / drop / frag)。
 *   - 平文の STEM / GOSSIP の中身 (packet_id) は見える。
 *   - それ以外 (他人宛てのフレーム、他人の鍵で封印された層) は見えない。
 *   攻撃者のノードも実コードどおりに振る舞う (誠実だが観測する。握りつぶしなどはしない)。
 */

export type Mode = 'trusted' | 'open';

export interface SimParams {
  /** 総ノード数 (trusted モードでは信頼 Guard も含む) */
  n: number;
  /** 通常ノード同士の平均次数 */
  degree: number;
  /** 攻撃者の割合 (総ノード数に対して。信頼 Guard は常に誠実) */
  advFraction: number;
  mode: Mode;
  /** trusted モードの信頼 Guard の数 */
  trustedCount: number;
  /** trusted モードで、各利用者がつなぐ信頼 Guard の数 */
  trustedPerClient: number;
  /** 投稿数 */
  posts: number;
  /** 投稿者の人数 (投稿者は誠実な利用者から重複なく選ぶ。posts / authors 回ずつ投稿する) */
  authors: number;
  /** 投稿どうしの平均間隔 (実 ms, 指数分布) */
  postGapMs: number;
  /** モデル時間 / 実時間 */
  scale: number;
  /** false ならノードは cover を出さず、投稿のときだけ 1 枠を出す (対照実験用) */
  cover: boolean;
  seed: number;
  /** 起動から投稿開始までの上限 (実 ms) */
  warmupMaxMs?: number;
}

export const MODEL = {
  /** モデル時間でのパラメータ (CIRCUIT_CONFIG の本番値と、想定する WebRTC の遅延) */
  coverIntervalMs: 500,
  relayDelayMs: 40,
  linkLatencyMs: [20, 60] as const,
  linkJitterMs: 8,
};

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ───────────────────────────── 記録の型 ─────────────────────────────

interface Obs {
  t: number;
  from: string;
  type: number;
  pid?: string;
  /** ONION_STEM を自分の鍵で剥がした結果 */
  peel?: 'relay' | 'drop' | 'frag' | 'fail';
  nextHop?: string;
}

interface PidFrame { t: number; from: string; to: string }

interface CellEmit { t: number; kind: 'drop' | 'frag'; guard: string; m1: string }

export interface PostTruth {
  idx: number;
  pid: string;
  author: string;
  guard: string | null;
  m1: string | null;
  /** broadcast() を呼んだ時刻 */
  tPost: number;
  /** 本物のセルを author が送り出した時刻 (見つからなければ null) */
  tEmit: number | null;
  echoOk: boolean;
  /** STEM フレーム (受信時刻順) */
  stem: PidFrame[];
  /** 最初の GOSSIP フレーム (= 最初の flood) */
  firstGossip: PidFrame | null;
  /** 各ノードが投稿を受け取った時刻 (author は tPost) */
  delivered: Map<string, number>;
}

export interface World {
  params: SimParams;
  nodes: SimNode[];
  trusted: SimNode[];
  clients: SimNode[];
  adv: Set<string>;
  idOf: (name: string) => string;
  /** 利用者 (誠実) → 固定している Guard (起動直後の時点) */
  guardOf: Map<string, string | null>;
  /** 攻撃者ノードごとの受信ログ */
  advObs: Map<string, Obs[]>;
  pidFrames: Map<string, { stem: PidFrame[]; gossip: PidFrame[] }>;
  deliveredAt: Map<string, Map<string, number>>;
  emits: Map<string, CellEmit[]>;
  /** 平均リンク遅延 (実 ms) */
  meanLatencyMs: number;
  /** 投稿の間のイベントループの遅れ (実 ms, 20ms の sleep に対する実測超過の平均) */
  cpuLagMs: number;
  warmupMs: number;
  cleanup: () => void;
}

// ───────────────────────────── 構築 ─────────────────────────────

function now(): number { return performance.now(); }

export async function buildWorld(params: SimParams): Promise<World> {
  const rng = mulberry32(params.seed);
  const { scale } = params;
  const opts = {
    coverIntervalMs: params.cover ? MODEL.coverIntervalMs / scale : 1e9,
    relayDelayMs: MODEL.relayDelayMs / scale,
    // 歩き + flood が終わるまで十分に待つ (モデル時間 5 秒ぶん)
    echoTimeoutMs: 5000 / scale,
    readyWaitMs: 20_000,
  };

  const isTrusted = params.mode === 'trusted';
  const trusted: SimNode[] = [];
  const clients: SimNode[] = [];
  let guardList: string | undefined;
  let keyset: any;
  if (isTrusted) {
    for (let i = 0; i < params.trustedCount; i++) trusted.push(await createSimNode(`T${i}`, opts));
    const m = await makeMaintainer();
    keyset = m.keyset;
    guardList = makeList(m, trusted.map(t => t.identity), { now: Date.now() });
  }
  const nClients = params.n - trusted.length;
  const managers = new Map<SimNode, GuardManager>();
  for (let i = 0; i < nClients; i++) {
    const gm = new GuardManager({
      keyset, guardList, powParams: FAST_POW, sampleSize: params.trustedPerClient,
      fallbackGraceMs: 60_000, openSelectionDelayMs: 100, minOpenCandidates: 4,
    });
    await gm.init();
    const node = await createSimNode(`C${i}`, opts, gm);
    managers.set(node, gm);
    clients.push(node);
  }
  const nodes = [...trusted, ...clients];

  // ── トポロジー: ランダムなハミルトン閉路 (連結の保証) + ランダムな辺で平均次数まで ──
  const edges = new Set<string>();
  const deg = new Map<SimNode, number>();
  const maxDeg = 16;
  const lat = new Map<string, number>();
  const meanLat = (MODEL.linkLatencyMs[0] + MODEL.linkLatencyMs[1]) / 2 / scale;
  const connect = (a: SimNode, b: SimNode): boolean => {
    if (a === b) return false;
    const key = [a.name, b.name].sort().join('|');
    if (edges.has(key)) return false;
    edges.add(key);
    deg.set(a, (deg.get(a) ?? 0) + 1);
    deg.set(b, (deg.get(b) ?? 0) + 1);
    const base = (MODEL.linkLatencyMs[0] + rng() * (MODEL.linkLatencyMs[1] - MODEL.linkLatencyMs[0])) / scale;
    lat.set(key, base);
    // 開始側 (outbound) はランダム。Guard の重み (guardWeight) が outbound を 3 倍にするため、実網に近づける
    const outA = rng() < 0.5;
    linkWithLatency(a, b, base, (MODEL.linkJitterMs / scale), outA, rng);
    return true;
  };
  const shuffled = (arr: SimNode[]) => {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  };
  const ring = shuffled(clients);
  for (let i = 0; i < ring.length; i++) connect(ring[i], ring[(i + 1) % ring.length]);
  // 信頼 Guard: 各利用者が trustedPerClient 台につなぐ。Guard どうしも少しつなぐ
  if (isTrusted) {
    // ★ 利用者は GuardManager のサンプル (wantedGuardIds) の信頼 Guard につなぐ (実機の挙動。サンプル外につないでも Guard にならない)
    for (const c of clients) {
      for (const id of managers.get(c)!.wantedGuardIds()) {
        const g = trusted.find(t => t.identity.peerId === id);
        if (g) connect(c, g);
      }
    }
    for (let i = 0; i < trusted.length; i++) connect(trusted[i], trusted[(i + 1) % trusted.length]);
  }
  // 利用者同士の辺: 信頼 Guard ぶんの次数を引いて、平均次数に揃える
  const clientTarget = isTrusted ? Math.max(3, params.degree - params.trustedPerClient) : params.degree;
  let guardCount = 0;
  while (guardCount++ < 100_000) {
    const avg = clients.reduce((s, c) => s + (deg.get(c) ?? 0) - (isTrusted ? params.trustedPerClient : 0), 0) / clients.length;
    if (avg >= clientTarget) break;
    const a = clients[Math.floor(rng() * clients.length)];
    const b = clients[Math.floor(rng() * clients.length)];
    if ((deg.get(a) ?? 0) >= maxDeg || (deg.get(b) ?? 0) >= maxDeg) continue;
    connect(a, b);
  }

  // 利用者は最低 5 人の隣人を持つ (開放モードの Guard 選択は検証済み隣人 4 人以上を要する。
  // 実網では PEX が次数を引き上げる。ここで足りない節点を残すと、起動しないだけの節点になる)
  for (const c of clients) {
    let guardTries = 0;
    while ((deg.get(c) ?? 0) < 5 && guardTries++ < 200) {
      const b = clients[Math.floor(rng() * clients.length)];
      if ((deg.get(b) ?? 0) < maxDeg) connect(c, b);
    }
  }

  // ── 攻撃者 (信頼 Guard は常に誠実) ──
  const nAdv = Math.round(params.advFraction * params.n);
  const advNodes = shuffled(clients).slice(0, nAdv);
  const adv = new Set(advNodes.map(a => a.identity.peerId));

  // ── 観測の取り付け ──
  let currentEmitter: string | null = null;
  const advObs = new Map<string, Obs[]>();
  const pidFrames = new Map<string, { stem: PidFrame[]; gossip: PidFrame[] }>();
  const deliveredAt = new Map<string, Map<string, number>>();
  const emits = new Map<string, CellEmit[]>();

  for (const n of nodes) {
    const myId = n.identity.peerId;
    const pm: any = n.peerManager;
    const isAdv = adv.has(myId);
    let curve: { pk: Uint8Array; sk: Uint8Array } | null = null;
    if (isAdv) {
      const secret = (pm.nodeIdentity as any).exportSecret();
      curve = { pk: OnionRouter.toCurvePublicKey(secret.pubkey), sk: OnionRouter.toCurvePrivateKey(secret.privkey) };
      advObs.set(myId, []);
    }
    const inner = pm.handleData.bind(pm);
    pm.handleData = (from: string, data: Uint8Array) => {
      const t = now();
      inner(from, data); // createSimNode の薄い包みが inbox に積んでから本処理へ
      const m = n.inbox[n.inbox.length - 1];
      n.inbox.length = 0;
      if (!m) return;
      let pid: string | undefined;
      let peel: Obs['peel'];
      let nextHop: string | undefined;
      if (m.type === WireType.STEM) pid = m.payload?.item?.packet?.packet_id;
      else if (m.type === WireType.GOSSIP) pid = m.payload?.packet?.packet_id;
      if (pid) {
        let rec = pidFrames.get(pid);
        if (!rec) { rec = { stem: [], gossip: [] }; pidFrames.set(pid, rec); }
        (m.type === WireType.STEM ? rec.stem : rec.gossip).push({ t, from, to: myId });
      }
      if (isAdv) {
        if (m.type === WireType.ONION_STEM && m.payload?.onionBytes instanceof Uint8Array && curve) {
          const r = OnionRouter.unwrapWithCurveKeys(m.payload.onionBytes, curve.pk, curve.sk);
          if (!r) peel = 'fail';
          else if (r.type === 'relay') { peel = 'relay'; nextHop = r.nextHop; }
          else peel = r.type === 'drop' ? 'drop' : 'frag';
        }
        if (m.type === WireType.ONION_STEM || pid) advObs.get(myId)!.push({ t, from, type: m.type, pid, peel, nextHop });
      }
    };

    // 本物 (frag) のセルをいつ・どの Guard / M1 へ出したかの真値
    const circ: any = n.circuit;
    const origEmit = circ.emitCell.bind(circ);
    circ.emitCell = () => { currentEmitter = myId; try { origEmit(); } finally { currentEmitter = null; } };

    n.gossip.onMessage(p => {
      let d = deliveredAt.get(p.packet_id);
      if (!d) { d = new Map(); deliveredAt.set(p.packet_id, d); }
      if (!d.has(myId)) d.set(myId, now());
    });
  }

  const origWrap = OnionRouter.wrapCircuit;
  (OnionRouter as any).wrapCircuit = function (exit: any, hops: any[]) {
    if (currentEmitter) {
      let list = emits.get(currentEmitter);
      if (!list) { list = []; emits.set(currentEmitter, list); }
      list.push({ t: now(), kind: exit.type === 'frag' ? 'frag' : 'drop', guard: hops[0].peerId, m1: hops[1].peerId });
    }
    return origWrap.call(OnionRouter, exit, hops);
  };

  // 起動
  for (const n of nodes) n.circuit.start();

  // 全員が Guard と M1 の候補を持つまで待つ (cover の無い実験では、Guard の選択を手で促す)
  const t0 = now();
  const warmupMax = params.warmupMaxMs ?? 30_000;
  for (;;) {
    for (const c of clients) (c.circuit as any).currentGuard();
    const ready = clients.every(c => (c.circuit as any).guardNeighbors.size > 0);
    if (ready || now() - t0 > warmupMax) break;
    await sleep(25);
  }

  const warmupMs = now() - t0;
  const guardOf = new Map<string, string | null>();
  for (const c of clients) guardOf.set(c.identity.peerId, c.dandelion.getPinnedGuardId());

  return {
    params, nodes, trusted, clients, adv, guardOf,
    idOf: (name) => nodes.find(n => n.name === name)!.identity.peerId,
    advObs, pidFrames, deliveredAt, emits,
    meanLatencyMs: meanLat,
    cpuLagMs: 0,
    warmupMs,
    cleanup: () => { (OnionRouter as any).wrapCircuit = origWrap; stopAll(nodes); },
  };
}

/** 遅延つきの双方向リンク (onionNet.link は遅延 0)。direction は Guard の重み付けに効く */
function linkWithLatency(a: SimNode, b: SimNode, baseMs: number, jitterMs: number, aOutbound: boolean, rng: () => number): void {
  const half = (from: SimNode, to: SimNode, outbound: boolean) => ({
    peerId: to.identity.peerId,
    position: to.identity.position,
    rtt: 0,
    isConnected: true,
    isVerified: true,
    direction: outbound ? 'outbound' : 'inbound',
    verifiedAt: Date.now(),
    pubkey: to.identity.pubkey,
    powCounter: to.identity.powCounter,
    send: (data: Uint8Array) => {
      const copy = data.slice();
      const delay = Math.max(0, baseMs + rng() * jitterMs);
      setTimeout(() => (to.peerManager as any).handleData(from.identity.peerId, copy), delay);
    },
    close: vi.fn(),
  });
  (a.peerManager as any)._peers.set(b.identity.peerId, half(a, b, aOutbound));
  (b.peerManager as any)._peers.set(a.identity.peerId, half(b, a, !aOutbound));
}

// ───────────────────────────── 投稿 ─────────────────────────────

export async function runPosts(world: World): Promise<PostTruth[]> {
  const { params } = world;
  const rng = mulberry32(params.seed ^ 0x9e3779b9);
  const honest = world.clients.filter(c => !world.adv.has(c.identity.peerId));
  const order = honest.slice();
  for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
  const authors = order.slice(0, Math.min(params.authors, order.length));

  const posts: PostTruth[] = [];
  const pending: Promise<void>[] = [];
  const nonce = new Uint8Array(8);
  let lagSum = 0, lagN = 0;

  for (let i = 0; i < params.posts; i++) {
    const author = authors[i % authors.length];
    // 同じ人の連投が固まらないよう、順序は巡回 + 乱数のゆらぎ
    const a = rng() < 0.5 ? author : authors[Math.floor(rng() * authors.length)];
    crypto.getRandomValues(nonce);
    const bytes = new Uint8Array(16);
    bytes.set(nonce, 0);
    new DataView(bytes.buffer).setUint32(8, i, true);
    const pkt = makeCheapPacket(bytes);
    const truth: PostTruth = {
      idx: i, pid: pkt.packet_id, author: a.identity.peerId,
      guard: a.dandelion.getPinnedGuardId(), m1: null,
      tPost: now(), tEmit: null, echoOk: false, stem: [], firstGossip: null, delivered: new Map(),
    };
    posts.push(truth);
    const pr = a.gossip.broadcast(pkt).then(ok => { truth.echoOk = ok; });
    pending.push(pr);
    if (!params.cover) {
      // cover の無い対照実験: 本物が送出待ちに入ったら 1 枠だけ出す
      for (let k = 0; k < 200; k++) {
        if ((a.circuit as any).queue.length > 0) { a.circuit.flushOnce(); break; }
        await sleep(1);
      }
    }
    const gap = -Math.log(1 - rng()) * params.postGapMs;
    const s = now();
    await sleep(gap);
    lagSum += Math.max(0, now() - s - gap); lagN++;
  }
  // 最後の投稿の歩きと flood が終わるまで待つ
  await Promise.race([Promise.all(pending), sleep(15_000)]);
  await sleep(2000 / params.scale + 300);
  world.cpuLagMs = lagN ? lagSum / lagN : 0;

  // ── 真値の組み立て ──
  for (const p of posts) {
    const rec = world.pidFrames.get(p.pid);
    p.stem = (rec?.stem ?? []).slice().sort((x, y) => x.t - y.t);
    p.firstGossip = (rec?.gossip ?? []).slice().sort((x, y) => x.t - y.t)[0] ?? null;
    p.delivered = new Map(world.deliveredAt.get(p.pid) ?? []);
  }
  // 本物のセル: author の frag の送出を、投稿の順に 1 つずつ割り当てる
  const byAuthor = new Map<string, PostTruth[]>();
  for (const p of posts) (byAuthor.get(p.author) ?? byAuthor.set(p.author, []).get(p.author)!).push(p);
  for (const [author, list] of byAuthor) {
    const frags = (world.emits.get(author) ?? []).filter(e => e.kind === 'frag').sort((x, y) => x.t - y.t);
    let cursor = 0;
    for (const p of list.sort((x, y) => x.tPost - y.tPost)) {
      while (cursor < frags.length && frags[cursor].t < p.tPost) cursor++;
      const e = frags[cursor++];
      if (e) { p.tEmit = e.t; p.m1 = e.m1; p.guard = e.guard; }
    }
  }
  return posts;
}

// ───────────────────────────── 解析 ─────────────────────────────

const pct = (xs: number[], q: number) => {
  if (xs.length === 0) return NaN;
  const s = xs.slice().sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(q * s.length))];
};
const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN);

export interface Summary {
  label: string;
  n: number;
  nAdv: number;
  nHonestClients: number;
  posts: number;
  postsEchoed: number;
  authors: number;
  scale: number;
  cpuLagMs: number;
  warmupMs: number;
  baseline: number;
  // 1. 作者の IP を知られる確率
  pGuardAdv: number; // 誠実な利用者のうち、Guard が攻撃者の割合 (母集団全体)
  pGuardAdvPosts: number; // 投稿の中での割合
  pM1Adv: number;
  pStrictPerPost: number; // 投稿 1 件あたり、Guard と M1 側の突き合わせで作者を当てられる確率 (全投稿)
  qStrictGivenGuardAdv: number; // 作者の Guard が攻撃者のとき、1 件で当てられる確率
  pLearnK: Record<number, number>; // k 件投稿した作者が、いずれかで特定される確率 (分解式)
  pLearnKEmpirical: Record<number, number | null>; // 作者ごとの先頭 k 件の実測 (その作者数が足りるときだけ)
  anonSetGivenAdvM1: number; // trusted: M1 が攻撃者のとき、作者が居る Guard の利用者数 (平均)
  guardClients: number; // Guard あたりの利用者数 (平均)
  // 2. 最初の放送者の推測
  heuristicStemOrGossip: HeuristicResult;
  heuristicGossipOnly: HeuristicResult;
  // 3. Guard のタイミング攻撃
  timing: TimingResult | null;
  // 4. 歩数・配送
  walk: { mean: number; hist: Record<number, number>; p50: number; p95: number; expectedMean: number };
  delivery: { p50: number; p95: number; p50Reach95: number; meanReachFraction: number; tFirstFlood: { p50: number; p95: number } };
  /** グラフ距離 (リンクの本数)。最初に flood した者 (Fluff 地点) が作者からどれだけ離れているか */
  distance: {
    authorToFluffer: number;
    m1ToFluffer: number;
    guardToFluffer: number;
    randomPair: number;
    pFlufferIsNeighborOfAuthor: number;
    pFlufferWithin2OfAuthor: number;
    hist: Record<number, number>;
  };
  /** 同じ作者の続けての投稿で、M1 が同じだった割合 */
  m1Repeat: number;
  invariants: {
    authorFirstGossip: number; // 最初の flood を出したのが作者だった件数
    m1ToGuard: number; // M1 が Guard へ STEM を渡した件数
    guardSawClearFromAuthor: number; // Stem の間に、作者から自分の Guard へ平文 STEM が出た件数
    guardSawClearTotal: number; // Guard が作者以外から含め、Stem の間に平文 STEM を受けた件数
    authorStemBeforeFirstStemRecv: number; // 作者が、投稿の歩きが始まる前に平文を出した件数
    postsWithoutStem: number;
  };
}

export interface HeuristicResult {
  usable: number;
  pAuthor: number;
  pGuard: number;
  pM1: number;
  pFluffer: number;
  pAdvAdjacentToAuthor: number;
}

export interface TimingResult {
  instances: number;
  accuracy: number;
  baseline: number;
  top3: number;
  meanCandidateSet: number;
  /** 全投稿を対象にした攻撃: 攻撃者の Guard の利用者全員から 1 人を選ぶ */
  global: { posts: number; accuracy: number; randomBaseline: number; upperBound: number; precisionTop10pct: number };
}

export function analyze(world: World, posts: PostTruth[], label: string): Summary {
  const { params, adv } = world;
  const scale = params.scale;
  const honest = world.clients.filter(c => !adv.has(c.identity.peerId));
  const honestIds = new Set(honest.map(h => h.identity.peerId));
  const valid = posts.filter(p => p.tEmit !== null && p.m1 && p.guard);

  // Guard あたりの利用者
  const clientsOfGuard = new Map<string, string[]>();
  for (const c of world.clients) {
    const g = world.guardOf.get(c.identity.peerId);
    if (g) (clientsOfGuard.get(g) ?? clientsOfGuard.set(g, []).get(g)!).push(c.identity.peerId);
  }
  const guardClients = mean([...clientsOfGuard.values()].map(v => v.length));

  const pGuardAdv = mean(honest.map(h => (adv.has(world.guardOf.get(h.identity.peerId) ?? '') ? 1 : 0)));
  const guardAdvPosts = valid.filter(p => adv.has(p.guard!));

  // 攻撃者の観測を投稿ごとに引けるようにする
  const sightings = (p: PostTruth) => {
    const out: Array<{ t: number; at: string; from: string; kind: 'STEM' | 'GOSSIP' }> = [];
    for (const f of p.stem) if (adv.has(f.to)) out.push({ t: f.t, at: f.to, from: f.from, kind: 'STEM' });
    const g = world.pidFrames.get(p.pid)?.gossip ?? [];
    for (const f of g) if (adv.has(f.to)) out.push({ t: f.t, at: f.to, from: f.from, kind: 'GOSSIP' });
    return out.sort((x, y) => x.t - y.t);
  };

  // ── 1. 厳密な特定 (Guard + M1 側の突き合わせ) ──
  const R = MODEL.relayDelayMs / scale;
  const Lmax = (MODEL.linkLatencyMs[1] + MODEL.linkJitterMs) / scale;
  const Wm1 = 10 * R + 2 * Lmax + 5; // Guard で受けてから M1 が復元するまで
  const Wstem = 20 * R + 3 * Lmax + 5; // さらに M1 が最初の Stem を出して W1 に届くまで
  let m1AdvCount = 0;
  const strictOutcome = new Map<number, number>(); // post idx → 当たる確率 (期待値)
  for (const p of valid) {
    let gotM1 = false;
    if (adv.has(p.m1!)) { m1AdvCount++; gotM1 = true; }
    if (!adv.has(p.guard!)) continue;
    // M1 を知る機会: M1 が攻撃者 (自分で復元) / 最初の Stem を受けた W1 が攻撃者
    let evT: number | null = null;
    let window = Wm1;
    if (gotM1) {
      // M1 が frag を剥がした時刻 = 攻撃者ログの frag のうち、guard から来て最も tGuard に近いもの
      const obs = world.advObs.get(p.m1!) ?? [];
      const cand = obs.filter(o => o.peel === 'frag' && o.from === p.guard && o.t >= p.tEmit!).sort((x, y) => x.t - y.t)[0];
      evT = cand ? cand.t : null;
    }
    if (evT === null && p.stem.length > 0 && adv.has(p.stem[0].to) && p.stem[0].from === p.m1) {
      evT = p.stem[0].t;
      window = Wstem;
    }
    if (evT === null) { strictOutcome.set(p.idx, 0); continue; }
    // Guard (攻撃者) のログ: 自分の利用者から来た relay セルのうち、次ホップが M1 のもの
    const obs = world.advObs.get(p.guard!) ?? [];
    const cands = new Set<string>();
    for (const o of obs) {
      if (o.peel === 'relay' && o.nextHop === p.m1 && o.t <= evT && evT - o.t <= window) cands.add(o.from);
    }
    strictOutcome.set(p.idx, cands.has(p.author) ? 1 / cands.size : 0);
  }
  const pStrictPerPost = valid.length ? [...strictOutcome.values()].reduce((a, b) => a + b, 0) / valid.length : 0;
  const qStrict = guardAdvPosts.length ? mean(guardAdvPosts.map(p => strictOutcome.get(p.idx) ?? 0)) : 0;

  const pLearnK: Record<number, number> = {};
  const pLearnKEmp: Record<number, number | null> = {};
  for (const k of [1, 10, 50]) {
    pLearnK[k] = pGuardAdv * (1 - Math.pow(1 - qStrict, k));
    // 実測: 作者ごとに、先頭 k 件のどれかで (期待値 0.5 以上 = 候補が 2 人以下で当たる) 特定された割合
    const byAuthor = new Map<string, PostTruth[]>();
    for (const p of valid) (byAuthor.get(p.author) ?? byAuthor.set(p.author, []).get(p.author)!).push(p);
    const eligible = [...byAuthor.values()].filter(l => l.length >= k);
    if (eligible.length < 10) { pLearnKEmp[k] = null; continue; }
    let hit = 0;
    for (const l of eligible) {
      const first = l.sort((x, y) => x.tPost - y.tPost).slice(0, k);
      // 期待値でなく、同点は一様に引いた結果を使う (決定的にするため確率の総和の上限 1 で打ち切る)
      const miss = first.reduce((m, p) => m * (1 - (strictOutcome.get(p.idx) ?? 0)), 1);
      hit += 1 - miss;
    }
    pLearnKEmp[k] = hit / eligible.length;
  }

  // trusted: M1 が攻撃者 → Guard が分かる → 作者は Guard の利用者のどれか
  const advM1 = valid.filter(p => adv.has(p.m1!));
  const anonSetGivenAdvM1 = mean(advM1.map(p => clientsOfGuard.get(p.guard!)?.length ?? NaN));

  // ── 2. 最初の放送者の推測 ──
  const heuristic = (gossipOnly: boolean): HeuristicResult => {
    let usable = 0, a = 0, g = 0, m = 0, f = 0, adj = 0;
    for (const p of valid) {
      const s = sightings(p).filter(x => !adv.has(x.from) && (!gossipOnly || x.kind === 'GOSSIP'));
      if (s.length === 0) continue;
      usable++;
      const guess = s[0].from;
      if (guess === p.author) a++;
      if (guess === p.guard) g++;
      if (guess === p.m1) m++;
      if (p.firstGossip && guess === p.firstGossip.from) f++;
      // 推測の相手が作者の直接の隣人か (おおよその位置の目安)
      const author = world.nodes.find(n => n.identity.peerId === p.author)!;
      if ((author.peerManager as any)._peers.has(guess)) adj++;
    }
    return {
      usable, pAuthor: a / Math.max(1, usable), pGuard: g / Math.max(1, usable), pM1: m / Math.max(1, usable),
      pFluffer: f / Math.max(1, usable), pAdvAdjacentToAuthor: adj / Math.max(1, usable),
    };
  };

  // ── 3. Guard のタイミング攻撃 ──
  const timing = timingAttack(world, valid, sightings, scale);

  // ── 4. 歩数と配送 ──
  const stemLens = valid.filter(p => p.stem.length > 0).map(p => p.stem.length);
  const hist: Record<number, number> = {};
  for (const l of stemLens) hist[Math.min(l, 15)] = (hist[Math.min(l, 15)] ?? 0) + 1;
  const full: number[] = [], reach95: number[] = [], fracs: number[] = [], tFlood: number[] = [];
  for (const p of valid) {
    const times = [...p.delivered.entries()].filter(([id]) => id !== p.author).map(([, t]) => t - p.tPost).sort((x, y) => x - y);
    const total = params.n - 1;
    fracs.push(times.length / total);
    if (times.length >= total) full.push(times[times.length - 1] * scale);
    const i95 = Math.ceil(0.95 * total) - 1;
    if (times.length > i95) reach95.push(times[i95] * scale);
    if (p.firstGossip) tFlood.push((p.firstGossip.t - p.tPost) * scale);
  }

  // ── グラフ距離 ──
  const adjacency = new Map<string, string[]>();
  for (const n of world.nodes) adjacency.set(n.identity.peerId, [...(n.peerManager as any)._peers.keys()]);
  const bfsCache = new Map<string, Map<string, number>>();
  const bfs = (src: string) => {
    let d = bfsCache.get(src);
    if (d) return d;
    d = new Map([[src, 0]]);
    const q = [src];
    for (let i = 0; i < q.length; i++) for (const v of adjacency.get(q[i]) ?? []) if (!d.has(v)) { d.set(v, d.get(q[i])! + 1); q.push(v); }
    bfsCache.set(src, d);
    return d;
  };
  const dA: number[] = [], dM: number[] = [], dG: number[] = [];
  const dHist: Record<number, number> = {};
  for (const p of valid) {
    if (!p.firstGossip) continue;
    const fl = p.firstGossip.from;
    const da = bfs(p.author).get(fl);
    if (da === undefined) continue;
    dA.push(da);
    dHist[Math.min(da, 8)] = (dHist[Math.min(da, 8)] ?? 0) + 1;
    dM.push(bfs(p.m1!).get(fl) ?? NaN);
    dG.push(bfs(p.guard!).get(fl) ?? NaN);
  }
  const allIds = world.nodes.map(n => n.identity.peerId);
  const rp: number[] = [];
  for (let i = 0; i < 400; i++) {
    const a = allIds[(i * 7919) % allIds.length], b = allIds[(i * 104729 + 13) % allIds.length];
    if (a !== b) rp.push(bfs(a).get(b) ?? NaN);
  }
  // 同じ作者の続けての投稿の M1
  let rep = 0, repN = 0;
  {
    const by = new Map<string, PostTruth[]>();
    for (const p of valid) (by.get(p.author) ?? by.set(p.author, []).get(p.author)!).push(p);
    for (const l of by.values()) {
      l.sort((x, y) => x.tPost - y.tPost);
      for (let i = 1; i < l.length; i++) { repN++; if (l[i].m1 === l[i - 1].m1) rep++; }
    }
  }

  // ── 不変条件 ──
  let authorFirstGossip = 0, m1ToGuard = 0, sawFromAuthor = 0, sawTotal = 0, early = 0, noStem = 0;
  for (const p of valid) {
    if (p.firstGossip && p.firstGossip.from === p.author) authorFirstGossip++;
    if (p.stem.length === 0) { noStem++; continue; }
    if (p.stem.some(f => f.from === p.m1 && f.to === p.guard)) m1ToGuard++;
    const tFlood0 = p.firstGossip?.t ?? Infinity;
    const stemToGuard = p.stem.filter(f => f.to === p.guard && f.t < tFlood0);
    if (stemToGuard.length) sawTotal++;
    if (stemToGuard.some(f => f.from === p.author)) sawFromAuthor++;
    if (p.stem.some(f => f.from === p.author && f.t < p.stem[0].t)) early++;
  }

  return {
    label,
    n: params.n,
    nAdv: adv.size,
    nHonestClients: honest.length,
    posts: valid.length,
    postsEchoed: valid.filter(p => p.echoOk).length,
    authors: new Set(valid.map(p => p.author)).size,
    scale,
    cpuLagMs: world.cpuLagMs,
    warmupMs: world.warmupMs,
    baseline: 1 / honest.length,
    pGuardAdv,
    pGuardAdvPosts: valid.length ? guardAdvPosts.length / valid.length : 0,
    pM1Adv: valid.length ? m1AdvCount / valid.length : 0,
    pStrictPerPost,
    qStrictGivenGuardAdv: qStrict,
    pLearnK,
    pLearnKEmpirical: pLearnKEmp,
    anonSetGivenAdvM1,
    guardClients,
    heuristicStemOrGossip: heuristic(false),
    heuristicGossipOnly: heuristic(true),
    timing,
    walk: {
      mean: mean(stemLens), hist, p50: pct(stemLens, 0.5), p95: pct(stemLens, 0.95),
      expectedMean: 1 / 0.25,
    },
    delivery: {
      p50: pct(full, 0.5), p95: pct(full, 0.95), p50Reach95: pct(reach95, 0.5),
      meanReachFraction: mean(fracs),
      tFirstFlood: { p50: pct(tFlood, 0.5), p95: pct(tFlood, 0.95) },
    },
    distance: {
      authorToFluffer: mean(dA), m1ToFluffer: mean(dM.filter(Number.isFinite)), guardToFluffer: mean(dG.filter(Number.isFinite)),
      randomPair: mean(rp.filter(Number.isFinite)),
      pFlufferIsNeighborOfAuthor: dA.filter(d => d === 1).length / Math.max(1, dA.length),
      pFlufferWithin2OfAuthor: dA.filter(d => d <= 2).length / Math.max(1, dA.length),
      hist: dHist,
    },
    m1Repeat: repN ? rep / repN : NaN,
    invariants: {
      authorFirstGossip, m1ToGuard,
      guardSawClearFromAuthor: sawFromAuthor, guardSawClearTotal: sawTotal,
      authorStemBeforeFirstStemRecv: early, postsWithoutStem: noStem,
    },
  };
}

/**
 * 攻撃者の Guard が、自分の利用者のセルの時刻と「投稿が網に最初に現れた時刻」から作者を当てる。
 *
 * 攻撃者は各セルを「(その時刻の) 1 枚」としか見られない (本物か drop かは区別できない)。
 * 作者のセルから tS (攻撃者が最初に投稿を見た時刻) までの遅れ Δ の分布 K は、
 * 攻撃者が自分で何度か投稿して測れる (ここでは Guard が誠実な投稿の実測を使う = 評価対象と重ならない)。
 * 利用者 c のスコア = c のセルそれぞれの K(tS - t_cell) の和。最大の利用者を作者と推測する。
 */
function timingAttack(
  world: World,
  valid: PostTruth[],
  sightings: (p: PostTruth) => Array<{ t: number; at: string; from: string; kind: 'STEM' | 'GOSSIP' }>,
  scale: number,
): TimingResult | null {
  const { adv } = world;
  const coverReal = world.params.cover ? MODEL.coverIntervalMs / scale : 20 / scale;
  const bin = Math.max(0.5, coverReal / 10);
  const nb = 400;
  const delta = (p: PostTruth, tS: number) => tS - (p.tEmit! + world.meanLatencyMs);

  // 学習: Guard が攻撃者でない投稿の遅れ
  const train = valid.filter(p => !adv.has(p.guard!));
  const counts = new Array(nb).fill(0);
  let total = 0;
  for (const p of train) {
    const s = sightings(p)[0];
    if (!s) continue;
    const b = Math.floor(delta(p, s.t) / bin);
    if (b >= 0 && b < nb) { counts[b]++; total++; }
  }
  if (total < 20) return null;
  // 平滑 (前後 1 ビン)
  const K = counts.map((c, i) => (counts[i - 1] ?? 0) * 0.5 + c + (counts[i + 1] ?? 0) * 0.5);
  const kernel = (d: number) => {
    const b = Math.floor(d / bin);
    return b >= 0 && b < nb ? (K[b] + 0.05) / (total + 0.05 * nb) : 0.05 / (total + 0.05 * nb);
  };

  const targets = valid.filter(p => adv.has(p.guard!));
  let acc = 0, base = 0, top3 = 0, setSize = 0, used = 0;
  for (const p of targets) {
    const s = sightings(p)[0];
    if (!s) continue;
    const obs = world.advObs.get(p.guard!) ?? [];
    const byClient = new Map<string, number[]>();
    for (const o of obs) if (o.peel === 'relay') (byClient.get(o.from) ?? byClient.set(o.from, []).get(o.from)!).push(o.t);
    if (!byClient.has(p.author)) continue;
    const scores = new Map<string, number>();
    for (const [c, ts] of byClient) {
      let sc = 0;
      for (const t of ts) if (t <= s.t) sc += kernel(s.t - t);
      scores.set(c, sc);
    }
    const max = Math.max(...scores.values());
    const ties = [...scores.entries()].filter(([, v]) => v >= max - 1e-12).map(([c]) => c);
    acc += ties.includes(p.author) ? 1 / ties.length : 0;
    const ranked = [...scores.entries()].sort((x, y) => y[1] - x[1]).map(([c]) => c);
    top3 += ranked.slice(0, 3).includes(p.author) ? 1 : 0;
    base += 1 / byClient.size;
    setSize += byClient.size;
    used++;
  }
  if (used === 0) return null;

  // 全投稿を対象にした攻撃 (作者の Guard が攻撃者かどうかを知らずに、攻撃者の Guard の利用者全員から選ぶ)
  const allClients = new Map<string, number[]>();
  for (const g of adv) for (const o of world.advObs.get(g) ?? []) {
    if (o.peel === 'relay') (allClients.get(o.from) ?? allClients.set(o.from, []).get(o.from)!).push(o.t);
  }
  for (const a of adv) allClients.delete(a); // 自分の仲間は作者でない
  const glob: Array<{ ok: number; best: number }> = [];
  let ub = 0, rnd = 0;
  for (const p of valid) {
    const s = sightings(p)[0];
    if (!s) continue;
    let best = -1, bestSet: string[] = [];
    for (const [c, ts] of allClients) {
      let sc = 0;
      for (const t of ts) if (t <= s.t) sc += kernel(s.t - t);
      if (sc > best + 1e-12) { best = sc; bestSet = [c]; } else if (Math.abs(sc - best) <= 1e-12) bestSet.push(c);
    }
    const inSet = allClients.has(p.author);
    ub += inSet ? 1 : 0;
    rnd += inSet ? 1 / allClients.size : 0;
    glob.push({ ok: bestSet.includes(p.author) ? 1 / bestSet.length : 0, best });
  }
  glob.sort((x, y) => y.best - x.best);
  const top = glob.slice(0, Math.max(1, Math.floor(glob.length * 0.1)));
  const global = {
    posts: glob.length,
    accuracy: mean(glob.map(g => g.ok)),
    randomBaseline: rnd / Math.max(1, glob.length),
    upperBound: ub / Math.max(1, glob.length),
    precisionTop10pct: mean(top.map(g => g.ok)),
  };
  return { instances: used, accuracy: acc / used, baseline: base / used, top3: top3 / used, meanCandidateSet: setSize / used, global };
}

// ───────────────────────────── 整形 ─────────────────────────────

export const f3 = (x: number) => (Number.isFinite(x) ? x.toFixed(3) : 'n/a');
export const f1 = (x: number) => (Number.isFinite(x) ? x.toFixed(1) : 'n/a');

export async function runConfig(params: SimParams, label: string): Promise<{ summary: Summary; wallMs: number }> {
  const t0 = now();
  const world = await buildWorld(params);
  try {
    const posts = await runPosts(world);
    const summary = analyze(world, posts, label);
    return { summary, wallMs: now() - t0 };
  } finally {
    world.cleanup();
  }
}

// ───────────────────────────── 複数の網の統合 ─────────────────────────────

function wmean(items: Array<{ v: number; w: number }>): number {
  let s = 0, w = 0;
  for (const { v, w: x } of items) if (Number.isFinite(v) && x > 0) { s += v * x; w += x; }
  return w > 0 ? s / w : NaN;
}

/**
 * 同じ設定で作り直した複数の網 (トポロジーと攻撃者の配置が違う) の結果を 1 つにまとめる。
 * 率は件数で重み付けした平均、件数は合計、百分位は網ごとの値の平均 (近似)。
 */
export function mergeSummaries(list: Summary[]): Summary {
  if (list.length === 1) return list[0];
  const first = list[0];
  const W = (s: Summary) => s.posts;
  const avg = (get: (s: Summary) => number, w: (s: Summary) => number = W) => wmean(list.map(s => ({ v: get(s), w: w(s) })));
  const sum = (get: (s: Summary) => number) => list.reduce((a, s) => a + get(s), 0);
  const mergeHist = (get: (s: Summary) => Record<number, number>) => {
    const h: Record<number, number> = {};
    for (const s of list) for (const [k, v] of Object.entries(get(s))) h[+k] = (h[+k] ?? 0) + v;
    return h;
  };
  const guardAdvW = (s: Summary) => s.posts * s.pGuardAdvPosts;
  const pGuardAdv = avg(s => s.pGuardAdv, s => s.nHonestClients);
  const q = avg(s => s.qStrictGivenGuardAdv, guardAdvW);
  const pLearnK: Record<number, number> = {};
  for (const k of [1, 10, 50]) pLearnK[k] = Number.isFinite(q) ? pGuardAdv * (1 - Math.pow(1 - q, k)) : 0;
  const heur = (get: (s: Summary) => HeuristicResult): HeuristicResult => {
    const w = (s: Summary) => get(s).usable;
    return {
      usable: sum(s => get(s).usable),
      pAuthor: avg(s => get(s).pAuthor, w), pGuard: avg(s => get(s).pGuard, w), pM1: avg(s => get(s).pM1, w),
      pFluffer: avg(s => get(s).pFluffer, w), pAdvAdjacentToAuthor: avg(s => get(s).pAdvAdjacentToAuthor, w),
    };
  };
  const timings = list.filter(s => s.timing);
  let timing: TimingResult | null = null;
  if (timings.length) {
    const tw = (s: Summary) => s.timing!.instances;
    const gw = (s: Summary) => s.timing!.global.posts;
    timing = {
      instances: timings.reduce((a, s) => a + s.timing!.instances, 0),
      accuracy: wmean(timings.map(s => ({ v: s.timing!.accuracy, w: tw(s) }))),
      baseline: wmean(timings.map(s => ({ v: s.timing!.baseline, w: tw(s) }))),
      top3: wmean(timings.map(s => ({ v: s.timing!.top3, w: tw(s) }))),
      meanCandidateSet: wmean(timings.map(s => ({ v: s.timing!.meanCandidateSet, w: tw(s) }))),
      global: {
        posts: timings.reduce((a, s) => a + gw(s), 0),
        accuracy: wmean(timings.map(s => ({ v: s.timing!.global.accuracy, w: gw(s) }))),
        randomBaseline: wmean(timings.map(s => ({ v: s.timing!.global.randomBaseline, w: gw(s) }))),
        upperBound: wmean(timings.map(s => ({ v: s.timing!.global.upperBound, w: gw(s) }))),
        precisionTop10pct: wmean(timings.map(s => ({ v: s.timing!.global.precisionTop10pct, w: gw(s) }))),
      },
    };
  }
  return {
    label: first.label, n: first.n, scale: first.scale,
    nAdv: avg(s => s.nAdv, () => 1), nHonestClients: avg(s => s.nHonestClients, () => 1),
    posts: sum(s => s.posts), postsEchoed: sum(s => s.postsEchoed), authors: sum(s => s.authors),
    cpuLagMs: avg(s => s.cpuLagMs), warmupMs: avg(s => s.warmupMs), baseline: avg(s => s.baseline),
    pGuardAdv, pGuardAdvPosts: avg(s => s.pGuardAdvPosts), pM1Adv: avg(s => s.pM1Adv),
    pStrictPerPost: avg(s => s.pStrictPerPost), qStrictGivenGuardAdv: q,
    pLearnK, pLearnKEmpirical: { 1: null, 10: null, 50: null },
    anonSetGivenAdvM1: avg(s => s.anonSetGivenAdvM1, s => s.posts * s.pM1Adv),
    guardClients: avg(s => s.guardClients, () => 1),
    heuristicStemOrGossip: heur(s => s.heuristicStemOrGossip),
    heuristicGossipOnly: heur(s => s.heuristicGossipOnly),
    timing,
    walk: {
      mean: avg(s => s.walk.mean), hist: mergeHist(s => s.walk.hist), p50: avg(s => s.walk.p50), p95: avg(s => s.walk.p95),
      expectedMean: first.walk.expectedMean,
    },
    delivery: {
      p50: avg(s => s.delivery.p50), p95: avg(s => s.delivery.p95), p50Reach95: avg(s => s.delivery.p50Reach95),
      meanReachFraction: avg(s => s.delivery.meanReachFraction),
      tFirstFlood: { p50: avg(s => s.delivery.tFirstFlood.p50), p95: avg(s => s.delivery.tFirstFlood.p95) },
    },
    distance: {
      authorToFluffer: avg(s => s.distance.authorToFluffer), m1ToFluffer: avg(s => s.distance.m1ToFluffer),
      guardToFluffer: avg(s => s.distance.guardToFluffer), randomPair: avg(s => s.distance.randomPair, () => 1),
      pFlufferIsNeighborOfAuthor: avg(s => s.distance.pFlufferIsNeighborOfAuthor),
      pFlufferWithin2OfAuthor: avg(s => s.distance.pFlufferWithin2OfAuthor),
      hist: mergeHist(s => s.distance.hist),
    },
    m1Repeat: avg(s => s.m1Repeat),
    invariants: {
      authorFirstGossip: sum(s => s.invariants.authorFirstGossip), m1ToGuard: sum(s => s.invariants.m1ToGuard),
      guardSawClearFromAuthor: sum(s => s.invariants.guardSawClearFromAuthor),
      guardSawClearTotal: sum(s => s.invariants.guardSawClearTotal),
      authorStemBeforeFirstStemRecv: sum(s => s.invariants.authorStemBeforeFirstStemRecv),
      postsWithoutStem: sum(s => s.invariants.postsWithoutStem),
    },
  };
}

/** worlds 個の網を作り直して統合する */
export async function runMany(params: SimParams, label: string, worlds: number): Promise<{ summary: Summary; wallMs: number }> {
  const t0 = now();
  const list: Summary[] = [];
  for (let i = 0; i < worlds; i++) {
    const { summary } = await runConfig({ ...params, seed: params.seed + i * 7777 }, label);
    list.push(summary);
  }
  return { summary: mergeSummaries(list), wallMs: now() - t0 };
}
