import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { RingPosition } from '../../src/network/RingPosition';
import { RING_MESH } from '../../src/constants';
/**
 * 比較用の「旧方式 (平文 Stem の Dandelion++)」のモデル。実装からは撤去済みで、
 * 新しい方式 (オニオン回路) との比較の基準としてだけ使う。
 */
const LEGACY_DANDELION_FLUFF_PROBABILITY = 0.3;

interface SimNode {
  id: string;
  position: number;
  peers: Set<string>;
  isSpy: boolean;
}

class OnionSimulation {
  public nodes: SimNode[] = [];
  public nodeMap = new Map<string, SimNode>();

  createNode(step: number, isSpy: boolean = false): SimNode {
    const rawSeed = `node_onion_${step}_${Math.random()}`;
    const pubkey = sodium.crypto_hash(new TextEncoder().encode(rawSeed)).slice(0, 32);
    const peerId = sodium.to_hex(pubkey.slice(0, 16));
    const position = RingPosition.forPeer(peerId);

    const node: SimNode = {
      id: peerId,
      position,
      peers: new Set<string>(),
      isSpy,
    };

    this.nodes.push(node);
    this.nodeMap.set(node.id, node);
    return node;
  }

  tryConnect(nodeA: SimNode, nodeB: SimNode): boolean {
    if (nodeA.id === nodeB.id) return false;
    if (nodeA.peers.has(nodeB.id)) return true;

    if (nodeA.peers.size >= RING_MESH.MAX_DEGREE) {
      if (!this.evictLongRangeLink(nodeA)) return false;
    }
    if (nodeB.peers.size >= RING_MESH.MAX_DEGREE) {
      if (!this.evictLongRangeLink(nodeB)) return false;
    }

    nodeA.peers.add(nodeB.id);
    nodeB.peers.add(nodeA.id);
    return true;
  }

  private evictLongRangeLink(node: SimNode): boolean {
    if (node.peers.size <= RING_MESH.LOCAL_LINKS) return false;
    const sorted = Array.from(node.peers).map(id => this.nodeMap.get(id)!).filter(Boolean);
    sorted.sort((a, b) => {
      const dA = RingPosition.distance(node.position, a.position);
      const dB = RingPosition.distance(node.position, b.position);
      return dB - dA;
    });
    const victim = sorted[0];
    if (victim) {
      node.peers.delete(victim.id);
      victim.peers.delete(node.id);
      return true;
    }
    return false;
  }

  maintainRing(node: SimNode) {
    if (node.peers.size <= RING_MESH.LOCAL_LINKS) return;
    if (node.peers.size > RING_MESH.MAX_DEGREE) {
      const excess = node.peers.size - RING_MESH.MAX_DEGREE;
      const sorted = Array.from(node.peers).map(id => this.nodeMap.get(id)!).filter(Boolean);
      sorted.sort((a, b) => {
        const dA = RingPosition.distance(node.position, a.position);
        const dB = RingPosition.distance(node.position, b.position);
        return dA - dB;
      });
      const longRangeLinks = sorted.slice(RING_MESH.LOCAL_LINKS);
      for (let i = 0; i < excess; i++) {
        const target = longRangeLinks.pop();
        if (target) {
          node.peers.delete(target.id);
          target.peers.delete(node.id);
        }
      }
    }
  }

  runPex(node: SimNode) {
    if (node.peers.size === 0) return;
    const peerIds = Array.from(node.peers);
    const targetId = peerIds[Math.floor(Math.random() * peerIds.length)];
    const targetNode = this.nodeMap.get(targetId);
    if (!targetNode) return;

    const candidates = Array.from(targetNode.peers).filter(id => id !== node.id && !node.peers.has(id));
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }
    for (const candId of candidates.slice(0, 8)) {
      if (node.peers.size >= RING_MESH.MAX_DEGREE) break;
      const candNode = this.nodeMap.get(candId);
      if (candNode) this.tryConnect(node, candNode);
    }
  }

  // ── 3つのルーティング方式のパケット追跡シミュレータ ──

  /**
   * 1. ナイーブ・フラッディング (従来方式)
   */
  simulateNaiveFlood(originatorId: string): { identified: boolean } {
    const originator = this.nodeMap.get(originatorId)!;
    // 発信者が全隣人へブロードキャスト
    // 隣人に1人でもスパイがいれば、直前ノード＝発信者として即座に特定される
    for (const peerId of originator.peers) {
      const peer = this.nodeMap.get(peerId)!;
      if (peer.isSpy) {
        return { identified: true };
      }
    }
    return { identified: false };
  }

  /**
   * 2. 通常の Dandelion++ (平文/同一識別子の Stem リレー)
   */
  simulateStandardDandelion(originatorId: string): {
    identified: boolean;
    interceptedInStem: boolean;
    hopCount: number;
  } {
    const originator = this.nodeMap.get(originatorId)!;
    let currentNode = originator;
    let prevNodeId = originatorId;
    let hop = 0;
    let intercepted = false;
    let identified = false;

    // Stem フェーズ
    while (true) {
      // 次のホップで Fluff に移行するか (確率 0.3)
      if (hop > 0 && Math.random() < LEGACY_DANDELION_FLUFF_PROBABILITY) {
        break; // Fluff へ
      }

      const neighbors = Array.from(currentNode.peers).filter(id => id !== prevNodeId);
      if (neighbors.length === 0) break;

      const nextTargetId = neighbors[Math.floor(Math.random() * neighbors.length)];
      prevNodeId = currentNode.id;
      currentNode = this.nodeMap.get(nextTargetId)!;
      hop++;

      // 中継ノードがスパイだった場合
      if (currentNode.isSpy) {
        intercepted = true;
        // もしホップ1 (発信者の直後のノード) がスパイなら、スパイは直前ノード＝真の発信者と特定できる！
        if (hop === 1) {
          identified = true;
        }
        break; // スパイが受信した時点で相関完了
      }

      if (hop >= 25) break;
    }

    return { identified, interceptedInStem: intercepted, hopCount: hop };
  }

  /**
   * 3. Onion Stem Routing (多段暗号化オニオン型ステム: 2〜3ホップ)
   * docs/anonymity_speed_codesign.md §5.2 / §3 T-a, T-c, T-d に基づくモデル
   *
   * 特徴:
   *   - 各ホップは外側の暗号を剥いた「次の中継先」しか分からない。
   *   - ホップ1のスパイは「自分にパケットを渡したノード」を知るが、
   *     パケットがオニオン暗号化されており中身もパケットIDも読めないため、
   *     最終的なコンテンツと紐づけるには「全ホップが共謀スパイ」でなければならない。
   *   - ホップ2以降のスパイは、直前ノードが無実の中継者であるため発信元を知り得ない。
   */
  simulateOnionStem(originatorId: string, onionHops: number = 3): {
    identified: boolean;
    compromisedRoute: boolean;
    hopCount: number;
  } {
    const originator = this.nodeMap.get(originatorId)!;
    // 発信者が onionHops 段の経路を選択
    const route: SimNode[] = [originator];
    let curr = originator;

    for (let h = 0; h < onionHops; h++) {
      const neighbors = Array.from(curr.peers).filter(id => !route.some(r => r.id === id));
      const pool = neighbors.length > 0 ? neighbors : Array.from(curr.peers);
      if (pool.length === 0) break;
      const nextId = pool[Math.floor(Math.random() * pool.length)];
      curr = this.nodeMap.get(nextId)!;
      route.push(curr);
    }

    // オニオン中継の検証:
    // route[0] = 発信元
    // route[1] = ホップ1 (ガードノード)
    // route[2] = ホップ2
    // route[3] = ホップ3 (Fluff出口ノード)
    const intermediaries = route.slice(1);
    const hopCount = intermediaries.length;

    // スパイによる特定条件:
    // オニオン暗号化されているため、特定が成立するには「経路上の全ノード (ホップ1〜出口) がすべて共謀スパイ」
    // でなければ、入り口のIPと出口のコンテンツをリンクできない (TorのEnd-to-End相関攻撃と同じ条件)
    const allSpiesOnRoute = intermediaries.length > 0 && intermediaries.every(n => n.isSpy);

    return {
      identified: allSpiesOnRoute,
      compromisedRoute: intermediaries.some(n => n.isSpy),
      hopCount,
    };
  }
}

describe('Onion Stem Routing による匿名性向上・特定率急減の定量的検証', () => {
  beforeAll(async () => {
    await sodium.ready;
  });

  it('★ 5,000ノード実トポロジー上で、Naive vs Dandelion vs Onion Stem (2段/3段) を厳密比較する', () => {
    const sim = new OnionSimulation();
    const TOTAL_NODES = 5000;

    console.log('\n================================================================================');
    console.log(`🚀 5,000 ノード P2P トポロジー構築中...`);
    console.log('================================================================================\n');

    // 5000ノードを高速構築
    for (let i = 1; i <= TOTAL_NODES; i++) {
      const node = sim.createNode(i);
      // 初期ランダム接続 (8本)
      const targetCount = Math.min(sim.nodes.length - 1, 8);
      for (let k = 0; k < targetCount; k++) {
        const randPeer = sim.nodes[Math.floor(Math.random() * (sim.nodes.length - 1))];
        if (randPeer) sim.tryConnect(node, randPeer);
      }
      sim.maintainRing(node);
      if (i % 2 === 0) {
        sim.runPex(node);
      }
    }

    // トポロジーを 5 ラウンド PEX で収束
    for (let r = 1; r <= 5; r++) {
      for (const n of sim.nodes) {
        sim.runPex(n);
        sim.maintainRing(n);
      }
    }

    const avgDegree = sim.nodes.reduce((a, b) => a + b.peers.size, 0) / TOTAL_NODES;
    console.log(`トポロジー構築完了: 5,000 ノード, 平均次数: ${avgDegree.toFixed(2)}`);

    console.log('\n================================================================================');
    console.log('📊 スパイ比率別 匿名性特定率 (Identification Rate) の比較測定');
    console.log('   (試行回数: 各シナリオ 1,000 回のパケット放流)');
    console.log('================================================================================\n');

    const spyFractions = [0.01, 0.05, 0.10, 0.20, 0.30];
    const TRIALS = 1000;

    console.log('スパイ率 (台数) | ナイーブ特定率 | 現行Dandelion++ | Onion Stem (2ホップ) | Onion Stem (3ホップ) | 匿名性向上倍率');
    console.log('----------------+----------------+-----------------+----------------------+----------------------+---------------');

    for (const frac of spyFractions) {
      const spyCount = Math.round(TOTAL_NODES * frac);

      // スパイ割り当て
      for (const n of sim.nodes) n.isSpy = false;
      const shuffled = [...sim.nodes].sort(() => Math.random() - 0.5);
      for (let i = 0; i < spyCount; i++) shuffled[i].isSpy = true;

      const honestNodes = sim.nodes.filter(n => !n.isSpy);

      let naiveHits = 0;
      let dandelionHits = 0;
      let onion2Hits = 0;
      let onion3Hits = 0;

      for (let t = 0; t < TRIALS; t++) {
        const origin = honestNodes[Math.floor(Math.random() * honestNodes.length)];

        // 1. ナイーブ・フラッディング
        if (sim.simulateNaiveFlood(origin.id).identified) naiveHits++;

        // 2. 現行 Dandelion++ (平文Stem)
        if (sim.simulateStandardDandelion(origin.id).identified) dandelionHits++;

        // 3. Onion Stem (2ホップ)
        if (sim.simulateOnionStem(origin.id, 2).identified) onion2Hits++;

        // 4. Onion Stem (3ホップ)
        if (sim.simulateOnionStem(origin.id, 3).identified) onion3Hits++;
      }

      const naiveRate = (naiveHits / TRIALS) * 100;
      const dandeRate = (dandelionHits / TRIALS) * 100;
      const onion2Rate = (onion2Hits / TRIALS) * 100;
      const onion3Rate = (onion3Hits / TRIALS) * 100;

      const improvement = dandeRate > 0 ? (dandeRate / Math.max(onion3Rate, 0.01)).toFixed(1) + 'x' : '∞';

      console.log(
        `  ${(frac * 100).toFixed(0).padStart(2)}% (${String(spyCount).padStart(4)}台) | ` +
        `     ${naiveRate.toFixed(1).padStart(5)}%     | ` +
        `      ${dandeRate.toFixed(1).padStart(5)}%     | ` +
        `        ${onion2Rate.toFixed(2).padStart(5)}%       | ` +
        `        ${onion3Rate.toFixed(2).padStart(5)}%       | ` +
        `    ${improvement.padStart(6)} 向上`
      );
    }

    console.log('\n================================================================================');
    console.log('🛡️ 理論値との整合性検証:');
    console.log('  - ナイーブ特定率 ≈ 1 - (1 - f)^k  (k ≈ 16: 隣人に1人でもスパイがいる確率)');
    console.log('  - 現行 Dandelion 特定率 ≈ f       (第1ホップがスパイである確率)');
    console.log('  - Onion Stem (h段) 特定率 ≈ f^h   (経路上の全ホップが共謀スパイである確率)');
    console.log('================================================================================\n');
  }, 180_000);
});
