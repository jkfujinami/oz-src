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
  trackerContactCount: number;
  isSpy: boolean;
  joinedAtStep: number;
  isTrackerConnected: boolean;
}

class SimTracker {
  private sessions = new Map<string, SimNode>();
  public totalReferrals = 0;
  public readonly MAX_SESSIONS = 5000;

  join(node: SimNode): { peers: string[]; accepted: boolean } {
    if (this.sessions.size >= this.MAX_SESSIONS) {
      return { peers: [], accepted: false };
    }

    const allIds = Array.from(this.sessions.keys()).filter((id) => id !== node.id);

    // Fisher-Yates shuffle
    for (let i = allIds.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [allIds[i], allIds[j]] = [allIds[j], allIds[i]];
    }

    const selected = allIds.slice(0, 8) /* トラッカーが最初に渡すピア数 */;
    for (const id of selected) {
      const peer = this.sessions.get(id);
      if (peer) {
        peer.trackerContactCount++;
        this.totalReferrals++;
      }
    }

    this.sessions.set(node.id, node);
    node.isTrackerConnected = true;
    return { peers: selected, accepted: true };
  }

  leave(nodeId: string) {
    const node = this.sessions.get(nodeId);
    if (node) {
      node.isTrackerConnected = false;
      this.sessions.delete(nodeId);
    }
  }

  get size(): number {
    return this.sessions.size;
  }
}

class NetworkSimulation5000 {
  public nodes: SimNode[] = [];
  public nodeMap = new Map<string, SimNode>();
  public tracker = new SimTracker();

  createNode(step: number, isSpy: boolean = false): SimNode {
    const rawSeed = `node5000_${step}_${Math.random()}`;
    const pubkey = sodium.crypto_hash(new TextEncoder().encode(rawSeed)).slice(0, 32);
    const peerId = sodium.to_hex(pubkey.slice(0, 16));
    const position = RingPosition.forPeer(peerId);

    const node: SimNode = {
      id: peerId,
      position,
      peers: new Set<string>(),
      trackerContactCount: 0,
      isSpy,
      joinedAtStep: step,
      isTrackerConnected: false,
    };

    this.nodes.push(node);
    this.nodeMap.set(node.id, node);
    return node;
  }

  tryConnect(nodeA: SimNode, nodeB: SimNode): boolean {
    if (nodeA.id === nodeB.id) return false;
    if (nodeA.peers.has(nodeB.id)) return true;

    if (nodeA.peers.size >= RING_MESH.MAX_DEGREE) {
      const evicted = this.evictLongRangeLink(nodeA);
      if (!evicted) return false;
    }

    if (nodeB.peers.size >= RING_MESH.MAX_DEGREE) {
      const evicted = this.evictLongRangeLink(nodeB);
      if (!evicted) return false;
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

    const offered = candidates.slice(0, 8);
    for (const candId of offered) {
      if (node.peers.size >= RING_MESH.MAX_DEGREE) break;
      const candNode = this.nodeMap.get(candId);
      if (candNode) this.tryConnect(node, candNode);
    }
  }

  // ── トポロジーメトリクス ──
  computeMetrics(sampleSize: number = 200) {
    const N = this.nodes.length;
    if (N === 0) return null;

    const degrees = this.nodes.map(n => n.peers.size);
    const sumDegree = degrees.reduce((a, b) => a + b, 0);
    const meanDegree = sumDegree / N;
    const minDegree = Math.min(...degrees);
    const maxDegree = Math.max(...degrees);
    const variance = degrees.reduce((acc, d) => acc + (d - meanDegree) ** 2, 0) / N;
    const stdDevDegree = Math.sqrt(variance);

    // 次数ジニ係数
    const sortedDeg = [...degrees].sort((a, b) => a - b);
    let giniNumerator = 0;
    for (let i = 0; i < N; i++) {
      giniNumerator += (2 * (i + 1) - N - 1) * sortedDeg[i];
    }
    const giniDegree = sumDegree > 0 ? giniNumerator / (N * sumDegree) : 0;

    // 連結成分 (BFS)
    const visited = new Set<string>();
    const components: number[] = [];
    for (const node of this.nodes) {
      if (!visited.has(node.id)) {
        let size = 0;
        const queue = [node.id];
        visited.add(node.id);
        while (queue.length > 0) {
          const currId = queue.shift()!;
          size++;
          const curr = this.nodeMap.get(currId);
          if (curr) {
            for (const peerId of curr.peers) {
              if (!visited.has(peerId)) {
                visited.add(peerId);
                queue.push(peerId);
              }
            }
          }
        }
        components.push(size);
      }
    }
    const maxComponentSize = Math.max(...components);
    const connectivityRatio = maxComponentSize / N;
    const isolatedNodes = degrees.filter(d => d === 0).length;

    // リング距離分布
    let totalDist = 0;
    let totalEdges = 0;
    let localLinksCount = 0;
    const distanceBins = [0, 0, 0, 0, 0];

    for (const node of this.nodes) {
      for (const peerId of node.peers) {
        if (node.id < peerId) {
          const peer = this.nodeMap.get(peerId)!;
          const d = RingPosition.distance(node.position, peer.position);
          totalDist += d;
          totalEdges++;
          if (d < 0.05) localLinksCount++;
          if (d < 0.05) distanceBins[0]++;
          else if (d < 0.1) distanceBins[1]++;
          else if (d < 0.2) distanceBins[2]++;
          else if (d < 0.35) distanceBins[3]++;
          else distanceBins[4]++;
        }
      }
    }
    const meanRingDist = totalEdges > 0 ? totalDist / totalEdges : 0;

    // 平均経路長と直径 (サンプリング BFS)
    const sampleNodes = this.nodes.slice(0, sampleSize);
    let totalHops = 0;
    let pathCount = 0;
    let diameter = 0;

    for (const start of sampleNodes) {
      const dist = new Map<string, number>();
      dist.set(start.id, 0);
      const queue = [start.id];
      while (queue.length > 0) {
        const u = queue.shift()!;
        const d = dist.get(u)!;
        const uNode = this.nodeMap.get(u)!;
        for (const v of uNode.peers) {
          if (!dist.has(v)) {
            dist.set(v, d + 1);
            queue.push(v);
            totalHops += d + 1;
            pathCount++;
            if (d + 1 > diameter) diameter = d + 1;
          }
        }
      }
    }
    const avgPathLength = pathCount > 0 ? totalHops / pathCount : 0;

    // クラスタリング係数
    let totalClusterCoeff = 0;
    let clusterEvaluated = 0;
    for (const node of sampleNodes) {
      const neighbors = Array.from(node.peers);
      const k = neighbors.length;
      if (k >= 2) {
        let triangles = 0;
        for (let i = 0; i < k; i++) {
          for (let j = i + 1; j < k; j++) {
            const u = this.nodeMap.get(neighbors[i]);
            if (u && u.peers.has(neighbors[j])) triangles++;
          }
        }
        totalClusterCoeff += (2 * triangles) / (k * (k - 1));
        clusterEvaluated++;
      }
    }
    const avgClusteringCoeff = clusterEvaluated > 0 ? totalClusterCoeff / clusterEvaluated : 0;

    return {
      N,
      totalEdges,
      meanDegree,
      minDegree,
      maxDegree,
      stdDevDegree,
      giniDegree,
      componentsCount: components.length,
      connectivityRatio,
      isolatedNodes,
      meanRingDist,
      localRatio: totalEdges > 0 ? localLinksCount / totalEdges : 0,
      longRangeRatio: totalEdges > 0 ? 1 - (localLinksCount / totalEdges) : 0,
      distanceBins,
      avgPathLength,
      diameter,
      avgClusteringCoeff,
    };
  }

  // ── スパイノード・パケット相関解析シミュレーション ──
  /**
   * 単一パケットの放流とスパイ観測シミュレーション
   *
   * @param originatorId 発信元ノードID
   * @param useDandelion true: Dandelion++ (Stem & Fluff), false: ナイーブフラッディング
   * @returns 攻撃者が推定した発信元ノードID (First-Spy-Observer)
   */
  simulatePacketBroadcast(originatorId: string, useDandelion: boolean): {
    estimatedOriginatorId: string | null;
    capturedAtHop: number | null;
    isFluffCaptured: boolean;
    stemLength: number;
  } {
    const originator = this.nodeMap.get(originatorId)!;
    const spyObserved = new Map<string, { senderId: string; hop: number; timestamp: number }>();
    let currentStep = 0;

    if (!useDandelion) {
      // ── ナイーブ・フラッディング: 発信者が全隣人へブロードキャスト ──
      const delivered = new Set<string>([originatorId]);
      const queue: Array<{ nodeId: string; senderId: string; hop: number }> = [];

      for (const peerId of originator.peers) {
        queue.push({ nodeId: peerId, senderId: originatorId, hop: 1 });
      }

      while (queue.length > 0) {
        const item = queue.shift()!;
        if (delivered.has(item.nodeId)) continue;
        delivered.add(item.nodeId);

        const node = this.nodeMap.get(item.nodeId)!;
        if (node.isSpy) {
          if (!spyObserved.has('first')) {
            spyObserved.set('first', { senderId: item.senderId, hop: item.hop, timestamp: currentStep });
          }
        }

        // フラッディング転送
        currentStep++;
        for (const nextPeerId of node.peers) {
          if (!delivered.has(nextPeerId)) {
            queue.push({ nodeId: nextPeerId, senderId: node.id, hop: item.hop + 1 });
          }
        }
      }

      const first = spyObserved.get('first');
      return {
        estimatedOriginatorId: first ? first.senderId : null,
        capturedAtHop: first ? first.hop : null,
        isFluffCaptured: true,
        stemLength: 0,
      };
    }

    // ── Dandelion++ ルーティング (OZ 実装忠実模倣) ──
    let currentNode = originator;
    let prevNodeId: string = originatorId;
    let stemHop = 0;
    let isFluff = false;
    let stemCapturedBySpy: { senderId: string; hop: number } | null = null;

    // Stem フェーズ (1本足リレー、幾何分布 p=0.3)
    while (!isFluff) {
      if (currentNode.isSpy) {
        // スパイが Stem 経路で受信！
        if (!stemCapturedBySpy) {
          stemCapturedBySpy = { senderId: prevNodeId, hop: stemHop };
        }
      }

      // 次のホップで Fluff に移行するか？ (LEGACY_DANDELION_FLUFF_PROBABILITY = 0.3)
      if (stemHop > 0 && Math.random() < LEGACY_DANDELION_FLUFF_PROBABILITY) {
        isFluff = true;
        break;
      }

      // 送信元を除いた隣人からランダムに1人選んで Stem 転送
      const neighbors = Array.from(currentNode.peers).filter(id => id !== prevNodeId);
      if (neighbors.length === 0) {
        isFluff = true;
        break;
      }

      const nextTargetId = neighbors[Math.floor(Math.random() * neighbors.length)];
      prevNodeId = currentNode.id;
      currentNode = this.nodeMap.get(nextTargetId)!;
      stemHop++;

      if (stemHop >= 30) {
        isFluff = true; // 安全リミット
        break;
      }
    }

    // Fluff フェーズ (currentNode から全隣人へフラッディング)
    const delivered = new Set<string>([currentNode.id]);
    const queue: Array<{ nodeId: string; senderId: string; hop: number }> = [];
    for (const peerId of currentNode.peers) {
      queue.push({ nodeId: peerId, senderId: currentNode.id, hop: stemHop + 1 });
    }

    while (queue.length > 0) {
      const item = queue.shift()!;
      if (delivered.has(item.nodeId)) continue;
      delivered.add(item.nodeId);

      const node = this.nodeMap.get(item.nodeId)!;
      if (node.isSpy) {
        if (!spyObserved.has('first')) {
          spyObserved.set('first', { senderId: item.senderId, hop: item.hop, timestamp: currentStep });
        }
      }

      currentStep++;
      for (const nextPeerId of node.peers) {
        if (!delivered.has(nextPeerId)) {
          queue.push({ nodeId: nextPeerId, senderId: node.id, hop: item.hop + 1 });
        }
      }
    }

    // 攻撃者の推定:
    // もし Stem 経路でスパイがパケットを受信していたら、その直前ノードを最有力容疑者とする。
    // Stem で捕捉できず Fluff 後に初めて捕捉した場合、Fluff で最初にパケットを渡してきたノードを推定する。
    if (stemCapturedBySpy) {
      return {
        estimatedOriginatorId: stemCapturedBySpy.senderId,
        capturedAtHop: stemCapturedBySpy.hop,
        isFluffCaptured: false,
        stemLength: stemHop,
      };
    }

    const firstFluff = spyObserved.get('first');
    return {
      estimatedOriginatorId: firstFluff ? firstFluff.senderId : null,
      capturedAtHop: firstFluff ? firstFluff.hop : null,
      isFluffCaptured: true,
      stemLength: stemHop,
    };
  }
}

describe('5000ノード大規模網収束 ＆ スパイノード匿名性相関分析シミュレーション', () => {
  beforeAll(async () => {
    await sodium.ready;
  });

  it('★ 1~5000ノード逐次参加、トポロジー偏り検証、スパイノード相関による匿名性限界測定', () => {
    const sim = new NetworkSimulation5000();
    const milestones = [100, 500, 1000, 2500, 5000];

    console.log('\n================================================================================');
    console.log('🚀 OZ P2P ネットワーク 1~5000 ノード 逐次参加＆トポロジー検証');
    console.log('================================================================================\n');

    // 5000 ノードの逐次参加ループ
    for (let step = 1; step <= 5000; step++) {
      const newNode = sim.createNode(step, false);

      const { peers: trackerPeers } = sim.tracker.join(newNode);
      for (const peerId of trackerPeers) {
        const peerNode = sim.nodeMap.get(peerId);
        if (peerNode) sim.tryConnect(newNode, peerNode);
      }

      sim.runPex(newNode);
      sim.maintainRing(newNode);

      // 既参加ノードのバックグラウンド PEX (間引き実行で高速化)
      if (step % 2 === 0) {
        const randNode = sim.nodes[Math.floor(Math.random() * sim.nodes.length)];
        sim.runPex(randNode);
        sim.maintainRing(randNode);
      }

      // トラッカー退去
      if (step > 40) {
        const matureNode = sim.nodes[step - 40];
        if (matureNode.isTrackerConnected) sim.tracker.leave(matureNode.id);
      }

      if (milestones.includes(step)) {
        const m = sim.computeMetrics(150)!;
        console.log(
          `[N=${String(step).padStart(4)}] 連結率:${(m.connectivityRatio * 100).toFixed(1)}% | ` +
          `平均次数:${m.meanDegree.toFixed(2)} (範囲 ${m.minDegree}-${m.maxDegree}, σ=${m.stdDevDegree.toFixed(2)}) | ` +
          `平均経路長:${m.avgPathLength.toFixed(2)} (直径 ${m.diameter}) | ` +
          `クラスタ係数:${m.avgClusteringCoeff.toFixed(3)} | ` +
          `局所率:${(m.localRatio * 100).toFixed(1)}%`
        );
      }
    }

    console.log('\n--- 5000ノード到達後: 自律収束（Relaxation 10 ラウンド）---');
    for (const node of sim.nodes) sim.tracker.leave(node.id);

    for (let round = 1; round <= 10; round++) {
      // サンプリングでPEX実行
      for (const node of sim.nodes) {
        sim.runPex(node);
        sim.maintainRing(node);
      }
      if (round % 5 === 0) {
        const m = sim.computeMetrics(200)!;
        console.log(
          `[収束Round ${String(round).padStart(2)}] 連結率:${(m.connectivityRatio * 100).toFixed(1)}% | ` +
          `平均次数:${m.meanDegree.toFixed(2)} (範囲 ${m.minDegree}-${m.maxDegree}, 次数Gini=${m.giniDegree.toFixed(3)}) | ` +
          `経路長:${m.avgPathLength.toFixed(2)} (直径 ${m.diameter}) | ` +
          `クラスタ係数:${m.avgClusteringCoeff.toFixed(3)} | ` +
          `局所率:${(m.localRatio * 100).toFixed(1)}%`
        );
      }
    }

    const m5000 = sim.computeMetrics(250)!;
    console.log('\n================================================================================');
    console.log('📊 5000ノード 最終トポロジー測定結果');
    console.log('================================================================================');
    console.log(`総ノード数:              ${m5000.N}`);
    console.log(`総エッジ数:              ${m5000.totalEdges}`);
    console.log(`平均次数 (Mean Degree):   ${m5000.meanDegree.toFixed(2)} / 上限 16`);
    console.log(`次数範囲 (Min - Max):     ${m5000.minDegree} - ${m5000.maxDegree} (σ = ${m5000.stdDevDegree.toFixed(2)})`);
    console.log(`次数のジニ係数:           ${m5000.giniDegree.toFixed(4)}`);
    console.log(`最大連結成分割合:         ${(m5000.connectivityRatio * 100).toFixed(2)}% (孤立ノード: ${m5000.isolatedNodes})`);
    console.log(`平均最短経路長 (Hops):   ${m5000.avgPathLength.toFixed(2)}`);
    console.log(`ネットワーク直径 (Hops): ${m5000.diameter}`);
    console.log(`平均クラスタリング係数:   ${m5000.avgClusteringCoeff.toFixed(4)}`);
    console.log(`平均リンクリング距離:     ${m5000.meanRingDist.toFixed(4)}`);
    console.log(`ローカル / ロング比率:   局所 ${(m5000.localRatio * 100).toFixed(1)}% / ロングレンジ ${(m5000.longRangeRatio * 100).toFixed(1)}%`);

    console.log('\nリンク距離の空間ヒストグラム [0, 0.5]:');
    const binLabels = ['[0, 0.05) 超近傍', '[0.05, 0.1) 近傍', '[0.1, 0.2) 中距離', '[0.2, 0.35) 準対角', '[0.35, 0.5] 完全対角'];
    for (let i = 0; i < 5; i++) {
      const pct = ((m5000.distanceBins[i] / m5000.totalEdges) * 100).toFixed(1);
      const bar = '█'.repeat(Math.round(Number(pct) / 2));
      console.log(`  ${binLabels[i].padEnd(18)} : ${String(m5000.distanceBins[i]).padStart(6)} 件 (${pct.padStart(5)}%) ${bar}`);
    }

    // ── スパイノード混入＆パケット相関解析 ──
    console.log('\n================================================================================');
    console.log('🕵️ スパイノード混入＆パケット相関・匿名性崩壊度合いの定量的測定 (Attack Analysis)');
    console.log('================================================================================\n');

    const spyFractions = [0.01, 0.05, 0.10, 0.20, 0.30];
    const TEST_PACKET_COUNT = 500;

    console.log('スパイ割合 | 試行回数 | ナイーブ特定率 | Dandelion特定率 | 冤罪率(False Alarm) | Stem迎撃率');
    console.log('-----------+----------+----------------+-----------------+---------------------+-----------');

    for (const frac of spyFractions) {
      const spyCount = Math.round(5000 * frac);
      // ランダムに spyCount 個のノードをスパイに指定
      for (const n of sim.nodes) n.isSpy = false;
      const shuffled = [...sim.nodes].sort(() => Math.random() - 0.5);
      for (let i = 0; i < spyCount; i++) shuffled[i].isSpy = true;

      const honestNodes = sim.nodes.filter(n => !n.isSpy);

      // A. ナイーブ・フラッディングの特定率
      let naiveCorrect = 0;
      for (let t = 0; t < TEST_PACKET_COUNT; t++) {
        const origin = honestNodes[Math.floor(Math.random() * honestNodes.length)];
        const result = sim.simulatePacketBroadcast(origin.id, false);
        if (result.estimatedOriginatorId === origin.id) {
          naiveCorrect++;
        }
      }
      const naiveAccuracy = (naiveCorrect / TEST_PACKET_COUNT) * 100;

      // B. Dandelion++ (OZ現行) の特定率
      let dandelionCorrect = 0;
      let dandelionFalsePositive = 0; // スパイが別ノードを発信者と誤認
      let stemIntercepted = 0;

      for (let t = 0; t < TEST_PACKET_COUNT; t++) {
        const origin = honestNodes[Math.floor(Math.random() * honestNodes.length)];
        const result = sim.simulatePacketBroadcast(origin.id, true);

        if (!result.isFluffCaptured) {
          stemIntercepted++;
        }

        if (result.estimatedOriginatorId === origin.id) {
          dandelionCorrect++;
        } else if (result.estimatedOriginatorId !== null) {
          dandelionFalsePositive++;
        }
      }

      const dandelionAccuracy = (dandelionCorrect / TEST_PACKET_COUNT) * 100;
      const falseAlarmRate = (dandelionFalsePositive / TEST_PACKET_COUNT) * 100;
      const stemInterceptRate = (stemIntercepted / TEST_PACKET_COUNT) * 100;

      console.log(
        `  ${(frac * 100).toFixed(0).padStart(2)}% (${String(spyCount).padStart(4)}台) | ` +
        `  ${TEST_PACKET_COUNT}件  | ` +
        `    ${naiveAccuracy.toFixed(1).padStart(5)}%     | ` +
        `     ${dandelionAccuracy.toFixed(1).padStart(5)}%      | ` +
        `       ${falseAlarmRate.toFixed(1).padStart(5)}%        | ` +
        `  ${stemInterceptRate.toFixed(1).padStart(5)}%`
      );
    }

    // 基本アサーション
    expect(m5000.connectivityRatio).toBe(1.0);
    expect(m5000.isolatedNodes).toBe(0);
    expect(m5000.meanDegree).toBeGreaterThanOrEqual(12);
    expect(m5000.diameter).toBeLessThanOrEqual(15);
  }, 360_000);
});
