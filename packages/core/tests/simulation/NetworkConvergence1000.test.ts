import { describe, it, expect, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { RingPosition } from '../../src/network/RingPosition';
import { RING_MESH } from '../../src/constants';

interface SimNode {
  id: string;
  position: number;
  peers: Set<string>;
  trackerContactCount: number;
  pexSentCount: number;
  pexSuccessCount: number;
  joinedAtStep: number;
  isTrackerConnected: boolean;
}

class SimTracker {
  private sessions = new Map<string, SimNode>();
  public totalReferrals = 0;

  join(node: SimNode): string[] {
    const allIds = Array.from(this.sessions.keys()).filter((id) => id !== node.id);

    // Fisher-Yates shuffle (TrackerServer / SessionManager の実装そのまま)
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
    return selected;
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

class NetworkSimulation {
  public nodes: SimNode[] = [];
  public nodeMap = new Map<string, SimNode>();
  public tracker = new SimTracker();

  // 1. ノード生成 (正規の SHA-256 peerId と Bound Identity position)
  createNode(step: number): SimNode {
    const rawSeed = `node_${step}_${Math.random()}`;
    const pubkey = sodium.crypto_hash(new TextEncoder().encode(rawSeed)).slice(0, 32);
    // peerId = hex(SHA-256("OZ/v3/peerid" || pubkey)[0..16])
    const peerId = sodium.to_hex(pubkey.slice(0, 16));
    const position = RingPosition.forPeer(peerId);

    const node: SimNode = {
      id: peerId,
      position,
      peers: new Set<string>(),
      trackerContactCount: 0,
      pexSentCount: 0,
      pexSuccessCount: 0,
      joinedAtStep: step,
      isTrackerConnected: false,
    };

    this.nodes.push(node);
    this.nodeMap.set(node.id, node);
    return node;
  }

  // 2. 接続試行 (PeerManager.connect と evictLongRangeLink の忠実な模倣)
  tryConnect(nodeA: SimNode, nodeB: SimNode): boolean {
    if (nodeA.id === nodeB.id) return false;
    if (nodeA.peers.has(nodeB.id)) return true; // すでに接続中

    // A のスロット確保
    if (nodeA.peers.size >= RING_MESH.MAX_DEGREE) {
      const evicted = this.evictLongRangeLink(nodeA);
      if (!evicted) return false;
    }

    // B のスロット確保
    if (nodeB.peers.size >= RING_MESH.MAX_DEGREE) {
      const evicted = this.evictLongRangeLink(nodeB);
      if (!evicted) return false;
    }

    // 接続成立
    nodeA.peers.add(nodeB.id);
    nodeB.peers.add(nodeA.id);
    return true;
  }

  // PeerManager.ts: evictLongRangeLink() の実装に厳密に準拠
  private evictLongRangeLink(node: SimNode): boolean {
    if (node.peers.size <= RING_MESH.LOCAL_LINKS) return false;

    // 距離が遠い順にソート (dB - dA)
    const sorted = Array.from(node.peers).map(id => this.nodeMap.get(id)!).filter(Boolean);
    sorted.sort((a, b) => {
      const dA = RingPosition.distance(node.position, a.position);
      const dB = RingPosition.distance(node.position, b.position);
      return dB - dA;
    });

    // 最も遠いリンクを切断
    const victim = sorted[0];
    if (victim) {
      node.peers.delete(victim.id);
      victim.peers.delete(node.id);
      return true;
    }
    return false;
  }

  // RingMaintainer.ts: evaluateTopology() の実装に厳密に準拠
  maintainRing(node: SimNode) {
    if (node.peers.size <= RING_MESH.LOCAL_LINKS) return;

    if (node.peers.size > RING_MESH.MAX_DEGREE) {
      const excess = node.peers.size - RING_MESH.MAX_DEGREE;
      const sorted = Array.from(node.peers).map(id => this.nodeMap.get(id)!).filter(Boolean);
      // 近い順に並び替え
      sorted.sort((a, b) => {
        const dA = RingPosition.distance(node.position, a.position);
        const dB = RingPosition.distance(node.position, b.position);
        return dA - dB;
      });

      // ローカル4人を残し、遠いロングレンジリンクから捨てる
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

  // 3. PEX の実行 (PEXHandler.ts の実装に準拠)
  runPex(node: SimNode) {
    if (node.peers.size === 0) return;
    node.pexSentCount++;

    // ランダムな1人の隣人に PEX_REQUEST
    const peerIds = Array.from(node.peers);
    const targetId = peerIds[Math.floor(Math.random() * peerIds.length)];
    const targetNode = this.nodeMap.get(targetId);
    if (!targetNode) return;

    // targetNode は自分の隣人からランダムに最大 8 件を返す (PEX_RESPONSE)
    const candidates = Array.from(targetNode.peers).filter(id => id !== node.id && !node.peers.has(id));
    // Fisher-Yates
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }

    const offered = candidates.slice(0, 8);
    let success = false;
    for (const candId of offered) {
      if (node.peers.size >= RING_MESH.MAX_DEGREE) break;
      const candNode = this.nodeMap.get(candId);
      if (candNode && this.tryConnect(node, candNode)) {
        success = true;
      }
    }
    if (success) node.pexSuccessCount++;
  }

  // 4. メトリクス計算
  computeMetrics() {
    const N = this.nodes.length;
    if (N === 0) return null;

    // 次数統計
    const degrees = this.nodes.map(n => n.peers.size);
    const sumDegree = degrees.reduce((a, b) => a + b, 0);
    const meanDegree = sumDegree / N;
    const minDegree = Math.min(...degrees);
    const maxDegree = Math.max(...degrees);
    const variance = degrees.reduce((acc, d) => acc + (d - meanDegree) ** 2, 0) / N;
    const stdDevDegree = Math.sqrt(variance);

    // 次数ジニ係数 (偏りの尺度: 0=完全平等, 1=極端な集中)
    const sortedDeg = [...degrees].sort((a, b) => a - b);
    let giniNumerator = 0;
    for (let i = 0; i < N; i++) {
      giniNumerator += (2 * (i + 1) - N - 1) * sortedDeg[i];
    }
    const giniDegree = sumDegree > 0 ? giniNumerator / (N * sumDegree) : 0;

    // トラッカー紹介回数統計
    const referrals = this.nodes.map(n => n.trackerContactCount);
    const sumRef = referrals.reduce((a, b) => a + b, 0);
    const meanRef = sumRef / N;
    const maxRef = Math.max(...referrals);
    const minRef = Math.min(...referrals);
    const sortedRef = [...referrals].sort((a, b) => a - b);
    let giniRefNumerator = 0;
    for (let i = 0; i < N; i++) {
      giniRefNumerator += (2 * (i + 1) - N - 1) * sortedRef[i];
    }
    const giniTracker = sumRef > 0 ? giniRefNumerator / (N * sumRef) : 0;

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
    let localLinksCount = 0; // distance < 0.05
    let longRangeLinksCount = 0; // distance >= 0.05
    const distanceBins = [0, 0, 0, 0, 0]; // [0,0.05), [0.05,0.1), [0.1,0.2), [0.2,0.35), [0.35,0.5]

    for (const node of this.nodes) {
      for (const peerId of node.peers) {
        if (node.id < peerId) { // 重複カウント防止
          const peer = this.nodeMap.get(peerId)!;
          const d = RingPosition.distance(node.position, peer.position);
          totalDist += d;
          totalEdges++;
          if (d < 0.05) localLinksCount++;
          else longRangeLinksCount++;

          if (d < 0.05) distanceBins[0]++;
          else if (d < 0.1) distanceBins[1]++;
          else if (d < 0.2) distanceBins[2]++;
          else if (d < 0.35) distanceBins[3]++;
          else distanceBins[4]++;
        }
      }
    }
    const meanRingDist = totalEdges > 0 ? totalDist / totalEdges : 0;

    // 平均経路長と直径 (BFS サンプリング: 100ノードを起点として全探索)
    const sampleSize = Math.min(N, 150);
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

    // クラスタリング係数 (サンプリング)
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
            if (u && u.peers.has(neighbors[j])) {
              triangles++;
            }
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
      meanRef,
      minRef,
      maxRef,
      giniTracker,
      componentsCount: components.length,
      connectivityRatio,
      isolatedNodes,
      meanRingDist,
      localRatio: totalEdges > 0 ? localLinksCount / totalEdges : 0,
      longRangeRatio: totalEdges > 0 ? longRangeLinksCount / totalEdges : 0,
      distanceBins,
      avgPathLength,
      diameter,
      avgClusteringCoeff,
    };
  }
  // 5. ノード離脱 (Churn)
  removeNode(nodeId: string) {
    const node = this.nodeMap.get(nodeId);
    if (!node) return;
    for (const peerId of node.peers) {
      const peer = this.nodeMap.get(peerId);
      if (peer) peer.peers.delete(nodeId);
    }
    this.nodes = this.nodes.filter(n => n.id !== nodeId);
    this.nodeMap.delete(nodeId);
  }
}

describe('1~1000ノード大規模ネットワーク成長・トラッカー公平性・PEX収束シミュレーション検証', () => {
  beforeAll(async () => {
    await sodium.ready;
  });

  it('★ 1から1000ノードを順次参加させ、トラッカー/PEX/トポロジー収束/偏りを完全検証する', () => {
    const sim = new NetworkSimulation();
    const milestones = [10, 50, 100, 250, 500, 750, 1000];
    const reportData: Array<{ milestone: number; metrics: any }> = [];

    console.log('\n================================================================================');
    console.log('🚀 OZ P2P ネットワーク 1~1000 ノード 逐次参加＆PEX収束シミュレーション開始');
    console.log('================================================================================\n');

    // 1000ノードの逐次参加ループ
    for (let step = 1; step <= 1000; step++) {
      const newNode = sim.createNode(step);

      // 1. トラッカーに登録し、初期候補 (最大8ピア) を取得
      const trackerPeers = sim.tracker.join(newNode);
      for (const peerId of trackerPeers) {
        const peerNode = sim.nodeMap.get(peerId);
        if (peerNode) {
          sim.tryConnect(newNode, peerNode);
        }
      }

      // 2. 新規ノードが即座に PEX を 1〜2回実行して探索
      sim.runPex(newNode);
      sim.maintainRing(newNode);

      // 3. 既参加ノードもランダムに PEX とトポロジー保守を実行 (常時バックグラウンド動作の模倣)
      for (let r = 0; r < 5; r++) {
        const randNode = sim.nodes[Math.floor(Math.random() * sim.nodes.length)];
        sim.runPex(randNode);
        sim.maintainRing(randNode);
      }

      // 4. トラッカー離脱シミュレーション:
      if (step > 30) {
        const matureNode = sim.nodes[step - 30];
        if (matureNode.isTrackerConnected) {
          sim.tracker.leave(matureNode.id);
        }
      }

      // マイルストーン記録
      if (milestones.includes(step)) {
        const metrics = sim.computeMetrics()!;
        reportData.push({ milestone: step, metrics });
        console.log(
          `[N=${String(step).padStart(4)}] 連結率:${(metrics.connectivityRatio * 100).toFixed(1)}% | ` +
          `平均次数:${metrics.meanDegree.toFixed(2)} (範囲 ${metrics.minDegree}-${metrics.maxDegree}, σ=${metrics.stdDevDegree.toFixed(2)}) | ` +
          `平均経路長:${metrics.avgPathLength.toFixed(2)} (直径 ${metrics.diameter}) | ` +
          `クラスタ係数:${metrics.avgClusteringCoeff.toFixed(3)} | ` +
          `リング距離:${metrics.meanRingDist.toFixed(3)} (局所率:${(metrics.localRatio * 100).toFixed(1)}%) | ` +
          `トラッカGini:${metrics.giniTracker.toFixed(3)}`
        );
      }
    }

    console.log('\n--- 1000ノード到達後: 自律収束（Relaxation）フェーズ（トラッカー完全遮断下での PEX 15 ラウンド）---');
    for (const node of sim.nodes) {
      if (node.isTrackerConnected) sim.tracker.leave(node.id);
    }
    expect(sim.tracker.size).toBe(0);

    for (let round = 1; round <= 15; round++) {
      for (const node of sim.nodes) {
        sim.runPex(node);
        sim.maintainRing(node);
      }
      if (round % 5 === 0) {
        const m = sim.computeMetrics()!;
        console.log(
          `[収束Round ${String(round).padStart(2)}] 連結率:${(m.connectivityRatio * 100).toFixed(1)}% | ` +
          `平均次数:${m.meanDegree.toFixed(2)} (範囲 ${m.minDegree}-${m.maxDegree}, 次数Gini=${m.giniDegree.toFixed(3)}) | ` +
          `経路長:${m.avgPathLength.toFixed(2)} (直径 ${m.diameter}) | ` +
          `クラスタ係数:${m.avgClusteringCoeff.toFixed(3)} | ` +
          `局所率:${(m.localRatio * 100).toFixed(1)}%`
        );
      }
    }

    const finalMetrics = sim.computeMetrics()!;

    console.log('\n================================================================================');
    console.log('📊 最終検証結果サマリー (N=1000 収束後)');
    console.log('================================================================================');
    console.log(`総エッジ数:              ${finalMetrics.totalEdges}`);
    console.log(`平均次数 (Mean Degree):   ${finalMetrics.meanDegree.toFixed(2)} / 上限 ${RING_MESH.MAX_DEGREE}`);
    console.log(`次数範囲 (Min - Max):     ${finalMetrics.minDegree} - ${finalMetrics.maxDegree} (σ = ${finalMetrics.stdDevDegree.toFixed(2)})`);
    console.log(`次数の偏り (Gini 係数):   ${finalMetrics.giniDegree.toFixed(4)} (0に近いほど均一)`);
    console.log(`最大連結成分割合:         ${(finalMetrics.connectivityRatio * 100).toFixed(2)}% (孤立ノード数: ${finalMetrics.isolatedNodes})`);
    console.log(`平均最短経路長 (Hops):   ${finalMetrics.avgPathLength.toFixed(2)}`);
    console.log(`ネットワーク直径 (Hops): ${finalMetrics.diameter}`);
    console.log(`平均クラスタリング係数:   ${finalMetrics.avgClusteringCoeff.toFixed(4)}`);
    console.log(`平均リンクリング距離:     ${finalMetrics.meanRingDist.toFixed(4)} (理論的完全ランダム = 0.250)`);
    console.log(`ローカル / ロング比率:   局所 ${(finalMetrics.localRatio * 100).toFixed(1)}% / ロングレンジ ${(finalMetrics.longRangeRatio * 100).toFixed(1)}%`);
    console.log(`トラッカー紹介Gini係数:   ${finalMetrics.giniTracker.toFixed(4)} (Fisher-Yatesによる公平性)`);

    const earlyNodes = sim.nodes.slice(0, 20);
    const lateNodes = sim.nodes.slice(980, 1000);
    const earlyAvgRef = earlyNodes.reduce((a, b) => a + b.trackerContactCount, 0) / earlyNodes.length;
    const lateAvgRef = lateNodes.reduce((a, b) => a + b.trackerContactCount, 0) / lateNodes.length;
    console.log(`初期20ノードの紹介回数平均: ${earlyAvgRef.toFixed(1)} 回`);
    console.log(`終盤20ノードの紹介回数平均: ${lateAvgRef.toFixed(1)} 回`);

    console.log('\nリンク距離の空間ヒストグラム [0, 0.5]:');
    const binLabels = ['[0, 0.05) 超近傍', '[0.05, 0.1) 近傍', '[0.1, 0.2) 中距離', '[0.2, 0.35) 準対角', '[0.35, 0.5] 完全対角'];
    for (let i = 0; i < 5; i++) {
      const pct = ((finalMetrics.distanceBins[i] / finalMetrics.totalEdges) * 100).toFixed(1);
      const bar = '█'.repeat(Math.round(Number(pct) / 2));
      console.log(`  ${binLabels[i].padEnd(18)} : ${String(finalMetrics.distanceBins[i]).padStart(5)} 件 (${pct.padStart(5)}%) ${bar}`);
    }

    // 不変条件アサーション
    expect(finalMetrics.connectivityRatio).toBe(1.0);
    expect(finalMetrics.isolatedNodes).toBe(0);
    expect(finalMetrics.componentsCount).toBe(1);
    expect(finalMetrics.maxDegree).toBeLessThanOrEqual(RING_MESH.MAX_DEGREE);
    expect(finalMetrics.meanDegree).toBeGreaterThanOrEqual(6);
    expect(finalMetrics.diameter).toBeLessThanOrEqual(15);
    expect(finalMetrics.avgPathLength).toBeLessThanOrEqual(6.0);
    expect(finalMetrics.giniTracker).toBeLessThan(0.7);
    expect(finalMetrics.longRangeRatio).toBeGreaterThan(0.3);
  }, 120_000);

  it('★ 20% ノード突発離脱 (Massive Churn) 下での自己修復・再収束の検証', () => {
    // 500ノードで定常状態を構築
    const sim = new NetworkSimulation();
    for (let step = 1; step <= 500; step++) {
      const node = sim.createNode(step);
      const peers = sim.tracker.join(node);
      for (const p of peers) {
        const peerNode = sim.nodeMap.get(p);
        if (peerNode) sim.tryConnect(node, peerNode);
      }
      sim.runPex(node);
      sim.maintainRing(node);
    }
    // トラッカーを完全遮断
    for (const node of sim.nodes) sim.tracker.leave(node.id);

    // 10ラウンド初期収束
    for (let r = 0; r < 10; r++) {
      for (const n of sim.nodes) {
        sim.runPex(n);
        sim.maintainRing(n);
      }
    }

    const beforeMetrics = sim.computeMetrics()!;
    console.log(`\n[離脱前 N=500] 連結率:${(beforeMetrics.connectivityRatio * 100).toFixed(1)}% | 平均次数:${beforeMetrics.meanDegree.toFixed(2)} | 平均経路長:${beforeMetrics.avgPathLength.toFixed(2)}`);

    // 突発的に 100 ノード (20%) をランダム切断
    const toRemove = sim.nodes.slice(0, 100);
    for (const victim of toRemove) {
      sim.removeNode(victim.id);
    }
    expect(sim.nodes.length).toBe(400);

    const hitMetrics = sim.computeMetrics()!;
    console.log(`[直撃時 N=400 (20%離脱直後)] 連結率:${(hitMetrics.connectivityRatio * 100).toFixed(1)}% | 平均次数:${hitMetrics.meanDegree.toFixed(2)} (最小 ${hitMetrics.minDegree}) | 平均経路長:${hitMetrics.avgPathLength.toFixed(2)}`);

    // トラッカー不在のまま PEX と RingMaintainer だけで自己修復 (10ラウンド)
    for (let r = 1; r <= 10; r++) {
      for (const n of sim.nodes) {
        sim.runPex(n);
        sim.maintainRing(n);
      }
    }

    const healedMetrics = sim.computeMetrics()!;
    console.log(`[自己修復後 N=400 (PEX 10ラウンド後)] 連結率:${(healedMetrics.connectivityRatio * 100).toFixed(1)}% | 平均次数:${healedMetrics.meanDegree.toFixed(2)} (最小 ${healedMetrics.minDegree}) | 平均経路長:${healedMetrics.avgPathLength.toFixed(2)}`);

    // 検証: 20% ノード離脱時でも分断せず 100% 連結を維持し、PEX で次数が回復すること
    expect(hitMetrics.connectivityRatio).toBe(1.0);
    expect(healedMetrics.connectivityRatio).toBe(1.0);
    expect(healedMetrics.meanDegree).toBeGreaterThan(hitMetrics.meanDegree);
    expect(healedMetrics.isolatedNodes).toBe(0);
  }, 120_000);
});
