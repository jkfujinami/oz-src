import { NodeIdentity } from '../crypto/NodeIdentity';

/**
 * RingPosition — リング座標。
 *
 * 旧実装は `crypto.getRandomValues` で座標を生成し localStorage に保存していた。
 * つまり座標は「自己申告」であり、
 *   - 狙った topicHash の隣に着地して K=5 の保持者になる
 *   - 特定ノードを取り囲んで eclipse する
 * が無コストで可能だった (本家 OZ 18.5.3 の「★未解決だった重大欠陥」)。
 *
 * 現在は Bound Identity に置き換えてある:
 *
 *     position = SHA256("OZ/v3/position" ‖ peerId)
 *     peerId   = SHA256("OZ/v3/peerid"   ‖ pubkey)[0..16]  (+ NodeId PoW)
 *
 * 座標は peerId の純粋関数なので、
 *   - ネットワーク上で position を送る必要がない (送らせない)
 *   - 受信側は相手の peerId から自分で計算する
 * となり、「申告された座標」という攻撃面そのものが存在しなくなる。
 *
 * @see NodeIdentity
 */
export class RingPosition {
  private constructor(private readonly _value: number) {}

  get value(): number {
    return this._value;
  }

  /**
   * peerId からリング座標を導出する。
   *
   * ネットワークから受け取ったピアの座標は必ずこれで計算すること。
   * 相手が名乗った数値をそのまま使ってはならない。
   */
  static forPeer(peerId: string): number {
    return NodeIdentity.derivePosition(peerId);
  }

  /** peerId から RingPosition インスタンスを作る */
  static of(peerId: string): RingPosition {
    return new RingPosition(RingPosition.forPeer(peerId));
  }

  /**
   * リング上の2点間の最短距離を計算する
   * @param a 位置 a [0, 1)
   * @param b 位置 b [0, 1)
   * @returns 距離 [0, 0.5]
   */
  static distance(a: number, b: number): number {
    const d = Math.abs(a - b);
    return Math.min(d, 1.0 - d);
  }
}
