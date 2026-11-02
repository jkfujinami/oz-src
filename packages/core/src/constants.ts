export const RING_MESH = {
  // ── 接続構成 ──
  /** ローカルリンク数: 左2 + 右2 = 4本（リング維持） */
  LOCAL_LINKS: 4,
  /** 1ノードの最大WebRTC接続数 (§2.45) */
  MAX_DEGREE: 16,
  /**
   * 自分で選んで張る (outbound) 接続の目標数。
   * これに満たない間は、次数が上限に達していても outbound を張りに行き、
   * inbound の枠と入れ替える (inbound だけで隣人を埋め尽くされないように)。
   */
  OUTBOUND_TARGET: 8,

  // ── タイマー ──
  REPAIR_CHECK_INTERVAL: 10_000, // 修復チェック間隔 (10秒)
} as const;

// トラッカーの URL は固定しない (公式のトラッカーは無い)。network/TrackerUrl.ts と
// OzNodeConfig.trackerUrl を参照。

/**
 * Guard 役 (role: 'guard') のノードが受け入れる最大の接続数。
 * 多数の利用者がこのノードを 1 ホップ目に選ぶので、通常 (MAX_DEGREE) より大きくする。
 */
export const GUARD_MAX_DEGREE = 256;

/**
 * 一般のノード (role: 'client') が、信頼 Guard を使えていない間 (オープン網・リストの Guard に誰もつながらない) に
 * 受け入れる最大の接続数。この間は誰もが 1 ホップ目に選ばれうるので、Guard 役のノードに利用者が集中しないよう多めに受け入れる
 * (OzNode)。信頼 Guard につながったら MAX_DEGREE に戻す。
 */
export const OPEN_SERVICE_MAX_DEGREE = 64;
