/**
 * ThreadRanker
 * スレッドの「熱量(PoW)」と「重力(経過時間)」から、
 * Hacker News / Reddit 流のランキングスコアを算出する。
 */
export class ThreadRanker {
  // 重力定数 (1.8 は標準的な情報の沈下速度)
  private static readonly GRAVITY = 1.8;
  // スコアが無限大になるのを防ぐオフセット(時間単位)
  private static readonly TIME_OFFSET_HOURS = 2;
  // ス레立て自体の基礎難易度 (ベースの勢い)
  private static readonly BASE_SCORE = 16;

  /**
   * スレッドのランキングスコアを算出する
   * @param maxCumulativePow スレッド内での最大累積難易度
   * @param createdAtMs スレッドの作成日時(ミリ秒または秒)
   */
  static calculateScore(maxCumulativePow: number, createdAtMs: number): number {
    const now = Date.now();
    
    // 防御: NaN, undefined, 0, 負値 は全て「たった今」として扱う
    const safePow = (typeof maxCumulativePow === 'number' && !isNaN(maxCumulativePow)) ? maxCumulativePow : 0;
    let safeCreatedAt = (typeof createdAtMs === 'number' && !isNaN(createdAtMs) && createdAtMs > 0) ? createdAtMs : now;
    
    // 単位正規化: 10^10 未満なら秒単位(Ozプロトコル標準)と判断してミリ秒に変換
    if (safeCreatedAt < 10000000000) {
      safeCreatedAt = safeCreatedAt * 1000;
    }
    
    // 経過時間を時間(hours)単位に変換
    const hoursSinceCreated = (now - safeCreatedAt) / (1000 * 60 * 60);

    // 数式: Score = (PoW + Base) / (Hours + Offset)^G
    const numerator = safePow + this.BASE_SCORE;
    const denominator = Math.pow(Math.max(0, hoursSinceCreated) + this.TIME_OFFSET_HOURS, this.GRAVITY);

    const score = numerator / denominator;
    
    // 最終防御: NaN/Infinity が出たら BASE_SCORE のデフォルトスコアを返す
    if (!isFinite(score)) return this.BASE_SCORE / Math.pow(this.TIME_OFFSET_HOURS, this.GRAVITY);
    return score;
  }

  /**
   * スレッドリストをスコア順にソートする
   */
  static sortThreadsByScore<T extends { max_pow: number; created_at: number }>(threads: T[]): T[] {
    return [...threads].sort((a, b) => {
      const scoreA = this.calculateScore(a.max_pow, a.created_at);
      const scoreB = this.calculateScore(b.max_pow, b.created_at);
      return scoreB - scoreA; // スコア降順
    });
  }
}
