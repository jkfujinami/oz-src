export class DifficultyEstimator {
  static readonly WINDOW = 100;              // 直近100件で計算
  static readonly TARGET_INTERVAL = 3000;    // 目標: 3秒/件に制限する
  static readonly BASE_DIFFICULTY = 12;      // (~0.5秒/回)
  static readonly MIN_DIFFICULTY = 8;        // (~0.1秒)
  static readonly MAX_DIFFICULTY = 24;       // (~30秒) 炎上時

  /**
   * ローカルの過去ログのタイムスタンプ配列（msec）から、ネットワークにおける
   * 今現在の「投稿の熱量（速度）」を元にして最新の計算難易度を導出する。
   * これにより、ボットの一斉送信をネットワークの仕組み自体が自動で「遅延」させる。
   */
  static compute(recentTimestamps: number[]): number {
    if (recentTimestamps.length < 2) return DifficultyEstimator.MIN_DIFFICULTY;

    const sorted = [...recentTimestamps].sort((a, b) => a - b);
    const windowSize = Math.min(DifficultyEstimator.WINDOW, sorted.length);
    const elapsed = sorted[sorted.length - 1] - sorted[sorted.length - windowSize];
    
    if (elapsed === 0) return DifficultyEstimator.MAX_DIFFICULTY;

    const actualInterval = elapsed / windowSize;
    const ratio = DifficultyEstimator.TARGET_INTERVAL / actualInterval;

    const difficulty = Math.round(
      DifficultyEstimator.BASE_DIFFICULTY + Math.log2(ratio),
    );

    return Math.max(
      DifficultyEstimator.MIN_DIFFICULTY,
      Math.min(DifficultyEstimator.MAX_DIFFICULTY, difficulty),
    );
  }
}
