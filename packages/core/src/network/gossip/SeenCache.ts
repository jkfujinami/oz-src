export class SeenCache {
  private cache: Map<string, number> = new Map();
  
  // 最大保持パケット数: 50,000件 (1IDあたり32byte=約1.6MBの極小メモリフットプリント)
  private readonly MAX_SIZE = 50_000;
  
  // キャッシュ有効期限: 15分 (これより過去のパケットは時刻バリデーター自体が弾くため、15分で十分)
  public static readonly TTL_MS = 15 * 60 * 1000;
  private readonly TTL_MS = SeenCache.TTL_MS;
  
  // クリーンアップタイマー
  private timer: ReturnType<typeof setInterval>;

  constructor() {
    // 5分ごとに期限切れを掃除
    this.timer = setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  public has(packetId: string): boolean {
    return this.cache.has(packetId);
  }

  public add(packetId: string): void {
    if (this.cache.has(packetId)) return;
    this.cache.set(packetId, Date.now());

    // JSのMapは挿入順を保持するため、先頭が「最も古いキー」
    if (this.cache.size > this.MAX_SIZE) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [id, insertedAt] of this.cache.entries()) {
      if (now - insertedAt > this.TTL_MS) {
        this.cache.delete(id);
      } else {
        // 挿入順なので、1つでもTTL内ならそれ以降は全てTTL内
        break;
      }
    }
  }

  public destroy(): void {
    clearInterval(this.timer);
    this.cache.clear();
  }
}
