import { CHUNK_HEADER_SIZE as HEADER_SIZE, CHUNK_SIZE, MAX_CHUNKS_PER_MESSAGE } from './ChunkedSender';

const REASSEMBLY_TIMEOUT = 10_000;

/**
 * 再組み立ての上限。
 *
 * 旧実装にはこれが無く、
 *   - pending が無制限に増える (msgId を変えながらヘッダだけ送りつける)
 *   - 1 メッセージが totalChunks=65535 × 4096B = 268MB まで伸びる
 * ため、隣人 1 人がメモリを枯渇させられた。
 *
 * GossipPacket の上限は payload 2KB なので、実運用で必要なのは
 * せいぜい数十 KB (追いつき・トンネルのフレームも 16KiB)。そこに余裕を取る。
 */
const MAX_MESSAGE_BYTES = 1024 * 1024;
const MAX_PENDING_MESSAGES = 64;
const MAX_CHUNKS = Math.min(MAX_CHUNKS_PER_MESSAGE, Math.ceil(MAX_MESSAGE_BYTES / CHUNK_SIZE));

interface PendingMessage {
  chunks: Map<number, ArrayBuffer>;
  totalChunks: number;
  totalSize: number;
  createdAt: number;
}

export class ChunkedReceiver {
  private pending = new Map<number, PendingMessage>();
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor(private onMessage: (data: ArrayBuffer) => void) {
    this.cleanupTimer = setInterval(() => this.cleanup(), 5000);
  }

  receive(raw: ArrayBuffer): void {
    if (raw.byteLength < HEADER_SIZE) {
      this.onMessage(raw);
      return;
    }

    const view = new DataView(raw);

    if (view.getUint8(0) !== 0x00) {
      this.onMessage(raw);
      return;
    }

    const msgId = view.getUint16(1);
    const seqNo = view.getUint8(3);
    const totalChunks = view.getUint8(4) + 1; // ヘッダに載るのは lastIdx (= total - 1)

    if (seqNo >= totalChunks) {
      this.onMessage(raw);
      return;
    }

    // 宣言されたチャンク数が上限を超えるものは、組み立てる前に捨てる
    if (totalChunks > MAX_CHUNKS) return;
    // ★ 長さ欄は無い (実バイト数が長さ)。送信側は 1..CHUNK_SIZE で切るので、空や大きすぎるものは捨てる
    const chunkSize = raw.byteLength - HEADER_SIZE;
    if (chunkSize < 1 || chunkSize > CHUNK_SIZE) return;

    let pm = this.pending.get(msgId);
    if (!pm) {
      // 同時に組み立て中のメッセージ数に上限を設ける。
      // 上限に達したら最も古いものを捨てる (新しい正常な通信を優先する)。
      if (this.pending.size >= MAX_PENDING_MESSAGES) {
        const oldest = this.pending.keys().next().value;
        if (oldest !== undefined) this.pending.delete(oldest);
      }
      pm = { chunks: new Map(), totalChunks, totalSize: 0, createdAt: Date.now() };
      this.pending.set(msgId, pm);
    }

    // 同じ msgId で totalChunks を変えてくる送信者は信用しない
    if (pm.totalChunks !== totalChunks) {
      this.pending.delete(msgId);
      return;
    }
    // 同じ seq の重複送信でサイズを水増しさせない
    if (pm.chunks.has(seqNo)) return;

    const payload = raw.slice(HEADER_SIZE);

    if (pm.totalSize + payload.byteLength > MAX_MESSAGE_BYTES) {
      this.pending.delete(msgId);
      return;
    }

    pm.chunks.set(seqNo, payload);
    pm.totalSize += payload.byteLength;

    if (pm.chunks.size === pm.totalChunks) {
      const assembled = new ArrayBuffer(pm.totalSize);
      const dst = new Uint8Array(assembled);
      let offset = 0;
      for (let i = 0; i < pm.totalChunks; i++) {
        const chunk = new Uint8Array(pm.chunks.get(i)!);
        dst.set(chunk, offset);
        offset += chunk.byteLength;
      }
      this.pending.delete(msgId);
      this.onMessage(assembled);
    }
  }

  /** 組み立て途中のメッセージ数 (診断・テスト用) */
  get pendingCount(): number {
    return this.pending.size;
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.pending.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [msgId, pm] of this.pending) {
      if (now - pm.createdAt > REASSEMBLY_TIMEOUT) {
        this.pending.delete(msgId);
      }
    }
  }
}
