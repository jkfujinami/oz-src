import { WireType } from '../wire/WireTypes';

/**
 * チャンクのヘッダ (5 バイト): [0x00][msgId u16][idx u8][lastIdx u8]   (lastIdx = チャンク数 - 1)
 *
 * ★ 旧ヘッダは 12 バイト (msgId u32 / seq u16 / total u16 / 各チャンクの長さ u16 / 最終フラグ u8) だった。
 *   - 各チャンクの長さ: 実バイト数から分かる (受信側が食い違いを検査する必要自体がなくなる)
 *   - 最終フラグ: idx === lastIdx から導出できる
 *   - msgId は u16 で足りる (同時に組み立て中なのは最大 64 件、10 秒で捨てる)
 *   - idx / lastIdx は u8。total ではなく lastIdx (= total - 1) を載せるので、1 メッセージは
 *     最大 256 チャンク = ちょうど 1MB まで運べる (再組み立ての上限と同じ)
 *   先頭の 0x00 は「チャンクである」印。チャンクにしない通常のフレームの先頭は WireType (0x10 以上) なので衝突しない。
 */
export const CHUNK_SIZE = 4096;
export const CHUNK_HEADER_SIZE = 5;
/** 1 メッセージのチャンク数の上限 (lastIdx が u8 なので 256) */
export const MAX_CHUNKS_PER_MESSAGE = 256;

/**
 * これ以下のメッセージは分割せず、DataChannel の 1 メッセージで送る。
 * ★ 16KiB は RFC 8831 の相互運用の目安で、SDP の a=max-message-size も最低 16384 を載せる (WebRTCPeer.optimizeSdp)。
 *   正規のフレームはどれも 16KiB 以下 (トンネル・追いつき・leaseSet の一括送信がちょうど 16KiB) なので、実際には分割しない。
 *   旧版は 4KiB を超えるものを全部分割していた: 1 段ごとにコピーが 3 回と送信が 3 回増え、受け手の組み立ての同時数の上限
 *   (64 件) を超えるとフレームごと捨てられていた。受け手 (ChunkedReceiver) は先頭が 0x00 でないものを素通しするので、
 *   旧版の受け手にも届く。
 */
export const UNCHUNKED_MAX_BYTES = 16 * 1024;

/**
 * 送出の制御 (大きなデータの系統だけ)。DataChannel の送信待ち (bufferedAmount) が HIGH_WATER を超えたら手元の列に貯め、
 * LOW_WATER まで減った (bufferedamountlow) ら続きを出す。
 * ★ 送信待ちを膨らませすぎない: Chromium は送信待ちが 16MiB を超えると DataChannel を閉じる (send が失敗する)。
 *   また 1 本の DataChannel は順序つきなので、大きなデータが何 MiB も溜まると、後ろの投稿・オニオンのセル・PING が
 *   その分だけ遅れる。列に貯めておけば、制御の系統 (urgent) は列を飛ばして先に出せる。
 */
export const SEND_HIGH_WATER = 1024 * 1024;
export const SEND_LOW_WATER = 256 * 1024;
/** 手元の列の上限。超える分は捨てる (相手が受け取れていない。HIGH_WATER と合わせて 16MiB より十分下) */
export const MAX_QUEUED_BYTES = 8 * 1024 * 1024;
/** bufferedamountlow が使えない実装のための見回りの間隔 */
const DRAIN_POLL_MS = 20;

/**
 * 大きなデータを運ぶ系統: 追いつき (0x6x)・leaseSet (0x7x)・トンネル (0x8x)・Ozzy (0x9x)。この系統は手元の列で送出を絞る。
 * ★ 列は 1 本なので、この系統どうしの順序は保つ (CATCHUP_DATA → CATCHUP_END、応答の片の番号順など)。
 *   それ以外 (制御 0x1x・PEX 0x2x・シグナリング 0x3x・Gossip / Stem / オニオンのセル 0x4x) は列に並ばず、すぐ送る。
 *   この 2 つの間の順序に依存するやり取りは無い。
 */
export function isBulkFrame(firstByte: number): boolean {
  return firstByte >= WireType.CATCHUP_REQ && firstByte < 0xa0;
}

export interface SendOptions {
  /** 大きなデータの系統 (isBulkFrame)。手元の列で送出を絞る */
  bulk?: boolean;
  /** 相手が受け取れる 1 メッセージの上限 (RTCSctpTransport.maxMessageSize)。分からなければ省略 */
  maxMessageBytes?: number;
}

/** 送る DataChannel のうち、ここで使うところ (テストでは偽物を渡す) */
type Channel = Pick<RTCDataChannel, 'send' | 'bufferedAmount'> & Partial<Pick<RTCDataChannel, 'readyState' | 'bufferedAmountLowThreshold' | 'addEventListener' | 'removeEventListener'>>;

/**
 * ChunkedSender — 1 本の DataChannel への送出。16KiB を超えるものは 4KiB に分割し、大きなデータの系統は送信待ちを見て絞る。
 * DataChannel ごとに 1 つ持つ (WebRTCPeer)。
 */
export class ChunkedSender {
  private msgCounter = 0;
  /** 大きなデータの系統の、送り待ちの片 (先頭は head) */
  private queue: Uint8Array[] = [];
  private head = 0;
  private queued = 0;
  private dc: Channel | null = null;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly onLow = () => this.drain();

  /** 列の上限を超えて捨てたメッセージの数 (診断用) */
  public dropped = 0;

  /** 手元の列に溜まっているバイト数 (bufferedAmount に足して、送り手が送出を待つのに使う) */
  public get queuedBytes(): number {
    return this.queued;
  }

  /**
   * 送る。大きなデータの系統で、列の上限を超えるなら捨てて false。
   * 送れなくなった (閉じた) DataChannel への送信は黙って捨てる (相手が切れたときは PeerManager が後片付けをする)。
   */
  send(dc: Channel, data: Uint8Array, opts: SendOptions = {}): boolean {
    const pieces = this.split(data, Math.min(UNCHUNKED_MAX_BYTES, opts.maxMessageBytes ?? UNCHUNKED_MAX_BYTES));
    if (!opts.bulk) {
      for (const p of pieces) dc.send(p as any);
      return true;
    }
    if (this.dc !== dc) this.attach(dc);
    if (this.queued + data.byteLength > MAX_QUEUED_BYTES) {
      this.dropped++;
      return false;
    }
    for (const p of pieces) {
      this.queue.push(p);
      this.queued += p.byteLength;
    }
    this.drain();
    return true;
  }

  private split(data: Uint8Array, maxUnchunked: number): Uint8Array[] {
    if (data.byteLength <= maxUnchunked) return [data];
    const totalChunks = Math.ceil(data.byteLength / CHUNK_SIZE);
    if (totalChunks > MAX_CHUNKS_PER_MESSAGE) throw new RangeError(`ChunkedSender: message too large (${data.byteLength}B)`);
    const msgId = (this.msgCounter++) & 0xFFFF;
    const out: Uint8Array[] = [];
    for (let seq = 0; seq < totalChunks; seq++) {
      const payload = data.subarray(seq * CHUNK_SIZE, Math.min((seq + 1) * CHUNK_SIZE, data.byteLength));
      const chunk = new Uint8Array(CHUNK_HEADER_SIZE + payload.byteLength);
      chunk[0] = 0x00;
      chunk[1] = msgId >>> 8;
      chunk[2] = msgId & 0xff;
      chunk[3] = seq;
      chunk[4] = totalChunks - 1;
      chunk.set(payload, CHUNK_HEADER_SIZE);
      out.push(chunk);
    }
    return out;
  }

  /** 送信待ちが LOW_WATER まで減ったら知らせてもらう (使えない実装は見回りだけで回す) */
  private attach(dc: Channel): void {
    this.detach();
    this.dc = dc;
    try {
      dc.bufferedAmountLowThreshold = SEND_LOW_WATER;
      dc.addEventListener?.('bufferedamountlow', this.onLow);
    } catch {
      // 見回りで足りる
    }
  }

  private detach(): void {
    try {
      this.dc?.removeEventListener?.('bufferedamountlow', this.onLow);
    } catch {
      // 閉じた DataChannel
    }
    this.dc = null;
  }

  /** 送信待ちが HIGH_WATER 以下の間、列の先頭から送る */
  private drain(): void {
    const dc = this.dc;
    if (!dc) return;
    if (dc.readyState !== undefined && dc.readyState !== 'open') return this.clear();
    try {
      while (this.head < this.queue.length && dc.bufferedAmount <= SEND_HIGH_WATER) {
        const p = this.queue[this.head];
        this.queue[this.head++] = undefined as any;
        this.queued -= p.byteLength;
        dc.send(p as any);
      }
    } catch {
      return this.clear(); // 閉じかけ・送信待ちの上限。続きは送れない
    }
    if (this.head >= this.queue.length) {
      this.queue = [];
      this.head = 0;
      return;
    }
    if (this.head > 1024 && this.head * 2 > this.queue.length) {
      this.queue = this.queue.slice(this.head);
      this.head = 0;
    }
    if (!this.pollTimer) {
      this.pollTimer = setTimeout(() => {
        this.pollTimer = null;
        this.drain();
      }, DRAIN_POLL_MS);
    }
  }

  /** 列を捨てる (DataChannel が閉じた) */
  public clear(): void {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = null;
    this.queue = [];
    this.head = 0;
    this.queued = 0;
    this.detach();
  }
}
