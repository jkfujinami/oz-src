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
const MAX_BUFFERED = 64 * 1024;

export class ChunkedSender {
  private msgCounter = 0;

  async send(dc: RTCDataChannel, data: Uint8Array): Promise<void> {
    if (data.byteLength <= CHUNK_SIZE) {
      dc.send(data as any);
      return;
    }

    const totalChunks = Math.ceil(data.byteLength / CHUNK_SIZE);
    if (totalChunks > MAX_CHUNKS_PER_MESSAGE) throw new RangeError(`ChunkedSender: message too large (${data.byteLength}B)`);
    const msgId = (this.msgCounter++) & 0xFFFF;

    for (let seq = 0; seq < totalChunks; seq++) {
      while (dc.bufferedAmount > MAX_BUFFERED) {
        await new Promise(r => setTimeout(r, 10));
      }

      const offset = seq * CHUNK_SIZE;
      const end = Math.min(offset + CHUNK_SIZE, data.byteLength);
      const payload = data.subarray(offset, end);

      const chunk = new Uint8Array(CHUNK_HEADER_SIZE + payload.byteLength);
      chunk[0] = 0x00;
      chunk[1] = msgId >>> 8;
      chunk[2] = msgId & 0xff;
      chunk[3] = seq;
      chunk[4] = totalChunks - 1;
      chunk.set(payload, CHUNK_HEADER_SIZE);

      dc.send(chunk as any);
    }
  }
}
