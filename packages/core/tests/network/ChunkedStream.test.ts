import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ChunkedSender, isBulkFrame, UNCHUNKED_MAX_BYTES, SEND_HIGH_WATER, SEND_LOW_WATER, MAX_QUEUED_BYTES,
} from '../../src/network/stream/ChunkedSender';
import { WireType } from '../../src/network/wire/WireTypes';
import { ChunkedReceiver } from '../../src/network/stream/ChunkedReceiver';

/**
 * チャンク形式 (5 バイトヘッダ, ビッグエンディアン):
 *   [0]     0x00 (チャンクの印)
 *   [1..2]  msgId    u16
 *   [3]     idx      u8
 *   [4]     lastIdx  u8 (= チャンク数 - 1。最後のチャンクは idx === lastIdx)
 * チャンクの長さは実バイト数 (1..4096)。
 */
const CHUNK = 4096;
const HEADER = 5;

/** 送られたものを記録する偽の RTCDataChannel。fireLow で bufferedamountlow を起こす (events: false なら購読できない実装) */
function fakeChannel(opts: { events?: boolean } = {}) {
  const sent: Uint8Array[] = [];
  const listeners: Array<() => void> = [];
  const dc: any = {
    bufferedAmount: 0,
    bufferedAmountLowThreshold: 0,
    readyState: 'open',
    send: vi.fn((d: Uint8Array) => { sent.push(new Uint8Array(d)); }),
  };
  if (opts.events !== false) {
    dc.addEventListener = (type: string, cb: () => void) => { if (type === 'bufferedamountlow') listeners.push(cb); };
    dc.removeEventListener = (_type: string, cb: () => void) => {
      const i = listeners.indexOf(cb);
      if (i >= 0) listeners.splice(i, 1);
    };
  }
  return { dc, sent, fireLow: () => listeners.slice().forEach(cb => cb()) };
}

/** 4096 を超えるものを分割させる (チャンクの形式を確かめる用。本番の閾値は UNCHUNKED_MAX_BYTES) */
const SMALL = { maxMessageBytes: CHUNK };
const BULK = { bulk: true };

/** ワイヤに乗ったバイト列を受信側が受け取る ArrayBuffer にする */
const toBuf = (u: Uint8Array): ArrayBuffer => u.slice().buffer;

function pattern(n: number, seed = 1): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; out[i] = x >>> 24; }
  return out;
}

/** 手でチャンクを作る (攻撃的な入力用) */
function chunk(msgId: number, seq: number, total: number, payload: Uint8Array, opts: { marker?: number } = {}) {
  const out = new Uint8Array(HEADER + payload.length);
  const v = new DataView(out.buffer);
  v.setUint8(0, opts.marker ?? 0);
  v.setUint16(1, msgId);
  v.setUint8(3, seq);
  v.setUint8(4, total - 1);
  out.set(payload, HEADER);
  return out.buffer;
}

describe('ChunkedSender', () => {
  it('16KiB 以下は分割せず 1 回で送る (ヘッダを付けない)。正規のフレームの最大 (トンネル・追いつき) がちょうど 16KiB', async () => {
    const s = new ChunkedSender();
    for (const n of [1, 100, CHUNK, CHUNK + 1, UNCHUNKED_MAX_BYTES]) {
      const { dc, sent } = fakeChannel();
      const data = pattern(n);
      s.send(dc, data);
      expect(sent).toHaveLength(1);
      expect(sent[0]).toEqual(data);
    }
  });

  it('16KiB を超えるものは 4096 ずつに分ける。相手の上限 (maxMessageBytes) が小さければ、それを超えるものを分ける', () => {
    const { dc, sent } = fakeChannel();
    new ChunkedSender().send(dc, pattern(UNCHUNKED_MAX_BYTES + 1));
    expect(sent).toHaveLength(5);
    const small = fakeChannel();
    new ChunkedSender().send(small.dc, pattern(CHUNK + 1), { maxMessageBytes: CHUNK });
    expect(small.sent).toHaveLength(2);
  });

  it('4097 バイトを 4096 で分けると 2 チャンクで、ヘッダの各欄が正しい', async () => {
    const s = new ChunkedSender();
    const { dc, sent } = fakeChannel();
    const data = pattern(CHUNK + 1);
    s.send(dc, data, SMALL);
    expect(sent).toHaveLength(2);

    const v0 = new DataView(sent[0].buffer);
    expect(v0.getUint8(0)).toBe(0);
    expect(v0.getUint8(3)).toBe(0); // idx
    expect(v0.getUint8(4)).toBe(1); // lastIdx
    expect(sent[0].length).toBe(HEADER + CHUNK);

    const v1 = new DataView(sent[1].buffer);
    expect(v1.getUint16(1)).toBe(v0.getUint16(1));
    expect(v1.getUint8(3)).toBe(1);
    expect(v1.getUint8(4)).toBe(1);
    expect(sent[1].length).toBe(HEADER + 1);

    expect(sent[0].subarray(HEADER)).toEqual(data.subarray(0, CHUNK));
    expect(sent[1].subarray(HEADER)).toEqual(data.subarray(CHUNK));
  });

  it('ちょうど 4096 の倍数ならチャンク数は割り切れた数', async () => {
    const { dc, sent } = fakeChannel();
    new ChunkedSender().send(dc, pattern(CHUNK * 3), SMALL);
    expect(sent).toHaveLength(3);
    expect(sent[2].length).toBe(HEADER + CHUNK);
  });

  it('msgId はメッセージごとに 1 ずつ増える (分割しない送信では消費しない)', async () => {
    const s = new ChunkedSender();
    const { dc, sent } = fakeChannel();
    s.send(dc, pattern(CHUNK + 1), SMALL);
    s.send(dc, pattern(10), SMALL);
    s.send(dc, pattern(CHUNK + 1), SMALL);
    const id0 = new DataView(sent[0].buffer).getUint16(1);
    const id1 = new DataView(sent[3].buffer).getUint16(1);
    expect(id1).toBe(id0 + 1);
  });

  it('msgId は u16 で一周する', async () => {
    const s = new ChunkedSender();
    (s as any).msgCounter = 0xffff;
    const { dc, sent } = fakeChannel();
    s.send(dc, pattern(CHUNK + 1), SMALL);
    s.send(dc, pattern(CHUNK + 1), SMALL);
    expect(new DataView(sent[0].buffer).getUint16(1)).toBe(0xffff);
    expect(new DataView(sent[2].buffer).getUint16(1)).toBe(0);
  });

  it('ヘッダは 5 バイト (旧 12 バイト)。1MB のメッセージは 256 チャンクに収まり、それを超えると拒否する', async () => {
    const { dc, sent } = fakeChannel();
    new ChunkedSender().send(dc, pattern(1024 * 1024));
    expect(sent).toHaveLength(256);
    expect(sent[255][4]).toBe(255);
    expect(sent[255][3]).toBe(255);
    expect(() => new ChunkedSender().send(fakeChannel().dc, pattern(1024 * 1024 + 1))).toThrow(RangeError);
  });

  it('大きなデータの系統は 追いつき・leaseSet・トンネル・Ozzy だけ (制御・PEX・シグナリング・Gossip・Stem・セルは含まない)', () => {
    const bulk = new Set<number>([
      WireType.CATCHUP_REQ, WireType.CATCHUP_DATA, WireType.CATCHUP_END,
      WireType.LEASESET, WireType.LEASESET_SYNC_REQ, WireType.LEASESET_SYNC,
      WireType.TUNNEL_REGISTER, WireType.TUNNEL_REGISTERED, WireType.TUNNEL_SEND, WireType.TUNNEL_FWD, WireType.TUNNEL_DELIVER,
      WireType.TUNNEL_REPLY, WireType.TUNNEL_RET, WireType.TUNNEL_RESULT, WireType.TUNNEL_ERROR,
      WireType.OZZY_REPLY, WireType.OZZY_RESULT, WireType.OZZY_WORKER_REQ, WireType.OZZY_WORKER_ADS, WireType.OZZY_UP, WireType.OZZY_UP_FWD,
    ]);
    const types = Object.values(WireType).filter((v): v is WireType => typeof v === 'number' && v !== WireType.UNKNOWN);
    for (const t of types) expect(isBulkFrame(t), `0x${t.toString(16)}`).toBe(bulk.has(t));
    expect(isBulkFrame(0x00)).toBe(false); // チャンクの印
  });

  describe('送信待ちの制御 (大きなデータの系統)', () => {
    beforeEach(() => { vi.useFakeTimers(); });
    afterEach(() => { vi.useRealTimers(); });

    it('送信待ちが HIGH_WATER を超えていたら手元の列に貯め、bufferedamountlow で送った順に出す', () => {
      const { dc, sent, fireLow } = fakeChannel();
      dc.bufferedAmount = SEND_HIGH_WATER + 1;
      const s = new ChunkedSender();
      const a = pattern(UNCHUNKED_MAX_BYTES, 1), b = pattern(100, 2), c = pattern(5000, 3);
      for (const d of [a, b, c]) expect(s.send(dc, d, BULK)).toBe(true);
      expect(sent).toHaveLength(0);
      expect(s.queuedBytes).toBe(a.length + b.length + c.length);
      expect(dc.bufferedAmountLowThreshold).toBe(SEND_LOW_WATER);
      dc.bufferedAmount = 0;
      fireLow();
      expect(sent).toEqual([a, b, c]); // 後から来た小さいフレームが前を追い越さない
      expect(s.queuedBytes).toBe(0);
    });

    it('列が空いていなければ、送信待ちが少なくても新しいフレームは列の後ろに並ぶ', () => {
      const { dc, sent, fireLow } = fakeChannel();
      const s = new ChunkedSender();
      dc.bufferedAmount = SEND_HIGH_WATER + 1;
      const a = pattern(100, 1), b = pattern(100, 2);
      s.send(dc, a, BULK);
      dc.bufferedAmount = 0;
      s.send(dc, b, BULK); // ここで列の先頭から出す
      expect(sent).toEqual([a, b]);
      fireLow();
      expect(sent).toHaveLength(2);
    });

    it('bufferedamountlow が無い実装でも、見回りで続きを出す', async () => {
      const { dc, sent } = fakeChannel({ events: false });
      const s = new ChunkedSender();
      dc.bufferedAmount = SEND_HIGH_WATER + 1;
      s.send(dc, pattern(100), BULK);
      await vi.advanceTimersByTimeAsync(100);
      expect(sent).toHaveLength(0);
      dc.bufferedAmount = 0;
      await vi.advanceTimersByTimeAsync(25);
      expect(sent).toHaveLength(1);
    });

    it('制御の系統 (投稿・セル・PING) は列に並ばずすぐ送る: 大きなデータの後ろで待たせない', () => {
      const { dc, sent, fireLow } = fakeChannel();
      const s = new ChunkedSender();
      dc.bufferedAmount = SEND_HIGH_WATER + 1;
      const bulk = pattern(UNCHUNKED_MAX_BYTES, 1), urgent = pattern(1200, 2);
      s.send(dc, bulk, BULK);
      s.send(dc, urgent);
      expect(sent).toEqual([urgent]);
      dc.bufferedAmount = 0;
      fireLow();
      expect(sent).toEqual([urgent, bulk]);
    });

    it('列の上限 (MAX_QUEUED_BYTES) を超える分は捨てて false。DataChannel が閉じていたら列を捨てる', () => {
      const { dc, sent, fireLow } = fakeChannel();
      const s = new ChunkedSender();
      dc.bufferedAmount = SEND_HIGH_WATER + 1;
      const frame = pattern(UNCHUNKED_MAX_BYTES);
      const fits = MAX_QUEUED_BYTES / frame.length;
      for (let i = 0; i < fits; i++) expect(s.send(dc, frame, BULK)).toBe(true);
      expect(s.send(dc, frame, BULK)).toBe(false);
      expect(s.dropped).toBe(1);
      dc.readyState = 'closed';
      fireLow();
      expect(sent).toHaveLength(0);
      expect(s.queuedBytes).toBe(0);
    });
  });
});

describe('ChunkedReceiver', () => {
  let got: ArrayBuffer[];
  let rx: ChunkedReceiver;

  beforeEach(() => {
    vi.useFakeTimers();
    got = [];
    rx = new ChunkedReceiver(d => got.push(d));
  });
  afterEach(() => {
    rx.destroy();
    vi.useRealTimers();
  });

  async function sendThrough(data: Uint8Array) {
    const { dc, sent } = fakeChannel();
    new ChunkedSender().send(dc, data, SMALL);
    return sent;
  }

  it('Sender が分割したものを元どおりに組み立てる (大きさいろいろ)', async () => {
    for (const n of [CHUNK + 1, CHUNK * 2, CHUNK * 5 + 123, 200_000]) {
      const data = pattern(n, n);
      for (const c of await sendThrough(data)) rx.receive(toBuf(c));
      expect(new Uint8Array(got.pop()!)).toEqual(data);
      expect(rx.pendingCount).toBe(0);
    }
  });

  it('順不同で届いても組み立てる', async () => {
    const data = pattern(CHUNK * 4 + 7);
    const chunks = await sendThrough(data);
    for (const i of [3, 0, 4, 2, 1]) rx.receive(toBuf(chunks[i]));
    expect(got).toHaveLength(1);
    expect(new Uint8Array(got[0])).toEqual(data);
  });

  it('同じ seq の重複は無視し、二重に数えない', async () => {
    const data = pattern(CHUNK * 3);
    const chunks = await sendThrough(data);
    rx.receive(toBuf(chunks[0]));
    rx.receive(toBuf(chunks[0]));
    rx.receive(toBuf(chunks[1]));
    expect(got).toHaveLength(0);
    rx.receive(toBuf(chunks[2]));
    expect(got).toHaveLength(1);
    expect(new Uint8Array(got[0])).toEqual(data);
  });

  it('重複チャンクで中身を差し替えられない (最初に届いたものが残る)', () => {
    rx.receive(chunk(9, 0, 2, new Uint8Array([1, 1])));
    rx.receive(chunk(9, 0, 2, new Uint8Array([6, 6])));
    rx.receive(chunk(9, 1, 2, new Uint8Array([2])));
    expect(Array.from(new Uint8Array(got[0]))).toEqual([1, 1, 2]);
  });

  it('複数のメッセージが交互に届いても混ざらない', () => {
    const a = [pattern(10, 1), pattern(10, 2)];
    const b = [pattern(5, 3), pattern(5, 4), pattern(5, 5)];
    rx.receive(chunk(1, 0, 2, a[0]));
    rx.receive(chunk(2, 2, 3, b[2]));
    rx.receive(chunk(2, 0, 3, b[0]));
    rx.receive(chunk(1, 1, 2, a[1]));
    rx.receive(chunk(2, 1, 3, b[1]));
    expect(got.map(g => Array.from(new Uint8Array(g)))).toEqual([
      [...a[0], ...a[1]],
      [...b[0], ...b[1], ...b[2]],
    ]);
  });

  it('チャンクでないもの (先頭が 0x00 以外、またはヘッダ 5 バイト未満) はそのまま渡す', () => {
    const frame = new Uint8Array([0x12, 0x82, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    rx.receive(toBuf(frame));
    rx.receive(toBuf(new Uint8Array([0x00, 1, 2, 3])));
    expect(got).toHaveLength(2);
    expect(new Uint8Array(got[0])).toEqual(frame);
    expect(rx.pendingCount).toBe(0);
  });

  it('idx > lastIdx のヘッダはチャンクとして扱わない (素通し)', () => {
    rx.receive(chunk(1, 4, 3, new Uint8Array(4)));
    rx.receive(chunk(1, 255, 1, new Uint8Array(4)));
    expect(got).toHaveLength(2);
    expect(rx.pendingCount).toBe(0);
  });

  it('total=1 のチャンクは即座に 1 メッセージになる', () => {
    rx.receive(chunk(5, 0, 1, new Uint8Array([7, 8, 9])));
    expect(Array.from(new Uint8Array(got[0]))).toEqual([7, 8, 9]);
  });

  it('★宣言できるチャンク数は構造上 256 (= 1MB / 4096) まで。最大宣言でも組み立てを始められる', () => {
    rx.receive(chunk(3, 0, 256, new Uint8Array(10)));
    expect(rx.pendingCount).toBe(1);
  });

  it('★1 チャンクが 4096 バイトを超えるもの・空のものは組み立てを始めずに捨てる', () => {
    rx.receive(chunk(1, 0, 2, new Uint8Array(CHUNK + 1)));
    rx.receive(chunk(2, 0, 2, new Uint8Array(0)));
    expect(rx.pendingCount).toBe(0);
    expect(got).toHaveLength(0);
    rx.receive(chunk(3, 0, 2, new Uint8Array(CHUNK)));
    expect(rx.pendingCount).toBe(1);
  });

  it('★同じ msgId で total を変えてきたら、組み立て中のものごと捨てる', () => {
    rx.receive(chunk(1, 0, 3, new Uint8Array(4)));
    expect(rx.pendingCount).toBe(1);
    rx.receive(chunk(1, 1, 4, new Uint8Array(4)));
    expect(rx.pendingCount).toBe(0);
    // その後に元の続きが来ても完成しない (新しい組み立てとして始まる)
    rx.receive(chunk(1, 1, 3, new Uint8Array(4)));
    rx.receive(chunk(1, 2, 3, new Uint8Array(4)));
    expect(got).toHaveLength(0);
  });

  it('★1 メッセージの合計は 1MB まで (チャンクごとに 4096 以内なので、256 チャンクでちょうど届く)', () => {
    const full = new Uint8Array(CHUNK);
    for (let seq = 0; seq < 255; seq++) rx.receive(chunk(1, seq, 256, full));
    expect(rx.pendingCount).toBe(1);
    rx.receive(chunk(1, 255, 256, full));
    expect(got).toHaveLength(1);
    expect(got[0].byteLength).toBe(1024 * 1024);
  });

  it('ちょうど 1MB のメッセージは組み立てられる', async () => {
    const data = pattern(1024 * 1024);
    for (const c of await sendThrough(data)) rx.receive(toBuf(c));
    expect(got).toHaveLength(1);
    expect(got[0].byteLength).toBe(1024 * 1024);
  });

  it('★同時に組み立てる数は 64 まで。超えたら最も古いものを捨てる', () => {
    for (let id = 0; id < 64; id++) rx.receive(chunk(id, 0, 2, new Uint8Array([id])));
    expect(rx.pendingCount).toBe(64);
    rx.receive(chunk(1000, 0, 2, new Uint8Array([0xff])));
    expect(rx.pendingCount).toBe(64);
    // id=1 は残っている
    rx.receive(chunk(1, 1, 2, new Uint8Array([9])));
    expect(got.map(g => Array.from(new Uint8Array(g)))).toEqual([[1, 9]]);
    // 最古 (id=0) は消えているので、続きが来ても完成しない (新しい組み立てとして始まるだけ)
    rx.receive(chunk(0, 1, 2, new Uint8Array([0])));
    expect(got).toHaveLength(1);
  });

  it('★組み立てが 10 秒以上終わらないものは定期掃除で捨てる', () => {
    rx.receive(chunk(1, 0, 2, new Uint8Array([1])));
    vi.advanceTimersByTime(10_000);
    // 10 秒ちょうどの掃除 (5 秒刻み) ではまだ消えない
    expect(rx.pendingCount).toBe(1);
    vi.advanceTimersByTime(5_000);
    expect(rx.pendingCount).toBe(0);
    rx.receive(chunk(1, 1, 2, new Uint8Array([2])));
    expect(got).toHaveLength(0);
  });

  it('期限内に揃えば掃除の影響を受けない', () => {
    rx.receive(chunk(1, 0, 2, new Uint8Array([1])));
    vi.advanceTimersByTime(9_000);
    rx.receive(chunk(1, 1, 2, new Uint8Array([2])));
    expect(Array.from(new Uint8Array(got[0]))).toEqual([1, 2]);
  });

  it('destroy で保留を捨て、タイマーも止まる', () => {
    rx.receive(chunk(1, 0, 2, new Uint8Array([1])));
    rx.destroy();
    expect(rx.pendingCount).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});
