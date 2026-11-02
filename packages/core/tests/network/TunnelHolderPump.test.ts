import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { TunnelHolder, TUNNEL_HOLDER_LIMITS } from '../../src/network/storage/TunnelHolder';
import { StorageIdentity } from '../../src/network/storage/StorageIdentity';
import { TUNNEL_CHUNK_DATA_BYTES, TUNNEL_KIND, decryptChunk, newRespKey } from '../../src/network/tunnel/TunnelCrypto';
import { WireType } from '../../src/network/wire/WireTypes';
import { LOGIC_FAKE_TIMERS } from '../helpers/logicHarness';

const GATEWAY = 'a'.repeat(32);
const HOP = 'b'.repeat(32);

/**
 * TunnelHolder の応答の送出 (pump)。平均 1 片 / CHUNK_INTERVAL_MS を保ったまま、
 *   - 受け口への送信待ちが PUMP_MAX_BUFFERED を超えている間は送らない
 *   - タイマーが遅れた分 (バックグラウンドのタブなど) は、PUMP_BURST_MS ぶんまで次の回にまとめて送る
 */
describe('TunnelHolder: 応答の片の送出', () => {
  let t: number;
  let buffered: number;
  let sent: Array<{ seq: number; final: boolean; body: Uint8Array }>;
  let holder: TunnelHolder;
  let identity: StorageIdentity;

  beforeAll(async () => {
    await sodiumReady;
    identity = await StorageIdentity.loadOrCreate(null, 1);
  });

  beforeEach(() => {
    vi.useFakeTimers(LOGIC_FAKE_TIMERS);
    t = 1_000_000;
    buffered = 0;
    sent = [];
    const peerManager: any = {
      on: () => {}, off: () => {},
      sendMessage: (to: string, type: WireType, msg: any) => {
        expect(to).toBe(GATEWAY);
        expect(type).toBe(WireType.TUNNEL_REPLY);
        sent.push({ seq: msg.seq, final: msg.final, body: msg.body });
      },
      bufferedAmountOf: () => buffered,
    };
    const dispatcher: any = { register: () => {} };
    const leaseRouter: any = { onPublished: () => {} };
    holder = new TunnelHolder(peerManager, dispatcher, leaseRouter, identity, null, { now: () => t });
  });

  afterEach(() => {
    holder.destroy();
    vi.useRealTimers();
  });

  /** n 片の応答を 1 つ積む (中身は respond が respKey で暗号化する) */
  async function respond(n: number) {
    const key = newRespKey();
    const copy = key.slice();
    const payload = new Uint8Array(n * TUNNEL_CHUNK_DATA_BYTES).map((_, i) => i & 0xff);
    const released = vi.fn();
    await (holder as any).respond(GATEWAY, 7, HOP, TUNNEL_KIND.FETCH_BUCKET, key, async () => payload, released);
    return { key: copy, payload, released };
  }

  const burst = TUNNEL_HOLDER_LIMITS.PUMP_BURST_MS / TUNNEL_HOLDER_LIMITS.CHUNK_INTERVAL_MS;

  it('受け口への送信待ちが上限を超えている間は送らず、減ったら続きを番号順に送る', async () => {
    buffered = TUNNEL_HOLDER_LIMITS.PUMP_MAX_BUFFERED + 1;
    const { key, payload, released } = await respond(5);
    t += 500;
    await vi.advanceTimersByTimeAsync(500);
    expect(sent).toHaveLength(0);

    buffered = 0;
    t += 100;
    await vi.advanceTimersByTimeAsync(100);
    expect(sent.map(s => s.seq)).toEqual([0, 1, 2, 3, 4]);
    expect(sent.map(s => s.final)).toEqual([false, false, false, false, true]);
    expect(released).toHaveBeenCalledTimes(1);
    const plain = sent.map(s => decryptChunk(key, TUNNEL_KIND.FETCH_BUCKET, s.seq, s.body)!.data);
    expect(new Uint8Array(plain.flatMap(p => Array.from(p)))).toEqual(payload);
  });

  it('タイマーが遅れて (1 秒) 発火しても、貯まった枠のぶん (PUMP_BURST_MS) をまとめて送る。それ以上は送らない', async () => {
    await respond(3 * burst);
    await vi.advanceTimersToNextTimerAsync();
    expect(sent).toHaveLength(burst); // 最初は枠が満杯

    // 次のタイマーは 10ms 後の予定。1 秒遅れて発火した
    t += 1000;
    await vi.advanceTimersToNextTimerAsync();
    expect(sent).toHaveLength(2 * burst); // 旧実装はここで 1 片だけ
    expect(sent.map(s => s.seq)).toEqual(Array.from({ length: 2 * burst }, (_, i) => i));
  });

  it('平均の速さは 1 片 / CHUNK_INTERVAL_MS のまま (枠を使い切ったあとは間隔どおり)', async () => {
    await respond(3 * burst);
    await vi.advanceTimersToNextTimerAsync();
    expect(sent).toHaveLength(burst);
    for (let i = 0; i < 10; i++) {
      t += TUNNEL_HOLDER_LIMITS.CHUNK_INTERVAL_MS;
      await vi.advanceTimersByTimeAsync(TUNNEL_HOLDER_LIMITS.CHUNK_INTERVAL_MS);
    }
    expect(sent.length).toBeGreaterThanOrEqual(burst + 9);
    expect(sent.length).toBeLessThanOrEqual(burst + 10);
  });
});
