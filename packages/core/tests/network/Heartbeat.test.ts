import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Heartbeat } from '../../src/network/Heartbeat';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { FakeNetworkPeerManager, pid } from '../helpers/fakeNetworkPeerManager';

const INTERVAL = 15_000;

describe('Heartbeat', () => {
  let pm: FakeNetworkPeerManager;
  let d: MessageDispatcher;
  let hb: Heartbeat;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    pm = new FakeNetworkPeerManager();
    d = new MessageDispatcher();
    hb = new Heartbeat(pm, d);
  });
  afterEach(() => {
    hb.stop();
    vi.useRealTimers();
  });

  const pings = () => pm.sent.filter(s => s.type === WireType.PING);
  const pongs = () => pm.sent.filter(s => s.type === WireType.PONG);

  it('start 前は何も送らず、start 後は 15 秒ごとに接続中の全ピアへ PING を送る', () => {
    pm.addPeer(pid(1));
    pm.addPeer(pid(2));
    pm.addPeer(pid(3), { isConnected: false });
    vi.advanceTimersByTime(INTERVAL * 2);
    expect(pm.sent).toHaveLength(0);

    hb.start();
    vi.advanceTimersByTime(INTERVAL - 1);
    expect(pings()).toHaveLength(0);
    vi.advanceTimersByTime(1);
    expect(pings().map(s => s.to).sort()).toEqual([pid(1), pid(2)]);
    vi.advanceTimersByTime(INTERVAL);
    expect(pings()).toHaveLength(4);
  });

  it('start を二度呼んでもタイマーは 1 つ、stop で止まる', () => {
    pm.addPeer(pid(1));
    hb.start();
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    expect(pings()).toHaveLength(1);
    hb.stop();
    hb.stop();
    vi.advanceTimersByTime(INTERVAL * 3);
    expect(pings()).toHaveLength(1);
  });

  it('★PING に時計の値を載せない: nonce は crypto.getRandomValues の 32 ビット nonce', () => {
    pm.addPeer(pid(1));
    const nonces = [0xdeadbeef, 7, 0xffffffff];
    let i = 0;
    const spy = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((arr: Uint32Array) => {
      arr[0] = nonces[i++ % nonces.length];
      return arr;
    }) as any);
    try {
      hb.start();
      vi.advanceTimersByTime(INTERVAL * 3);
    } finally {
      spy.mockRestore();
    }
    expect(pings().map(p => p.payload.nonce)).toEqual(nonces);
    expect(Object.keys(pings()[0].payload)).toEqual(['nonce']);
  });

  it('PING を受けたら同じ nonce の数値だけを PONG で返す', () => {
    d.dispatch(pid(7), WireType.PING, { nonce: 12345, extra: 'x' });
    expect(pongs()).toEqual([{ to: pid(7), type: WireType.PONG, payload: { nonce: 12345 } }]);
  });

  it('★nonce が整数でない PING には応答しない (任意のオブジェクトを反射させない)', () => {
    for (const msg of [{ nonce: 'x' }, { nonce: { a: 1 } }, { nonce: NaN }, { nonce: Infinity }, { nonce: 1.5 }, {}, null, undefined, 42]) {
      d.dispatch(pid(7), WireType.PING, msg);
    }
    expect(pongs()).toHaveLength(0);
  });

  it('自分が送った nonce の PONG で RTT を手元の時計から測る', () => {
    const peer = pm.addPeer(pid(1));
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const ts = pings()[0].payload.nonce;
    vi.advanceTimersByTime(123);
    d.dispatch(pid(1), WireType.PONG, { nonce: ts });
    expect(peer.rtt).toBe(123);
  });

  it('★自分が送っていない nonce の PONG は無視する', () => {
    const peer = pm.addPeer(pid(1), { rtt: 50 });
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const ts = pings()[0].payload.nonce;
    d.dispatch(pid(1), WireType.PONG, { nonce: (ts + 1) >>> 0 });
    d.dispatch(pid(1), WireType.PONG, { nonce: String(ts) + 'x' });
    d.dispatch(pid(1), WireType.PONG, null);
    expect(peer.rtt).toBe(50);
  });

  it('★他のピア宛ての nonce を別のピアが返しても受け付けない', () => {
    const a = pm.addPeer(pid(1), { rtt: 10 });
    const b = pm.addPeer(pid(2), { rtt: 20 });
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const tsForA = pings().find(s => s.to === pid(1))!.payload.nonce;
    vi.advanceTimersByTime(5);
    d.dispatch(pid(2), WireType.PONG, { nonce: tsForA });
    expect(b.rtt).toBe(20);
    expect(a.rtt).toBe(10);
  });

  it('同じ PONG を二度返しても RTT は最初の 1 回でしか更新されない', () => {
    const peer = pm.addPeer(pid(1));
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const ts = pings()[0].payload.nonce;
    vi.advanceTimersByTime(40);
    d.dispatch(pid(1), WireType.PONG, { nonce: ts });
    vi.advanceTimersByTime(1000);
    d.dispatch(pid(1), WireType.PONG, { nonce: ts });
    expect(peer.rtt).toBe(40);
  });

  it('返事の来ない古い記録は 2 周期を過ぎると捨てられ、遅れて来た PONG は無視される', () => {
    const peer = pm.addPeer(pid(1), { rtt: 7 });
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const ts = pings()[0].payload.nonce;
    // 3 周期後の pingAll で now - at = 45s > 30s となり消える
    vi.advanceTimersByTime(INTERVAL * 3);
    d.dispatch(pid(1), WireType.PONG, { nonce: ts });
    expect(peer.rtt).toBe(7);
  });

  it('切断済みのピアからの PONG で落ちない', () => {
    pm.addPeer(pid(1));
    hb.start();
    vi.advanceTimersByTime(INTERVAL);
    const ts = pings()[0].payload.nonce;
    pm._peers.delete(pid(1));
    expect(() => d.dispatch(pid(1), WireType.PONG, { nonce: ts })).not.toThrow();
  });
});
