import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RingMaintainer } from '../../src/network/RingMaintainer';
import { PEXHandler } from '../../src/network/PEXHandler';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { RING_MESH } from '../../src/constants';
import { FakeNetworkPeerManager, pid } from '../helpers/fakeNetworkPeerManager';

const TICK = RING_MESH.REPAIR_CHECK_INTERVAL;

describe('RingMaintainer', () => {
  let pm: FakeNetworkPeerManager;
  let pex: PEXHandler;
  let rm: RingMaintainer;

  beforeEach(() => {
    vi.useFakeTimers();
    pm = new FakeNetworkPeerManager();
    pex = new PEXHandler(pm, new MessageDispatcher());
    rm = new RingMaintainer(pm, pex);
  });
  afterEach(() => {
    rm.destroy();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const pexRequests = () => pm.sent.filter(s => s.type === WireType.PEX_REQUEST);

  it('接続・切断のたびに PeerManager.rebalance に調整を任せる', () => {
    pm.emit('peer:connect', pid(1));
    pm.emit('peer:disconnect', pid(1));
    expect(pm.rebalance).toHaveBeenCalledTimes(2);
  });

  it('rebalance を持たない PeerManager でも落ちない', () => {
    (pm as any).rebalance = undefined;
    expect(() => rm.evaluateTopology()).not.toThrow();
  });

  it('10 秒ごとに調整し、次数が足りなければ接続中の 1 人だけに PEX を依頼する', () => {
    for (let i = 1; i <= 3; i++) pm.addPeer(pid(i));
    pm.addPeer(pid(4), { isConnected: false });
    pm.outboundCount = 3;
    vi.advanceTimersByTime(TICK - 1);
    expect(pexRequests()).toHaveLength(0);
    vi.advanceTimersByTime(1);
    expect(pm.rebalance).toHaveBeenCalledTimes(1);
    expect(pexRequests()).toHaveLength(1);
    expect([pid(1), pid(2), pid(3)]).toContain(pexRequests()[0].to);
    expect(pexRequests()[0].payload).toEqual({});
  });

  it('依頼先は接続中のピアから選ぶ (Math.random で選ばれた添字)', () => {
    for (let i = 1; i <= 4; i++) pm.addPeer(pid(i));
    pm.outboundCount = 0;
    vi.spyOn(Math, 'random').mockReturnValue(0.99);
    vi.advanceTimersByTime(TICK);
    expect(pexRequests()[0].to).toBe(pid(4));
  });

  it('隣人がいなければ PEX は送らない (トラッカー頼み)', () => {
    vi.advanceTimersByTime(TICK * 3);
    expect(pexRequests()).toHaveLength(0);
    expect(pm.rebalance).toHaveBeenCalledTimes(3);
  });

  it('次数が上限かつ outbound が目標に達していれば PEX しない', () => {
    for (let i = 1; i <= 3; i++) pm.addPeer(pid(i));
    pm.degreeOverride = RING_MESH.MAX_DEGREE;
    pm.outboundCount = RING_MESH.OUTBOUND_TARGET;
    vi.advanceTimersByTime(TICK * 2);
    expect(pexRequests()).toHaveLength(0);
  });

  it('次数が上限でも outbound が目標未満なら PEX する', () => {
    for (let i = 1; i <= 3; i++) pm.addPeer(pid(i));
    pm.degreeOverride = RING_MESH.MAX_DEGREE;
    pm.outboundCount = RING_MESH.OUTBOUND_TARGET - 1;
    vi.advanceTimersByTime(TICK);
    expect(pexRequests()).toHaveLength(1);
  });

  it('outboundCount を持たない PeerManager では目標達成とみなし、次数だけで判断する', () => {
    for (let i = 1; i <= 3; i++) pm.addPeer(pid(i));
    pm.outboundCount = undefined;
    pm.degreeOverride = RING_MESH.MAX_DEGREE;
    vi.advanceTimersByTime(TICK);
    expect(pexRequests()).toHaveLength(0);
    pm.degreeOverride = RING_MESH.MAX_DEGREE - 1;
    vi.advanceTimersByTime(TICK);
    expect(pexRequests()).toHaveLength(1);
  });

  it('次数は数えるが接続中のピアが 1 人もいない場合は PEX しない', () => {
    pm.addPeer(pid(1), { isConnected: false });
    pm.degreeOverride = 1;
    pm.outboundCount = 0;
    vi.advanceTimersByTime(TICK);
    expect(pexRequests()).toHaveLength(0);
  });

  it('destroy で定期処理が止まる', () => {
    pm.addPeer(pid(1));
    pm.outboundCount = 0;
    rm.destroy();
    vi.advanceTimersByTime(TICK * 5);
    expect(pexRequests()).toHaveLength(0);
    expect(pm.rebalance).not.toHaveBeenCalled();
  });
});
