import { describe, it, expect, vi } from 'vitest';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';

describe('MessageDispatcher', () => {
  it('登録した WireType のハンドラにだけ (peerId, payload) を渡す', () => {
    const d = new MessageDispatcher();
    const ping = vi.fn();
    const pong = vi.fn();
    d.register(WireType.PING, ping);
    d.register(WireType.PONG, pong);
    d.dispatch('peer-a', WireType.PING, { ts: 1 });
    expect(ping).toHaveBeenCalledWith('peer-a', { ts: 1 });
    expect(pong).not.toHaveBeenCalled();
  });

  it('同じ型に複数のハンドラを登録でき、登録順に全員へ配る', () => {
    const d = new MessageDispatcher();
    const order: string[] = [];
    d.register(WireType.PEX_RESPONSE, () => order.push('pex'));
    d.register(WireType.PEX_RESPONSE, () => order.push('onion'));
    d.dispatch('p', WireType.PEX_RESPONSE, {});
    expect(order).toEqual(['pex', 'onion']);
  });

  it('同じ関数を二度登録しても一度しか呼ばれない', () => {
    const d = new MessageDispatcher();
    const h = vi.fn();
    d.register(WireType.GOSSIP, h);
    d.register(WireType.GOSSIP, h);
    d.dispatch('p', WireType.GOSSIP, {});
    expect(h).toHaveBeenCalledTimes(1);
  });

  it('ハンドラの無い型は黙って捨てる (例外を投げない)', () => {
    const d = new MessageDispatcher();
    expect(() => d.dispatch('p', WireType.CATCHUP_END, {})).not.toThrow();
    expect(() => d.dispatch('p', 0x99, null)).not.toThrow();
  });

  it('★1 つのハンドラが例外を投げても、他のハンドラには配られ、呼び出し元にも漏れない', () => {
    const d = new MessageDispatcher();
    const after = vi.fn();
    d.register(WireType.CATCHUP_DATA, () => { throw new Error('boom'); });
    d.register(WireType.CATCHUP_DATA, after);
    expect(() => d.dispatch('p', WireType.CATCHUP_DATA, { x: 1 })).not.toThrow();
    expect(after).toHaveBeenCalledWith('p', { x: 1 });
  });

  it('unregister したハンドラには配らない (他は残る)', () => {
    const d = new MessageDispatcher();
    const a = vi.fn();
    const b = vi.fn();
    d.register(WireType.STEM, a);
    d.register(WireType.STEM, b);
    d.unregister(WireType.STEM, a);
    d.dispatch('p', WireType.STEM, {});
    expect(a).not.toHaveBeenCalled();
    expect(b).toHaveBeenCalledTimes(1);
    // 未登録の型・関数の unregister は無害
    expect(() => d.unregister(WireType.CATCHUP_REQ, a)).not.toThrow();
  });

  it('ハンドラ内で自分を unregister しても、その回の配信は壊れない', () => {
    const d = new MessageDispatcher();
    const second = vi.fn();
    const first = () => d.unregister(WireType.PING, first);
    d.register(WireType.PING, first);
    d.register(WireType.PING, second);
    d.dispatch('p', WireType.PING, {});
    expect(second).toHaveBeenCalledTimes(1);
    d.dispatch('p', WireType.PING, {});
    expect(second).toHaveBeenCalledTimes(2);
  });

  it('payload はそのまま (コピーせずに) 渡す', () => {
    const d = new MessageDispatcher();
    const payload = { a: 1 };
    let got: unknown;
    d.register(WireType.CATCHUP_REQ, (_p, m) => { got = m; });
    d.dispatch('p', WireType.CATCHUP_REQ, payload);
    expect(got).toBe(payload);
  });
});
