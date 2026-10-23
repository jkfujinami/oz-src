import { describe, it, expect, beforeEach, vi } from 'vitest';
import { PEXHandler } from '../../src/network/PEXHandler';
import { MessageDispatcher } from '../../src/network/MessageDispatcher';
import { WireType } from '../../src/network/wire/WireTypes';
import { RING_MESH } from '../../src/constants';
import { FakeNetworkPeerManager, pid } from '../helpers/fakeNetworkPeerManager';

describe('PEXHandler', () => {
  let pm: FakeNetworkPeerManager;
  let d: MessageDispatcher;
  let pex: PEXHandler;

  beforeEach(() => {
    pm = new FakeNetworkPeerManager(pid(0xfff));
    d = new MessageDispatcher();
    pex = new PEXHandler(pm, d);
  });

  const responses = () => pm.sent.filter(s => s.type === WireType.PEX_RESPONSE);

  describe('requestPeers', () => {
    it('宛先を指定すればその 1 人にだけ 空の PEX_REQUEST を送る', () => {
      pm.addPeer(pid(1));
      pm.addPeer(pid(2));
      pex.requestPeers(pid(2));
      expect(pm.sent).toEqual([{ to: pid(2), type: WireType.PEX_REQUEST, payload: {} }]);
    });

    it('宛先を省略すれば隣人全員に送る', () => {
      pm.addPeer(pid(1));
      pm.addPeer(pid(2));
      pex.requestPeers();
      expect(pm.sent.map(s => s.to).sort()).toEqual([pid(1), pid(2)]);
      expect(pm.sent.every(s => s.type === WireType.PEX_REQUEST)).toBe(true);
    });
  });

  describe('PEX_REQUEST への応答', () => {
    it('検証済み・接続中の隣人だけを返し、要求者自身は含めない', () => {
      pm.addPeer(pid(1));
      pm.addPeer(pid(2), { isVerified: false });
      pm.addPeer(pid(3), { isConnected: false });
      pm.addPeer(pid(4));
      d.dispatch(pid(4), WireType.PEX_REQUEST, {});
      const r = responses();
      expect(r).toHaveLength(1);
      expect(r[0].to).toBe(pid(4));
      expect(r[0].payload.peers).toEqual([{ id: pid(1) }]);
    });

    it('★position も zones も載せない。pubkey と powCounter が分かる隣人はそれを添える', () => {
      const pubkey = new Uint8Array(32).fill(9);
      pm.addPeer(pid(1), { pubkey, powCounter: 42, position: 0.123 } as any);
      pm.addPeer(pid(2), { position: 0.9 });
      d.dispatch(pid(9), WireType.PEX_REQUEST, {});
      const peers = responses()[0].payload.peers;
      const byId = Object.fromEntries(peers.map((p: any) => [p.id, p]));
      expect(byId[pid(1)]).toEqual({ id: pid(1), pubkey, powCounter: 42 });
      expect(byId[pid(2)]).toEqual({ id: pid(2) });
      for (const p of peers) {
        expect(p).not.toHaveProperty('position');
        expect(p).not.toHaveProperty('zones');
      }
    });

    it('pubkey だけ・powCounter だけの隣人は id のみ', () => {
      pm.addPeer(pid(1), { pubkey: new Uint8Array(32) } as any);
      pm.addPeer(pid(2), { powCounter: 3 } as any);
      d.dispatch(pid(9), WireType.PEX_REQUEST, {});
      for (const p of responses()[0].payload.peers) expect(Object.keys(p)).toEqual(['id']);
    });

    it('★隣人が多くても返すのは 8 件まで', () => {
      for (let i = 1; i <= 20; i++) pm.addPeer(pid(i));
      d.dispatch(pid(99), WireType.PEX_REQUEST, {});
      const peers = responses()[0].payload.peers;
      expect(peers).toHaveLength(8);
      expect(new Set(peers.map((p: any) => p.id)).size).toBe(8);
    });

    it('★返す 8 件は暗号論的乱数で選ぶ (先頭固定だと早期接続した攻撃者が紹介され続ける)', () => {
      for (let i = 1; i <= 20; i++) pm.addPeer(pid(i));
      // 乱数源を差し替えて、結果が乱数に従うことを確かめる
      const run = (fill: number) => {
        const spy = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((a: Uint32Array) => { a[0] = fill; return a; }) as any);
        try {
          pm.sent = [];
          d.dispatch(pid(99), WireType.PEX_REQUEST, {});
          return responses()[0].payload.peers.map((p: any) => p.id);
        } finally {
          spy.mockRestore();
        }
      };
      const a = run(0);
      const b = run(0x7fffffff);
      expect(a).not.toEqual(b);
      // 挿入順の先頭 8 件そのままではない
      const firstEight = Array.from({ length: 8 }, (_, i) => pid(i + 1));
      expect(a).not.toEqual(firstEight);
    });

    it('隣人がいなければ空の配列を返す', () => {
      d.dispatch(pid(1), WireType.PEX_REQUEST, {});
      expect(responses()[0].payload).toEqual({ peers: [] });
    });
  });

  describe('PEX_RESPONSE の処理', () => {
    it('知らない正しい形式の peerId に、紹介者経由で outbound として接続しに行く', () => {
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pid(5) }, { id: pid(6) }] });
      expect(pm.connect.mock.calls).toEqual([[pid(5), true, pid(1)], [pid(6), true, pid(1)]]);
    });

    it('★peerId の形式 (hex 32 文字) を検証し、それ以外は無視する', () => {
      d.dispatch(pid(1), WireType.PEX_RESPONSE, {
        peers: [
          { id: 'A'.repeat(32) }, { id: 'a'.repeat(31) }, { id: 'a'.repeat(33) }, { id: 'g'.repeat(32) },
          { id: 123 }, null, { id: `${'a'.repeat(32)}\n` }, { id: pid(5) }, // ← 8 件目まで
        ],
      });
      expect(pm.connect.mock.calls).toEqual([[pid(5), true, pid(1)]]);
      pm.connect.mockClear();
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{}, 'x', { id: [pid(6)] }, { id: { toString: () => pid(6) } }] });
      expect(pm.connect).not.toHaveBeenCalled();
    });

    it('自分自身・既に接続中/接続処理中の相手には接続しない', () => {
      pm.addPeer(pid(2));
      pm.addPeer(pid(3), { isConnected: false, isConnecting: true });
      pm.addPeer(pid(4), { isConnected: false });
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pm.myPeerId }, { id: pid(2) }, { id: pid(3) }, { id: pid(4) }] });
      // 切れているだけ (接続処理中でもない) の相手には張り直す
      expect(pm.connect.mock.calls).toEqual([[pid(4), true, pid(1)]]);
    });

    it('★相手が何件返してきても処理するのは先頭 8 件まで', () => {
      const peers = Array.from({ length: 50 }, (_, i) => ({ id: pid(100 + i) }));
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers });
      expect(pm.connect).toHaveBeenCalledTimes(8);
      expect(pm.connect.mock.calls.map(c => c[0])).toEqual(peers.slice(0, 8).map(p => p.id));
    });

    it('次数が上限かつ outbound も目標に達していれば接続しない', () => {
      pm.degreeOverride = RING_MESH.MAX_DEGREE;
      pm.outboundCount = RING_MESH.OUTBOUND_TARGET;
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pid(5) }] });
      expect(pm.connect).not.toHaveBeenCalled();
    });

    it('次数が上限でも outbound が目標未満なら接続しに行く (inbound で埋め尽くされない)', () => {
      pm.degreeOverride = RING_MESH.MAX_DEGREE;
      pm.outboundCount = RING_MESH.OUTBOUND_TARGET - 1;
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pid(5) }] });
      expect(pm.connect).toHaveBeenCalledWith(pid(5), true, pid(1));
    });

    it('outboundCount を持たない PeerManager では 0 とみなす (次数上限でも接続しに行く)', () => {
      pm.degreeOverride = RING_MESH.MAX_DEGREE;
      pm.outboundCount = undefined;
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pid(5) }] });
      expect(pm.connect).toHaveBeenCalledTimes(1);
    });

    it('次数に空きがあれば outbound 数に関係なく接続しに行く', () => {
      pm.degreeOverride = RING_MESH.MAX_DEGREE - 1;
      pm.outboundCount = RING_MESH.OUTBOUND_TARGET + 5;
      d.dispatch(pid(1), WireType.PEX_RESPONSE, { peers: [{ id: pid(5) }] });
      expect(pm.connect).toHaveBeenCalledTimes(1);
    });

    it('peers が配列でない応答は捨てる (例外を投げない)', () => {
      for (const msg of [null, undefined, {}, { peers: 'x' }, { peers: { 0: { id: pid(5) } } }, 7]) {
        expect(() => d.dispatch(pid(1), WireType.PEX_RESPONSE, msg)).not.toThrow();
      }
      expect(pm.connect).not.toHaveBeenCalled();
    });
  });
});
