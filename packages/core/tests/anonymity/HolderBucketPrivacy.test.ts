import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { WireType } from '../../src/network/wire/WireTypes';
import { DAY_MS } from '../../src/crypto/PowPolicy';
import { encodeFetchRequest } from '../../src/network/history/FetchBucket';
import { createSimNode, link, announceVerified, stopAll, makePacket } from '../helpers/onionNet';
import { stopStorage } from '../helpers/storageNet';
import { attachTunnel, attachBehind, stopTunnel, until, type TunnelSimNode } from '../helpers/tunnelNet';

/**
 * 保持者の IP ↔ バケットの対応は、信頼 Guard 以外には流れない (history v2 §5)。
 *
 *   監視ノード (信頼 Guard ではない、網に混ぜた一般ノード) が見られるのは flood されるもの (leaseSet・投稿) だけ。
 *   leaseSet には SID・枠・受け口の Guard の peerId が載るが、保持者の peerId / 公開鍵 (= IP につながる情報) は載らない。
 *   取得の要求・応答 (TUNNEL_*) は Guard 同士と、読み手・保持者の 1 ホップ目の間だけを流れる。監視ノードには 1 通も来ない。
 */
const TAG = 0x321;
const BASE = Math.floor((Date.now() - 6 * DAY_MS) / DAY_MS) * DAY_MS + 9 * 3600_000;
const BIRTH_DAY = Math.floor(BASE / DAY_MS);

const hasBytes = (hay: Uint8Array, needle: Uint8Array): boolean => {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

describe('匿名性: 保持者の IP ↔ バケットは、信頼 Guard 以外のワイヤに現れない', () => {
  let nodes: TunnelSimNode[] = [];
  let g1: TunnelSimNode, g2: TunnelSimNode, h: TunnelSimNode, r: TunnelSimNode, mon1: TunnelSimNode, mon2: TunnelSimNode;

  beforeAll(async () => {
    await sodiumReady;
    const ids = new Set<string>();
    const mkG = async (n: string) => attachTunnel(await createSimNode(n), { storage: { slots: 1, wait: false }, relay: { role: 'guard', isBackbone: (id) => ids.has(id) } });
    g1 = await mkG('g1'); g2 = await mkG('g2');
    ids.add(g1.identity.peerId); ids.add(g2.identity.peerId);
    link(g1, g2); announceVerified(g1, g2);
    const mk = async (n: string, w = false) => attachTunnel(await createSimNode(n), { storage: { slots: 1, wait: w } });
    h = await mk('holder', true);
    r = await mk('reader');
    // 監視ノード: 信頼 Guard ではない一般ノード。Guard の隣人として網に混ざり、flood を全部受け取る
    mon1 = await mk('mon1'); mon2 = await mk('mon2');
    nodes = [g1, g2, h, r, mon1, mon2];
    attachBehind(h, g1);
    attachBehind(r, g2);
    attachBehind(mon1, g1);
    attachBehind(mon2, g2);
    link(mon1, mon2); // 監視ノード同士も協力できる
    const p = makePacket([5], BASE, { tag: TAG, age: 0 });
    await h.storage.holder!.put(p);
    h.storage.router.publish();
    await until(() => h.storage.tunnel!.registered && r.storage.leaseSets.size === 1, 5000, 'ready');
    const res = await r.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(true);
  }, 30_000);

  afterAll(async () => {
    stopTunnel(nodes);
    await stopStorage(nodes);
    stopAll(nodes);
  });

  it('★監視ノードには TUNNEL_* が 1 通も来ない。来るのは flood される leaseSet (と SYNC) だけ', () => {
    for (const mon of [mon1, mon2]) {
      const types = new Set(mon.inbox.map(m => m.type));
      for (const t of types) {
        expect([WireType.LEASESET, WireType.LEASESET_SYNC, WireType.LEASESET_SYNC_REQ, WireType.PING, WireType.PONG]).toContain(t);
      }
      expect(mon.inbox.some(m => m.type >= 0x80 && m.type <= 0x88)).toBe(false);
    }
  });

  it('★監視ノードが集められる全フレームに、バケット (birthDay・tag・since の要求) も保持者の peerId・公開鍵も載らない。leaseSet が名指すのは受け口の Guard だけ', () => {
    const request = encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since: 0 });
    const holderRaw = Encoding.fromHex(h.identity.peerId);
    const holderKey = h.identity.pubkey;
    const readerRaw = Encoding.fromHex(r.identity.peerId);
    for (const mon of [mon1, mon2]) {
      expect(mon.inbox.length).toBeGreaterThan(0);
      for (const f of mon.inbox) {
        expect(hasBytes(f.raw, request)).toBe(false);
        expect(hasBytes(f.raw, holderRaw), 'holder peerId').toBe(false);
        expect(hasBytes(f.raw, holderKey), 'holder pubkey').toBe(false);
        expect(hasBytes(f.raw, readerRaw), 'reader peerId').toBe(false);
      }
      // 手元の leaseSet から引ける受け口は Guard (g1)。保持者の IP を持つのは g1 だけ
      const ls = mon.storage.leaseSets.get(h.sid)!;
      expect(ls.gateway).toBe(g1.identity.peerId);
    }
  });

  it('★保持者と読み手は、自分の 1 ホップ目の Guard としか話さない。保持者が受け取った全フレームは g1 から、読み手の要求は g2 だけへ', () => {
    for (const f of h.inbox) expect(f.from).toBe(g1.identity.peerId);
    for (const f of r.inbox) expect(f.from).toBe(g2.identity.peerId);
    // 取得の要求・応答が通ったのは Guard の間 (バックボーン) と両端の 1 ホップ目だけ
    const tunnelSenders = new Set<string>();
    for (const n of nodes) for (const f of n.inbox) if (f.type >= 0x80 && f.type <= 0x88) tunnelSenders.add(`${n.name}<-${f.from === g1.identity.peerId ? 'g1' : f.from === g2.identity.peerId ? 'g2' : f.from === h.identity.peerId ? 'holder' : f.from === r.identity.peerId ? 'reader' : 'other'}`);
    expect(Array.from(tunnelSenders).sort()).toEqual(['g1<-g2', 'g1<-holder', 'g2<-g1', 'g2<-reader', 'holder<-g1', 'reader<-g2'].sort());
  });
});
