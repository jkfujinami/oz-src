import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { WireType } from '../../src/network/wire/WireTypes';
import { TUNNEL_ERROR_CODE } from '../../src/network/wire/WireCodec';
import { DAY_MS } from '../../src/crypto/PowPolicy';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { FETCH_STATUS, decodeFetchResponse, encodeFetchRequest } from '../../src/network/history/FetchBucket';
import { TUNNEL_CHUNK_DATA_BYTES, TUNNEL_KIND, decryptChunk, parseRequestPlain, newRespKey, sealRequest } from '../../src/network/tunnel/TunnelCrypto';
import { createSimNode, link, announceVerified, stopAll, sleep, makePacket, type SimNode } from '../helpers/onionNet';
import { stopStorage } from '../helpers/storageNet';
import { attachTunnel, attachBehind, stopTunnel, until, type TunnelSimNode, type AttachTunnelOptions } from '../helpers/tunnelNet';
import type { GossipPacket } from '../../src/types';

/**
 * トンネルと HistoryClient の、複数ノードでの端から端まで。本物の PeerManager・WireCodec・GossipRouter・LeaseSetRouter・
 * StorageService (暗号化 DB + HolderStore)・TunnelRelay / TunnelHolder / TunnelClient / HistoryClient を通す。
 *
 *      r1 ─┐              ┌─ r2
 *    h1a ──┤ g1 ═══ g2 ├── h2a        (═ = バックボーン。h* = 保持者、r* = 読み手)
 *    h1b ──┘              └── h2b
 *
 * 保持者は自分の Guard を受け口にして leaseSet を出し、TUNNEL_REGISTER で登録する。読み手は 1 ホップ目 (自分の Guard)
 * に TUNNEL_SEND し、相手の Guard (バックボーン) を経て保持者に届く。
 */
const TAG = 0x123;
const COUNT = 4;

/** 5 日前の正午 (UTC)。Guard の 72 時間バッファより古い。同じ日 (birthDay) に収まる */
const BASE = Math.floor((Date.now() - 5 * DAY_MS) / DAY_MS) * DAY_MS + 12 * 3600_000;
const BIRTH_DAY = Math.floor(BASE / DAY_MS);

let packets: GossipPacket[];
beforeAll(async () => {
  await sodiumReady;
  packets = Array.from({ length: COUNT }, (_, i) => makePacket([i + 1], BASE + i * 60_000, { tag: TAG, age: 0 }));
}, 60_000);

const idsOf = (list: GossipPacket[]) => list.map(p => p.packet_id).sort();
const hasBytes = (hay: Uint8Array, needle: Uint8Array): boolean => {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

interface Net {
  g1: TunnelSimNode; g2: TunnelSimNode;
  h1a: TunnelSimNode; h1b: TunnelSimNode; h2a: TunnelSimNode; h2b: TunnelSimNode;
  r1: TunnelSimNode; r2: TunnelSimNode;
  all: TunnelSimNode[];
  holders: TunnelSimNode[];
}

describe('トンネル + HistoryClient: 複数ノードでの端から端まで', () => {
  let net: Net;

  async function build(opts: { guard?: AttachTunnelOptions; holder?: AttachTunnelOptions; reader?: AttachTunnelOptions; data?: Array<keyof Net> } = {}): Promise<Net> {
    const guardIds = new Set<string>();
    const mkGuard = async (name: string) => attachTunnel(await createSimNode(name), {
      ...opts.guard,
      storage: { slots: 1, wait: false, ...opts.guard?.storage },
      relay: { role: 'guard', isBackbone: (id) => guardIds.has(id), ...opts.guard?.relay },
    });
    const g1 = await mkGuard('g1');
    const g2 = await mkGuard('g2');
    guardIds.add(g1.identity.peerId);
    guardIds.add(g2.identity.peerId);
    link(g1, g2);
    announceVerified(g1, g2);
    const mk = async (name: string, guard: TunnelSimNode, o?: AttachTunnelOptions) => {
      const n = await attachTunnel(await createSimNode(name), { ...o, storage: { slots: 1, ...o?.storage } });
      attachBehind(n, guard);
      return n;
    };
    const h1a = await mk('h1a', g1, opts.holder);
    const h1b = await mk('h1b', g1, opts.holder);
    const h2a = await mk('h2a', g2, opts.holder);
    const h2b = await mk('h2b', g2, opts.holder);
    const r1 = await mk('r1', g1, { ...opts.reader, storage: { wait: false, ...opts.reader?.storage } });
    const r2 = await mk('r2', g2, { ...opts.reader, storage: { wait: false, ...opts.reader?.storage } });
    const holders = [h1a, h1b, h2a, h2b];
    // データを持たせる (既定は g2 の後ろの保持者だけ。g1 の後ろは空 = 読み手 r1 は別の Guard の後ろから取るしかない)
    const withData = opts.data ?? ['h2a', 'h2b'];
    const named: Record<string, TunnelSimNode> = { h1a, h1b, h2a, h2b };
    for (const name of withData) for (const p of packets) await named[name as string].storage.holder!.put(p);
    for (const h of holders) h.storage.router.publish();
    net = { g1, g2, h1a, h1b, h2a, h2b, r1, r2, holders, all: [g1, g2, ...holders, r1, r2] };
    // 受け口への登録と、leaseSet の配布が済むまで待つ
    await until(() => holders.every(h => h.storage.tunnel!.registered), 5000, 'registered');
    await until(() => [r1, r2].every(r => r.storage.leaseSets.size === 4), 5000, 'leaseSets');
    return net;
  }

  beforeAll(async () => { await sodiumReady; });
  afterEach(async () => {
    if (!net) return;
    stopTunnel(net.all);
    await stopStorage(net.all);
    stopAll(net.all);
  });

  it('★別の Guard の後ろの保持者から、72 時間より古いバケットを取れる。手元へ配られ、再 flood はされない', async () => {
    await build();
    const { r1, g1, g2 } = net;
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: COUNT, reason: 'ok' });
    expect(idsOf(r1.received)).toEqual(idsOf(packets));
    // 取ってきた分は網に出ていない (GOSSIP は 1 通も流れていない)
    for (const n of net.all) expect(n.inbox.filter(m => m.type === WireType.GOSSIP)).toHaveLength(0);
    // g1 の後ろの保持者は空 (NOT_HELD)、データは g2 の後ろ: 要求は g1 から g2 を経ている
    expect(g2.inbox.filter(m => m.type === WireType.TUNNEL_FWD && m.from === g1.identity.peerId).length).toBeGreaterThanOrEqual(1);
    expect(r1.history.stats.fetches).toBe(1);
  });

  it('★R の Guard (G_R) は要求の平文を見ない。保持者は R の peerId を知らない (経路上の全フレームで検査)', async () => {
    await build();
    const { r1, r2, g1, g2, h1a, h1b, h2a, h2b } = net;
    await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });

    // 1. G_R が見た TUNNEL_SEND の本体は sealed box。G_R の鍵では開けず、宛先の保持者の SID の鍵でだけ開く
    const sends = g1.inbox.filter(m => m.type === WireType.TUNNEL_SEND && m.from === r1.identity.peerId);
    expect(sends.length).toBeGreaterThanOrEqual(2);
    const plainPayload = encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since: 0 });
    const respKeys: Uint8Array[] = [];
    for (const s of sends) {
      expect(g1.storage.identity.openSealed(s.payload.body)).toBeNull();
      expect(g2.storage.identity.openSealed(s.payload.body)).toBeNull();
      const openers = [h1a, h1b, h2a, h2b].filter(h => h.storage.identity.openSealed(s.payload.body));
      expect(openers).toHaveLength(1); // 宛先 1 台だけ
      const req = parseRequestPlain(openers[0].storage.identity.openSealed(s.payload.body)!)!;
      expect(req.kind).toBe(TUNNEL_KIND.FETCH_BUCKET);
      expect(Array.from(req.payload)).toEqual(Array.from(plainPayload));
      respKeys.push(req.respKey);
    }
    // 2. 経路上の Guard (g1・g2) が受け取った全フレームのどこにも、要求の平文 (バケット) も応答の鍵も、応答の中身 (投稿) も現れない
    const guardFrames = [...g1.inbox, ...g2.inbox];
    for (const f of guardFrames) {
      expect(hasBytes(f.raw, plainPayload), 'bucket plaintext').toBe(false);
      for (const k of respKeys) expect(hasBytes(f.raw, k), 'respKey').toBe(false);
      for (const p of packets) expect(hasBytes(f.raw, encodePacket(p).subarray(40, 80)), 'packet bytes').toBe(false);
    }
    // 3. 保持者が受け取った全フレームは、自分の Guard からだけ。R の peerId (hex でも生でも) はどこにも載らない
    const rawId = Encoding.fromHex(r1.identity.peerId);
    for (const h of [h1a, h1b, h2a, h2b]) {
      const guard = h === h1a || h === h1b ? g1 : g2;
      for (const f of h.inbox) {
        expect(f.from).toBe(guard.identity.peerId);
        expect(hasBytes(f.raw, rawId), `${h.name} <- ${f.type}`).toBe(false);
        expect(hasBytes(f.raw, r1.identity.pubkey), 'pubkey').toBe(false);
      }
      // 保持者が知る「要求の来た方向」は、G_R (r1 の Guard = g1) だけ
      for (const hop of h.storage.tunnel!.seenHops) expect(hop).toBe(g1.identity.peerId);
    }
    // 4. G_h (g2) が見た相手は G_R (g1) と保持者だけ。R の id は届かない
    for (const f of g2.inbox) expect([g1.identity.peerId, h2a.identity.peerId, h2b.identity.peerId, h1a.identity.peerId, h1b.identity.peerId, r1.identity.peerId, r2.identity.peerId].includes(f.from)).toBe(true);
    for (const f of g2.inbox.filter(m => m.type === WireType.TUNNEL_FWD || m.type === WireType.TUNNEL_REPLY)) {
      expect(f.from === r1.identity.peerId).toBe(false);
      expect(hasBytes(f.raw, rawId)).toBe(false);
    }
  });

  it('★同じ Guard の後ろの保持者へは、G_R = G_h として直接つながる (FWD を経由しない)', async () => {
    await build({ data: ['h1a', 'h1b'] });
    const { r1, g1, g2 } = net;
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(true);
    expect(idsOf(r1.received)).toEqual(idsOf(packets));
    // データを持つのは g1 の後ろだけ。ただし候補は 4 台で乱数順なので、g2 側が先に NOT_HELD を返すことはある
    expect(g1.inbox.filter(m => m.type === WireType.TUNNEL_SEND).length).toBeGreaterThanOrEqual(2);
    void g2;
  });

  it('★since: 手元にあるより新しい分だけを取る (差分)。0 件でも「持っている」保持者の OK は完了とする', async () => {
    await build();
    const { r1 } = net;
    const sinceMin = Math.floor((BASE + 2 * 60_000 - Date.UTC(2025, 0, 1)) / 60_000); // 3 件目以降
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: sinceMin });
    expect(res.completed).toBe(true);
    expect(idsOf(r1.received)).toEqual(idsOf(packets.slice(2)));
    // 全部より新しい since: 何も無い。保持者が OK (0 件) を返すので完了
    const r2res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: sinceMin + 1000 });
    expect(r2res).toMatchObject({ completed: true, packets: 0, reason: 'ok' });
  });

  it('★どの保持者もそのバケットを持っていなければ、全員に NOT_HELD で尋ねて exhausted (取れない)', async () => {
    await build({ data: [] });
    const res = await net.r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: false, packets: 0, reason: 'exhausted', attempts: 4 });
    expect(net.r1.received).toHaveLength(0);
  });

  it('★hedged request: 速いと記録された 2 台が黙っていると、待ち時間のあと 3 台目へ回って完了する。完了した保持者の速さが記録される', async () => {
    await build({ data: ['h1a', 'h1b', 'h2a', 'h2b'] });
    const { r1, h1a, h1b, h2a, h2b } = net;
    // 速い順 (記録): h2a, h2b (どちらも黙らせる) → h1a → h1b
    for (const h of [h2a, h2b]) (h.storage.tunnel as any).handleDeliver = () => {};
    r1.history.recordSpeed(h2a.sid, 50);
    r1.history.recordSpeed(h2b.sid, 60);
    r1.history.recordSpeed(h1a.sid, 400);
    r1.history.recordSpeed(h1b.sid, 500);
    const t0 = performance.now();
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    const took = performance.now() - t0;
    expect(res).toMatchObject({ completed: true, packets: COUNT });
    expect(res.attempts).toBe(3); // 2 台 + hedge の 1 台
    expect(took).toBeGreaterThanOrEqual(140); // hedgeMs = 150
    expect(took).toBeLessThan(1500); // 黙った保持者の inactivity (2s) を待たない
    expect(h2a.storage.tunnel!.stats.served + h2b.storage.tunnel!.stats.served).toBe(0);
    expect(h1a.storage.tunnel!.stats.served).toBe(1);
    // 完了した保持者の速さは実測に更新される (移動平均で、記録した 400 より速くなる)
    expect(r1.history.speedOf(h1a.sid)!).toBeLessThan(400);
    // 完了後は他の要求を打ち切っている (経路の状態は残っても 60 秒で消える)
    expect(r1.tunnel.inFlight).toBe(0);
  });

  it('★失敗した保持者 (応答が来ない) は罰を受けて後回しになる (記録は 60 秒相当)。持っていないだけ (NOT_HELD) の保持者は罰を受けない', async () => {
    await build({ data: ['h2a'], reader: { history: { inactivityMs: 250, hedgeMs: 5000 } } });
    const { r1, h2a, h1a } = net;
    (h2a.storage.tunnel as any).handleDeliver = () => {}; // データを持つ唯一の保持者が黙る
    r1.history.recordSpeed(h2a.sid, 10);
    r1.history.recordSpeed(h1a.sid, 20); // NOT_HELD を返す
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: false, reason: 'exhausted' });
    expect(r1.history.speedOf(h2a.sid)!).toBeGreaterThan(10_000); // 罰 (60 秒) が移動平均に入った
    expect(r1.history.speedOf(h1a.sid)).toBe(20); // 持っていないだけ: そのまま
  });

  it('★経路上の Guard が応答の片を改ざんしても、読み手は復号できず取り込まない (取れなければ取れないと返す)', async () => {
    await build({ data: ['h2a', 'h2b'] });
    const { r1, g1 } = net;
    const orig = (g1.relay as any).routeBack.bind(g1.relay);
    (g1.relay as any).routeBack = (tag: number, seq: number, final: boolean, body: Uint8Array) => {
      const bad = body.slice();
      bad[Math.floor(bad.length / 2)] ^= 0x40;
      orig(tag, seq, final, bad);
    };
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(false);
    expect(res.packets).toBe(0);
    expect(r1.received).toHaveLength(0);
    expect(r1.history.stats.badChunks).toBeGreaterThan(0);
  });

  it('★経路の途中で最後の片を黙って落とされても、完了とは見なさない (final は暗号文の中)。その経路しか無ければ取れず、何も配られない', async () => {
    await build({ data: ['h2a', 'h2b'], reader: { history: { inactivityMs: 300, hedgeMs: 100 } } });
    const { r1, g2 } = net;
    const orig = (g2.relay as any).handleReply.bind(g2.relay);
    (g2.relay as any).handleReply = (from: string, msg: any) => { if (!msg.final) orig(from, msg); }; // 応答は 1 片で final: 全部落ちる
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(false);
    expect(res.packets).toBe(0);
    expect(r1.received).toHaveLength(0);
  });

  it('★最後の片が落ちる経路 (g2) と、落ちない経路 (g1 の後ろ) があれば、後者の保持者で完了する', async () => {
    await build({ data: ['h1a', 'h2a', 'h2b'], reader: { history: { inactivityMs: 300, hedgeMs: 100 } } });
    const { r1, g2, h1a, h2a, h2b, h1b } = net;
    const orig = (g2.relay as any).handleReply.bind(g2.relay);
    (g2.relay as any).handleReply = (from: string, msg: any) => { if (!msg.final) orig(from, msg); };
    r1.history.recordSpeed(h2a.sid, 1);
    r1.history.recordSpeed(h2b.sid, 2);
    r1.history.recordSpeed(h1b.sid, 3);
    r1.history.recordSpeed(h1a.sid, 4);
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(true);
    expect(idsOf(r1.received)).toEqual(idsOf(packets));
    expect(h1a.storage.tunnel!.stats.served).toBe(1);
  });

  it('★応答が上限を超えたら MORE で打ち切り、since で続きを頼む (ページング)。全部揃うまで同じ保持者に頼み続け、重複は 1 回だけ配る', async () => {
    // 1 回の応答は 450 バイトまで = 数件ずつ
    await build({ data: ['h2a', 'h2b'], holder: { storage: { tunnel: { limits: { maxResponseBytes: 450 } } } } });
    const { r1, h2a, h2b } = net;
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: COUNT });
    expect(idsOf(r1.received)).toEqual(idsOf(packets));
    expect(r1.received).toHaveLength(COUNT); // 重なった分 (境目の 1 件) を二重に配っていない
    const served = h2a.storage.tunnel!.stats.served + h2b.storage.tunnel!.stats.served;
    expect(served).toBeGreaterThanOrEqual(3); // 少なくとも 3 ページ
  });

  it('★保持者が偽の投稿 (PoW が通らない) を混ぜて返したら、その保持者を打ち切り、正しい投稿だけを配る。別の保持者から完了する', async () => {
    await build({ data: ['h1b'], reader: { history: { hedgeMs: 100, inactivityMs: 3000 } } });
    const { r1, h2a, h1a, h1b, h2b } = net;
    // h2a は、正しい投稿 1 件 + 偽造 (nonce を壊した) 1 件を持っている。速さの記録で最初に当たる
    const forged: GossipPacket = { ...packets[1], pow_nonce: (packets[1].pow_nonce + 12345) >>> 0 };
    await h2a.storage.holder!.put(packets[0]);
    await h2a.storage.holder!.put(forged);
    // 他の 2 台は黙り、本物を持つ h1b は最後
    for (const h of [h1a, h2b]) (h.storage.tunnel as any).handleDeliver = () => {};
    r1.history.recordSpeed(h2a.sid, 1);
    r1.history.recordSpeed(h1a.sid, 100);
    r1.history.recordSpeed(h2b.sid, 200);
    r1.history.recordSpeed(h1b.sid, 300);
    const res = await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.completed).toBe(true);
    expect(r1.history.stats.rejectedPackets).toBeGreaterThanOrEqual(1);
    expect(r1.received.some(p => p.packet_id === forged.packet_id && p.pow_nonce === forged.pow_nonce)).toBe(false);
    // 正しい投稿は全部届いている (偽物を返した保持者の分も、検証に通ったものは使える)
    expect(idsOf(r1.received)).toEqual(idsOf(packets));
    expect(r1.history.speedOf(h2a.sid)!).toBeGreaterThan(10_000); // 偽物を返した保持者は後回し
  });

  it('★読み手が保持者でもある場合: 取ってきた投稿は自分の担当なら預かる (保管候補のフック)。lastSeen (追いつきの起点) は動かさない', async () => {
    await build({ reader: { storage: { wait: true } } }); // 枠を解いてある = 担当になれる
    const { r1 } = net;
    expect(r1.storage.holder!.hasBucket(BIRTH_DAY, TAG)).toBe(false);
    await r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    await until(async () => { await r1.storage.holder!.flush(); return r1.storage.holder!.hasBucket(BIRTH_DAY, TAG); }, 3000, 'stored');
    expect((await r1.storage.holder!.getBucket(BIRTH_DAY, TAG)).length).toBe(COUNT);
  });

  it('自分自身の SID には頼まない (自分の担当は手元の保管でまかなう)', async () => {
    await build({ data: ['h1a'] });
    const { h1a } = net;
    h1a.history.recordSpeed(h1a.sid, 1);
    const res = await h1a.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res.attempts).toBeLessThanOrEqual(3);
    expect(h1a.tunnel.inFlight).toBe(0);
  });

  it('★経路の状態は 60 秒 (テストでは短縮) で消える: 応答が来ない要求が、どの Guard にも状態を残さない', async () => {
    await build({
      data: ['h2a', 'h2b'],
      guard: { relay: { limits: { idleMs: 200 } } },
      reader: { history: { inactivityMs: 5000, hedgeMs: 5000 } },
    });
    const { r1, g1, g2, h2a, h2b } = net;
    for (const h of [h2a, h2b]) (h.storage.tunnel as any).handleDeliver = () => {};
    const ctl = new AbortController();
    const p = r1.history.fetchBucket(BIRTH_DAY, TAG, { since: 0, signal: ctl.signal });
    await until(() => g1.relay.upstreamCount >= 1 && g2.relay.downstreamCount >= 1, 3000, 'routes');
    ctl.abort();
    expect((await p).reason).toBe('aborted');
    await sleep(250);
    g1.relay.sweep();
    g2.relay.sweep();
    expect(g1.relay.routeCount).toBe(0);
    expect(g2.relay.routeCount).toBe(0);
  });

  it('保持者の受け口への登録: 受け口が切れて張り直されたら (検証済みになったら) 登録し直す', async () => {
    await build();
    const { h2a, g2 } = net;
    expect(g2.relay.tunnelCount).toBe(4 / 2); // h2a・h2b
    // 切断 → g2 は登録を忘れる
    (g2.peerManager as any).emit('peer:disconnect', h2a.identity.peerId);
    (h2a.peerManager as any).emit('peer:disconnect', g2.identity.peerId);
    expect(g2.relay.tunnelCount).toBe(1);
    expect(h2a.storage.tunnel!.registered).toBe(false);
    // つなぎ直して検証済み
    announceVerified(h2a, g2);
    await until(() => h2a.storage.tunnel!.registered && g2.relay.tunnelCount === 2, 3000, 're-register');
  });

  it('読み手: 1 ホップ目が無ければ no-first-hop (待ち時間のあと)。保持者の leaseSet が無ければ no-holders', async () => {
    await build();
    const lone = await attachTunnel(await createSimNode('lone'), { storage: { slots: 1, wait: false }, history: { readyWaitMs: 100, holdersWaitMs: 60 } });
    net.all.push(lone);
    expect(await lone.history.fetchBucket(BIRTH_DAY, TAG)).toMatchObject({ completed: false, reason: 'no-first-hop', attempts: 0 });
    attachBehind(lone, net.g1);
    // SYNC が届く前の短い待ちでは leaseSet が揃わないことがあるが、揃えば取れる
    const res = await lone.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(['ok', 'no-holders']).toContain(res.reason);
    // 1 ホップ目はあるが、保持者の leaseSet が 1 つも無い網
    const gx = await attachTunnel(await createSimNode('gx'), { storage: { slots: 1, wait: false } });
    const empty = await attachTunnel(await createSimNode('empty'), { storage: { slots: 1, wait: false }, history: { holdersWaitMs: 60 } });
    net.all.push(gx, empty);
    attachBehind(empty, gx);
    expect(await empty.history.fetchBucket(BIRTH_DAY, TAG)).toMatchObject({ completed: false, reason: 'no-holders', attempts: 0 });
  });
});

describe('トンネル: 保持者の制限 (返しのホップごとの頻度・同時数)', () => {
  let nodes: TunnelSimNode[] = [];
  afterEach(async () => {
    stopTunnel(nodes);
    await stopStorage(nodes);
    stopAll(nodes);
    nodes = [];
  });

  async function trio(holderLimits: any) {
    const g = await attachTunnel(await createSimNode('g'), { storage: { slots: 1, wait: false }, relay: { role: 'guard', limits: { peer: { reqPerSec: 1000, reqBurst: 1000, concurrent: 1000 } } } });
    const h = await attachTunnel(await createSimNode('h'), { storage: { slots: 1, tunnel: { limits: holderLimits } } });
    const r = await attachTunnel(await createSimNode('r'), { storage: { slots: 1, wait: false } });
    nodes = [g, h, r];
    attachBehind(h, g);
    attachBehind(r, g);
    for (const p of packets) await h.storage.holder!.put(p);
    h.storage.router.publish();
    await until(() => h.storage.tunnel!.registered && r.storage.leaseSets.size === 1, 5000, 'ready');
    return { g, h, r };
  }

  /** 生の要求を 1 件出して、結果 (chunk を受け取った / error) を返す */
  function rawRequest(r: TunnelSimNode, h: TunnelSimNode, g: TunnelSimNode, since = 0) {
    const ls = r.storage.leaseSets.get(h.sid)!;
    const sealed = sealRequest(h.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, newRespKey(), encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since }))!;
    return new Promise<{ ok: boolean; code?: number }>((resolve) => {
      r.tunnel.request({ gateway: ls.gateway, tunnelId: ls.tunnelId, body: sealed }, (ev) => {
        if (ev.type === 'chunk') resolve({ ok: true });
        else resolve({ ok: false, code: ev.code });
      });
    });
    void g;
  }

  it('★返しのホップごとの頻度: burst を超えた要求は BUSY が R まで戻る。時間が経てば通る', async () => {
    const { g, h, r } = await trio({ perHopBurst: 3, perHopReqPerSec: 1, chunkIntervalMs: 1 });
    const results = await Promise.all(Array.from({ length: 6 }, () => rawRequest(r, h, g)));
    const busy = results.filter(x => !x.ok && x.code === TUNNEL_ERROR_CODE.BUSY);
    expect(results.filter(x => x.ok)).toHaveLength(3);
    expect(busy).toHaveLength(3);
    expect(h.storage.tunnel!.stats.rejected.rate).toBe(3);
  });

  it('★同時数: 応答中の要求が返しのホップごとの上限に達したら、新しい要求は BUSY', async () => {
    const { g, h, r } = await trio({ perHopConcurrent: 2, maxConcurrent: 2, chunkIntervalMs: 200, perHopBurst: 100 });
    const results = await Promise.all(Array.from({ length: 5 }, () => rawRequest(r, h, g)));
    expect(results.filter(x => x.ok).length).toBe(2);
    expect(results.filter(x => x.code === TUNNEL_ERROR_CODE.BUSY).length).toBe(3);
    expect(h.storage.tunnel!.stats.rejected.concurrent).toBe(3);
  });

  it('★開けない要求 (封印が他人宛て・壊れている) は BAD_REQUEST。保持者は何も返さない', async () => {
    const { g, h, r } = await trio({});
    const ls = r.storage.leaseSets.get(h.sid)!;
    const other = await attachTunnel(await createSimNode('o'), { storage: { slots: 1, wait: false } });
    nodes.push(other);
    const wrong = sealRequest(other.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, newRespKey(), encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since: 0 }))!;
    const garbage = new Uint8Array(90).fill(3);
    // kind 違い
    const badKind = sealRequest(h.storage.identity.publicKey, 9, newRespKey(), encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since: 0 }))!;
    // payload の長さ違い
    const badPayload = sealRequest(h.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, newRespKey(), Uint8Array.of(1, 2, 3))!;
    const codes: Array<number | undefined> = [];
    for (const body of [wrong, garbage, badKind, badPayload]) {
      codes.push(await new Promise<number | undefined>((resolve) => {
        r.tunnel.request({ gateway: ls.gateway, tunnelId: ls.tunnelId, body }, (ev) => resolve(ev.type === 'error' ? ev.code : undefined));
      }));
    }
    expect(codes).toEqual([TUNNEL_ERROR_CODE.BAD_REQUEST, TUNNEL_ERROR_CODE.BAD_REQUEST, TUNNEL_ERROR_CODE.BAD_REQUEST, TUNNEL_ERROR_CODE.BAD_REQUEST]);
    expect(h.storage.tunnel!.stats.rejected.badRequest).toBe(4);
    void g;
  });

  it('★大きな応答は 15KiB ずつの片に分かれ、seq は 0 から連番、final は最後の片だけ。復号して連結すると応答が戻る (4MiB 上限の MORE も)', async () => {
    const { g, h, r } = await trio({ chunkIntervalMs: 1, maxResponseBytes: 60_000 });
    // 別のバケット (tag 0x456) に、検証を通らない代役の大きな投稿を 40 件 (約 2.2KB ずつ = 88KB)
    const synth = (i: number): GossipPacket => ({
      packet_id: i.toString(16).padStart(32, '0'), timestamp: BASE + i * 60_000, tag: 0x456, age: 0, effort_exp: 0,
      pow_nonce: 1, pow_solution: new Uint8Array(16), payload: new Uint8Array(2100).fill(i & 0xff),
    });
    for (let i = 0; i < 40; i++) await h.storage.holder!.put(synth(i));
    const ls = r.storage.leaseSets.get(h.sid)!;
    const fetchPage = async (since: number) => {
      const respKey = newRespKey();
      const sealed = sealRequest(h.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, respKey, encodeFetchRequest({ birthDay: BIRTH_DAY, tag: 0x456, since }))!;
      const chunks: Array<{ seq: number; final: boolean; len: number; plain: ReturnType<typeof decryptChunk> }> = [];
      await new Promise<void>((resolve) => {
        r.tunnel.request({ gateway: ls.gateway, tunnelId: ls.tunnelId, body: sealed }, (ev) => {
          if (ev.type !== 'chunk') return resolve();
          chunks.push({ seq: ev.seq, final: ev.final, len: ev.body.length, plain: decryptChunk(respKey, TUNNEL_KIND.FETCH_BUCKET, ev.seq, ev.body) });
          if (ev.final) resolve();
        });
      });
      const parts = chunks.map(c => c.plain!.data);
      const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let o = 0;
      for (const p of parts) { all.set(p, o); o += p.length; }
      return { chunks, res: decodeFetchResponse(all)! };
    };
    const first = await fetchPage(0);
    expect(first.chunks.length).toBeGreaterThanOrEqual(3);
    expect(first.chunks.map(c => c.seq)).toEqual(first.chunks.map((_, i) => i)); // 連番
    expect(first.chunks.map(c => c.final)).toEqual(first.chunks.map((_, i) => i === first.chunks.length - 1)); // final は最後だけ (フレーム側)
    expect(first.chunks.map(c => c.plain!.final)).toEqual(first.chunks.map((_, i) => i === first.chunks.length - 1)); // 暗号文の中も同じ
    for (const c of first.chunks.slice(0, -1)) expect(c.plain!.data.length).toBe(TUNNEL_CHUNK_DATA_BYTES); // 最後以外は 15KiB
    expect(first.res.status).toBe(FETCH_STATUS.MORE);
    expect(first.res.packets.length).toBeGreaterThan(20);
    expect(first.res.packets.length).toBeLessThan(40);
    // 続き: nextSince から。最後まで届く
    let since = first.res.nextSince;
    const got = new Set(first.res.packets.map(p => Encoding.toHex(p)));
    for (let page = 0; page < 5; page++) {
      const next = await fetchPage(since);
      next.res.packets.forEach(p => got.add(Encoding.toHex(p)));
      if (next.res.status === FETCH_STATUS.OK) break;
      since = next.res.nextSince;
    }
    expect(got.size).toBe(40);
    // 持っていないバケット: NOT_HELD (1 片)
    const none = await new Promise<number>((resolve) => {
      const respKey = newRespKey();
      const sealed = sealRequest(h.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, respKey, encodeFetchRequest({ birthDay: BIRTH_DAY, tag: 0x7ff, since: 0 }))!;
      r.tunnel.request({ gateway: ls.gateway, tunnelId: ls.tunnelId, body: sealed }, (ev) => {
        if (ev.type !== 'chunk') return;
        resolve(decodeFetchResponse(decryptChunk(respKey, TUNNEL_KIND.FETCH_BUCKET, ev.seq, ev.body)!.data)!.status);
      });
    });
    expect(none).toBe(FETCH_STATUS.NOT_HELD);
    void g;
  });

  it('★受け口でない相手から来た DELIVER は無視する (最後に出した leaseSet の受け口だけを信じる)', async () => {
    const { g, h, r } = await trio({});
    const evil = await attachTunnel(await createSimNode('evil'), { storage: { slots: 1, wait: false } });
    nodes.push(evil);
    link(evil, h);
    const sealed = sealRequest(h.storage.identity.publicKey, TUNNEL_KIND.FETCH_BUCKET, newRespKey(), encodeFetchRequest({ birthDay: BIRTH_DAY, tag: TAG, since: 0 }))!;
    evil.peerManager.sendMessage(h.identity.peerId, WireType.TUNNEL_DELIVER, { returnTag: 5, fromHop: g.identity.peerId, body: sealed });
    await sleep(60);
    expect(h.storage.tunnel!.stats.rejected.source).toBe(1);
    expect(h.storage.tunnel!.stats.served).toBe(0);
    void r;
  });
});

describe('トンネル: リストが無い網 (オープン) では受け口へ G_R が直接つなぐ', () => {
  let nodes: TunnelSimNode[] = [];
  afterEach(async () => {
    stopTunnel(nodes);
    await stopStorage(nodes);
    stopAll(nodes);
    nodes = [];
  });

  it('★R ─ N ─ M ─ G ─ H: N (R の 1 ホップ目、ただの隣人) は G とつながっていないので、G_h = G へ自分から張って転送する。H が見るのは N だけ', async () => {
    const dialed: string[] = [];
    let gNode!: TunnelSimNode;
    let nNode!: TunnelSimNode;
    const mk = async (name: string, o: AttachTunnelOptions = {}) => attachTunnel(await createSimNode(name), { ...o, storage: { slots: 1, ...o.storage } });
    const r = await mk('r', { storage: { wait: false } });
    const n = await mk('n', {
      storage: { wait: false },
      relay: { role: 'client', dial: (id) => { dialed.push(id); setTimeout(() => { link(nNode, gNode); announceVerified(nNode, gNode); }, 5); } },
    });
    const m = await mk('m', { storage: { wait: false } });
    const g = await mk('g', { storage: { wait: false } });
    const h = await mk('h');
    nNode = n; gNode = g;
    nodes = [r, n, m, g, h];
    link(n, m); link(m, g);
    attachBehind(r, n);
    attachBehind(h, g);
    for (const p of packets) await h.storage.holder!.put(p);
    h.storage.router.publish();
    await until(() => h.storage.tunnel!.registered && r.storage.leaseSets.size === 1, 5000, 'ready');
    expect(n.peerManager.peers.has(g.identity.peerId)).toBe(false);

    const res = await r.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: COUNT });
    expect(dialed).toEqual([g.identity.peerId]);
    expect(idsOf(r.received)).toEqual(idsOf(packets));
    // H が受け取ったのは G からだけ。fromHop = N。R の id は載らない
    for (const f of h.inbox) expect(f.from).toBe(g.identity.peerId);
    expect(Array.from(h.storage.tunnel!.seenHops)).toEqual([n.identity.peerId]);
    const rawId = Encoding.fromHex(r.identity.peerId);
    for (const f of [...g.inbox, ...h.inbox]) expect(hasBytes(f.raw, rawId)).toBe(false);
    // 2 回目はもうつながっているので、張り直さない
    await r.history.fetchBucket(BIRTH_DAY, TAG, { since: 0 });
    expect(dialed).toHaveLength(1);
  });
});
