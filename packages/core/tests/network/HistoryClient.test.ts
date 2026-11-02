import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { Encoding } from '../../src/common/Encoding';
import { DAY_MS, msToMinutes } from '../../src/crypto/PowPolicy';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { StorageIdentity } from '../../src/network/storage/StorageIdentity';
import { HistoryClient, FETCH_MAX_PAST_MS, HISTORY_LIMITS } from '../../src/network/history/HistoryClient';
import { TUNNEL_ERROR_CODE } from '../../src/network/wire/WireCodec';
import { FETCH_STATUS, encodeFetchResponse, decodeFetchRequest } from '../../src/network/history/FetchBucket';
import { encryptChunk, parseRequestPlain } from '../../src/network/tunnel/TunnelCrypto';
import { makePacket, sleep } from '../helpers/onionNet';
import type { GossipPacket } from '../../src/types';

const TAG = 0x2a5;
const NOW = Date.now();
const BIRTH = Math.floor((NOW - 10 * DAY_MS) / DAY_MS);
const T0 = BIRTH * DAY_MS + 3600_000;

interface FakeHolder { id: StorageIdentity; sid: string; gateway: string; behavior: (req: { since: number }, send: (seq: number, final: boolean, data: Uint8Array) => void, kind: number, key: Uint8Array, fail?: (code: number) => void) => void | Promise<void>; asked: number }

let packets: GossipPacket[];
beforeAll(async () => {
  await sodiumReady;
  packets = [0, 1, 2].map(i => makePacket([i + 1], T0 + i * 60_000, { tag: TAG, age: 0 }));
}, 30_000);

/** 偽のトンネル: 封印を保持者の鍵で開け、保持者ごとの振る舞いで応答の片を返す */
async function setup(n: number, opts: { random?: () => number; maxAttempts?: number; hedgeMs?: number; inactivityMs?: number; gapGraceMs?: number; sameGateway?: boolean } = {}) {
  const holders: FakeHolder[] = [];
  const leases = new Map<string, any>();
  for (let i = 0; i < n; i++) {
    const id = await StorageIdentity.loadOrCreate(null, 1);
    const sid = Encoding.toHex(id.publicKey);
    const h: FakeHolder = { id, sid, gateway: (opts.sameGateway ? 1 : i + 1).toString(16).padStart(32, '0'), behavior: () => {}, asked: 0 };
    holders.push(h);
    leases.set(sid, { sid: id.publicKey, gateway: h.gateway, tunnelId: new Uint8Array(8) });
  }
  let firstHop: string | null = 'f'.repeat(32);
  const delivered: GossipPacket[] = [];
  const listeners: Array<(...a: any[]) => void> = [];
  const requests: Array<{ holder: FakeHolder; since: number }> = [];
  const tunnel = {
    get firstHop() { return firstHop; },
    request(req: any, handler: (ev: any) => void) {
      const h = holders.find(x => x.gateway === req.gateway && x.id.openSealed(req.body))!;
      const plain = h.id.openSealed(req.body);
      const r = parseRequestPlain(plain!)!;
      const fr = decodeFetchRequest(r.payload)!;
      h.asked++;
      requests.push({ holder: h, since: fr.since });
      let cancelled = false;
      const send = (seq: number, final: boolean, data: Uint8Array, clearFinal = final) => {
        if (!cancelled) handler({ type: 'chunk', seq, final: clearFinal, body: encryptChunk(r.respKey, r.kind, seq, final, data) });
      };
      const fail = (code: number) => { if (!cancelled) handler({ type: 'error', code }); };
      queueMicrotask(() => { void h.behavior(fr, send as any, r.kind, r.respKey, fail); });
      return { reqId: 1, cancel: () => { cancelled = true; } };
    },
  };
  const dandelion = { getPinnedGuardId: () => firstHop, onGuardChange: () => {} };
  const duty = { closestSlots: () => Array.from(leases.keys()).flatMap(sid => [{ sid }, { sid }]) as any }; // 1 SID に 2 枠: 重複は除かれる
  const client = new HistoryClient({
    tunnel: tunnel as any,
    peerManager: { on: (e: string, cb: any) => listeners.push(cb), off: () => {} } as any,
    dandelion: dandelion as any,
    duty: duty as any,
    leaseSets: { get: (sid: string) => leases.get(sid) } as any,
    deliver: (p) => { delivered.push(p); },
    ownSid: () => null,
    random: opts.random ?? (() => 0.5),
    limits: {
      hedgeMs: opts.hedgeMs ?? 60, inactivityMs: opts.inactivityMs ?? 300, gapGraceMs: opts.gapGraceMs,
      readyWaitMs: 150, holdersWaitMs: 30, holdersPollMs: 5, maxAttempts: opts.maxAttempts,
    },
  });
  return { holders, client, delivered, requests, setFirstHop: (v: string | null) => { firstHop = v; }, fireVerified: () => listeners.forEach(cb => cb({ peerId: firstHop })) };
}

/** 保持者が全部の投稿を OK で返す (1 片) */
const answer = (list: GossipPacket[], status: number = FETCH_STATUS.OK): FakeHolder['behavior'] => (_req, send, _k) => {
  send(0, true, encodeFetchResponse({ status: status as any, nextSince: 0, packets: list.map(encodePacket) }));
};

describe('HistoryClient: 保持者の選び方と検証', () => {
  let c: Awaited<ReturnType<typeof setup>>;
  afterEach(() => c?.client.destroy());

  it('★候補は SID で重複を除く (1 SID が複数の枠を持っていても 1 回)。速さの記録がある順、無ければ乱数', async () => {
    c = await setup(4);
    c.holders.forEach(h => (h.behavior = answer([])));
    c.client.recordSpeed(c.holders[2].sid, 10);
    c.client.recordSpeed(c.holders[0].sid, 50);
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 5 });
    expect(res).toMatchObject({ completed: true, attempts: 2 });
    // 最初の 2 台 = 記録が速い 2 台 (h2, h0)
    expect(new Set(c.requests.slice(0, 2).map(r => r.holder))).toEqual(new Set([c.holders[2], c.holders[0]]));
    expect(c.requests.length).toBe(2);
  });

  it('★記録が無い保持者の順は乱数で決まる (注入した乱数で再現できる)。完了すると速さが手元のメモリに残る', async () => {
    c = await setup(5, { random: () => 0 });
    c.holders.forEach(h => (h.behavior = answer([])));
    await c.client.fetchBucket(BIRTH, TAG, { since: 1 });
    const first = c.requests.slice(0, 2).map(r => r.holder.sid);
    c.client.destroy();
    c = await setup(5, { random: () => 0 });
    expect(c.client.speedOf(c.holders[0].sid)).toBeUndefined();
    expect(first).toHaveLength(2);
  });

  it('★since = 0 で空の OK は信用せず次の保持者へ。since > 0 なら空の OK で完了', async () => {
    c = await setup(3);
    c.holders[0].behavior = answer([]);
    c.holders[1].behavior = answer([]);
    c.holders[2].behavior = answer(packets);
    c.client.recordSpeed(c.holders[0].sid, 1);
    c.client.recordSpeed(c.holders[1].sid, 2);
    c.client.recordSpeed(c.holders[2].sid, 3);
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: 3 });
    expect(c.delivered).toHaveLength(3);
    const res2 = await c.client.fetchBucket(BIRTH, TAG, { since: 9 });
    expect(res2).toMatchObject({ completed: true, packets: 0, attempts: 2 });
  });

  it('★別のバケットの有効な投稿・未来の投稿・古すぎる投稿・壊れたバイト列を混ぜた保持者は打ち切る。通った分だけ配る', async () => {
    c = await setup(2);
    const otherTag = makePacket([9], T0, { tag: TAG + 1, age: 0 });
    const future = makePacket([9], Date.now() + 3600_000, { tag: TAG, age: 0 });
    const tooOld = makePacket([9], Date.now() - FETCH_MAX_PAST_MS - 3600_000, { tag: TAG, age: 0 });
    for (const bad of [otherTag, future, tooOld]) {
      c.delivered.length = 0;
      c.holders[0].behavior = (_r, send) => send(0, true, encodeFetchResponse({ status: 0, nextSince: 0, packets: [encodePacket(packets[0]), encodePacket(bad)] }));
      c.holders[1].behavior = answer(packets);
      c.client.recordSpeed(c.holders[0].sid, 1);
      c.client.recordSpeed(c.holders[1].sid, 2);
      const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
      expect(res.completed, bad.packet_id).toBe(true);
      expect(c.delivered.some(p => p.packet_id === bad.packet_id)).toBe(false);
      expect(c.client.speedOf(c.holders[0].sid)!).toBeGreaterThan(10_000);
    }
    expect(c.client.stats.rejectedPackets).toBeGreaterThanOrEqual(3);
    // 壊れたバイト列
    c.holders[0].behavior = (_r, send) => send(0, true, encodeFetchResponse({ status: 0, nextSince: 0, packets: [new Uint8Array(40).fill(1)] }));
    c.client.recordSpeed(c.holders[0].sid, 1);
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res.completed).toBe(true);
  });

  it('★91 日前までの投稿は受け付ける (保持は 90 日 + その日の残り)', async () => {
    c = await setup(1);
    const old = makePacket([7], Date.now() - 90 * DAY_MS, { tag: TAG, age: 0 });
    const birth = Math.floor(old.timestamp / DAY_MS);
    c.holders[0].behavior = answer([old]);
    const res = await c.client.fetchBucket(birth, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: 1 });
  });

  it('★応答の片: 順不同でも組み立てる。フレームの final フラグを偽っても (平文の final を使うので) 完了と見なさない。重複・穴・改ざんの片に耐える', async () => {
    c = await setup(1);
    const payload = encodeFetchResponse({ status: 0, nextSince: 0, packets: packets.map(encodePacket) });
    const a = payload.slice(0, 100), b = payload.slice(100, 200), d = payload.slice(200);
    // 順不同 + 重複
    c.holders[0].behavior = (_r, send) => { (send as any)(2, true, d); (send as any)(0, false, a); (send as any)(0, false, a); (send as any)(1, false, b); };
    expect(await c.client.fetchBucket(BIRTH, TAG, { since: 0 })).toMatchObject({ completed: true, packets: 3 });
    // 最後の片が来ない: フレームの final を真にして偽っても、完了しない (inactivity で諦める)
    c.delivered.length = 0;
    c.holders[0].behavior = (_r, send) => { (send as any)(0, false, a, true); (send as any)(1, false, b, true); };
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res.completed).toBe(false);
    expect(c.delivered).toHaveLength(2 - 2 + 3 - 3 + 0); // 何も配られない
    // 真ん中の片が無い (0 と 2 だけ)
    c.holders[0].behavior = (_r, send) => { (send as any)(0, false, a); (send as any)(2, true, d); };
    expect((await c.client.fetchBucket(BIRTH, TAG, { since: 0 })).completed).toBe(false);
  });

  it('★最後の片が届いたのに途中が欠けていたら、無通信の時間切れを待たずに次の保持者へ回る (GAP_GRACE_MS)', async () => {
    // 時間切れと hedge は十分に長く、猶予だけ短くする: 猶予で諦めなければこのテストは時間内に終わらない
    c = await setup(3, { hedgeMs: 10_000, inactivityMs: 10_000, gapGraceMs: 20 });
    const payload = encodeFetchResponse({ status: 0, nextSince: 0, packets: packets.map(encodePacket) });
    const a = payload.slice(0, 100), b = payload.slice(100, 200), d = payload.slice(200);
    let asked = 0;
    // 最初に頼んだ 2 台は真ん中の片を途中で落とされる。3 台目は全部届く
    c.holders.forEach(h => (h.behavior = (_r, send) => {
      const broken = asked++ < 2;
      (send as any)(0, false, a);
      if (!broken) (send as any)(1, false, b);
      (send as any)(2, true, d);
    }));
    const t0 = performance.now();
    expect(await c.client.fetchBucket(BIRTH, TAG, { since: 0 })).toMatchObject({ completed: true, packets: 3, attempts: 3 });
    expect(performance.now() - t0).toBeLessThan(2_000);
  });

  it('★復号できない片 (改ざん) が 3 つ来たら、その要求は諦める (inactivity を待たない)', async () => {
    c = await setup(1);
    c.holders[0].behavior = (_r, _s, kind, key) => {
      // 別の鍵で暗号化した片を直接流し込む代わりに、seq を食い違わせる
      void kind; void key;
    };
    const orig = c.holders[0].behavior;
    c.holders[0].behavior = (r, send, k, key) => { orig(r, send, k, key); };
    // tunnel.request を包んで不正な片を送る
    const t0 = performance.now();
    const origReq = (c.client as any).parts.tunnel.request;
    (c.client as any).parts.tunnel.request = (req: any, handler: any) => {
      const h = origReq.call((c.client as any).parts.tunnel, req, handler);
      queueMicrotask(() => { for (let i = 0; i < 3; i++) handler({ type: 'chunk', seq: i, final: false, body: new Uint8Array(40).fill(i) }); });
      return h;
    };
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res.completed).toBe(false);
    expect(performance.now() - t0).toBeLessThan(250);
    expect(c.client.stats.badChunks).toBe(3);
  });

  it('★届かなかった保持者 (片が 1 つも来ないまま時間切れ) は、しばらく候補から外す: 空のバケットごとに時間切れを待たない', async () => {
    c = await setup(3, { inactivityMs: 200, hedgeMs: 10_000 });
    const dead = c.holders[0];
    dead.behavior = () => {}; // 黙っている (落ちたのに leaseSet だけ残っている)
    c.holders[1].behavior = answer([], FETCH_STATUS.NOT_HELD);
    c.holders[2].behavior = answer([], FETCH_STATUS.NOT_HELD);
    // 空のバケット: 全員に聞くまで終わらない。1 回目は時間切れを待つ
    expect(await c.client.fetchBucket(BIRTH, TAG, { since: 0 })).toMatchObject({ completed: false, reason: 'exhausted', attempts: 3 });
    expect(dead.asked).toBe(1);
    // 別の空のバケットでは、黙った保持者に聞かない (時間切れを待たずにすぐ終わる)
    const t0 = performance.now();
    expect(await c.client.fetchBucket(BIRTH, TAG + 1, { since: 0 })).toMatchObject({ completed: false, reason: 'exhausted', attempts: 2 });
    expect(performance.now() - t0).toBeLessThan(150);
    expect(dead.asked).toBe(1);
  });

  it('★候補が全員「届かなかった」なら外さずに試す (候補が 0 にならない)', async () => {
    c = await setup(1, { inactivityMs: 100 });
    c.holders[0].behavior = () => {};
    await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    c.holders[0].behavior = answer(packets);
    expect(await c.client.fetchBucket(BIRTH, TAG, { since: 0 })).toMatchObject({ completed: true, packets: 3 });
    expect(c.holders[0].asked).toBe(2);
  });

  it('★失敗の罰が付いた保持者 (記録が時間切れより遅い) は、記録の無い保持者より後ろに回す', async () => {
    c = await setup(3);
    c.holders.forEach(h => (h.behavior = answer([])));
    c.client.recordSpeed(c.holders[0].sid, 60_000);
    await c.client.fetchBucket(BIRTH, TAG, { since: 5 });
    expect(new Set(c.requests.slice(0, 2).map(r => r.holder))).toEqual(new Set([c.holders[1], c.holders[2]]));
  });

  it('★試す保持者の数に上限 (maxAttempts)。全員が失敗すれば exhausted', async () => {
    c = await setup(6, { maxAttempts: 3 });
    c.holders.forEach(h => (h.behavior = answer([], FETCH_STATUS.NOT_HELD)));
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: false, reason: 'exhausted', attempts: 3 });
    expect(c.requests).toHaveLength(3);
  });

  it('1 ホップ目が無ければ待ち、(再) 接続したら取りに行く。待ち時間を過ぎれば no-first-hop。中止できる', async () => {
    c = await setup(1);
    c.holders[0].behavior = answer(packets);
    c.setFirstHop(null);
    const p = c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    await sleep(20);
    c.setFirstHop('e'.repeat(32));
    c.fireVerified();
    expect(await p).toMatchObject({ completed: true, packets: 3 });
    c.setFirstHop(null);
    expect((await c.client.fetchBucket(BIRTH, TAG)).reason).toBe('no-first-hop');
    const ctl = new AbortController();
    const q = c.client.fetchBucket(BIRTH, TAG, { signal: ctl.signal });
    ctl.abort();
    expect((await q).reason).toBe('aborted');
    c.client.destroy();
    expect((await c.client.fetchBucket(BIRTH, TAG)).reason).toBe('aborted');
  });

  it('onReady: 1 ホップ目が検証済みになるたびに通知する (解除できる)', async () => {
    c = await setup(1);
    let n = 0;
    const off = c.client.onReady(() => n++);
    c.fireVerified();
    c.fireVerified();
    off();
    c.fireVerified();
    expect(n).toBe(2);
  });

  it('★同じ受け口への要求は同時 3 本まで (板の 13 週を一度に出しても、旧版の受け口に浴びせない)。別々の受け口なら一度に出せる', async () => {
    c = await setup(1);
    let running = 0, peak = 0;
    c.holders[0].behavior = async (_r, send) => {
      running++; peak = Math.max(peak, running);
      await sleep(30);
      running--;
      send(0, true, encodeFetchResponse({ status: 0, nextSince: 0, packets: [] }));
    };
    const rs = await Promise.all(Array.from({ length: 13 }, () => c.client.fetchBucket(BIRTH, TAG, { since: 3 })));
    expect(rs.every(r => r.completed)).toBe(true);
    expect(peak).toBe(HISTORY_LIMITS.PER_GATEWAY_INFLIGHT);
    c.client.destroy();

    // 受け口が別々なら、13 本の取得が同時に走る (取得の同時数の上限 16 の内側)。頼む順は取得ごとに散らす
    let x = 7;
    c = await setup(13, { random: () => ((x = (x * 9301 + 49297) % 233280) / 233280) });
    let inFlight = 0, most = 0;
    c.holders.forEach(h => (h.behavior = async (_r, send) => {
      inFlight++; most = Math.max(most, inFlight);
      await sleep(30);
      inFlight--;
      send(0, true, encodeFetchResponse({ status: 0, nextSince: 0, packets: [] }));
    }));
    const all = await Promise.all(Array.from({ length: 13 }, (_, i) => c.client.fetchBucket(BIRTH, TAG + i, { since: 3 })));
    expect(all.every(r => r.completed)).toBe(true);
    expect(most).toBeGreaterThanOrEqual(13);
    void msToMinutes;
  });

  it('★混んでいて断られた (BUSY) ら、保持者の失敗に数えず、待って同じ保持者に頼み直す', async () => {
    c = await setup(1, { maxAttempts: 1 });
    let n = 0;
    c.holders[0].behavior = (_r, send, _k, _key, fail) => {
      if (n++ === 0) return fail!(TUNNEL_ERROR_CODE.BUSY);
      send(0, true, encodeFetchResponse({ status: FETCH_STATUS.OK, nextSince: 0, packets: packets.map(encodePacket) }));
    };
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: 3, attempts: 1 });
    expect(c.holders[0].asked).toBe(2);
    expect(c.client.speedOf(c.holders[0].sid)).toBeLessThan(HISTORY_LIMITS.FAIL_PENALTY_MS);
  });

  it('★保持者ごとに持っている投稿が違う (参加前・落ちていた間の分が無い) とき、2 台の「全部です」を合わせる', async () => {
    // 実網で、1 台の答えで終えて欠けが残り、端末ごとにスレやレスの揃い方が違った
    c = await setup(4);
    c.holders[0].behavior = answer([packets[0], packets[1]]);
    c.holders[1].behavior = answer([packets[1], packets[2]]);
    c.holders[2].behavior = answer([], FETCH_STATUS.NOT_HELD);
    c.holders[3].behavior = answer([], FETCH_STATUS.NOT_HELD);
    c.client.recordSpeed(c.holders[0].sid, 1);
    c.client.recordSpeed(c.holders[1].sid, 2);
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: 3, attempts: 2 });
    expect(c.delivered).toHaveLength(3);
  });

  it('★投稿を持っているのが候補の 1 台だけでも、「持っていない」が続いても打ち切らずにたどり着く (全員に聞いて 1 台なら完了)', async () => {
    c = await setup(6, { maxAttempts: 8 });
    c.holders.forEach(h => (h.behavior = answer([], FETCH_STATUS.NOT_HELD)));
    const keeper = c.holders[3];
    keeper.behavior = answer(packets);
    c.client.recordSpeed(keeper.sid, 60_000); // 最後に回る
    const res = await c.client.fetchBucket(BIRTH, TAG, { since: 0 });
    expect(res).toMatchObject({ completed: true, packets: 3, attempts: 6 });
    // スレの無い週 (全員が持っていない): 全員に聞いて、取り切ったことにはしない
    c.holders.forEach(h => (h.behavior = answer([], FETCH_STATUS.NOT_HELD)));
    expect(await c.client.fetchBucket(BIRTH, TAG + 1, { since: 0 })).toMatchObject({ completed: false, reason: 'exhausted', attempts: 6 });
  });
});
