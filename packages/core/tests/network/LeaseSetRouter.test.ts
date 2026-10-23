import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { WireCodec, MAX_LEASESET_FRAME_BYTES } from '../../src/network/wire/WireCodec';
import { MINUTE_MS, msToMinutes } from '../../src/crypto/PowPolicy';
import { LeaseSetRouter, LEASESET_ROUTER_LIMITS } from '../../src/network/storage/LeaseSetRouter';
import { LeaseSetStore } from '../../src/network/storage/LeaseSetStore';
import {
  LEASESET_MIN_REPLACE_MS, LEASESET_PUBLISH_GAP_MS, LEASESET_REPUBLISH_MS, decodeLeaseSet, signLeaseSet, verifyLeaseSet,
} from '../../src/network/storage/LeaseSet';
import { solveSlot, type SlotSolution } from '../../src/network/storage/SlotPow';
import { FakeNetworkPeerManager, newDispatcher, pid } from '../helpers/fakeNetworkPeerManager';
import { fakeLeaseSet } from '../helpers/storageNet';

const EFFORT = 1;
const T0 = Date.UTC(2026, 9, 15, 12, 0, 0);

interface Sid { pk: Uint8Array; sk: Uint8Array; slots: SlotSolution[] }
let sids: Sid[];

beforeAll(async () => {
  await sodiumReady;
  sids = [];
  for (let n = 0; n < 4; n++) {
    const kp = sodium.crypto_sign_keypair();
    const slots: SlotSolution[] = [];
    for (let i = 0; i < 2; i++) slots.push((await solveSlot(kp.publicKey, i, { effort: EFFORT }))!);
    sids.push({ pk: kp.publicKey, sk: kp.privateKey, slots });
  }
}, 30_000);

/** 本物の署名・PoW の leaseSet */
function lease(sid: Sid, o: { gateway?: string; expiresMin?: number; slots?: number } = {}): Uint8Array {
  return signLeaseSet(
    {
      sid: sid.pk,
      slots: sid.slots.slice(0, o.slots ?? 2),
      gateway: o.gateway ?? pid(0x9a7e),
      tunnelId: new Uint8Array(8).fill(3),
      expiresMin: o.expiresMin ?? msToMinutes(Date.now()) + 360,
    },
    (m) => sodium.crypto_sign_detached(m, sid.sk),
  );
}

/** DandelionRouter の代役 (固定した 1 ホップ目と、その変化の通知だけ) */
function fakeDandelion() {
  const listeners: Array<(g: string | null) => void> = [];
  let pinned: string | null = null;
  return {
    getPinnedGuardId: () => pinned,
    onGuardChange: (cb: (g: string | null) => void) => { listeners.push(cb); },
    set(g: string | null) { pinned = g; listeners.forEach(cb => cb(g)); },
  };
}

function setup(opts: { allowed?: (id: string) => boolean; own?: Sid | null; router?: object } = {}) {
  const pm = new FakeNetworkPeerManager(pid(0xabc));
  const dispatcher = newDispatcher();
  const dandelion = fakeDandelion();
  const store = new LeaseSetStore();
  const own = opts.own === undefined ? sids[0] : opts.own;
  const source = own
    ? { publicKey: own.pk, sign: (m: Uint8Array) => sodium.crypto_sign_detached(m, own.sk), slots: () => own.slots }
    : null;
  const router = new LeaseSetRouter(pm, dispatcher, dandelion as any, store, source, opts.allowed ?? (() => true), {
    slotEffort: EFFORT, syncMinIntervalMs: 0, syncFrameIntervalMs: 1, ...opts.router,
  });
  const recv = (from: string, bytes: Uint8Array) => dispatcher.dispatch(from, WireType.LEASESET, { leaseSet: bytes });
  const sentTo = (type: number, to?: string) => pm.sent.filter(m => m.type === type && (to === undefined || m.to === to));
  return { pm, dispatcher, dandelion, store, router, recv, sentTo };
}

const A = pid(0xa), B = pid(0xb), C = pid(0xc);

describe('LeaseSetRouter: flood', () => {
  it('★新しく入った leaseSet だけを、送ってきた相手以外の全隣人へ中継する。同じものの再送は中継しない', () => {
    const t = setup({ own: null });
    for (const p of [A, B, C]) t.pm.addPeer(p);
    const b1 = lease(sids[1]);
    t.recv(A, b1);
    expect(t.store.size).toBe(1);
    expect(t.sentTo(WireType.LEASESET).map(m => m.to).sort()).toEqual([B, C].sort());
    expect(Array.from(t.sentTo(WireType.LEASESET, B)[0].payload.leaseSet)).toEqual(Array.from(b1));

    t.recv(B, b1); // 同じバイト列: SeenCache で落ちる
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(2);
    expect(t.router.stats.accepted).toBe(1);
  });

  it('未検証・切断中の隣人へは中継しない', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    t.pm.addPeer(B, { isVerified: false });
    t.pm.addPeer(C, { isConnected: false });
    t.recv(A, lease(sids[1]));
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(0);
  });

  it('★同じ SID の古い (期限が遅くない) leaseSet は stale: 入れず、中継もしない。新しいものは (10 分空けば) 置き換えて中継する', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(T0);
    try {
      const t = setup({ own: null });
      for (const p of [A, B]) t.pm.addPeer(p);
      const nowMin = msToMinutes(Date.now());
      const newer = lease(sids[1], { expiresMin: nowMin + 300 });
      const older = lease(sids[1], { expiresMin: nowMin + 200 });
      const newest = lease(sids[1], { expiresMin: nowMin + 340 });
      t.recv(A, newer);
      expect(t.sentTo(WireType.LEASESET)).toHaveLength(1);
      t.recv(A, older);
      expect(t.sentTo(WireType.LEASESET)).toHaveLength(1);
      expect(t.router.stats.stale).toBe(1);
      vi.setSystemTime(T0 + LEASESET_MIN_REPLACE_MS);
      t.recv(A, newest);
      expect(t.sentTo(WireType.LEASESET)).toHaveLength(2);
      expect(t.store.get(Buffer.from(sids[1].pk).toString('hex'))!.expiresMin).toBe(nowMin + 340);
    } finally {
      vi.useRealTimers();
    }
  });

  it('★署名し直しの flood を止める: 同じ SID の置き換えは 10 分に 1 回。早すぎるものは入れず・中継せず・数える (受け口を替えても同じ)', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(T0);
    try {
      const t = setup({ own: null });
      for (const p of [A, B]) t.pm.addPeer(p);
      const nowMin = msToMinutes(Date.now());
      const sid = Buffer.from(sids[1].pk).toString('hex');
      t.recv(A, lease(sids[1], { expiresMin: nowMin + 200, gateway: pid(0x11) })); // 最初の 1 件は常に受け付ける
      expect(t.router.stats.accepted).toBe(1);
      // 攻撃: 1 分ごとに、期限をわずかに延ばし、受け口も毎回変えて署名し直す
      for (let i = 1; i <= 9; i++) {
        vi.setSystemTime(T0 + i * MINUTE_MS);
        t.recv(A, lease(sids[1], { expiresMin: nowMin + 200 + i, gateway: pid(0x20 + i) }));
      }
      expect(t.router.stats.accepted).toBe(1);
      expect(t.router.stats.tooSoon).toBe(9);
      expect(t.sentTo(WireType.LEASESET, B)).toHaveLength(1); // 最初の 1 件だけが網に出た
      expect(t.store.get(sid)!.gateway).toBe(pid(0x11));
      // 10 分たてば置き換わる
      vi.setSystemTime(T0 + LEASESET_MIN_REPLACE_MS);
      t.recv(A, lease(sids[1], { expiresMin: nowMin + 300, gateway: pid(0x99) }));
      expect(t.router.stats.accepted).toBe(2);
      expect(t.store.get(sid)!.gateway).toBe(pid(0x99));
      expect(t.sentTo(WireType.LEASESET, B)).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('★不正なものは入れず、中継せず、理由別に数える: 署名・枠の PoW・期限・遠すぎ・受け口・壊れた構造', () => {
    const trusted = pid(0x7777);
    const t = setup({ own: null, allowed: (id) => id === trusted });
    for (const p of [A, B]) t.pm.addPeer(p);
    const nowMin = msToMinutes(Date.now());
    const good = lease(sids[1], { gateway: trusted });
    const badSig = good.slice(); badSig[badSig.length - 1] ^= 1;
    const fakePow = signLeaseSet(
      { sid: sids[1].pk, slots: [{ nonce: 1, solution: new Uint8Array(16) }], gateway: trusted, tunnelId: new Uint8Array(8), expiresMin: nowMin + 300 },
      (m) => sodium.crypto_sign_detached(m, sids[1].sk),
    );
    const expired = lease(sids[1], { gateway: trusted, expiresMin: nowMin - 1 });
    const far = lease(sids[1], { gateway: trusted, expiresMin: nowMin + 400 });
    const untrusted = lease(sids[1], { gateway: pid(0x1234) });
    const malformed = new Uint8Array(200).fill(7);
    for (const b of [badSig, fakePow, expired, far, untrusted, malformed]) t.recv(A, b);
    expect(t.store.size).toBe(0);
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(0);
    const r = t.router.stats.rejected;
    expect(r.get('bad-signature')).toBe(1);
    expect(r.get('bad-slot-pow')).toBe(1);
    expect(r.get('expired')).toBe(1);
    expect(r.get('too-far')).toBe(1);
    expect(r.get('untrusted-gateway')).toBe(1);
    expect(r.get('malformed')).toBe(1);
    t.recv(A, good);
    expect(t.store.size).toBe(1);
  });

  it('同じ不正なバイト列を繰り返し送られても検証は 1 回 (SeenCache)', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    const bad = lease(sids[1]); bad[bad.length - 1] ^= 1;
    for (let i = 0; i < 20; i++) t.recv(A, bad);
    expect(t.router.stats.rejected.get('bad-signature')).toBe(1);
  });

  it('壊れた payload (leaseSet が無い) は何もしない', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    t.dispatcher.dispatch(A, WireType.LEASESET, {});
    t.dispatcher.dispatch(A, WireType.LEASESET, { leaseSet: 'x' });
    expect(t.store.size).toBe(0);
  });
});

describe('LeaseSetRouter: 自分の leaseSet の発行', () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'] }); vi.setSystemTime(T0); });
  afterEach(() => { vi.useRealTimers(); });

  it('受け口 (1 ホップ目) が無い・枠が無い・容認されない受け口なら発行しない', () => {
    const t = setup({ allowed: (id) => id === pid(0x1) });
    t.pm.addPeer(A);
    expect(t.router.publish()).toBeNull(); // 1 ホップ目が無い
    t.dandelion.set(A);
    expect(t.router.publish()).toBeNull(); // A は受け口として認められない (警告状態)
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(0);
    expect(t.store.size).toBe(0);
    const noSlots = setup({ own: { ...sids[0], slots: [] } });
    noSlots.dandelion.set(A);
    expect(noSlots.router.publish()).toBeNull();
    const noSource = setup({ own: null });
    noSource.dandelion.set(A);
    expect(noSource.router.publish()).toBeNull();
  });

  it('★発行: 検証を通る leaseSet を作り、手元に入れ、全隣人へ flood する。受け口は 1 ホップ目、IP は載らない', () => {
    const t = setup();
    for (const p of [A, B]) t.pm.addPeer(p);
    t.dandelion.set(A);
    const bytes = t.router.publish()!;
    const ls = decodeLeaseSet(bytes)!;
    expect(ls.gateway).toBe(A);
    expect(ls.slots).toHaveLength(2);
    expect(verifyLeaseSet(ls, { nowMs: Date.now(), gatewayAllowed: () => true, slotEffort: EFFORT })).toEqual({ ok: true });
    expect(ls.expiresMin).toBe(msToMinutes(Date.now()) + 360); // 期限 6 時間
    expect(t.store.size).toBe(1);
    expect(t.sentTo(WireType.LEASESET).map(m => m.to).sort()).toEqual([A, B].sort());
    expect(t.router.currentTunnel).toEqual({ gateway: A, tunnelId: ls.tunnelId });
    // 自分の leaseSet が戻ってきても再び flood しない (SeenCache)
    t.recv(B, bytes);
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(2);
  });

  it('★出し直しは最短 10 分 30 秒ごと: 早く呼んでも 1 本に遅らせてまとめる。出せば期限は必ず進む', () => {
    const t = setup();
    t.pm.addPeer(A);
    t.dandelion.set(A);
    const a = decodeLeaseSet(t.router.publish()!)!;
    // 枠が解けた・Guard が替わった等で何度呼んでも、間隔が空くまでは出さない (戻り値は null)
    expect(t.router.publish()).toBeNull();
    expect(t.router.publish()).toBeNull();
    expect(t.router.stats.published).toBe(1);
    expect(t.router.stats.deferred).toBe(1); // 遅らせる予約は 1 本だけ
    vi.advanceTimersByTime(LEASESET_PUBLISH_GAP_MS - 1000);
    expect(t.router.stats.published).toBe(1);
    vi.advanceTimersByTime(2000);
    expect(t.router.stats.published).toBe(2);
    const b = decodeLeaseSet(t.sentTo(WireType.LEASESET, A).at(-1)!.payload.leaseSet)!;
    expect(b.expiresMin).toBeGreaterThan(a.expiresMin);
    expect(Buffer.from(b.tunnelId).equals(Buffer.from(a.tunnelId))).toBe(true); // 同じ受け口なら tunnelId も同じ
    // 受け手の規則 (10 分) より必ず長い間隔なので、他の端末に too-soon で捨てられない
    expect(LEASESET_PUBLISH_GAP_MS).toBeGreaterThan(LEASESET_MIN_REPLACE_MS);
  });

  it('★受け口の変更も同じ間隔に従う: 変わってもすぐ出さず、間隔が空いたときに新しい受け口で 1 本出す。前の受け口に戻れば前の tunnelId', () => {
    const t = setup();
    for (const p of [A, B]) t.pm.addPeer(p);
    t.router.start();
    t.dandelion.set(A);
    const first = decodeLeaseSet(t.sentTo(WireType.LEASESET, B).at(-1)!.payload.leaseSet)!;
    expect(first.gateway).toBe(A);
    const sent = () => t.sentTo(WireType.LEASESET).length;
    const n1 = sent();
    t.dandelion.set(B); // 発行から 0 秒: 待つ
    expect(sent()).toBe(n1);
    expect(t.router.currentTunnel!.gateway).toBe(A); // 待つ間は前の受け口のまま
    vi.advanceTimersByTime(LEASESET_PUBLISH_GAP_MS + 1);
    const second = decodeLeaseSet(t.sentTo(WireType.LEASESET, A).at(-1)!.payload.leaseSet)!;
    expect(second.gateway).toBe(B);
    expect(Buffer.from(second.tunnelId).equals(Buffer.from(first.tunnelId))).toBe(false);
    t.dandelion.set(A);
    vi.advanceTimersByTime(LEASESET_PUBLISH_GAP_MS + 1);
    const third = decodeLeaseSet(t.sentTo(WireType.LEASESET, B).at(-1)!.payload.leaseSet)!;
    expect(third.gateway).toBe(A);
    expect(Buffer.from(third.tunnelId).equals(Buffer.from(first.tunnelId))).toBe(true);
    t.router.destroy();
  });

  it('★出すたびに onPublished が受け口と tunnelId を渡す (TunnelHolder が登録に使う)', () => {
    const t = setup();
    t.pm.addPeer(A);
    t.dandelion.set(A);
    const got: Array<{ gateway: string; tunnelId: Uint8Array }> = [];
    t.router.onPublished(x => got.push(x));
    const ls = decodeLeaseSet(t.router.publish()!)!;
    expect(got).toHaveLength(1);
    expect(got[0].gateway).toBe(A);
    expect(Buffer.from(got[0].tunnelId).equals(Buffer.from(ls.tunnelId))).toBe(true);
  });

  it('★2 時間ごとに出し直し、期限は 6 時間先に更新される', () => {
    const t = setup();
    t.pm.addPeer(A);
    t.dandelion.set(A);
    t.router.start();
    const count = () => t.sentTo(WireType.LEASESET, A).length;
    const n0 = count();
    expect(n0).toBeGreaterThanOrEqual(1);
    vi.advanceTimersByTime(LEASESET_REPUBLISH_MS - 1000);
    expect(count()).toBe(n0);
    vi.advanceTimersByTime(2000);
    expect(count()).toBe(n0 + 1);
    const last = decodeLeaseSet(t.sentTo(WireType.LEASESET, A).at(-1)!.payload.leaseSet)!;
    expect(last.expiresMin).toBe(msToMinutes(Date.now()) + 360);
    vi.advanceTimersByTime(LEASESET_REPUBLISH_MS);
    expect(count()).toBe(n0 + 2);
    t.router.destroy();
    vi.advanceTimersByTime(LEASESET_REPUBLISH_MS * 3);
    expect(count()).toBe(n0 + 2); // 停止後は出さない
  });

  it('期限が切れた leaseSet は 1 分ごとの掃除で消える', () => {
    const t = setup({ own: null });
    t.router.start();
    const nowMin = msToMinutes(Date.now());
    t.pm.addPeer(A);
    t.recv(A, lease(sids[1], { expiresMin: nowMin + 5 }));
    expect(t.store.size).toBe(1);
    vi.advanceTimersByTime(6 * MINUTE_MS + LEASESET_ROUTER_LIMITS.PRUNE_INTERVAL_MS);
    expect(t.store.size).toBe(0);
    t.router.destroy();
  });
});

describe('LeaseSetRouter: 新参者への一括送信 (SYNC)', () => {
  it('★1 ホップ目が検証済みになったら SYNC_REQ を 1 回だけ送る。切れて張り直したらもう一度', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    t.pm.addPeer(B);
    t.dandelion.set(A);
    expect(t.sentTo(WireType.LEASESET_SYNC_REQ, A)).toHaveLength(1); // 既に検証済みの 1 ホップ目に固定した
    t.pm.emit('peer:verified', { peerId: A });
    t.pm.emit('peer:verified', { peerId: B }); // 1 ホップ目でない相手には頼まない
    expect(t.sentTo(WireType.LEASESET_SYNC_REQ)).toHaveLength(1);
    t.pm.emit('peer:disconnect', A);
    t.pm.emit('peer:verified', { peerId: A });
    expect(t.sentTo(WireType.LEASESET_SYNC_REQ, A)).toHaveLength(2);
  });

  it('握手前 (未検証) の 1 ホップ目には頼まない。検証されたら頼む', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A, { isVerified: false });
    t.dandelion.set(A);
    expect(t.sentTo(WireType.LEASESET_SYNC_REQ)).toHaveLength(0);
    (t.pm.peers.get(A) as any).isVerified = true;
    t.pm.emit('peer:verified', { peerId: A });
    expect(t.sentTo(WireType.LEASESET_SYNC_REQ)).toHaveLength(1);
  });

  it('★応答: 手持ちの期限内の leaseSet を全部、1 フレーム 16KiB 未満に分けて送る。期限切れは送らない', async () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    const n = 700;
    for (let i = 0; i < n; i++) t.store.add(fakeLeaseSet(i + 1, 1 + (i % 4)));
    t.store.add(fakeLeaseSet(99999, 1, { expiresMin: msToMinutes(Date.now()) - 1 })); // 入らない (切れている)
    t.dispatcher.dispatch(A, WireType.LEASESET_SYNC_REQ, {});
    await vi.waitFor(() => {
      const sent = t.sentTo(WireType.LEASESET_SYNC, A).reduce((s, m) => s + m.payload.leaseSets.length, 0);
      expect(sent).toBe(n);
    }, { timeout: 3000 });
    const frames = t.sentTo(WireType.LEASESET_SYNC, A);
    expect(frames.length).toBeGreaterThan(5);
    frames.forEach((f, i) => {
      const wire = WireCodec.encode(WireType.LEASESET_SYNC, f.payload); // 上限超過なら RangeError
      expect(wire.length).toBeLessThanOrEqual(MAX_LEASESET_FRAME_BYTES);
      // 最後以外は詰められるだけ詰める (次の 1 件が入らなかった = 上限まで残り 1 件分 (最大 447 バイト) 未満)
      if (i < frames.length - 1) expect(MAX_LEASESET_FRAME_BYTES - wire.length).toBeLessThan(2 + 445);
    });
    // 重複なく全員分
    const all = frames.flatMap(f => f.payload.leaseSets.map((b: Uint8Array) => Buffer.from(b).toString('hex')));
    expect(new Set(all).size).toBe(n);
    t.router.destroy();
  });

  it('応答は要求した相手が検証済みで、間隔を守っているときだけ。連打・未検証・切断は無視', () => {
    const t = setup({ own: null, router: { syncMinIntervalMs: 60_000, syncFrameIntervalMs: 1000 } });
    t.pm.addPeer(A);
    t.pm.addPeer(B, { isVerified: false });
    for (let i = 0; i < 5; i++) t.store.add(fakeLeaseSet(i + 1));
    t.dispatcher.dispatch(B, WireType.LEASESET_SYNC_REQ, {});
    t.dispatcher.dispatch(pid(0xdead), WireType.LEASESET_SYNC_REQ, {});
    expect(t.sentTo(WireType.LEASESET_SYNC)).toHaveLength(0);
    t.dispatcher.dispatch(A, WireType.LEASESET_SYNC_REQ, {});
    expect(t.sentTo(WireType.LEASESET_SYNC, A)).toHaveLength(1);
    t.dispatcher.dispatch(A, WireType.LEASESET_SYNC_REQ, {});
    expect(t.sentTo(WireType.LEASESET_SYNC, A)).toHaveLength(1); // 1 分以内の再要求
    t.router.destroy();
  });

  it('手持ちが空なら何も送らない', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    t.dispatcher.dispatch(A, WireType.LEASESET_SYNC_REQ, {});
    expect(t.sentTo(WireType.LEASESET_SYNC)).toHaveLength(0);
  });

  it('★受信: 頼んだ相手の SYNC だけ受け取り、検証して手元に入れる。中継はしない。頼んでいない相手のものは無視', () => {
    const t = setup({ own: null });
    for (const p of [A, B, C]) t.pm.addPeer(p);
    t.dandelion.set(A); // A に SYNC_REQ を出す
    const good1 = lease(sids[1]);
    const good2 = lease(sids[2]);
    const bad = lease(sids[3]); bad[bad.length - 1] ^= 1;
    // 頼んでいない B からは無視
    t.dispatcher.dispatch(B, WireType.LEASESET_SYNC, { leaseSets: [good1] });
    expect(t.store.size).toBe(0);
    t.dispatcher.dispatch(A, WireType.LEASESET_SYNC, { leaseSets: [good1, bad, good2] });
    expect(t.store.size).toBe(2);
    expect(t.router.stats.rejected.get('bad-signature')).toBe(1);
    expect(t.sentTo(WireType.LEASESET)).toHaveLength(0); // SYNC で届いたものは中継しない
    // 同じものを flood で受けても (SeenCache で) 重複しない
    t.recv(C, good1);
    expect(t.store.size).toBe(2);
  });

  it('SYNC の待ち時間を過ぎたら受け取らない', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(T0);
    try {
      const t = setup({ own: null });
      t.pm.addPeer(A);
      t.dandelion.set(A);
      vi.setSystemTime(T0 + LEASESET_ROUTER_LIMITS.SYNC_WAIT_MS + 1000);
      t.dispatcher.dispatch(A, WireType.LEASESET_SYNC, { leaseSets: [lease(sids[1], { expiresMin: msToMinutes(Date.now()) + 300 })] });
      expect(t.store.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('LeaseSetRouter: 後始末', () => {
  it('destroy 後は何も受け付けず、購読を外す', () => {
    const t = setup({ own: null });
    t.pm.addPeer(A);
    t.router.destroy();
    t.recv(A, lease(sids[1]));
    expect(t.store.size).toBe(0);
    expect(t.pm.listenerCount('peer:verified')).toBe(0);
    expect(t.pm.listenerCount('peer:disconnect')).toBe(0);
  });
});
