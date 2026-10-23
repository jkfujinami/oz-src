import { describe, it, expect, beforeAll } from 'vitest';
import type { NodeIdentity } from '../../src/crypto/NodeIdentity';
import {
  GuardManager,
  GUARD_SAMPLE_SIZE,
  GUARD_SAMPLE_MIN_LIFETIME_MS,
  GUARD_SAMPLE_MAX_LIFETIME_MS,
} from '../../src/trust/GuardManager';
import { sodiumReady } from '../../src/crypto/sodium';
import { DAY, FAST, NOW, MemoryStore, makeList, makeMaintainer, mineIdentities, type Maintainer } from '../helpers/guardFixtures';

describe('GuardManager: 信頼リストの検証・保存・再読み込み', () => {
  let m: Maintainer;
  let ids: NodeIdentity[];

  beforeAll(async () => {
    await sodiumReady;
    m = await makeMaintainer();
    ids = await mineIdentities(6);
  });

  function make(store: MemoryStore, over: Partial<ConstructorParameters<typeof GuardManager>[0]> = {}, clock = { t: NOW }) {
    const gm = new GuardManager({
      keyset: m.keyset, store, powParams: FAST, now: () => clock.t, ...over,
    });
    return { gm, clock };
  }

  it('取り込んだリストを保存し、再起動後に読み込み直して信頼判定に使える', async () => {
    const store = new MemoryStore();
    const a = make(store).gm;
    await a.init();
    const text = makeList(m, ids.slice(0, 3), { version: 4 });
    const res = await a.importList(text);
    expect(res.ok).toBe(true);
    await a.flush();
    expect((store.data.get('guard.list') as any).version).toBe(4);

    const b = make(store).gm;
    await b.init();
    const s = ids[0].exportSecret();
    expect(b.isTrusted(ids[0].peerId, s.pubkey)).toBe(true);
    expect(b.status.listVersion).toBe(4);
    expect(b.status.mode).toBe('none');
  });

  it('trustedGuardIds: リストの Guard すべて (失効したものを除く)。リストが無い・失効していれば空 (バックボーンの一覧)', async () => {
    const clock = { t: NOW };
    const { gm } = make(new MemoryStore(), {}, clock);
    await gm.init();
    expect(gm.trustedGuardIds()).toEqual([]);
    await gm.importList(makeList(m, ids.slice(0, 4), { version: 1, revoked: [ids[3]] }));
    expect(gm.trustedGuardIds().sort()).toEqual(ids.slice(0, 3).map(i => i.peerId).sort());
    clock.t = NOW + 365 * DAY; // リストの期限切れ
    expect(gm.trustedGuardIds()).toEqual([]);
  });

  it('巻き戻し (より古い版) は拒否し、状態を変えない', async () => {
    const store = new MemoryStore();
    const { gm } = make(store);
    await gm.init();
    expect((await gm.importList(makeList(m, ids.slice(0, 2), { version: 5 }))).ok).toBe(true);
    const old = await gm.importList(makeList(m, ids.slice(2, 4), { version: 4 }));
    expect(old).toMatchObject({ ok: false, reason: 'rollback' });
    expect(gm.isTrusted(ids[0].peerId, ids[0].exportSecret().pubkey)).toBe(true);
    expect(gm.isTrusted(ids[2].peerId, ids[2].exportSecret().pubkey)).toBe(false);
    await gm.flush();
    expect((store.data.get('guard.list') as any).version).toBe(5);
  });

  it('再起動後も、保存済みの版より古いリストは設定から与えられても採用しない', async () => {
    const store = new MemoryStore();
    const first = make(store).gm;
    await first.init();
    await first.importList(makeList(m, ids.slice(0, 2), { version: 7 }));
    await first.flush();

    const { gm } = make(store, { guardList: makeList(m, ids.slice(2, 4), { version: 3 }) });
    await gm.init();
    expect(gm.status.listVersion).toBe(7);
    expect(gm.isTrusted(ids[2].peerId, ids[2].exportSecret().pubkey)).toBe(false);
    // 同じ版の再取り込みは許す。より新しい版は受け入れる
    expect((await gm.importList(makeList(m, ids.slice(0, 2), { version: 7 }))).ok).toBe(true);
    expect((await gm.importList(makeList(m, ids.slice(2, 4), { version: 8 }))).ok).toBe(true);
  });

  it('設定のリストの版が保存済みより高ければ設定を採用して保存する', async () => {
    const store = new MemoryStore();
    const first = make(store).gm;
    await first.init();
    await first.importList(makeList(m, ids.slice(0, 2), { version: 2 }));
    await first.flush();

    const { gm } = make(store, { guardList: makeList(m, ids.slice(2, 4), { version: 3 }) });
    await gm.init();
    await gm.flush();
    expect(gm.status.listVersion).toBe(3);
    expect(gm.isTrusted(ids[2].peerId, ids[2].exportSecret().pubkey)).toBe(true);
    expect((store.data.get('guard.list') as any).version).toBe(3);
  });

  it('メンテナ以外の署名・壊れた文字列は拒否し、何も保存しない', async () => {
    const store = new MemoryStore();
    const other = await makeMaintainer();
    const { gm } = make(store);
    await gm.init();
    expect(await gm.importList(makeList(other, ids.slice(0, 2)))).toMatchObject({ ok: false, reason: 'insufficient-signatures' });
    expect(await gm.importList('garbage')).toMatchObject({ ok: false, reason: 'malformed' });
    await gm.flush();
    expect(store.data.has('guard.list')).toBe(false);
    expect(gm.hasUsableList).toBe(false);
  });

  it('鍵の組が無ければ常に拒否する (オープン動作のまま)', async () => {
    const gm = new GuardManager({ store: new MemoryStore(), powParams: FAST, now: () => NOW });
    await gm.init();
    expect(await gm.importList(makeList(m, ids.slice(0, 2)))).toMatchObject({ ok: false, reason: 'no-keyset' });
    expect(gm.status.reason).toBe('no-list');
  });

  it('失効したリストは「リスト無し」として扱い、状態には失効を出し続ける', async () => {
    const store = new MemoryStore();
    const { gm, clock } = make(store);
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 3), { version: 2, validityMs: 10 * DAY }));
    expect(gm.hasUsableList).toBe(true);
    expect(gm.wantedGuardIds().length).toBe(3);

    clock.t = NOW + 11 * DAY;
    expect(gm.hasUsableList).toBe(false);
    expect(gm.isTrusted(ids[0].peerId, ids[0].exportSecret().pubkey)).toBe(false);
    expect(gm.wantedGuardIds()).toEqual([]);

    // 失効後に select すると open 動作になり、理由に失効が出る
    gm.select([], new Map(), clock.t, null);
    expect(gm.status.reason).toBe('list-expired');
    expect(gm.status.listVersion).toBe(2);
    expect(gm.status.listExpiresAt).toBe(NOW + 10 * DAY);

    // 失効したまま再起動しても、失効と版を報告する。古い版は入れられない
    const re = make(store, {}, clock).gm;
    await re.init();
    expect(re.hasUsableList).toBe(false);
    expect(re.status).toMatchObject({ mode: 'none', reason: 'list-expired', listVersion: 2 });
    expect(await re.importList(makeList(m, ids.slice(0, 3), { version: 1, now: clock.t }))).toMatchObject({ ok: false, reason: 'rollback' });
    expect((await re.importList(makeList(m, ids.slice(0, 3), { version: 3, now: clock.t }))).ok).toBe(true);
    expect(re.hasUsableList).toBe(true);
  });

  it('peerId が同じでも公開鍵がリストと違えば信頼しない', async () => {
    const { gm } = make(new MemoryStore());
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 2)));
    const real = ids[0].exportSecret().pubkey;
    expect(gm.isTrusted(ids[0].peerId, real)).toBe(true);
    expect(gm.isTrusted(ids[0].peerId, ids[1].exportSecret().pubkey)).toBe(false);
    const flipped = real.slice();
    flipped[31] ^= 1;
    expect(gm.isTrusted(ids[0].peerId, flipped)).toBe(false);
    expect(gm.isTrusted(ids[0].peerId, null)).toBe(false);
    expect(gm.isTrusted(ids[0].peerId, real.slice(0, 31))).toBe(false);
    expect(gm.isTrusted(ids[5].peerId, ids[5].exportSecret().pubkey)).toBe(false); // リスト外
  });

  it('失効 (revoke) された Guard は信頼せず、サンプルにも入れない', async () => {
    const { gm } = make(new MemoryStore());
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 4), { revoked: [ids[1]] }));
    expect(gm.isTrusted(ids[1].peerId, ids[1].exportSecret().pubkey)).toBe(false);
    expect(gm.isRevoked(ids[1].peerId)).toBe(true);
    const wanted = gm.wantedGuardIds();
    expect(wanted).toHaveLength(3); // 4 - 1 = 3 人しか残らない
    expect(wanted).not.toContain(ids[1].peerId);
  });
});

describe('GuardManager: Guard サンプル (最大 3 人・各 30〜60 日)', () => {
  let m: Maintainer;
  let ids: NodeIdentity[];

  beforeAll(async () => {
    await sodiumReady;
    m = await makeMaintainer();
    ids = await mineIdentities(8);
  });

  function make(store: MemoryStore, clock = { t: NOW }, over: Partial<ConstructorParameters<typeof GuardManager>[0]> = {}) {
    return { gm: new GuardManager({ keyset: m.keyset, store, powParams: FAST, now: () => clock.t, ...over }), clock };
  }
  const idSet = (xs: NodeIdentity[]) => new Set(xs.map(x => x.peerId));

  it('リストから 3 人を選んで保存し、再起動後も同じサンプルを使う', async () => {
    const store = new MemoryStore();
    const { gm } = make(store);
    await gm.init();
    await gm.importList(makeList(m, ids, { validityMs: 170 * DAY }));
    const wanted = gm.wantedGuardIds();
    expect(GUARD_SAMPLE_SIZE).toBe(3);
    expect(wanted).toHaveLength(3);
    expect(new Set(wanted).size).toBe(3);
    for (const w of wanted) expect(idSet(ids).has(w)).toBe(true);

    await gm.flush();
    const saved = store.data.get('guard.sample') as Array<{ peerId: string; expiresAt: number }>;
    expect(saved.map(e => e.peerId)).toEqual(wanted);
    for (const e of saved) {
      expect(e.expiresAt - NOW).toBeGreaterThanOrEqual(GUARD_SAMPLE_MIN_LIFETIME_MS);
      expect(e.expiresAt - NOW).toBeLessThanOrEqual(GUARD_SAMPLE_MAX_LIFETIME_MS);
    }

    const again = make(store).gm;
    await again.init();
    expect(again.wantedGuardIds()).toEqual(wanted);
  });

  it('選択は注入した乱数に従う (一様抽選: 毎回リストの先頭になるとは限らない)', async () => {
    const { gm } = make(new MemoryStore(), { t: NOW }, { randomIndex: () => 0 });
    await gm.init();
    await gm.importList(makeList(m, ids));
    expect(gm.wantedGuardIds()).toEqual(ids.slice(0, 3).map(i => i.peerId));

    // 本物の乱数なら、何度か試せば先頭 3 人以外が混ざる
    const seen = new Set<string>();
    for (let i = 0; i < 40; i++) {
      const g = make(new MemoryStore()).gm;
      await g.init();
      await g.importList(makeList(m, ids));
      g.wantedGuardIds().forEach(w => seen.add(w));
    }
    expect(seen.size).toBeGreaterThan(3);
  });

  it('リストが 3 人未満なら、いる分だけ', async () => {
    const { gm } = make(new MemoryStore());
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 2)));
    expect(gm.wantedGuardIds()).toHaveLength(2);
  });

  it('新しいリストから外れた Guard はサンプルから外し、3 人に補充する (残りは保つ)', async () => {
    const store = new MemoryStore();
    const { gm } = make(store, { t: NOW }, { randomIndex: () => 0 });
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 5), { version: 1 }));
    const before = gm.wantedGuardIds();
    expect(before).toEqual(ids.slice(0, 3).map(i => i.peerId));

    // ids[1] を外し、ids[5..] を足した版 2
    const next = [ids[0], ids[2], ids[3], ids[4], ids[5]];
    await gm.importList(makeList(m, next, { version: 2 }));
    const after = gm.wantedGuardIds();
    expect(after).toHaveLength(3);
    expect(after).not.toContain(ids[1].peerId);
    expect(after.slice(0, 2)).toEqual([ids[0].peerId, ids[2].peerId]); // 残った 2 人は順序ごと保たれる
    await gm.flush();
    expect((store.data.get('guard.sample') as any[]).map(e => e.peerId)).toEqual(after);
  });

  it('失効 (revoke) された Guard もサンプルから外れる', async () => {
    const { gm } = make(new MemoryStore(), { t: NOW }, { randomIndex: () => 0 });
    await gm.init();
    await gm.importList(makeList(m, ids.slice(0, 5), { version: 1 }));
    await gm.importList(makeList(m, ids.slice(0, 5), { version: 2, revoked: [ids[0]] }));
    const w = gm.wantedGuardIds();
    expect(w).toHaveLength(3);
    expect(w).not.toContain(ids[0].peerId);
  });

  it('期限切れの Guard は外して引き直す', async () => {
    const store = new MemoryStore();
    const { gm, clock } = make(store);
    await gm.init();
    await gm.importList(makeList(m, ids, { validityMs: 170 * DAY }));
    const first = gm.wantedGuardIds();

    clock.t = NOW + 61 * DAY; // 最長の 60 日を過ぎれば全員が期限切れ
    const second = gm.wantedGuardIds();
    expect(second).toHaveLength(3);
    await gm.flush();
    for (const e of store.data.get('guard.sample') as any[]) expect(e.expiresAt).toBeGreaterThan(clock.t);
    expect(first).toHaveLength(3);
  });

  it('保存済みサンプルの期限切れ・リスト外のものは起動時に捨てて補充する', async () => {
    const store = new MemoryStore();
    const a = make(store);
    await a.gm.init();
    await a.gm.importList(makeList(m, ids.slice(0, 4), { version: 1, validityMs: 170 * DAY }));
    const before = a.gm.wantedGuardIds();
    await a.gm.flush();
    // 1 人を期限切れ、1 人をリスト外 (偽の ID) に書き換える
    store.data.set('guard.sample', [
      { peerId: before[0], expiresAt: NOW - 1 },
      { peerId: 'a'.repeat(32), expiresAt: NOW + 50 * DAY },
      { peerId: before[2], expiresAt: NOW + 50 * DAY },
    ]);
    const b = make(store).gm;
    await b.init();
    const w = b.wantedGuardIds();
    expect(w).toHaveLength(3);
    expect(w).toContain(before[2]);
    expect(w).not.toContain('a'.repeat(32));
    for (const id of w) expect(ids.slice(0, 4).map(i => i.peerId)).toContain(id);
  });

  it('フォールバック / オープンで選んだ隣人は決して保存しない', async () => {
    // オープン (リスト無し)
    const storeOpen = new MemoryStore();
    const open = new GuardManager({ store: storeOpen, powParams: FAST, now: () => NOW });
    await open.init();
    const peers = new Map<string, any>();
    const cands = Array.from({ length: 5 }, (_, i) => {
      const peerId = (i + 1).toString(16).repeat(32);
      peers.set(peerId, { peerId, direction: 'outbound' });
      return { peerId, pubkey: new Uint8Array(32) };
    });
    open.select(cands, peers, NOW, null);
    const picked = open.select(cands, peers, NOW + 60_000, null);
    expect(picked).not.toBeNull();
    expect(open.status.mode).toBe('open');
    await open.flush();
    expect(JSON.stringify([...storeOpen.data])).not.toContain(picked!.peerId);
    expect(storeOpen.data.has('guard.sample')).toBe(false);

    // フォールバック (リストはあるが信頼 Guard に未接続)
    const storeFb = new MemoryStore();
    const clock = { t: NOW };
    const fb = new GuardManager({ keyset: m.keyset, store: storeFb, powParams: FAST, now: () => clock.t });
    await fb.init();
    await fb.importList(makeList(m, ids.slice(0, 3)));
    fb.select(cands, peers, clock.t, null);
    clock.t += 60_000;
    const fbPick = fb.select(cands, peers, clock.t, null);
    expect(fb.status.mode).toBe('fallback');
    await fb.flush();
    expect(JSON.stringify([...storeFb.data])).not.toContain(fbPick!.peerId);
    const sample = storeFb.data.get('guard.sample') as any[];
    for (const e of sample) expect(ids.slice(0, 3).map(i => i.peerId)).toContain(e.peerId);
  });

  it('保存先が壊れていても落ちない (読めない・書けない)', async () => {
    const broken = {
      get: async () => { throw new Error('boom'); },
      set: async () => { throw new Error('boom'); },
    };
    const gm = new GuardManager({ keyset: m.keyset, store: broken, powParams: FAST, now: () => NOW });
    await expect(gm.init()).resolves.toBeUndefined();
    expect((await gm.importList(makeList(m, ids.slice(0, 3)))).ok).toBe(true);
    await expect(gm.flush()).resolves.toBeUndefined();
    expect(gm.wantedGuardIds()).toHaveLength(3);
  });
});
