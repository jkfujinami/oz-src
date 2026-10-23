import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { GuardManager } from '../../src/trust/GuardManager';
import {
  createSimNode, link, startAll, stopAll, sleep, makePacket, FAST_POW, type SimNode,
} from '../helpers/onionNet';
import { makeList, makeMaintainer, type Maintainer } from '../helpers/guardFixtures';

/**
 * 結合テスト: 最初に握手を終えた隣人が信頼できない相手でも、
 * 利用者の最初の 1 ホップ (Guard) は信頼 Guard になり、セルはそこにだけ出る。
 */
describe('信頼 Guard と Onion 回路の結合', () => {
  let m: Maintainer;
  let nodes: SimNode[] = [];

  beforeAll(async () => {
    await sodiumReady;
    m = await makeMaintainer();
  });

  afterEach(() => stopAll(nodes));

  const cellsFrom = (to: SimNode, from: SimNode) =>
    to.inbox.filter(x => x.from === from.identity.peerId && x.type === WireType.ONION_STEM).length;

  /** 信頼 Guard (trusted) と M1 兼 Stem の歩き先 (exit) を先に作り、そのリストを持つ利用者を作る */
  async function world(timing: { fallbackGraceMs: number; openSelectionDelayMs: number }) {
    const trusted = await createSimNode('trusted');
    const exit = await createSimNode('exit');
    const guards = new GuardManager({
      keyset: m.keyset,
      guardList: makeList(m, [trusted.identity]),
      powParams: FAST_POW,
      ...timing,
    });
    await guards.init();
    const client = await createSimNode('client', undefined, guards);
    nodes = [client, trusted, exit];
    return { client, trusted, exit, guards };
  }

  it('最初の隣人が信頼できない相手でも、信頼 Guard が固定され、セルはそこにだけ出る', async () => {
    const { client, trusted, exit, guards } = await world({ fallbackGraceMs: 2_000, openSelectionDelayMs: 50 });
    const stranger = await createSimNode('stranger');
    nodes.push(stranger);

    // 信頼できない隣人が先につながる (トラッカーに居座る攻撃者を想定)。M1 (exit) の隣人でもある
    link(client, stranger);
    link(stranger, exit);
    link(trusted, exit);
    // 利用者・信頼 Guard・M1 だけが cover を出す。信頼できない隣人は黙らせておく
    // (隣人が自分の Guard として利用者を選ぶと、利用者が中継したセルが混ざって数えにくくなる)
    startAll([client, trusted, exit]);

    await sleep(150);
    // 猶予の間、信頼できない隣人には 1 枚も出ない (fail-closed で止まる)
    expect(cellsFrom(stranger, client)).toBe(0);
    expect(client.dandelion.getPinnedGuardId()).toBeNull();
    expect(guards.status.mode).toBe('none');
    // 止まっている間の投稿は、平文に落ちず失敗する
    expect(await client.gossip.broadcast(makePacket([9, 9]))).toBe(false);
    expect(stranger.inbox.some(x => x.from === client.identity.peerId && x.type === WireType.GOSSIP)).toBe(false);

    // 信頼 Guard がつながる
    link(client, trusted);
    await sleep(150);
    expect(client.dandelion.getPinnedGuardId()).toBe(trusted.identity.peerId);
    expect(guards.status).toMatchObject({ mode: 'trusted', guardId: trusted.identity.peerId });

    const packet = makePacket([1, 2, 3]);
    expect(await client.gossip.broadcast(packet)).toBe(true);
    await sleep(60);

    expect(exit.received.map(p => p.packet_id)).toContain(packet.packet_id);
    expect(cellsFrom(trusted, client)).toBeGreaterThan(3);
    expect(cellsFrom(stranger, client)).toBe(0);
  });

  it('fallback で動いている最中に信頼 Guard がつながったら、以後のセルは信頼 Guard にだけ出る', async () => {
    const { client, trusted, exit, guards } = await world({ fallbackGraceMs: 150, openSelectionDelayMs: 50 });
    const strangers = await Promise.all([1, 2, 3, 4].map(i => createSimNode(`stranger${i}`)));
    nodes.push(...strangers);
    for (const s of strangers) { link(client, s); link(s, exit); }
    link(trusted, exit);
    startAll([client, trusted, exit]);

    await sleep(400);
    expect(guards.status.mode).toBe('fallback');
    const fallbackId = guards.status.guardId!;
    const fallbackNode = strangers.find(s => s.identity.peerId === fallbackId)!;
    expect(fallbackNode).toBeDefined();
    expect(cellsFrom(fallbackNode, client)).toBeGreaterThan(2);

    link(client, trusted);
    await sleep(150);
    expect(client.dandelion.getPinnedGuardId()).toBe(trusted.identity.peerId);
    expect(guards.status.mode).toBe('trusted');

    const before = strangers.map(s => cellsFrom(s, client));
    const trustedBefore = cellsFrom(trusted, client);
    await sleep(200);
    expect(strangers.map(s => cellsFrom(s, client))).toEqual(before);
    expect(cellsFrom(trusted, client)).toBeGreaterThan(trustedBefore + 3);
  });
});
