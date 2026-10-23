import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { WireType } from '../../src/network/wire/WireTypes';
import { createSimNode, link, startAll, stopAll, sleep, makePacket, type SimNode } from '../helpers/onionNet';

/**
 * 作者は、回路が使えないときに平文で何かを送ってはならない (C3 / C4)。
 */
describe('作者の発信は Fail-Closed (平文の GOSSIP / Stem を出さない)', () => {
  let nodes: SimNode[] = [];

  beforeAll(async () => {
    await sodiumReady;
  });
  afterEach(() => stopAll(nodes));

  const PLAINTEXT_TYPES = [WireType.GOSSIP, WireType.STEM];

  it('Guard が全セルを捨てても、投稿は平文では出ない', async () => {
    const author = await createSimNode('author');
    const guard = await createSimNode('guard');
    const other = await createSimNode('other');
    nodes = [author, guard, other];
    link(author, guard);
    link(guard, other);
    (guard.dispatcher as any).handlers.set(WireType.ONION_STEM, new Set());
    startAll(nodes);
    await sleep(60);

    expect(await author.gossip.broadcast(makePacket([3]))).toBe(false);

    const fromAuthor = guard.inbox.filter(m => m.from === author.identity.peerId);
    expect(fromAuthor.filter(m => PLAINTEXT_TYPES.includes(m.type))).toHaveLength(0);
  });

  it('回路が止まっている (起動前) なら送信を拒否する', async () => {
    const a = await createSimNode('a');
    const b = await createSimNode('b');
    nodes = [a, b];
    link(a, b);
    expect(await a.gossip.broadcast(makePacket([4]))).toBe(false);
    expect(b.inbox).toHaveLength(0);
  });
});
