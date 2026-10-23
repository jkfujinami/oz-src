import { describe, it, expect } from 'vitest';
import { OnionRouter, MAX_FRAGMENTS } from '../../src/crypto/OnionRouter';
import { encodeExitItem, fragmentCount, splitIntoFragments } from '../../src/crypto/ExitItem';
import { POW_POLICY, effortFor } from '../../src/crypto/PowPolicy';
import { PACKET_FIXED_OVERHEAD, encodePacket } from '../../src/crypto/PacketCodec';
import { buildPost } from '../helpers/postFixtures';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { WireType } from '../../src/network/wire/WireTypes';
import { MAX_FRAME_BYTES } from '../../src/network/PeerManager';

/**
 * セルの容量表 (v5 の成果を数字で固定する)。
 *
 * ★ 数字は OnionRouter.FRAG_DATA_MAX (1 セルに載る item のバイト数) から導く。
 *   オニオンの中継層が縮むと FRAG_DATA_MAX が増えるので、定数を直書きしない。
 * 本文は 'a' を n 個 (1 文字 1 バイト)。日本語は 1 文字 3 バイトなので floor(n / 3) 文字。
 * 条件: 返信・親 2 つ (最悪の構成)。トリップの有無で付帯は変わらない (署名ブロックは常に 96 バイト)。
 */
const FRAG = OnionRouter.FRAG_DATA_MAX;

/** 1 件 (ExitItem) のバイト数 */
async function itemBytes(n: number, trip: boolean, parents = 2): Promise<number> {
  const { packet } = await buildPost({ content: 'a'.repeat(n), trip, parents, pow: 'fake' });
  return encodeExitItem({ type: 'exit_fluff', packet }).length;
}

/** k 枚に収まる本文の最大バイト数 (付帯 = 本文 0 バイトの item の長さから引く。境界は実測で確かめる) */
async function capacity(cells: number, trip: boolean): Promise<number> {
  const overhead = await itemBytes(0, trip);
  const bytes = Math.min(cells * FRAG - overhead, POW_POLICY.MAX_CONTENT_BYTES); // 本文の上限 2048 が先に効く場合がある
  // 境界の確認: ちょうど入り、(上限でなければ) 1 バイト増えると入らない
  expect(await itemBytes(bytes, trip)).toBeLessThanOrEqual(cells * FRAG);
  if (bytes < POW_POLICY.MAX_CONTENT_BYTES) expect(await itemBytes(bytes + 1, trip)).toBeGreaterThan(cells * FRAG);
  return bytes;
}

describe('セルの容量 (1,200 バイトのセル × 最大 3 枚)', () => {
  it('容量表を計測して出力する / 2048 バイトの投稿は (トリップ・親 2 つ付きでも) 3 枚に収まる', async () => {
    const rows: string[] = [];
    rows.push('cells | trip | max bytes | max JP chars');
    const jp: Record<string, number> = {};
    for (const cells of [1, 2, 3]) {
      for (const trip of [false, true]) {
        const bytes = await capacity(cells, trip);
        jp[`${cells}/${trip}`] = Math.floor(bytes / 3);
        rows.push(`${cells}     | ${trip ? 'yes' : 'no '}  | ${String(bytes).padStart(9)} | ${String(Math.floor(bytes / 3)).padStart(12)}`);
      }
    }
    // eslint-disable-next-line no-console
    console.log(`\n[cell capacity] FRAG_DATA_MAX=${FRAG} per cell\n${rows.join('\n')}`);

    // 2048 バイトの本文 + トリップ + 親 2 が 3 枚に収まる (本機能の合格条件)
    const worst = await itemBytes(POW_POLICY.MAX_CONTENT_BYTES, true);
    expect(worst).toBeLessThanOrEqual(MAX_FRAGMENTS * FRAG);
    expect(fragmentCount(worst)).toBe(Math.ceil(worst / FRAG));
    expect(fragmentCount(worst)).toBeLessThanOrEqual(3);
    // トリップの有無で容量は変わらない (署名ブロックが同じ 96 バイトだから)
    for (const cells of [1, 2, 3]) expect(jp[`${cells}/true`]).toBe(jp[`${cells}/false`]);
  });

  it('最大の正規フレーム (本文 2048 バイト + トリップ + 親 2) は、受信側のフレーム長の上限に収まる', async () => {
    // ★ 上限 (PeerManager.MAX_FRAME_BYTES) を締めたので、正規の最大投稿を落とさないことを固定する
    const { packet } = await buildPost({ content: 'a'.repeat(POW_POLICY.MAX_CONTENT_BYTES), trip: true, parents: 2, pow: 'fake' });
    const gossip = WireCodec.encode(WireType.GOSSIP, { packet }).length;
    const stem = WireCodec.encode(WireType.STEM, { item: { type: 'exit_fluff', packet } }).length;
    const cell = WireCodec.encode(WireType.ONION_STEM, { onionBytes: new Uint8Array(OnionRouter.CELL_SIZE) }).length;
    // eslint-disable-next-line no-console
    console.log(`[max frames] GOSSIP=${gossip}/${MAX_FRAME_BYTES[WireType.GOSSIP]} STEM=${stem}/${MAX_FRAME_BYTES[WireType.STEM]} ONION_STEM=${cell}/${MAX_FRAME_BYTES[WireType.ONION_STEM]}`);
    expect(gossip).toBeLessThanOrEqual(MAX_FRAME_BYTES[WireType.GOSSIP]!);
    expect(stem).toBeLessThanOrEqual(MAX_FRAME_BYTES[WireType.STEM]!);
    expect(cell).toBeLessThanOrEqual(MAX_FRAME_BYTES[WireType.ONION_STEM]!);
  });

  it('★オーバーヘッド: 返信 (親 2) の付帯は 173 バイト、item (kind 1B) で 174 (旧: 約 270 / トリップ有り約 360)', async () => {
    const trip = await itemBytes(0, true);
    const noTrip = await itemBytes(0, false);
    // eslint-disable-next-line no-console
    console.log(`[overhead] item(kind 1B) with 2 parents: trip ${trip} B / no trip ${noTrip} B`);
    expect(trip).toBe(1 + 173);
    expect(noTrip).toBe(1 + 173);
    // 親 1 つ・トリップ有りの空の投稿 (旧形式の実測: 935 バイト、v1 のコンパクト形式: 約 330)
    expect(await itemBytes(0, true, 1)).toBe(1 + 157);
    expect(await itemBytes(0, true, 0)).toBe(1 + 141);
  });

  it('最大の投稿でも断片は 3 枚以内で、1 枚でも超える item は分割できない (null)', async () => {
    const { packet } = await buildPost({ content: 'a'.repeat(2048), trip: true, parents: 2, pow: 'fake' });
    const bytes = encodeExitItem({ type: 'exit_fluff', packet });
    const frags = splitIntoFragments(bytes, new Uint8Array(8))!;
    expect(frags.length).toBe(fragmentCount(bytes.length));
    expect(frags.length).toBeLessThanOrEqual(3);
    expect(frags.every(f => f.total === frags.length)).toBe(true);
    expect(splitIntoFragments(new Uint8Array(3 * FRAG), new Uint8Array(8))).not.toBeNull();
    expect(splitIntoFragments(new Uint8Array(3 * FRAG + 1), new Uint8Array(8))).toBeNull();
  });

  it('MAX_PAYLOAD_SIZE は「2048 バイト + 親 2 + 最長の thread_id (スレ立て) + 署名ブロック」ちょうどで、それより大きい投稿は作れない', async () => {
    const reply = await buildPost({ content: 'a'.repeat(2048), trip: true, parents: 2, pow: 'fake' });
    // 返信は thread_id (最長 1 + 32 バイト) が載らない分だけ小さい
    expect(reply.packet.payload.length).toBe(POW_POLICY.MAX_PAYLOAD_SIZE - 33);
    const meta = await buildPost({ content: 'a'.repeat(2048), trip: true, parents: 2, postType: 1, threadId: 't'.repeat(32), pow: 'fake' });
    expect(meta.packet.payload.length).toBe(POW_POLICY.MAX_PAYLOAD_SIZE);
    expect(encodePacket(meta.packet).length).toBe(PACKET_FIXED_OVERHEAD + meta.packet.payload.length);
    // 付帯の内訳が定数とそろっている
    expect(POW_POLICY.MAX_PAYLOAD_SIZE).toBe(POW_POLICY.SIV_BYTES + 1 + 33 + 2 * POW_POLICY.PACKET_ID_BYTES + 96 + POW_POLICY.MAX_CONTENT_BYTES);
  });

  it('長い投稿ほど多く払う: 最低 effort は 1000 バイト (1 セル) ごとに 1 ずつ増え、作者は最小の量子化値を選ぶ', async () => {
    const small = await buildPost({ content: 'a'.repeat(100), pow: 'fake' });
    const big = await buildPost({ content: 'a'.repeat(2048), parents: 2, trip: true, pow: 'fake' });
    expect(small.packet.effort_exp).toBe(effortFor(encodePacket(small.packet).length).exp);
    expect(small.packet.effort_exp).toBe(0);
    expect(big.packet.effort_exp).toBe(effortFor(encodePacket(big.packet).length).exp);
    expect(big.packet.effort_exp).toBeGreaterThan(0);
  });
});
