import { describe, it, expect, beforeAll } from 'vitest';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import {
  OnionRouter, SEALED_EXIT_LAYER_SIZE, RELAY_LAYER_OVERHEAD, FRAG_ID_BYTES, MAX_FRAGMENTS,
  type ExitPayload, type OnionHop,
} from '../../src/crypto/OnionRouter';

type Frag = Extract<ExitPayload, { type: 'frag' }>;

describe('OnionRouter (2 層オニオン・固定長セル・断片)', () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  function createMockNode(name: string) {
    const kp = sodium.crypto_sign_keypair();
    return {
      name,
      peerId: Buffer.from(sodium.randombytes_buf(16)).toString('hex'),
      pubkey: kp.publicKey,
      privkey: kp.privateKey,
    };
  }

  const frag = (len: number, idx = 0, total = 1): Frag => ({
    type: 'frag', id: new Uint8Array(FRAG_ID_BYTES).fill(7), idx, total, data: new Uint8Array(len).fill(0x5a),
  });

  it('セルは 1,200 バイト、出口層は 2 層セルがちょうど収まる長さから導出される', () => {
    expect(OnionRouter.CELL_SIZE).toBe(1200);
    // 1200 - ヘッダ 4 - seal 48 - 中継層の付加 17 - seal 48
    expect(OnionRouter.EXIT_LAYER_SIZE).toBe(1083);
    expect(SEALED_EXIT_LAYER_SIZE).toBe(1083 + 48);
  });

  it('中継層の付加バイト数 (kind 1 + peerId 16 = 17) は実測と一致し、最外殻にパディングが入らない', () => {
    const guard = createMockNode('guar');
    const m1 = createMockNode('m1');
    expect(RELAY_LAYER_OVERHEAD).toBe(17);
    // Guard が剥いた中継層の平文 = kind ‖ 次ホップ (生の 16 バイト) ‖ 封印された出口層
    const probe = OnionRouter.wrapCircuit({ type: 'drop' }, [
      { peerId: guard.peerId, pubkey: guard.pubkey },
      { peerId: m1.peerId, pubkey: m1.pubkey },
    ]);
    const relayPlain = sodium.crypto_box_seal_open(
      OnionRouter.unpadCell(probe)!, OnionRouter.toCurvePublicKey(guard.pubkey), OnionRouter.toCurvePrivateKey(guard.privkey),
    );
    expect(relayPlain.length - SEALED_EXIT_LAYER_SIZE).toBe(RELAY_LAYER_OVERHEAD);
    expect(relayPlain[0]).toBe(1);
    expect(Buffer.from(relayPlain.subarray(1, 17)).toString('hex')).toBe(m1.peerId);

    // セルの実データ長 = CELL_SIZE - 4 (= 隙間なし)
    const cell = OnionRouter.wrapCircuit(frag(10), [
      { peerId: guard.peerId, pubkey: guard.pubkey },
      { peerId: m1.peerId, pubkey: m1.pubkey },
    ]);
    expect(cell.length).toBe(OnionRouter.CELL_SIZE);
    const len = (cell[2] << 8) | cell[3];
    expect(len).toBe(OnionRouter.CELL_SIZE - 4);
  });

  it('断片 1 枚の最大データ (FRAG_DATA_MAX) は出口層にちょうど収まる', () => {
    // [FRAG u8][id 8][idx u8][total u8][data] + padCell ヘッダ 4 = EXIT_LAYER_SIZE
    expect(1 + FRAG_ID_BYTES + 1 + 1 + OnionRouter.FRAG_DATA_MAX).toBe(OnionRouter.EXIT_LAYER_SIZE - 4);
    expect(OnionRouter.FRAG_DATA_MAX).toBe(1068);
    const node = createMockNode('node');
    const hops = [{ peerId: node.peerId, pubkey: node.pubkey }, { peerId: createMockNode('m').peerId, pubkey: node.pubkey }];
    expect(() => OnionRouter.wrapCircuit(frag(OnionRouter.FRAG_DATA_MAX), hops)).not.toThrow();
    expect(() => OnionRouter.wrapCircuit(frag(OnionRouter.FRAG_DATA_MAX + 1), hops)).toThrow(/exceeds cell capacity/);
  });

  it('2 ホップ (Guard -> M1) のラップと段階的な復号: 断片が M1 で現れる', () => {
    const guard = createMockNode('guar');
    const m1 = createMockNode('m1');
    const hops: OnionHop[] = [
      { peerId: guard.peerId, pubkey: guard.pubkey },
      { peerId: m1.peerId, pubkey: m1.pubkey },
    ];
    const f = frag(OnionRouter.FRAG_DATA_MAX, 1, 3);
    const outer = OnionRouter.wrapCircuit(f, hops);

    const hop1 = OnionRouter.unwrap(outer, guard.pubkey, guard.privkey);
    expect(hop1?.type).toBe('relay');
    if (hop1?.type !== 'relay') return;
    expect(hop1.nextHop).toBe(m1.peerId);

    // Guard が M1 の鍵で復号しようとしても読めない
    expect(OnionRouter.unwrap(outer, m1.pubkey, m1.privkey)).toBeNull();

    const hop2 = OnionRouter.unwrap(OnionRouter.padCell(hop1.innerOnion), m1.pubkey, m1.privkey);
    expect(hop2?.type).toBe('frag');
    if (hop2?.type !== 'frag') return;
    expect(hop2.idx).toBe(1);
    expect(hop2.total).toBe(3);
    expect(Array.from(hop2.id)).toEqual(Array.from(f.id));
    expect(Array.from(hop2.data)).toEqual(Array.from(f.data));
  });

  it('不正な鍵や改ざんされたオニオンデータは安全に拒否 (null 返却) される', () => {
    const nodeA = createMockNode('node');
    const nodeB = createMockNode('badk');
    const onion = OnionRouter.wrapCircuit(frag(20), [{ peerId: nodeA.peerId, pubkey: nodeA.pubkey }]);
    expect(OnionRouter.unwrap(onion, nodeA.pubkey, nodeB.privkey)).toBeNull();
    const corrupted = new Uint8Array(onion);
    corrupted[10] ^= 0xff;
    expect(OnionRouter.unwrap(corrupted, nodeA.pubkey, nodeA.privkey)).toBeNull();
  });

  it('固定長セル以外 (生の暗号文・長さ違い) は受け付けない', () => {
    const node = createMockNode('node');
    const onion = OnionRouter.wrapCircuit(frag(20), [{ peerId: node.peerId, pubkey: node.pubkey }]);
    const raw = OnionRouter.unpadCell(onion)!;
    expect(OnionRouter.unwrap(raw, node.pubkey, node.privkey)).toBeNull();
    expect(OnionRouter.unwrap(onion.subarray(0, onion.length - 1), node.pubkey, node.privkey)).toBeNull();
  });

  it('出口層は固定長: drop・短い断片・最大の断片で Guard に見える長さが同じ', () => {
    const guard = createMockNode('guar');
    const exit = createMockNode('exit');
    const hops: OnionHop[] = [
      { peerId: guard.peerId, pubkey: guard.pubkey },
      { peerId: exit.peerId, pubkey: exit.pubkey },
    ];
    const cells = [
      OnionRouter.wrapCircuit({ type: 'drop' }, hops),
      OnionRouter.wrapCircuit(frag(1), hops),
      OnionRouter.wrapCircuit(frag(OnionRouter.FRAG_DATA_MAX), hops),
    ];
    const views = cells.map(c => OnionRouter.unwrap(c, guard.pubkey, guard.privkey));
    for (const v of views) {
      expect(v?.type).toBe('relay');
      if (v?.type === 'relay') expect(v.innerOnion.byteLength).toBe(SEALED_EXIT_LAYER_SIZE);
    }
    const types = views.map(v => OnionRouter.unwrap(OnionRouter.padCell((v as any).innerOnion), exit.pubkey, exit.privkey)?.type);
    expect(types).toEqual(['drop', 'frag', 'frag']);
  });

  /** 出口層の平文 (padCell 済み) を直接封印して、受信側の形式検査だけを確かめる */
  function sealedExit(node: ReturnType<typeof createMockNode>, plain: Uint8Array) {
    const padded = OnionRouter.padCell(plain, OnionRouter.EXIT_LAYER_SIZE);
    const sealed = sodium.crypto_box_seal(padded, OnionRouter.toCurvePublicKey(node.pubkey));
    return OnionRouter.unwrap(OnionRouter.padCell(sealed), node.pubkey, node.privkey);
  }
  const fragBytes = (kind: number, id: Uint8Array, idx: number, total: number, data: Uint8Array) =>
    Uint8Array.from([kind, ...id, idx, total, ...data]);

  it('不正な断片 (total > 3・idx >= total・id 長・データ長・kind・余り) は拒否する', () => {
    const node = createMockNode('node');
    const id = new Uint8Array(FRAG_ID_BYTES);
    const data = new Uint8Array(5);
    expect(sealedExit(node, fragBytes(2, id, 0, 1, data))?.type).toBe('frag');
    expect(sealedExit(node, fragBytes(2, id, 0, MAX_FRAGMENTS + 1, data))).toBeNull();
    expect(sealedExit(node, fragBytes(2, id, 0, 0, data))).toBeNull();
    expect(sealedExit(node, fragBytes(2, id, 3, 3, data))).toBeNull();
    expect(sealedExit(node, fragBytes(2, new Uint8Array(7), 0, 1, data))).toBeNull(); // id が短い分データがずれて total が不正になる
    expect(sealedExit(node, fragBytes(2, id, 0, 1, new Uint8Array(0)))).toBeNull();
    expect(sealedExit(node, fragBytes(9, id, 0, 1, data))).toBeNull();
    expect(sealedExit(node, Uint8Array.of(2, 1, 2, 3))).toBeNull(); // 断片のヘッダに満たない
    expect(sealedExit(node, new Uint8Array(0))).toBeNull();
  });

  it('drop は 1 バイトだけ。余りがあれば拒否する', () => {
    const node = createMockNode('node');
    expect(sealedExit(node, Uint8Array.of(3))?.type).toBe('drop');
    expect(sealedExit(node, Uint8Array.of(3, 0))).toBeNull();
  });

  it('出口層に中継層を入れ子にして M1 に転送させることはできない', () => {
    const node = createMockNode('node');
    const relay = Uint8Array.from([1, ...Buffer.from(createMockNode('x').peerId, 'hex'), 9, 9, 9]);
    expect(sealedExit(node, relay)).toBeNull();
  });

  it('不正な中継層 (kind 違い・宛先が欠けている・内側が空) は拒否する', () => {
    const node = createMockNode('node');
    const open = (plain: Uint8Array) => {
      const sealed = sodium.crypto_box_seal(plain, OnionRouter.toCurvePublicKey(node.pubkey));
      return OnionRouter.unwrap(OnionRouter.padCell(sealed), node.pubkey, node.privkey);
    };
    const hop = Buffer.from(createMockNode('x').peerId, 'hex');
    const relay = (kind: number, inner: number) => Uint8Array.from([kind, ...hop, ...new Uint8Array(inner)]);
    expect(open(relay(1, 100))?.type).toBe('relay');
    expect(open(relay(7, 100))).toBeNull();
    expect(open(relay(1, 0))).toBeNull();
    expect(open(Uint8Array.of(1, 1, 2, 3))).toBeNull();
  });

  it('3 層はセルに収まらない (回路は 2 層 [Guard, M1] 固定)', () => {
    const nodes = [createMockNode('a'), createMockNode('b'), createMockNode('c')];
    expect(() => OnionRouter.wrapCircuit(frag(1), nodes.map(n => ({ peerId: n.peerId, pubkey: n.pubkey })))).toThrow(/exceeds cell capacity/);
  });

  it('relay 層の宛先が peerId 形式でなければ組み立てを拒否する', () => {
    const node = createMockNode('node');
    for (const bad of ['not-a-peer-id', 'A'.repeat(32), 'a'.repeat(31), 'a'.repeat(34)]) {
      expect(() => OnionRouter.wrapCircuit({ type: 'drop' }, [
        { peerId: node.peerId, pubkey: node.pubkey },
        { peerId: bad, pubkey: node.pubkey },
      ])).toThrow(RangeError);
    }
  });

  it('旧 msgpack 形式の層は読めない (互換なし)', () => {
    const node = createMockNode('node');
    const legacy = new Uint8Array(OnionRouter.EXIT_LAYER_SIZE); // 0x00 埋め = マジックなし
    const sealed = sodium.crypto_box_seal(legacy, OnionRouter.toCurvePublicKey(node.pubkey));
    expect(OnionRouter.unwrap(OnionRouter.padCell(sealed), node.pubkey, node.privkey)).toBeNull();
  });
});
