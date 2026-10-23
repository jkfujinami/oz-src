/**
 * プロトコル適合ベクタ (golden vectors) の「入力」と「組み立て手順」。
 *
 * ★ これはテストファイルではない。
 *   - generateVectors.ts がこれを呼んで vectors/core_protocol_vectors.json を書き出す
 *   - ProtocolConformance.test.ts がこれを呼び直し、保存済みのバイト列と突き合わせる
 *
 * 入力はすべて固定値。乱数を使う箇所 (AEAD の nonce、セルのパディング) は
 * {@link withDeterministicRandom} で sodium.randombytes_buf を一時的に決定的な
 * 鍵ストリームへ差し替える。crypto_box_seal (オニオンの封印) は WASM 内部の
 * 乱数を使うので決定化できない。オニオンのセルは「保存したバイト列を復号できるか」
 * と構造 (長さ・マジック) だけで縛る。
 */
import { encode as msgpackEncode } from '@msgpack/msgpack';
import sodium from '../../src/crypto/sodium';
import { WireCodec } from '../../src/network/wire/WireCodec';
import { WireType } from '../../src/network/wire/WireTypes';
import {
  POW_POLICY,
  PACKET_VERSION,
  OZ_EPOCH_MS,
  POW_DOMAIN,
  ID_DOMAIN,
  powSeed,
  derivePacketId,
  solvePow,
  msToMinutes,
  type PowCommitted,
  type PowSolution,
} from '../../src/crypto/PowPolicy';
import { makeThreadId } from '../../src/logic/ThreadLimits';
import {
  NodeIdentity,
  NODE_ID_POW,
  NODE_ID_POW_FAST,
  PEER_ID_BYTES,
  CHALLENGE_BYTES,
  joinMessage,
  trackerJoinMessage,
  type JoinBinding,
  type NodeIdPowParams,
} from '../../src/crypto/NodeIdentity';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import { OnionRouter, SEALED_EXIT_LAYER_SIZE, RELAY_LAYER_OVERHEAD, MAX_FRAGMENTS, FRAG_ID_BYTES } from '../../src/crypto/OnionRouter';
import { encodePacket } from '../../src/crypto/PacketCodec';
import { encodeExitItem } from '../../src/crypto/ExitItem';
import { RATE_LIMITS } from '../../src/network/RateLimiter';
import { signLeaseSet } from '../../src/network/storage/LeaseSet';
import {
  TRACKER_PROTOCOL_VERSION,
  TRACKER_MAX_FRAME_BYTES,
  TRACKER_MAX_PEERS,
  TRACKER_FRAME_LIMITS,
  TRACKER_ERROR_CODES,
  encodeTrackerClientMessage,
  encodeTrackerServerMessage,
} from '../../src/network/TrackerProtocol';
import { SeenCache } from '../../src/network/gossip/SeenCache';
import { RING_MESH } from '../../src/constants';
import type { GossipPacket, IIdentity } from '../../src/types';

// ───────────────────────── 小道具 ─────────────────────────

export const toHex = (b: Uint8Array): string => sodium.to_hex(b);
export const fromHex = (h: string): Uint8Array => sodium.from_hex(h);
const ascii = (b: Uint8Array): string => new TextDecoder().decode(b);
const sha256Hex = (b: Uint8Array): string => toHex(sodium.crypto_hash_sha256(b));

/** 固定シードから作る Ed25519 鍵ペア */
export function seededKeyPair(byte: number) {
  return sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(byte));
}

/**
 * sodium.randombytes_buf を決定的な鍵ストリームに差し替えて fn を実行する。
 * 呼び出し回数ごとに nonce を変えるので、同じ長さを 2 回取っても別の値になる。
 */
export async function withDeterministicRandom<T>(label: string, fn: () => T | Promise<T>): Promise<T> {
  const original = sodium.randombytes_buf;
  const key = sodium.crypto_hash_sha256(new TextEncoder().encode(`oz-golden-rng/${label}`));
  let call = 0;
  (sodium as any).randombytes_buf = (n: number) => {
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setUint32(8, call++, false);
    return sodium.crypto_stream_chacha20_ietf_xor_ic(new Uint8Array(n), nonce, 0, key);
  };
  try {
    return await fn();
  } finally {
    (sodium as any).randombytes_buf = original;
  }
}

/** Date.now を固定して fn を実行する (PacketBuilder がヘッダ時刻に使う) */
export async function withFixedNow<T>(ms: number, fn: () => T | Promise<T>): Promise<T> {
  const original = Date.now;
  Date.now = () => ms;
  try {
    return await fn();
  } finally {
    Date.now = original;
  }
}

// ───────────────────────── 固定入力 ─────────────────────────

export const INPUTS = {
  /** PacketBuilder が分単位に丸めることを確かめるため、端数を持たせる */
  nowMs: 1_791_981_296_789, // 2026-10-14T12:34:56.789Z
  boardKeyByte: 0x42,
  /** スレ立て日 (2026-10-12) を埋め込んだ新形式の ID。投稿の age は 2 日になる */
  threadId: makeThreadId(Date.UTC(2026, 9, 12), 'goldenab01'),
  boardId: 'golden-board',
  nodeSeedByte: 0x11, // web/tests/vectors と同じ鍵 (peerId 9bf361b6...)
  verifierSeedByte: 0x22,
  relaySeedByte: 0x33,
  exitSeedByte: 0x44,
  sessionSeedByte: 0x5e,
  tripSeedByte: 0x7f,
  /** NodeId PoW の小さなパラメータ (Argon2id 8KiB, 1 pass) */
  tinyPow: { difficulty: 0, opsLimit: 1, memLimit: 8192 } as NodeIdPowParams,
  challenge: Uint8Array.from({ length: 32 }, (_, i) => (i * 3) & 0xff),
  signerFingerprint: 'sha-256 ' + Array.from({ length: 32 }, (_, i) => ((i * 7 + 1) & 0xff).toString(16).padStart(2, '0').toUpperCase()).join(':'),
  verifierFingerprint: 'sha-256 ' + Array.from({ length: 32 }, (_, i) => ((i * 11 + 5) & 0xff).toString(16).padStart(2, '0').toUpperCase()).join(':'),
  /** 外側ヘッダ (version | time | tag | age | e) とペイロード。PoW の解と packet_id を固定する */
  gossipHeader: {
    version: PACKET_VERSION,
    time: msToMinutes(Date.UTC(2026, 9, 14, 12, 0)),
    tag: 0x0abc,
    age: 2,
    effort_exp: 4, // effort 2
    payload: Uint8Array.from({ length: 150 }, (_, i) => (i * 13 + 7) & 0xff),
  } satisfies PowCommitted,
  aeadPlaintext: new TextEncoder().encode('OZ golden SIV plaintext'),
  /** SIV の AAD (version | time | tag | age) の見本 */
  aeadAad: Uint8Array.of(2, 0x12, 0x34, 0x56, 0x0a, 0xbc, 0x02),
  post: {
    content: 'ゴールデンベクタの投稿 / golden post',
    postType: 0,
    parents: ['aa'.repeat(16), 'bb'.repeat(16)],
  },
  /** 断片のデータ (中身は何でもよい。断片の形と封印だけを縛る) */
  onionFragData: Uint8Array.from({ length: 40 }, (_, i) => i),
  /** CATCHUP_REQ の since / CATCHUP_END の nextSince (OZ_EPOCH からの分) */
  catchupSince: 0x0abcde,
  catchupNextSince: 0x0abcf0,
  /** leaseSet の固定入力: SID の seed、枠 2 つ (PoW は解かない。ワイヤの形だけを縛る)、受け口、tunnelId、期限 */
  leaseSetSeedByte: 0x71,
  leaseSetExpiresMin: 0x0abd00,
  /** TUNNEL_* の reqId / returnTag (u32) */
  tunnelReqId: 0xa1b2c3d4,
  tunnelTag: 0x0f1e2d3c,
  trackerNonce: Uint8Array.from({ length: 32 }, (_, i) => (0x80 + i * 5) & 0xff),
  /** 大文字混じりで渡し、署名側で小文字に正規化されることも固定する */
  trackerHost: 'Tracker.Example.org:8443',
} as const;

export function boardKey(): Uint8Array {
  return new Uint8Array(32).fill(INPUTS.boardKeyByte);
}

export function joinBinding(): JoinBinding {
  return {
    verifierId: NodeIdentity.derivePeerId(seededKeyPair(INPUTS.verifierSeedByte).publicKey),
    signerFingerprint: INPUTS.signerFingerprint,
    verifierFingerprint: INPUTS.verifierFingerprint,
  };
}

/** 決定的な IIdentity (セッション鍵・トリップ鍵ともに固定シード)。withTrip なら署名ブロックはトリップだけ */
export function seededIdentity(withTrip = true): IIdentity {
  const session = seededKeyPair(INPUTS.sessionSeedByte);
  const trip = seededKeyPair(INPUTS.tripSeedByte);
  return {
    hasTrip: withTrip,
    sign: (data: Uint8Array) => ({
      sessionPubkey: session.publicKey,
      sessionSignature: sodium.crypto_sign_detached(data, session.privateKey),
      tripPubkey: withTrip ? trip.publicKey : null,
      tripSignature: withTrip ? sodium.crypto_sign_detached(data, trip.privateKey) : null,
    }),
  };
}

export const syncPowEngine = {
  compute: async (h: PowCommitted): Promise<PowSolution> => {
    const sol = solvePow(h);
    if (sol === null) throw new Error('PoW not found');
    return sol;
  },
};

/** GossipPacket を hex 表現にする (JSON 保存用) */
export function packetToJson(p: GossipPacket) {
  return {
    packet_id: p.packet_id,
    timestamp: p.timestamp,
    tag: p.tag,
    age: p.age,
    effort_exp: p.effort_exp,
    pow_nonce: p.pow_nonce,
    pow_solution: toHex(p.pow_solution),
    payload: toHex(p.payload),
  };
}

export function packetFromJson(j: ReturnType<typeof packetToJson>): GossipPacket {
  return { ...j, pow_solution: fromHex(j.pow_solution), payload: fromHex(j.payload) };
}

// ───────────────────────── セクション別の組み立て ─────────────────────────

export function buildConstants() {
  const wireTypes: Record<string, number> = {};
  for (const [name, value] of Object.entries(WireType)) {
    if (typeof value === 'number') wireTypes[name] = value;
  }
  const emptyCell = OnionRouter.padCell(new Uint8Array(0));
  return {
    wireTypes,
    onion: {
      CELL_SIZE: OnionRouter.CELL_SIZE,
      EXIT_LAYER_SIZE: OnionRouter.EXIT_LAYER_SIZE,
      FRAG_DATA_MAX: OnionRouter.FRAG_DATA_MAX,
      RELAY_LAYER_OVERHEAD,
      MAX_FRAGMENTS,
      FRAG_ID_BYTES,
      SEALED_EXIT_LAYER_SIZE,
      cellMagic: toHex(emptyCell.subarray(0, 2)),
    },
    powPolicy: { ...POW_POLICY },
    packetVersion: PACKET_VERSION,
    epochMs: OZ_EPOCH_MS,
    powDomain: ascii(POW_DOMAIN),
    idDomain: ascii(ID_DOMAIN),
    postSignedDomain: 'OZ/v5/post',
    sivLabels: { enc: 'oz/v5/enc', mac: 'oz/v5/mac' },
    tagLabels: { board: 'oz/v5/board-tag', thread: 'oz/v5/thread-tag' },
    nodeIdentity: {
      PEER_ID_BYTES,
      CHALLENGE_BYTES,
      NODE_ID_POW: { ...NODE_ID_POW },
      NODE_ID_POW_FAST: { ...NODE_ID_POW_FAST },
    },
    ringMesh: { ...RING_MESH },
    rateLimits: JSON.parse(JSON.stringify(RATE_LIMITS)) as Record<string, { ratePerSec: number; burst: number }>,
    seenCacheTtlMs: SeenCache.TTL_MS,
  };
}

export function buildKeyManagerSection() {
  const threadKey = KeyManager.deriveThreadKey(boardKey(), INPUTS.threadId);
  return {
    boardKey: toHex(boardKey()),
    threadId: INPUTS.threadId,
    threadKey: toHex(threadKey),
  };
}

export function buildNodeIdentitySection() {
  const kp = seededKeyPair(INPUTS.nodeSeedByte);
  const peerId = NodeIdentity.derivePeerId(kp.publicKey);
  const counter = NodeIdentity.solveNodeIdPow(kp.publicKey, NODE_ID_POW_FAST);
  return {
    seed: toHex(new Uint8Array(32).fill(INPUTS.nodeSeedByte)),
    pubkey: toHex(kp.publicKey),
    peerId,
    position: NodeIdentity.derivePosition(peerId),
    nodeIdPowFast: {
      params: { ...NODE_ID_POW_FAST },
      counter,
      hashAtCounter0: toHex(NodeIdentity.nodeIdPowHash(kp.publicKey, 0, NODE_ID_POW_FAST)),
      hashAtSolvedCounter: toHex(NodeIdentity.nodeIdPowHash(kp.publicKey, counter, NODE_ID_POW_FAST)),
    },
    nodeIdPowTiny: {
      params: { ...INPUTS.tinyPow },
      hashAtCounter0: toHex(NodeIdentity.nodeIdPowHash(kp.publicKey, 0, INPUTS.tinyPow)),
    },
  };
}

export function buildJoinSection() {
  const kp = seededKeyPair(INPUTS.nodeSeedByte);
  const counter = NodeIdentity.solveNodeIdPow(kp.publicKey, NODE_ID_POW_FAST);
  const identity = NodeIdentity.fromKeyPair(kp.publicKey, kp.privateKey, counter);
  const binding = joinBinding();
  const claim = identity.signClaim(new Uint8Array(INPUTS.challenge), binding);
  return {
    domain: 'OZ/v4/join',
    challenge: toHex(INPUTS.challenge),
    signerId: identity.peerId,
    binding: { ...binding },
    message: toHex(joinMessage(new Uint8Array(INPUTS.challenge), identity.peerId, binding)),
    signature: toHex(claim.signature),
    powCounter: claim.powCounter,
  };
}

/** トラッカー登録 (v3) の署名対象・署名・バイナリフレーム */
export function buildTrackerSection() {
  const kp = seededKeyPair(INPUTS.nodeSeedByte);
  const counter = NodeIdentity.solveNodeIdPow(kp.publicKey, NODE_ID_POW_FAST);
  const identity = NodeIdentity.fromKeyPair(kp.publicKey, kp.privateKey, counter);
  const nonce = new Uint8Array(INPUTS.trackerNonce);
  return {
    domain: 'OZ/v1/tracker-join',
    protocolVersion: TRACKER_PROTOCOL_VERSION,
    maxFrameBytes: TRACKER_MAX_FRAME_BYTES,
    maxPeers: TRACKER_MAX_PEERS,
    nonce: toHex(nonce),
    peerId: identity.peerId,
    host: INPUTS.trackerHost,
    message: toHex(trackerJoinMessage(nonce, identity.peerId, INPUTS.trackerHost)),
    signature: toHex(identity.signTrackerJoin(nonce, INPUTS.trackerHost)),
    powCounter: counter,
    errorCodes: [...TRACKER_ERROR_CODES],
    frameLimits: { ...TRACKER_FRAME_LIMITS },
    frames: {
      hello: toHex(encodeTrackerServerMessage({ type: 'hello', v: TRACKER_PROTOCOL_VERSION, nonce })),
      join: toHex(encodeTrackerClientMessage({
        type: 'join',
        v: TRACKER_PROTOCOL_VERSION,
        peerId: identity.peerId,
        pubkey: identity.pubkey,
        powCounter: counter,
        host: INPUTS.trackerHost.toLowerCase(),
        sig: identity.signTrackerJoin(nonce, INPUTS.trackerHost),
      })),
      peers: toHex(encodeTrackerServerMessage({ type: 'peers', peers: [{ peerId: identity.peerId }, { peerId: '00112233445566778899aabbccddeeff' }] })),
      error: toHex(encodeTrackerServerMessage({ type: 'error', code: 'bad-signature' })),
      relaySdp: toHex(encodeTrackerClientMessage({
        type: 'relay',
        targetPeerId: identity.peerId,
        payload: { sdp: { type: 'offer', sdp: 'v=0\r\n' } },
      })),
      relayIce: toHex(encodeTrackerServerMessage({
        type: 'relay',
        senderId: identity.peerId,
        payload: { candidate: { candidate: 'candidate:1 1 udp 1 192.0.2.1 9 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: null } },
      })),
    },
  };
}

export function buildGossipPowSection() {
  const header = INPUTS.gossipHeader;
  const seed = powSeed(header);
  const solved = solvePow(header)!;
  return {
    header: {
      version: header.version,
      time: header.time,
      tag: header.tag,
      age: header.age,
      effort_exp: header.effort_exp,
      payload: toHex(header.payload),
    },
    /** C = BLAKE2b-256("OZ/v5/pow" ‖ version ‖ time ‖ tag ‖ age ‖ e ‖ SHA-256(payload)) */
    seed: toHex(seed),
    packetId: derivePacketId(header),
    solvedNonce: solved.nonce,
    solution: toHex(solved.solution),
  };
}

export async function buildCryptoEngineSection() {
  const threadKey = KeyManager.deriveThreadKey(boardKey(), INPUTS.threadId);
  const payload = CryptoEngine.encrypt(threadKey, new Uint8Array(INPUTS.aeadPlaintext), INPUTS.aeadAad);
  return {
    threadKey: toHex(threadKey),
    plaintext: toHex(INPUTS.aeadPlaintext),
    aad: toHex(INPUTS.aeadAad),
    /** siv 16 ‖ 暗号文 (決定的。乱数を使わない) */
    payload: toHex(payload),
  };
}

export async function buildPacketBuilderSection() {
  const threadKey = KeyManager.deriveThreadKey(boardKey(), INPUTS.threadId);
  const p = INPUTS.post;
  const build = (withTrip: boolean) => withFixedNow(INPUTS.nowMs, () =>
    PacketBuilder.build({
      content: p.content, key: threadKey, identity: seededIdentity(withTrip), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: INPUTS.boardId, threadId: INPUTS.threadId,
      postType: p.postType, parents: [...p.parents],
    }),
  );
  const packet = await build(true);
  const sessionPacket = await build(false);
  // スレ立て (板の鍵で暗号化。tag は板の日替わりの値)
  const boardKeyBytes = boardKey();
  const meta = await withFixedNow(INPUTS.nowMs, () =>
    PacketBuilder.build({
      content: 'ゴールデンなスレタイ', key: boardKeyBytes, identity: seededIdentity(true), cryptoEngine: new CryptoEngine(),
      powEngine: syncPowEngine, boardId: INPUTS.boardId, threadId: INPUTS.threadId, postType: 1,
    }),
  );
  return {
    nowMs: INPUTS.nowMs,
    threadKey: toHex(threadKey),
    boardKey: toHex(boardKeyBytes),
    sessionPubkey: toHex(seededKeyPair(INPUTS.sessionSeedByte).publicKey),
    tripPubkey: toHex(seededKeyPair(INPUTS.tripSeedByte).publicKey),
    packet: packetToJson(packet),
    /** PacketCodec のバイト列 (ワイヤ・保存・追いつきで共通) */
    encodedPacket: toHex(encodePacket(packet)),
    /** トリップ無しの返信 (署名ブロックはセッション鍵) */
    sessionPacket: packetToJson(sessionPacket),
    encodedSessionPacket: toHex(encodePacket(sessionPacket)),
    /** スレ立て (post_type 1) */
    metaPacket: packetToJson(meta),
    encodedMetaPacket: toHex(encodePacket(meta)),
  };
}

/**
 * オニオン: パディングは決定化できるが、封印 (crypto_box_seal) は決定化できない。
 * 回路は実運用 (OnionCircuit) と同じ 2 ホップ [Guard, Exit]。
 */
export async function buildOnionSection() {
  const hops = [INPUTS.verifierSeedByte, INPUTS.exitSeedByte].map(b => {
    const kp = seededKeyPair(b);
    return { seed: toHex(new Uint8Array(32).fill(b)), peerId: NodeIdentity.derivePeerId(kp.publicKey), pubkey: toHex(kp.publicKey) };
  });
  const padded = await withDeterministicRandom('onion-pad', () =>
    OnionRouter.padCell(new TextEncoder().encode('golden cell payload')),
  );
  const cell = OnionRouter.wrapCircuit(
    { type: 'frag', id: new Uint8Array(FRAG_ID_BYTES).fill(0x9a), idx: 1, total: 3, data: new Uint8Array(INPUTS.onionFragData) },
    hops.map(h => ({ peerId: h.peerId, pubkey: fromHex(h.pubkey) })),
  );
  return {
    hops,
    fragData: toHex(INPUTS.onionFragData),
    /** 2 ホップ回路の外殻 (Guard に送るセル)。乱数入りなので再生成のたびに変わる */
    cell: toHex(cell),
    paddedCellPrefix: toHex(padded.subarray(0, 4 + 'golden cell payload'.length)),
    paddedCellSha256: sha256Hex(padded),
  };
}

/** 固定入力の leaseSet (2 枠)。Ed25519 の署名は決定的なので、バイト列まで固定できる */
function leaseSetBytes(gateway: string): Uint8Array {
  const kp = seededKeyPair(INPUTS.leaseSetSeedByte);
  return signLeaseSet(
    {
      sid: kp.publicKey,
      slots: [
        { nonce: 0x01020304, solution: Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i) },
        { nonce: 0xa0b0c0d0, solution: Uint8Array.from({ length: 16 }, (_, i) => 0xe0 - i) },
      ],
      gateway,
      tunnelId: Uint8Array.from({ length: 8 }, (_, i) => 0x30 + i),
      expiresMin: INPUTS.leaseSetExpiresMin,
    },
    (m) => sodium.crypto_sign_detached(m, kp.privateKey),
  );
}

/** 全 WireType の決定的なペイロード */
export function wirePayloads(ctx: {
  join: ReturnType<typeof buildJoinSection>;
  node: ReturnType<typeof buildNodeIdentitySection>;
  gossipPacket: GossipPacket;
  onionCell: Uint8Array;
}): Array<[string, WireType, any]> {
  const challenge = new Uint8Array(INPUTS.challenge);
  const pubkey = fromHex(ctx.node.pubkey);
  const packetBytes = encodePacket(ctx.gossipPacket);
  const other = NodeIdentity.derivePeerId(seededKeyPair(INPUTS.relaySeedByte).publicKey);
  const tunnelIdBytes = Uint8Array.from({ length: 8 }, (_, i) => 0x40 + i);
  const tunnelBody = Uint8Array.from({ length: 24 }, (_, i) => (i * 5 + 3) & 0xff);
  return [
    ['hello', WireType.HELLO, { challenge }],
    ['join', WireType.JOIN, {
      pubkey,
      powCounter: ctx.join.powCounter,
      signature: fromHex(ctx.join.signature),
    }],
    ['ping', WireType.PING, { nonce: 0xdeadbeef }],
    ['pong', WireType.PONG, { nonce: 0xdeadbeef }],
    ['pexRequest', WireType.PEX_REQUEST, {}],
    ['pexResponse', WireType.PEX_RESPONSE, {
      peers: [{ pubkey, powCounter: ctx.node.nodeIdPowFast.counter }],
    }],
    ['sdpRelay', WireType.SDP_RELAY, {
      targetPeerId: other,
      senderId: ctx.node.peerId,
      sdp: { type: 'offer', sdp: 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n' },
    }],
    ['iceRelay', WireType.ICE_RELAY, {
      targetPeerId: other,
      senderId: ctx.node.peerId,
      candidate: { candidate: 'candidate:1 1 udp 2122260223 192.0.2.1 54321 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: null },
    }],
    ['gossip', WireType.GOSSIP, { packet: ctx.gossipPacket }],
    // M1 以降の Stem。ペイロードは { item: ExitItem (コンパクト形式のバイト列) } で、ホップ数・TTL は載せない
    ['stem', WireType.STEM, { item: { type: 'exit_fluff', packet: ctx.gossipPacket } }],
    ['onionStem', WireType.ONION_STEM, { onionBytes: ctx.onionCell }],
    // 過去ログ v2: Guard の 72 時間バッファからの追いつき
    ['catchupReq', WireType.CATCHUP_REQ, { since: INPUTS.catchupSince }],
    ['catchupData', WireType.CATCHUP_DATA, { packets: [packetBytes, packetBytes.subarray(0, 20)] }],
    ['catchupEnd', WireType.CATCHUP_END, { status: 1, nextSince: INPUTS.catchupNextSince }],
    // 過去ログ v2 B-b1: leaseSet (保管担当の位置と受け口。network/storage/LeaseSet)
    ['leaseSet', WireType.LEASESET, { leaseSet: leaseSetBytes(ctx.node.peerId) }],
    ['leaseSetSyncReq', WireType.LEASESET_SYNC_REQ, {}],
    ['leaseSetSync', WireType.LEASESET_SYNC, { leaseSets: [leaseSetBytes(ctx.node.peerId), leaseSetBytes(other)] }],
    // 過去ログ v2 B-b2: トンネル (受け口への登録と、保持者への要求・応答の中継。network/tunnel)
    ['tunnelRegister', WireType.TUNNEL_REGISTER, { tunnelId: tunnelIdBytes }],
    ['tunnelRegistered', WireType.TUNNEL_REGISTERED, { tunnelId: tunnelIdBytes, ok: true }],
    ['tunnelSend', WireType.TUNNEL_SEND, { reqId: INPUTS.tunnelReqId, gateway: other, tunnelId: tunnelIdBytes, body: tunnelBody }],
    ['tunnelFwd', WireType.TUNNEL_FWD, { returnTag: INPUTS.tunnelTag, tunnelId: tunnelIdBytes, body: tunnelBody }],
    ['tunnelDeliver', WireType.TUNNEL_DELIVER, { returnTag: INPUTS.tunnelTag, fromHop: ctx.node.peerId, body: tunnelBody }],
    ['tunnelReply', WireType.TUNNEL_REPLY, { returnTag: INPUTS.tunnelTag, toHop: other, seq: 0x0102, final: true, body: tunnelBody }],
    ['tunnelRet', WireType.TUNNEL_RET, { returnTag: INPUTS.tunnelTag, seq: 0x0102, final: false, body: tunnelBody }],
    ['tunnelResult', WireType.TUNNEL_RESULT, { reqId: INPUTS.tunnelReqId, seq: 0x0102, final: true, body: tunnelBody }],
    ['tunnelError', WireType.TUNNEL_ERROR, { id: INPUTS.tunnelTag, code: 2 }],
    // Ozzy: オニオン回路の M1 が外部ロッカーから取った範囲の応答 (ozzy/MeshRange)
    ['ozzyReply', WireType.OZZY_REPLY, {
      header: Uint8Array.from({ length: 68 }, (_, i) => (i * 7) & 0xff), seq: 0x0102, final: true, body: tunnelBody,
    }],
    ['ozzyResult', WireType.OZZY_RESULT, { replyId: INPUTS.tunnelReqId, seq: 0x0102, final: true, body: tunnelBody }],
    // Ozzy: アップロードの本体 (告発者 → Guard → M1。ozzy/MeshRange の runJob)
    ['ozzyUp', WireType.OZZY_UP, {
      header: Uint8Array.from({ length: 80 }, (_, i) => (i * 11) & 0xff), seq: 0x0102, final: false, body: tunnelBody,
    }],
    ['ozzyUpFwd', WireType.OZZY_UP_FWD, {
      uploadId: Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i), seq: 0x0102, final: true, body: tunnelBody,
    }],
    // Ozzy: 参加者の中継 Worker の広告の交換 (ozzy/WorkerPool)
    ['ozzyWorkerReq', WireType.OZZY_WORKER_REQ, {}],
    ['ozzyWorkerAds', WireType.OZZY_WORKER_ADS, {
      ads: [{
        pubkey: Uint8Array.from({ length: 32 }, (_, i) => i), powCounter: 0x01020304, expiresMin: 29_000_000,
        url: 'https://ozzy.example.workers.dev', signature: Uint8Array.from({ length: 64 }, (_, i) => 255 - i),
      }],
    }],
  ];
}

export function buildWireSection(ctx: Parameters<typeof wirePayloads>[0]) {
  const frames: Record<string, { type: number; hex: string }> = {};
  for (const [name, type, payload] of wirePayloads(ctx)) {
    frames[name] = { type, hex: toHex(WireCodec.encode(type, payload)) };
  }
  return { frames };
}

/** gossip ベクタのパケット */
export function gossipPacketFrom(section: ReturnType<typeof buildGossipPowSection>): GossipPacket {
  return {
    packet_id: section.packetId,
    timestamp: OZ_EPOCH_MS + section.header.time * 60_000,
    tag: section.header.tag,
    age: section.header.age,
    effort_exp: section.header.effort_exp,
    pow_nonce: section.solvedNonce,
    pow_solution: fromHex(section.solution),
    payload: fromHex(section.header.payload),
  };
}

/** 回路の中の 1 件 (ExitItem) のコンパクト形式 */
export function buildExitItemSection(packet: GossipPacket) {
  return {
    fluff: toHex(encodeExitItem({ type: 'exit_fluff', packet })),
  };
}

export const VECTORS_COMMENT =
  'Generated by packages/core/tests/protocol/generateVectors.ts — do not edit by hand. ' +
  'Consumed by ProtocolConformance.test.ts. Regenerate ONLY for an intentional, versioned wire/crypto format change.';

/**
 * 全セクションを組み立てる。
 * onionCell を渡すと、ONION_STEM フレームはそのセルで組み立てる
 * (テストで「保存済みのセル」から決定的に再符号化するため)。
 */
export async function buildGoldenVectors(opts: { onionCell?: Uint8Array } = {}) {
  await sodium.ready;
  const constants = buildConstants();
  const keyManagerSection = buildKeyManagerSection();
  const node = buildNodeIdentitySection();
  const join = buildJoinSection();
  const tracker = buildTrackerSection();
  const gossipPow = buildGossipPowSection();
  const cryptoEngine = await buildCryptoEngineSection();
  const packetBuilder = await buildPacketBuilderSection();
  const onion = await buildOnionSection();
  const onionCell = opts.onionCell ?? fromHex(onion.cell);
  const wire = buildWireSection({
    join,
    node,
    gossipPacket: gossipPacketFrom(gossipPow),
    onionCell,
  });
  const exitItems = buildExitItemSection(gossipPacketFrom(gossipPow));
  return {
    _comment: VECTORS_COMMENT,
    constants,
    keyManager: keyManagerSection,
    nodeIdentity: node,
    join,
    tracker,
    gossipPow,
    cryptoEngine,
    packetBuilder,
    exitItems,
    onion: { ...onion, cell: toHex(onionCell) },
    wire,
  };
}

export type GoldenVectors = Awaited<ReturnType<typeof buildGoldenVectors>>;

// msgpackEncode は再エクスポートだけ (テストで期待バイト列を別経路で作るため)
export { msgpackEncode };
