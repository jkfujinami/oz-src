import sodium from '../../src/crypto/sodium';
import { CryptoEngine } from '../../src/crypto/CryptoEngine';
import { PoWEngine } from '../../src/crypto/PoWEngine';
import { PacketBuilder } from '../../src/crypto/PacketBuilder';
import type { GossipPacket, IIdentity, IPoWEngine } from '../../src/types';

/** 本物の Equi-X で解く (1 試行 60ms 前後)。検証 (PacketValidator) を通す必要があるテスト用 */
export const realPowEngine: IPoWEngine = { compute: async (h) => PoWEngine.computeSync(h) };
export const syncPowEngine = realPowEngine;

/**
 * 解かない代役 (0 と 0 埋めの解を返す)。PacketValidator を通らないので、ネットワークの検証を
 * 経由しないテスト (オーケストレータ単体など) だけで使う。
 * ★ 本番のコードにこの経路は無い。検証側に「テストなら通す」という分岐を入れていない
 *   (入れると、その分岐が攻撃面になる) ので、検証を通すテストは realPowEngine を使う。
 */
export const fakePowEngine: IPoWEngine = {
  compute: async () => ({ nonce: 0, solution: new Uint8Array(16) }),
};

/** トリップ有り/無しの IIdentity */
export function makeIdentity(withTrip: boolean): IIdentity {
  const session = sodium.crypto_sign_keypair();
  const trip = withTrip ? sodium.crypto_sign_keypair() : null;
  return {
    hasTrip: withTrip,
    sign: (data: Uint8Array) => ({
      sessionPubkey: session.publicKey,
      sessionSignature: sodium.crypto_sign_detached(data, session.privateKey),
      tripPubkey: trip ? trip.publicKey : null,
      tripSignature: trip ? sodium.crypto_sign_detached(data, trip.privateKey) : null,
    }),
  };
}

/** packet_id (hex 32 文字) の見本 */
export const parentIds = (n: number): string[] =>
  Array.from({ length: n }, (_, i) => String(i + 1).repeat(32).slice(0, 32));

export interface BuiltPost {
  packet: GossipPacket;
  /** 暗号化に使った鍵 (板の鍵またはスレの鍵) */
  threadKey: Uint8Array;
}

/**
 * 実際の PacketBuilder で投稿を作る。
 * 既定は返信 (postType 0)・板 'vip'・スレッド 'abcdefghij' (旧形式の ID なので tag はその日のもの)・PoW は本物。
 */
export async function buildPost(opts: {
  content: string;
  trip?: boolean;
  parents?: number;
  boardId?: string;
  threadId?: string;
  threadKey?: Uint8Array;
  postType?: number;
  identity?: IIdentity;
  /** 'fake' なら PoW を解かない (PacketValidator を通らない) */
  pow?: 'real' | 'fake';
  now?: number;
}): Promise<BuiltPost> {
  await sodium.ready;
  const threadKey = opts.threadKey ?? sodium.randombytes_buf(32);
  const packet = await PacketBuilder.build({
    content: opts.content,
    key: threadKey,
    identity: opts.identity ?? makeIdentity(opts.trip ?? false),
    cryptoEngine: new CryptoEngine(),
    powEngine: opts.pow === 'fake' ? fakePowEngine : realPowEngine,
    boardId: opts.boardId ?? 'vip',
    threadId: opts.threadId ?? 'abcdefghij',
    postType: opts.postType ?? 0,
    parents: parentIds(opts.parents ?? 0),
    now: opts.now,
  });
  return { packet, threadKey };
}
