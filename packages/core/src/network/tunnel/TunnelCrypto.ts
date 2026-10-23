import sodium from '../../crypto/sodium';

/**
 * TunnelCrypto — トンネルを通る要求と応答の、端から端までの暗号 (history v2 §4.4)。
 *
 *   要求   crypto_box_seal({ kind u8 ‖ respKey 32 ‖ payload }, H の X25519 公開鍵)
 *          H の X25519 鍵は、SID (Ed25519) から変換して使う (crypto_sign_ed25519_pk_to_curve25519)。
 *          ★ 封印した本人 (読み手) の鍵は載らない: sealed box は使い捨ての鍵で封印する。H は誰からの要求か分からない。
 *   応答   1 片ごとに XChaCha20-Poly1305(respKey, nonce = u64 seq, AAD = kind) で { final u8 ‖ データ } を暗号化する。
 *          ★ final (最後の片) は平文の中にも入れる。経路上の中継が末尾の片を黙って落としても (フレームの flags は
 *            中継が見られる・書き換えられる値)、読み手は「最後の片が来ていない」と分かり、途中で切れた応答を
 *            完全なものとして受け取らない。
 *          ★ respKey は要求ごとの乱数。同じ鍵で seq が重なることはない (seq は 0 から 1 ずつ)。
 *          ★ AAD に kind を入れる: 別の種類の応答に差し替えられない。
 *   中継 (Guard) が見るのは、封印された本文の大きさと、応答の片の数・大きさ・タイミングだけ。
 */

/** 要求の種類 */
export const TUNNEL_KIND = {
  FETCH_BUCKET: 1,
  /** チャンクを預ける (断片ごとの要求。network/storage/ChunkProtocol) */
  PUT_CHUNK: 2,
  /** チャンクを取る */
  GET_CHUNK: 3,
} as const;

export const RESP_KEY_BYTES = 32;
const SEAL_OVERHEAD = 48; // crypto_box_SEALBYTES
const AEAD_TAG_BYTES = 16;
const NONCE_BYTES = 24;

/** 応答 1 片に載せるデータの最大 (平文)。暗号化後 = 1 (final) + 15KiB + 16 でフレーム (16KiB) に収まる */
export const TUNNEL_CHUNK_DATA_BYTES = 15 * 1024;

/** 応答 1 片の暗号文の長さ (データ n バイト) */
export function chunkCipherBytes(dataBytes: number): number {
  return 1 + dataBytes + AEAD_TAG_BYTES;
}

/** 要求の封印後の長さ (payload n バイト) */
export function sealedRequestBytes(payloadBytes: number): number {
  return SEAL_OVERHEAD + 1 + RESP_KEY_BYTES + payloadBytes;
}

/** SID (Ed25519 公開鍵) から H の X25519 公開鍵を導く。不正な点なら null */
export function holderCurveKey(sidPublicKey: Uint8Array): Uint8Array | null {
  try {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(sidPublicKey);
  } catch {
    return null;
  }
}

export function newRespKey(): Uint8Array {
  return sodium.randombytes_buf(RESP_KEY_BYTES);
}

/** 要求を封印する。holderSid が不正な鍵なら null */
export function sealRequest(
  holderSid: Uint8Array, kind: number, respKey: Uint8Array, payload: Uint8Array,
): Uint8Array | null {
  const pk = holderCurveKey(holderSid);
  if (!pk || respKey.length !== RESP_KEY_BYTES) return null;
  const plain = new Uint8Array(1 + RESP_KEY_BYTES + payload.length);
  plain[0] = kind;
  plain.set(respKey, 1);
  plain.set(payload, 1 + RESP_KEY_BYTES);
  try {
    return sodium.crypto_box_seal(plain, pk);
  } finally {
    sodium.memzero(plain);
  }
}

export interface OpenedRequest {
  kind: number;
  respKey: Uint8Array;
  payload: Uint8Array;
}

/** 平文 (kind ‖ respKey ‖ payload) を読む。短すぎれば null */
export function parseRequestPlain(plain: Uint8Array): OpenedRequest | null {
  if (plain.length < 1 + RESP_KEY_BYTES) return null;
  return {
    kind: plain[0],
    respKey: plain.slice(1, 1 + RESP_KEY_BYTES),
    payload: plain.slice(1 + RESP_KEY_BYTES),
  };
}

/** nonce = 24 バイト。末尾 8 バイトに seq (ビッグエンディアン u64)。残りは 0 */
function nonceFor(seq: number): Uint8Array {
  const n = new Uint8Array(NONCE_BYTES);
  new DataView(n.buffer).setBigUint64(NONCE_BYTES - 8, BigInt(seq), false);
  return n;
}

/** 応答の 1 片を暗号化する。seq は u16 (フレームの seq と同じ値) */
export function encryptChunk(respKey: Uint8Array, kind: number, seq: number, final: boolean, data: Uint8Array): Uint8Array {
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xffff) throw new RangeError('seq out of range');
  const plain = new Uint8Array(1 + data.length);
  plain[0] = final ? 1 : 0;
  plain.set(data, 1);
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, Uint8Array.of(kind), null, nonceFor(seq), respKey);
}

/** 応答の 1 片を復号する。改ざん・別の seq・別の kind・別の鍵なら null */
export function decryptChunk(
  respKey: Uint8Array, kind: number, seq: number, cipher: Uint8Array,
): { final: boolean; data: Uint8Array } | null {
  if (cipher.length < chunkCipherBytes(0)) return null;
  try {
    const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, Uint8Array.of(kind), nonceFor(seq), respKey);
    if (plain.length < 1 || plain[0] > 1) return null;
    return { final: plain[0] === 1, data: plain.slice(1) };
  } catch {
    return null;
  }
}
