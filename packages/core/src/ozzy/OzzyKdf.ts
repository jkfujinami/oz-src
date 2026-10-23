/**
 * OzzyKdf — マスターシード S_file からの Split-Key 鍵導出ツリーと配置スロット計算。
 *
 * 設計仕様 (docs/design/03_storage_format.md §3.4 & docs/design/04_placement.md §4.3):
 *   S_file (32 B)
 *     ├── K_enc   (32 B): データチャンク復号鍵 (Reader と Uploader のみ保持、Fetcher には絶対渡さない)
 *     ├── K_tag   (32 B): 16 B チャンク識別タグ導出鍵
 *     ├── K_loc   (32 B): 一貫性ハッシュリング位置 L_s およびバケット内候補スロット cand_0..3 導出鍵
 *     └── K_lease (32 B): CloudLeaseSet の封印 URL 開封鍵 (Fetcher に渡して HTTP Range GET させる)
 */
import sodium, { sodiumReady } from '../crypto/sodium';

export const OZZY_SEED_BYTES = 32;
export const OZZY_KEY_BYTES = 32;
export const OZZY_TAG_BYTES = 16;

/** Tier 1 バケット (9.0 GiB = 2,304 × 4 MiB チャンク) のスロット区分 */
export const OZZY_TOTAL_SLOTS = 2304;
/** 先頭 10% (0..229): Manifest 専用保護プール */
export const OZZY_MANIFEST_POOL_SLOTS = 230;
/** 残り 90% (230..2303): 通常データチャンクプール */
export const OZZY_DATA_POOL_SLOTS = OZZY_TOTAL_SLOTS - OZZY_MANIFEST_POOL_SLOTS; // 2074
/** 1 チャンクあたりの候補スロット数 m = 4 */
export const OZZY_CANDIDATE_COUNT = 4;

export interface OzzyFileKeys {
  readonly seed: Uint8Array;
  readonly kEnc: Uint8Array;
  readonly kTag: Uint8Array;
  readonly kLoc: Uint8Array;
  readonly kLease: Uint8Array;
}

const enc = new TextEncoder();

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function keyedHash(domain: string, key: Uint8Array, outLen: number, ...parts: Uint8Array[]): Uint8Array {
  const domainBytes = enc.encode(domain);
  const input = concatBytes(u32le(domainBytes.length), domainBytes, ...parts);
  return sodium.crypto_generichash(outLen, input, key);
}

/** 新規ファイルの 32 B マスターシードを生成する */
export async function generateOzzySeed(): Promise<Uint8Array> {
  await sodiumReady;
  return sodium.randombytes_buf(OZZY_SEED_BYTES);
}

/** マスターシード S_file (またはストライプシード S_s) から 4 つの分離鍵を決定論的に導出する */
export async function deriveOzzyKeys(seed: Uint8Array): Promise<OzzyFileKeys> {
  await sodiumReady;
  if (seed.length !== OZZY_SEED_BYTES) {
    throw new RangeError(`Expected ${OZZY_SEED_BYTES}-byte seed, got ${seed.length}`);
  }
  return {
    seed: new Uint8Array(seed),
    kEnc: keyedHash('ozzy-v2-k-enc', seed, OZZY_KEY_BYTES),
    kTag: keyedHash('ozzy-v2-k-tag', seed, OZZY_KEY_BYTES),
    kLoc: keyedHash('ozzy-v2-k-loc', seed, OZZY_KEY_BYTES),
    kLease: keyedHash('ozzy-v2-k-lease', seed, OZZY_KEY_BYTES),
  };
}

/** ファイルマスターシードから各ストライプ固有のシード S_s を導出する */
export async function deriveStripeSeed(fileSeed: Uint8Array, stripeIndex: number): Promise<Uint8Array> {
  await sodiumReady;
  if (fileSeed.length !== OZZY_SEED_BYTES) {
    throw new RangeError('Invalid fileSeed length');
  }
  return keyedHash('ozzy-v2-stripe-seed', fileSeed, OZZY_SEED_BYTES, u32le(stripeIndex));
}

/**
 * チャンクの先頭 16 バイトに付与する識別タグ `tag` を計算する。
 * tag = BLAKE2b-128("ozzy-chunk-tag-v2", key=K_tag, stripeIndex || shareIndex)
 */
export function computeChunkTag(kTag: Uint8Array, stripeIndex: number, shareIndex: number): Uint8Array {
  if (kTag.length !== OZZY_KEY_BYTES) throw new RangeError('Invalid kTag length');
  return keyedHash('ozzy-chunk-tag-v2', kTag, OZZY_TAG_BYTES, u32le(stripeIndex), u32le(shareIndex));
}

/**
 * ストライプ s の一貫性ハッシュリング上の基準位置 L_s (64-bit BigInt) を計算する。
 */
export function computeStripeRingPosition(kLoc: Uint8Array, stripeIndex: number): bigint {
  if (kLoc.length !== OZZY_KEY_BYTES) throw new RangeError('Invalid kLoc length');
  const h = keyedHash('ozzy-stripe-loc-v2', kLoc, 16, u32le(stripeIndex));
  return new DataView(h.buffer, h.byteOffset, 8).getBigUint64(0, false);
}

/**
 * Tier 1 バケット内の m = 4 個の候補スロット番号 (cand_0..cand_3) を決定論的に計算する。
 * - isManifest === true の場合: 先頭 10% の Manifest 専用保護プール (0 .. 229) 内の互いに異なる 4 スロット
 * - isManifest === false の場合: 残り 90% のデータチャンクプール (230 .. 2303) 内の互いに異なる 4 スロット
 */
export function computeCandidateSlots(
  kLoc: Uint8Array,
  stripeIndex: number,
  shareIndex: number,
  isManifest: boolean,
): [number, number, number, number] {
  if (kLoc.length !== OZZY_KEY_BYTES) throw new RangeError('Invalid kLoc length');
  const domain = isManifest ? 'ozzy-slot-m-v2' : 'ozzy-slot-d-v2';
  const poolBase = isManifest ? 0 : OZZY_MANIFEST_POOL_SLOTS;
  const poolSize = isManifest ? OZZY_MANIFEST_POOL_SLOTS : OZZY_DATA_POOL_SLOTS;

  const chosen: number[] = [];
  let attempt = 0;
  while (chosen.length < OZZY_CANDIDATE_COUNT) {
    const h = keyedHash(domain, kLoc, 16, u32le(stripeIndex), u32le(shareIndex), u32le(attempt));
    const rawU32 = new DataView(h.buffer, h.byteOffset, 4).getUint32(0, true);
    const slot = poolBase + (rawU32 % poolSize);
    if (!chosen.includes(slot)) {
      chosen.push(slot);
    }
    attempt++;
  }
  return [chosen[0], chosen[1], chosen[2], chosen[3]];
}

/** K_lease (32 B) から SlabLeaseSet 署名用の Ed25519 キーペアを決定論的に導出する */
export async function deriveLeaseSignKeypair(kLease: Uint8Array): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  await sodiumReady;
  if (kLease.length !== OZZY_KEY_BYTES) throw new RangeError('Invalid kLease length');
  const signSeed = sodium.crypto_generichash(32, enc.encode('ozzy-v2-lease-sign-seed'), kLease);
  const kp = sodium.crypto_sign_seed_keypair(signSeed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/**
 * SlabLeaseSet の 16 B 識別子 = SHA-256("ozzy-ls-id-v3" ‖ 署名公開鍵) の先頭 16 B。
 * ★ 識別子を署名鍵に縛る: K_lease を知らない第三者は、この識別子に有効な署名の Lease を作れない。
 *   ディレクトリ (Worker) も K_lease 無しで「この識別子の正当な Lease か」を確かめられる (SHA-256 と Ed25519 は WebCrypto にある)。
 *   旧版は識別子を K_lease の鍵付きハッシュにしていたので、誰でも任意の鍵で署名した Lease を同じ識別子へ積めた。
 */
export function leaseSetIdFromSignPubKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32) throw new RangeError('Invalid lease sign public key');
  const domain = enc.encode('ozzy-ls-id-v3');
  const buf = new Uint8Array(domain.length + publicKey.length);
  buf.set(domain, 0);
  buf.set(publicKey, domain.length);
  return sodium.crypto_hash_sha256(buf).slice(0, 16);
}

/** K_lease から CloudLeaseSet の 16 B 識別子 leaseSetId を導出する */
export async function computeLeaseSetId(kLease: Uint8Array): Promise<Uint8Array> {
  const kp = await deriveLeaseSignKeypair(kLease);
  kp.privateKey.fill(0);
  return leaseSetIdFromSignPubKey(kp.publicKey);
}
