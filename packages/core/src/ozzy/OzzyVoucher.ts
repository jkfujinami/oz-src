/**
 * OzzyVoucher — ジャーナリスト (Member) が取材源・内部告発者 (Guest) に渡す無記名アップロード招待券 (`OZ_VOUCHER`)。
 *
 *   Member は登録済みのメンバー鍵 (ristretto255) を持つ。招待券はメンバーの公開鍵の束 (リング) に対する
 *   リンク可能リング署名 (LSAG) で発行する。Worker (Gatekeeper) に分かるのは「リングの誰か (= 登録メンバーの誰か) が
 *   発行した」ことだけで、**誰が発行したかは分からない**。
 *
 * ★ 旧版 (v2) は発行したメンバーの公開鍵 (sponsorMemberPubKey) をチャンクの PUT ごとに Worker へそのまま送っていた。
 *   Worker (= 運営・照会を受ける事業者) には、どのジャーナリストがどの告発者を招いたかが筒抜けだった。
 * ★ 使い過ぎの抑止はキーイメージ I = x·H(day) で行う。同じメンバーが同じ日 (validStartDay) に出した招待券は同じ I になり、
 *   Worker は I ごとに書き込み数を数える。日が違えば I は結び付かない (DDH)。I からメンバーは分からない。
 *   旧版はキーイメージを「日 ‖ バケット番号」で作り、バケット番号は発行者が自由に選べたので、上限を何度でも取り直せた。
 *
 *   リング署名 (ristretto255, Abe–Ohkubo–Suzuki 型 LSAG。2 つ目の基点を日ごとの H にしたもの)
 *     H  = from_hash(BLAKE2b-512("ozzy-voucher-ki-v3" ‖ validStartDay))
 *     I  = x·H
 *     c_{i+1} = Hs(m ‖ s_i·G + c_i·P_i ‖ s_i·H + c_i·I)、リングを一周して c_n = c_0
 *   m (署名対象) = MAGIC ‖ ver ‖ 有効期間 ‖ maxChunks ‖ 招待券の使い捨て鍵 (Ed25519) ‖ I ‖ H(リング)
 *
 *   招待券 (告発者に渡す)  core ‖ 使い捨ての秘密鍵 64          `[[ozzy-voucher:v3:<base64url>]]`
 *   証明 (チャンクごと)     core ‖ chunkTag 16 ‖ chunkSig 64     (X-Ozzy-Quota-Proof)
 *   core = MAGIC ‖ ver u8 ‖ start u16 ‖ end u16 ‖ maxChunks u16 ‖ voucherPub 32 ‖ I 32 ‖ n u8 ‖ ring 32n ‖ c0 32 ‖ s 32n
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import { bytesEqual } from '../files/FileFormat';

export const OZZY_VOUCHER_MAGIC = new Uint8Array([0x4f, 0x5a, 0x56, 0x33]); // "OZV3"
export const OZZY_VOUCHER_VERSION = 3;
/** リングの大きさの上限 (証明の大きさ ≈ 64n バイト) */
export const OZZY_VOUCHER_MAX_RING = 64;
/** Worker が求めるリングの大きさの下限 (名簿がこれより小さければ名簿全員) */
export const OZZY_VOUCHER_MIN_RING = 8;
/** 招待券の有効期間の上限 (日) */
export const OZZY_VOUCHER_MAX_DAYS = 14;

const POINT_BYTES = 32;
const SCALAR_BYTES = 32;
const enc = new TextEncoder();

/** メンバー鍵 (ristretto255)。publicKey を名簿に載せ、secretKey はメンバー本人だけが持つ */
export interface OzzyMemberKeypair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface OzzyUploadVoucher {
  readonly version: number;
  readonly validStartDay: number; // u16
  readonly validEndDay: number; // u16
  readonly maxChunks: number; // u16
  /** 使い捨ての Ed25519 公開鍵 (チャンクごとの署名を検証する) */
  readonly voucherPubKey: Uint8Array;
  /** 使い捨ての Ed25519 秘密鍵 (告発者が持つ。Worker へは送らない) */
  readonly voucherPrivKey: Uint8Array;
  /** キーイメージ I = x·H(validStartDay) */
  readonly keyImage: Uint8Array;
  /** リング (メンバーの公開鍵。バイト順に並べたもの) */
  readonly ring: readonly Uint8Array[];
  readonly c0: Uint8Array;
  readonly s: readonly Uint8Array[];
}

/** 新しいメンバー鍵を作る */
export async function generateMemberKeypair(): Promise<OzzyMemberKeypair> {
  await sodiumReady;
  const secretKey = sodium.crypto_core_ristretto255_scalar_random();
  return { publicKey: sodium.crypto_scalarmult_ristretto255_base(secretKey), secretKey };
}

/** 秘密鍵から公開鍵を求める */
export async function memberPublicKeyOf(secretKey: Uint8Array): Promise<Uint8Array> {
  await sodiumReady;
  return sodium.crypto_scalarmult_ristretto255_base(secretKey);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** リングを正規の順 (バイト順・重複なし) にする */
export function canonicalRing(keys: readonly Uint8Array[]): Uint8Array[] {
  const seen = new Set<string>();
  const out: Uint8Array[] = [];
  for (const k of keys) {
    const h = Encoding.toHex(k);
    if (seen.has(h)) continue;
    seen.add(h);
    out.push(k);
  }
  return out.sort(compareBytes);
}

/** 日ごとの 2 つ目の基点 H(day) */
function dayBase(day: number): Uint8Array {
  const input = new ByteWriter().raw(enc.encode('ozzy-voucher-ki-v3')).u16(day).finish();
  return sodium.crypto_core_ristretto255_from_hash(sodium.crypto_generichash(64, input, null));
}

function ringHash(ring: readonly Uint8Array[]): Uint8Array {
  const all = new Uint8Array(ring.length * POINT_BYTES);
  ring.forEach((k, i) => all.set(k, i * POINT_BYTES));
  return sodium.crypto_generichash(32, all, null);
}

function signedMessage(v: {
  validStartDay: number; validEndDay: number; maxChunks: number; voucherPubKey: Uint8Array; keyImage: Uint8Array; ring: readonly Uint8Array[];
}): Uint8Array {
  return new ByteWriter()
    .raw(OZZY_VOUCHER_MAGIC)
    .u8(OZZY_VOUCHER_VERSION)
    .u16(v.validStartDay)
    .u16(v.validEndDay)
    .u16(v.maxChunks)
    .raw(v.voucherPubKey)
    .raw(v.keyImage)
    .raw(ringHash(v.ring))
    .finish();
}

function challenge(m: Uint8Array, L: Uint8Array, R: Uint8Array): Uint8Array {
  const input = new ByteWriter().raw(enc.encode('ozzy-lsag-v3')).raw(m).raw(L).raw(R).finish();
  return sodium.crypto_core_ristretto255_scalar_reduce(sodium.crypto_generichash(64, input, null));
}

/** s·A + c·B (A を省くと基点 G) */
function mulAdd(s: Uint8Array, A: Uint8Array | null, c: Uint8Array, B: Uint8Array): Uint8Array {
  const sA = A ? sodium.crypto_scalarmult_ristretto255(s, A) : sodium.crypto_scalarmult_ristretto255_base(s);
  return sodium.crypto_core_ristretto255_add(sA, sodium.crypto_scalarmult_ristretto255(c, B));
}

/**
 * ジャーナリスト (Member) が招待券を発行する。ring は名簿の公開鍵 (自分の公開鍵が無ければ足す)。
 * ★ リングが小さいほど発行者が絞られる。Worker は OZZY_VOUCHER_MIN_RING 人 (名簿がそれより小さければ名簿全員) を求める。
 */
export async function issueUploadVoucher(params: {
  member: OzzyMemberKeypair;
  ring: readonly Uint8Array[];
  validStartDay: number;
  validDays?: number;
  maxChunks?: number; // 既定 2048 チャンク = 8 GiB
}): Promise<OzzyUploadVoucher> {
  await sodiumReady;
  const validDays = Math.min(OZZY_VOUCHER_MAX_DAYS, Math.max(0, params.validDays ?? OZZY_VOUCHER_MAX_DAYS));
  const validEndDay = params.validStartDay + validDays;
  const maxChunks = params.maxChunks ?? 2048;
  const ring = canonicalRing([...params.ring, params.member.publicKey]);
  if (ring.length > OZZY_VOUCHER_MAX_RING) throw new RangeError(`ring too large (max ${OZZY_VOUCHER_MAX_RING})`);
  for (const k of ring) if (k.length !== POINT_BYTES || !sodium.crypto_core_ristretto255_is_valid_point(k)) throw new RangeError('invalid ring member key');
  const me = ring.findIndex(k => bytesEqual(k, params.member.publicKey));

  const voucherKp = sodium.crypto_sign_keypair();
  const H = dayBase(params.validStartDay);
  const keyImage = sodium.crypto_scalarmult_ristretto255(params.member.secretKey, H);
  const m = signedMessage({ validStartDay: params.validStartDay, validEndDay, maxChunks, voucherPubKey: voucherKp.publicKey, keyImage, ring });

  const n = ring.length;
  const c: Uint8Array[] = new Array(n);
  const s: Uint8Array[] = new Array(n);
  const alpha = sodium.crypto_core_ristretto255_scalar_random();
  c[(me + 1) % n] = challenge(m, sodium.crypto_scalarmult_ristretto255_base(alpha), sodium.crypto_scalarmult_ristretto255(alpha, H));
  for (let k = 1; k < n; k++) {
    const i = (me + k) % n;
    s[i] = sodium.crypto_core_ristretto255_scalar_random();
    c[(i + 1) % n] = challenge(m, mulAdd(s[i], null, c[i], ring[i]), mulAdd(s[i], H, c[i], keyImage));
  }
  s[me] = sodium.crypto_core_ristretto255_scalar_sub(alpha, sodium.crypto_core_ristretto255_scalar_mul(c[me], params.member.secretKey));
  alpha.fill(0);

  return {
    version: OZZY_VOUCHER_VERSION,
    validStartDay: params.validStartDay,
    validEndDay,
    maxChunks,
    voucherPubKey: voucherKp.publicKey,
    voucherPrivKey: voucherKp.privateKey,
    keyImage,
    ring,
    c0: c[0],
    s,
  };
}

type VoucherCore = Omit<OzzyUploadVoucher, 'voucherPrivKey'>;

function writeCore(w: ByteWriter, v: VoucherCore): ByteWriter {
  w.raw(OZZY_VOUCHER_MAGIC)
    .u8(v.version)
    .u16(v.validStartDay)
    .u16(v.validEndDay)
    .u16(v.maxChunks)
    .raw(v.voucherPubKey)
    .raw(v.keyImage)
    .u8(v.ring.length);
  for (const k of v.ring) w.raw(k);
  w.raw(v.c0);
  for (const x of v.s) w.raw(x);
  return w;
}

function readCore(r: ByteReader): VoucherCore | null {
  if (!bytesEqual(r.bytes(4), OZZY_VOUCHER_MAGIC)) return null;
  const version = r.u8();
  if (version !== OZZY_VOUCHER_VERSION) return null;
  const validStartDay = r.u16();
  const validEndDay = r.u16();
  const maxChunks = r.u16();
  const voucherPubKey = r.bytes(32).slice();
  const keyImage = r.bytes(POINT_BYTES).slice();
  const n = r.u8();
  if (n < 1 || n > OZZY_VOUCHER_MAX_RING) return null;
  const ring: Uint8Array[] = [];
  for (let i = 0; i < n; i++) ring.push(r.bytes(POINT_BYTES).slice());
  const c0 = r.bytes(SCALAR_BYTES).slice();
  const s: Uint8Array[] = [];
  for (let i = 0; i < n; i++) s.push(r.bytes(SCALAR_BYTES).slice());
  return { version, validStartDay, validEndDay, maxChunks, voucherPubKey, keyImage, ring, c0, s };
}

/** リング署名を確かめる (リングが正規の順か・鍵が正しい点か・一周して c0 に戻るか) */
function verifyRing(v: VoucherCore): boolean {
  try {
    const n = v.ring.length;
    if (n < 1 || n > OZZY_VOUCHER_MAX_RING || v.s.length !== n) return false;
    for (let i = 1; i < n; i++) if (compareBytes(v.ring[i - 1], v.ring[i]) >= 0) return false;
    for (const k of v.ring) if (!sodium.crypto_core_ristretto255_is_valid_point(k)) return false;
    if (!sodium.crypto_core_ristretto255_is_valid_point(v.keyImage)) return false;
    const H = dayBase(v.validStartDay);
    const m = signedMessage(v);
    let c = v.c0;
    for (let i = 0; i < n; i++) c = challenge(m, mulAdd(v.s[i], null, c, v.ring[i]), mulAdd(v.s[i], H, c, v.keyImage));
    return bytesEqual(c, v.c0);
  } catch {
    return false;
  }
}

/** 検証済みのリング署名 (同じ招待券の証明はチャンクごとに来るので、重い検証は 1 回だけにする) */
const verifiedCores = new Map<string, boolean>();
const VERIFIED_CACHE_MAX = 1024;

function verifyRingCached(core: Uint8Array, v: VoucherCore): boolean {
  const key = Encoding.toHex(sodium.crypto_generichash(32, core, null));
  const hit = verifiedCores.get(key);
  if (hit !== undefined) return hit;
  const ok = verifyRing(v);
  verifiedCores.set(key, ok);
  if (verifiedCores.size > VERIFIED_CACHE_MAX) verifiedCores.delete(verifiedCores.keys().next().value!);
  return ok;
}

function chunkMessage(keyImage: Uint8Array, chunkTag: Uint8Array): Uint8Array {
  return new ByteWriter().raw(enc.encode('ozzy-voucher-chunk-v3')).raw(keyImage).raw(chunkTag).finish();
}

/**
 * 告発者 (Guest) が、受け取った招待券で特定の 4 MiB チャンク (tag) の書き込み証明 (`X-Ozzy-Quota-Proof`) を作る。
 * ★ 告発者の秘密鍵 voucherPrivKey は送らない。証明にメンバーを特定できる情報は入らない (リングとキーイメージだけ)。
 */
export async function signChunkWithVoucher(voucher: OzzyUploadVoucher, chunkTag: Uint8Array): Promise<string> {
  await sodiumReady;
  if (chunkTag.length !== 16) throw new RangeError('chunkTag must be 16 bytes');
  const chunkSignature = sodium.crypto_sign_detached(chunkMessage(voucher.keyImage, chunkTag), voucher.voucherPrivKey);
  return Encoding.toBase64(writeCore(new ByteWriter(), voucher).raw(chunkTag).raw(chunkSignature).finish());
}

/**
 * Gatekeeper Worker が `X-Ozzy-Quota-Proof` を検証する。
 * activeMemberRoster (メンバーの公開鍵の hex) を渡すと、リングの全員が名簿にいることと、リングの大きさが
 * min(名簿の人数, minRing) 以上であることを求める。
 */
export async function verifyChunkVoucherProof(
  proofToken: string,
  expectedChunkTag: Uint8Array,
  currentEpochDay: number,
  activeMemberRoster?: ReadonlySet<string>,
  opts: { minRing?: number } = {},
): Promise<{ ok: true; keyImageHex: string; maxChunks: number; ringSize: number } | { ok: false; reason: string }> {
  await sodiumReady;
  try {
    if (typeof proofToken !== 'string' || proofToken.length > 16 * 1024) return { ok: false, reason: 'malformed_proof' };
    const raw = Encoding.fromBase64(proofToken.trim());
    const r = new ByteReader(raw);
    const v = readCore(r);
    if (!v) return { ok: false, reason: 'bad_version' };
    const coreLen = raw.length - r.remaining;
    const chunkTag = r.bytes(16);
    const chunkSignature = r.bytes(64);
    r.end();

    if (v.validEndDay < v.validStartDay || v.validEndDay - v.validStartDay > OZZY_VOUCHER_MAX_DAYS) {
      return { ok: false, reason: 'bad_validity' };
    }
    if (currentEpochDay < v.validStartDay || currentEpochDay > v.validEndDay) return { ok: false, reason: 'voucher_expired' };
    if (!bytesEqual(chunkTag, expectedChunkTag)) return { ok: false, reason: 'tag_mismatch' };

    if (activeMemberRoster) {
      for (const k of v.ring) if (!activeMemberRoster.has(Encoding.toHex(k))) return { ok: false, reason: 'unknown_ring_member' };
      const need = Math.min(activeMemberRoster.size, opts.minRing ?? OZZY_VOUCHER_MIN_RING);
      if (v.ring.length < need) return { ok: false, reason: 'ring_too_small' };
    }
    if (!verifyRingCached(raw.subarray(0, coreLen), v)) return { ok: false, reason: 'invalid_ring_signature' };
    if (!sodium.crypto_sign_verify_detached(chunkSignature, chunkMessage(v.keyImage, chunkTag), v.voucherPubKey)) {
      return { ok: false, reason: 'invalid_chunk_signature' };
    }
    return { ok: true, keyImageHex: Encoding.toHex(v.keyImage), maxChunks: v.maxChunks, ringSize: v.ring.length };
  } catch {
    return { ok: false, reason: 'malformed_proof' };
  }
}

/** 招待券を `[[ozzy-voucher:v3:<base64url>]]` 文字列にする (使い捨ての秘密鍵を含む。告発者にだけ渡す) */
export function formatOzzyVoucherToken(v: OzzyUploadVoucher): string {
  const raw = writeCore(new ByteWriter(), v).raw(v.voucherPrivKey).finish();
  return `[[ozzy-voucher:v3:${Encoding.toBase64(raw)}]]`;
}

/** `[[ozzy-voucher:v3:<base64url>]]` 文字列から招待券を戻す。形が壊れていれば null (署名は Worker が確かめる) */
export function parseOzzyVoucherToken(input: string): OzzyUploadVoucher | null {
  const trimmed = input.trim();
  const m = /^\[\[ozzy-voucher:v3:([A-Za-z0-9_-]+)\]\]$/.exec(trimmed);
  const body = m ? m[1] : trimmed;
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  try {
    const r = new ByteReader(Encoding.fromBase64(body));
    const core = readCore(r);
    if (!core) return null;
    const voucherPrivKey = r.bytes(64).slice();
    r.end();
    return { ...core, voucherPrivKey };
  } catch {
    return null;
  }
}
