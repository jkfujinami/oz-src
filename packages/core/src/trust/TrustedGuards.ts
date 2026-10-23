import sodium from '../crypto/sodium';
import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { Encoding } from '../common/Encoding';
import { NodeIdentity, NODE_ID_POW, type NodeIdPowParams } from '../crypto/NodeIdentity';
import { toBytes } from '../crypto/PowPolicy';

/**
 * 信頼 Guard — 審査済みのメンバーが運用する Guard の署名付きリスト。
 *
 * ★ 何を防ぐか
 *
 *   Guard (オニオン回路の 1 ホップ目) は利用者の IP を見る位置にある。
 *   隣人から無作為に選ぶと、Sybil (攻撃者が大量に作ったノード) にこの位置を取られ得る。
 *   審査を通ったメンバーのノードだけを Guard の候補にすることで、これを防ぐ。
 *
 * ★ 二重の署名
 *
 *   1. 運用者の申告 (Guard 文字列): 運用者ノード自身の鍵で署名する。
 *      「この peerId は私が運用する」ことの所有証明で、他人の ID を勝手に
 *      載せることはできない。
 *   2. 信頼リスト: メンテナの鍵で署名する (k-of-n。当面 1-of-1)。
 *      メンテナの公開鍵の組はアプリに組み込む。リスト自体はどこから取り込んでもよい
 *      (署名を検証するので、途中の経路で改竄されても弾ける)。
 *
 * ★ 署名対象の正準化
 *
 *   オブジェクトのキー順に依存しないよう、署名対象は「決まった順の配列」を
 *   msgpack で符号化したものにする。整数は msgpack の最短表現になるので一意に定まる。
 */

const GUARD_DECL_DOMAIN = new TextEncoder().encode('OZ/v1/guard-decl');
const GUARD_LIST_DOMAIN = new TextEncoder().encode('OZ/v1/guard-list');

export const GUARD_STRING_PREFIX = 'oz-guard:';
export const GUARD_LIST_PREFIX = 'oz-guards:';

export const TRUSTED_GUARD_LIMITS = {
  /** リストに載せられる Guard の最大数 */
  MAX_GUARDS: 512,
  /** 失効リストの最大件数 */
  MAX_REVOKED: 4096,
  /** リストの有効期間の上限 (発行から失効まで)。これを超えるリストは受け付けない */
  MAX_VALIDITY_MS: 180 * 24 * 60 * 60 * 1000,
  /** 発行時刻が未来でも許す時計のずれ */
  CLOCK_SKEW_MS: 10 * 60 * 1000,
  /** 署名の最大数 (メンテナの数の上限) */
  MAX_SIGNATURES: 16,
  /** 文字列の長さの上限 (取り込み時の DoS 防止) */
  MAX_STRING_LENGTH: 2 * 1024 * 1024,
} as const;

/** アプリに組み込むメンテナの公開鍵の組 */
export interface MaintainerKeySet {
  /** 必要な署名の数 (k) */
  threshold: number;
  /** メンテナの Ed25519 公開鍵 (n 本) */
  keys: Uint8Array[];
}

/** 運用者の申告の中身 */
export interface GuardDeclaration {
  v: 1;
  peerId: string;
  pubkey: Uint8Array;
  powCounter: number;
  issuedAt: number;
}

/** 検証済みの信頼 Guard */
export interface TrustedGuard {
  peerId: string;
  pubkey: Uint8Array;
  powCounter: number;
}

/** 署名前のリストの中身 */
export interface GuardListContent {
  version: number;
  issuedAt: number;
  expiresAt: number;
  /** Guard 文字列 (運用者の署名つき) */
  guards: string[];
  /** 失効させた peerId */
  revoked: string[];
}

export type GuardListRejectReason =
  | 'malformed'
  | 'too-large'
  | 'no-keyset'
  | 'insufficient-signatures'
  | 'rollback'
  | 'expired'
  | 'not-yet-valid'
  | 'validity-too-long'
  | 'bad-guard'
  | 'too-many-guards';

export type GuardListResult =
  | { ok: true; version: number; issuedAt: number; expiresAt: number; guards: TrustedGuard[]; revoked: string[] }
  | { ok: false; reason: GuardListRejectReason; detail?: string };

// ── 共通 ──

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function fromBase64Url(text: string): Uint8Array {
  return sodium.from_base64(text, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/** メンテナ鍵の ID (公開鍵の SHA-256 の先頭 8 バイト)。表示と照合用 */
export function maintainerKeyId(pubkey: Uint8Array): string {
  return Encoding.toHex(sodium.crypto_hash_sha256(pubkey).slice(0, 8));
}

/** 公開鍵の指紋 (人が見比べる用。4 文字ずつ区切る) */
export function keyFingerprint(pubkey: Uint8Array): string {
  return Encoding.toHex(sodium.crypto_hash_sha256(pubkey).slice(0, 16)).match(/.{4}/g)!.join(' ');
}

function isSafeTime(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

// ── 運用者の申告 (Guard 文字列) ──

function declarationMessage(d: GuardDeclaration): Uint8Array {
  return concat(GUARD_DECL_DOMAIN, msgpackEncode([d.v, d.peerId, d.pubkey, d.powCounter, d.issuedAt]));
}

/**
 * 運用者が自分のノードの Guard 文字列を作る (Guard モードの「申告書の出力」)。
 */
export function createGuardString(identity: NodeIdentity, issuedAt: number = Date.now()): string {
  const secret = identity.exportSecret();
  const decl: GuardDeclaration = {
    v: 1,
    peerId: identity.peerId,
    pubkey: secret.pubkey,
    powCounter: secret.powCounter,
    issuedAt,
  };
  const sig = sodium.crypto_sign_detached(declarationMessage(decl), secret.privkey);
  return GUARD_STRING_PREFIX + toBase64Url(msgpackEncode([decl.v, decl.peerId, decl.pubkey, decl.powCounter, decl.issuedAt, sig]));
}

/**
 * Guard 文字列を検証して中身を返す。不正なら null。
 *
 * 確かめること:
 *   - 運用者の署名が正しい (所有証明)
 *   - peerId が公開鍵に束縛されている (Bound Identity)
 *   - NodeId PoW を満たす
 */
export function parseGuardString(text: string, powParams: NodeIdPowParams = NODE_ID_POW): TrustedGuard | null {
  if (typeof text !== 'string' || !text.startsWith(GUARD_STRING_PREFIX)) return null;
  if (text.length > 4096) return null;
  let raw: unknown;
  try {
    raw = msgpackDecode(fromBase64Url(text.slice(GUARD_STRING_PREFIX.length)));
  } catch {
    return null;
  }
  if (!Array.isArray(raw) || raw.length !== 6) return null;
  const [v, peerId, pubkeyRaw, powCounter, issuedAt, sigRaw] = raw;
  if (v !== 1 || typeof peerId !== 'string' || !isSafeTime(issuedAt)) return null;
  if (typeof powCounter !== 'number' || !Number.isSafeInteger(powCounter) || powCounter < 0) return null;
  const pubkey = toBytes(pubkeyRaw);
  const sig = toBytes(sigRaw);
  if (pubkey.length !== sodium.crypto_sign_PUBLICKEYBYTES || sig.length !== sodium.crypto_sign_BYTES) return null;

  const decl: GuardDeclaration = { v: 1, peerId, pubkey, powCounter, issuedAt };
  try {
    if (!sodium.crypto_sign_verify_detached(sig, declarationMessage(decl), pubkey)) return null;
  } catch {
    return null;
  }
  // peerId ↔ pubkey の束縛と NodeId PoW
  if (!NodeIdentity.verifyClaim({ peerId, pubkey, powCounter }, powParams)) return null;
  return { peerId, pubkey, powCounter };
}

// ── 信頼リスト ──

function listMessage(c: GuardListContent): Uint8Array {
  return concat(GUARD_LIST_DOMAIN, msgpackEncode([1, c.version, c.issuedAt, c.expiresAt, c.guards, c.revoked]));
}

/**
 * メンテナがリストに署名する (メンテナ用 CLI から使う)。
 *
 * 既存の署名つきリストを渡すと、その署名を保ったまま自分の署名を足す
 * (複数メンテナ体制で、順に署名を集めるため)。中身が違えば例外。
 */
export function signGuardList(
  content: GuardListContent,
  maintainerSecretKey: Uint8Array,
  existing?: string,
): string {
  validateContentShape(content);
  const message = listMessage(content);
  const pubkey = sodium.crypto_sign_ed25519_sk_to_pk(maintainerSecretKey);
  const sigs: Array<[string, Uint8Array]> = [];

  if (existing) {
    const prev = decodeListString(existing);
    if (!prev) throw new Error('signGuardList: existing list is malformed');
    if (!sodium.memcmp(listMessage(prev.content), message)) {
      throw new Error('signGuardList: existing list has different content');
    }
    sigs.push(...prev.sigs);
  }
  const keyId = maintainerKeyId(pubkey);
  const filtered = sigs.filter(([id]) => id !== keyId);
  filtered.push([keyId, sodium.crypto_sign_detached(message, maintainerSecretKey)]);

  return GUARD_LIST_PREFIX + toBase64Url(msgpackEncode([
    1, content.version, content.issuedAt, content.expiresAt, content.guards, content.revoked, filtered,
  ]));
}

function validateContentShape(c: GuardListContent): void {
  if (!Number.isSafeInteger(c.version) || c.version < 1) throw new RangeError('version must be a positive integer');
  if (!isSafeTime(c.issuedAt) || !isSafeTime(c.expiresAt) || c.expiresAt <= c.issuedAt) {
    throw new RangeError('issuedAt / expiresAt are invalid');
  }
  if (c.expiresAt - c.issuedAt > TRUSTED_GUARD_LIMITS.MAX_VALIDITY_MS) throw new RangeError('validity is too long');
  if (c.guards.length > TRUSTED_GUARD_LIMITS.MAX_GUARDS) throw new RangeError('too many guards');
  if (c.revoked.length > TRUSTED_GUARD_LIMITS.MAX_REVOKED) throw new RangeError('too many revocations');
}

function decodeListString(text: string): { content: GuardListContent; sigs: Array<[string, Uint8Array]> } | null {
  if (typeof text !== 'string' || !text.startsWith(GUARD_LIST_PREFIX)) return null;
  if (text.length > TRUSTED_GUARD_LIMITS.MAX_STRING_LENGTH) return null;
  let raw: unknown;
  try {
    raw = msgpackDecode(fromBase64Url(text.slice(GUARD_LIST_PREFIX.length).trim()));
  } catch {
    return null;
  }
  if (!Array.isArray(raw) || raw.length !== 7) return null;
  const [v, version, issuedAt, expiresAt, guards, revoked, sigs] = raw;
  if (v !== 1) return null;
  if (!Number.isSafeInteger(version) || (version as number) < 1) return null;
  if (!isSafeTime(issuedAt) || !isSafeTime(expiresAt)) return null;
  if (!Array.isArray(guards) || !guards.every((g) => typeof g === 'string')) return null;
  if (!Array.isArray(revoked) || !revoked.every((r) => typeof r === 'string')) return null;
  if (!Array.isArray(sigs) || sigs.length > TRUSTED_GUARD_LIMITS.MAX_SIGNATURES) return null;
  const parsedSigs: Array<[string, Uint8Array]> = [];
  for (const s of sigs) {
    if (!Array.isArray(s) || s.length !== 2 || typeof s[0] !== 'string') return null;
    parsedSigs.push([s[0], toBytes(s[1])]);
  }
  return {
    content: { version: version as number, issuedAt, expiresAt, guards: guards as string[], revoked: revoked as string[] },
    sigs: parsedSigs,
  };
}

/**
 * 署名を検証せずにリストの中身だけを読む。
 *
 * ★ 信頼の判断には絶対に使わないこと (メンテナ用 CLI が、既存リストに署名を
 *   足すときに発行・失効時刻を揃えるためだけに使う)。
 */
export function readGuardListUnverified(text: string): GuardListContent | null {
  return decodeListString(text.trim())?.content ?? null;
}

/**
 * 信頼リストを検証する。1 つでも条件を満たさなければ、リスト全体を拒否する (fail-closed)。
 *
 * @param minVersion 手元で既に受け入れた最大の版。これより古い版は拒否する (巻き戻し防止)。
 *                   同じ版の再取り込みは許す。
 */
export function verifyGuardList(
  text: string,
  keyset: MaintainerKeySet,
  opts: { now?: number; minVersion?: number; powParams?: NodeIdPowParams } = {},
): GuardListResult {
  const now = opts.now ?? Date.now();
  if (typeof text === 'string' && text.length > TRUSTED_GUARD_LIMITS.MAX_STRING_LENGTH) {
    return { ok: false, reason: 'too-large' };
  }
  const decoded = decodeListString(typeof text === 'string' ? text.trim() : (text as any));
  if (!decoded) return { ok: false, reason: 'malformed' };
  const { content, sigs } = decoded;

  // 1. メンテナの署名 (k-of-n)。同じ鍵の署名は 1 つとしか数えない
  if (!keyset || !Array.isArray(keyset.keys) || keyset.keys.length === 0 ||
      !Number.isInteger(keyset.threshold) || keyset.threshold < 1 || keyset.threshold > keyset.keys.length) {
    return { ok: false, reason: 'no-keyset' };
  }
  const message = listMessage(content);
  const keysById = new Map(keyset.keys.map((k) => [maintainerKeyId(k), k]));
  const validSigners = new Set<string>();
  for (const [keyId, sig] of sigs) {
    const key = keysById.get(keyId);
    if (!key || validSigners.has(keyId) || sig.length !== sodium.crypto_sign_BYTES) continue;
    try {
      if (sodium.crypto_sign_verify_detached(sig, message, key)) validSigners.add(keyId);
    } catch {
      // 不正な署名は数えない
    }
  }
  if (validSigners.size < keyset.threshold) {
    return { ok: false, reason: 'insufficient-signatures', detail: `${validSigners.size}/${keyset.threshold}` };
  }

  // 2. 版と期間
  if (opts.minVersion !== undefined && content.version < opts.minVersion) {
    return { ok: false, reason: 'rollback', detail: `${content.version} < ${opts.minVersion}` };
  }
  if (content.expiresAt <= content.issuedAt || content.expiresAt - content.issuedAt > TRUSTED_GUARD_LIMITS.MAX_VALIDITY_MS) {
    return { ok: false, reason: 'validity-too-long' };
  }
  if (content.issuedAt > now + TRUSTED_GUARD_LIMITS.CLOCK_SKEW_MS) return { ok: false, reason: 'not-yet-valid' };
  if (now >= content.expiresAt) return { ok: false, reason: 'expired' };

  // 3. 各 Guard (運用者の署名・束縛・PoW)。1 つでも不正ならリスト全体を拒否する
  if (content.guards.length > TRUSTED_GUARD_LIMITS.MAX_GUARDS || content.revoked.length > TRUSTED_GUARD_LIMITS.MAX_REVOKED) {
    return { ok: false, reason: 'too-many-guards' };
  }
  const revoked = new Set(content.revoked);
  const seen = new Set<string>();
  const guards: TrustedGuard[] = [];
  for (const g of content.guards) {
    const parsed = parseGuardString(g, opts.powParams);
    if (!parsed) return { ok: false, reason: 'bad-guard' };
    if (seen.has(parsed.peerId)) return { ok: false, reason: 'bad-guard', detail: 'duplicate' };
    seen.add(parsed.peerId);
    if (!revoked.has(parsed.peerId)) guards.push(parsed);
  }

  return {
    ok: true,
    version: content.version,
    issuedAt: content.issuedAt,
    expiresAt: content.expiresAt,
    guards,
    revoked: content.revoked,
  };
}
