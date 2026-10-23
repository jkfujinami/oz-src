/**
 * CloudLeaseSet — URL 秘匿と 24 時間オフライン可用性を両立する Split-Key LeaseSet 機構 & 一貫性ハッシュ配置リング。
 *
 * 設計仕様 (docs/design/04_placement.md §4.1 - §4.2, docs/design/05_lifetime.md §5.4):
 *   1. ProviderLeaseSet (0x60):
 *      - Tier 1 ストレージ提供者 (R2 + Gatekeeper Worker) のエンドポイント URL を封印して Gossip 同期。
 *      - 1 プロバイダあたり V = 16 個の仮想ノード (vnode) を一貫性ハッシュリング上に配置。
 *      - クラウド事業者多様性制約 (Provider Diversity Cap: 同一バックエンド最大 12 / 32 チャンク) を強制。
 *   2. SlabLeaseSet (0x61):
 *      - Tier 2 ロッカー Slab またはヤドカリ移設 (Hermit-Crab Migration) 先の URL をリース鍵 K_lease で暗号化封印。
 *      - K_lease から決定論的に導出した Ed25519 署名鍵で署名するため、リンク保持者は元のリンク [[ozzy:v2:...]] を
 *        1 文字も変えることなく新しい保管場所へファイルを引っ越し・昇格できる。
 *      - leaseSetId は署名公開鍵のハッシュ (OzzyKdf.leaseSetIdFromSignPubKey)。K_lease を知らない第三者は
 *        同じ識別子へ Lease を積めない。ディレクトリも K_lease 無しで確かめられる。
 *      - 同一 leaseSetId の Lease は先着順に最大 OZZY_MULTIHOME_LEASE_LIMIT 件まで持つ (新しいもので古いものを押し出さない)。
 *        押し出し式だと、リンクを持つ誰か (= K_lease を知る相手) が有効な署名のゴミ Lease を積むだけで、
 *        アップロードした本人の Lease を消せてしまう。
 */
import sodium, { sodiumReady } from '../crypto/sodium';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { Encoding } from '../common/Encoding';
import { ringDistance } from '../common/Ring';
import { bytesEqual } from '../files/FileFormat';
import {
  computeLeaseSetId,
  computeStripeRingPosition,
  deriveLeaseSignKeypair,
  leaseSetIdFromSignPubKey,
} from './OzzyKdf';
import { OZZY_RS_N } from './ReedSolomon';

export { deriveLeaseSignKeypair, leaseSetIdFromSignPubKey };

export const OZZY_MSG_PROVIDER_LEASESET = 0x60;
export const OZZY_MSG_SLAB_LEASESET = 0x61;
export const OZZY_VNODES_PER_PROVIDER = 16;
export const OZZY_MAX_SHARES_PER_BACKEND = 12;
export const OZZY_MULTIHOME_LEASE_LIMIT = 64;
/** SlabLeaseSet の有効期限の上限 (これより先の期限は受け付けない) */
export const OZZY_MAX_LEASE_LIFETIME_SEC = 400 * 86_400;

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export interface ProviderEndpointPayload {
  readonly workerUrl: string;
  readonly backendId: string; // "cloudflare-r2", "backblaze-b2", "oracle-s3" 等
  readonly authToken: string;
}

export interface ProviderLeaseSet {
  readonly version: number;
  readonly flags: number;
  readonly providerPubKey: Uint8Array; // 32 B Ed25519 PK
  readonly providerId: Uint8Array; // 32 B BLAKE2b-256(PK)
  readonly backendId: string; // 多様性キャップ計算用識別子
  readonly expiresAtSec: number;
  readonly freeDataSlots: number;
  readonly nonce: Uint8Array; // 24 B
  readonly sealedEndpoint: Uint8Array; // XChaCha20-Poly1305 暗号文
  readonly signature: Uint8Array; // 64 B Ed25519 署名
}

export interface SlabChunkSlotMapping {
  readonly shareIndex: number; // 0..31 (RS シェア番号)
  readonly slotOffsetIndex: number; // Slab ファイル内の何チャンク目か (byteOffset = slotOffsetIndex * chunkBytes)
}

export interface SlabEndpointPayload {
  readonly lockerId: string; // "catbox", "0x0.st", "lain.la", "qu.ax", "gofile", "pixeldrain" 等
  readonly downloadUrl: string;
  /** 常に空 (createSlabLeaseSet が空にする)。資格情報は Lease に入れない */
  readonly authToken: string;
  readonly supportsRange: boolean;
  /** シャッフル結合された Slab 内の [shareIndex <-> ファイル内チャンク位置] 対応表 */
  readonly chunkMap?: readonly SlabChunkSlotMapping[];
}

export interface SlabLeaseSet {
  readonly version: number;
  readonly slabChunkCount: number;
  readonly leaseSetId: Uint8Array; // 16 B
  readonly migrationSeq: number; // ヤドカリ移設世代番号 (1, 2, ...)
  readonly expiresAtSec: number;
  readonly leaseSignPubKey: Uint8Array; // 32 B Ed25519 PK (K_lease から決定論的導出)
  readonly nonce: Uint8Array; // 24 B
  readonly sealedLockerUrl: Uint8Array; // XChaCha20-Poly1305(key = K_lease)
  readonly signature: Uint8Array; // 64 B Ed25519 署名
}

/**
 * SSRF (Server-Side / Client-Side Request Forgery) 防御用の外部 HTTPS URL バリデータ。
 * 悪意あるノードが ProviderLeaseSet や SlabLeaseSet に `http://127.0.0.1` や `http://169.254.169.254` (クラウドメタデータ API)、
 * プライベート IP 帯、または `javascript:` / `file:` スキームを埋め込んで他の Fetcher にアクセスさせる攻撃を遮断する。
 */
export function isSafeExternalHttpsUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) return false;
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'https:') return false;
    if (u.username !== '' || u.password !== '') return false;

    const host = u.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host === '[::1]' ||
      host === '[::]' ||
      host.startsWith('[fe80:') ||
      host.startsWith('[fc') ||
      host.startsWith('[fd')
    ) {
      return false;
    }

    // IPv4 アドレス表記の場合はループバック・プライベート・リンクローカル帯 (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 0/8) を拒否
    const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (ipv4Match) {
      const octets = ipv4Match.slice(1, 5).map(x => parseInt(x, 10));
      if (octets.some(o => o < 0 || o > 255)) return false;
      const [a, b] = octets;
      if (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a >= 224
      ) {
        return false;
      }
    }

    return host.includes('.');
  } catch {
    return false;
  }
}

/**
 * ネットワーク共通の ProviderLeaseSet 封印鍵 (固定ドメインから導出)。
 * ★ 誰でも導出できる固定の鍵なので、秘匿ではなく「平文で流さない」程度の意味しかない。Worker の URL は公開情報として扱うこと。
 */
function getProviderNetworkSealKey(): Uint8Array {
  return sodium.crypto_generichash(32, enc.encode('ozzy-v2-provider-network-seal-key'), null);
}

function serializeProviderUnsigned(p: Omit<ProviderLeaseSet, 'signature'>): Uint8Array {
  const backendBytes = enc.encode(p.backendId);
  if (backendBytes.length < 1 || backendBytes.length > 64) throw new RangeError('Invalid backendId length');
  return new ByteWriter()
    .u8(OZZY_MSG_PROVIDER_LEASESET)
    .u8(p.version)
    .u16(p.flags)
    .raw(p.providerPubKey)
    .raw(p.providerId)
    .u8(backendBytes.length)
    .raw(backendBytes)
    .u64(BigInt(p.expiresAtSec))
    .u16((p.freeDataSlots >>> 16) & 0xffff)
    .u16(p.freeDataSlots & 0xffff)
    .raw(p.nonce)
    .varint(p.sealedEndpoint.length)
    .raw(p.sealedEndpoint)
    .finish();
}

/**
 * Tier 1 ストレージ提供者の ProviderLeaseSet を作成・封印・署名する。
 */
export async function createProviderLeaseSet(params: {
  providerPubKey: Uint8Array;
  providerPrivKey: Uint8Array;
  endpoint: ProviderEndpointPayload;
  expiresAtSec: number;
  freeDataSlots: number;
  flags?: number;
}): Promise<ProviderLeaseSet> {
  await sodiumReady;
  if (!isSafeExternalHttpsUrl(params.endpoint.workerUrl)) {
    throw new Error(`Unsafe or non-HTTPS workerUrl rejected: ${params.endpoint.workerUrl}`);
  }
  const providerId = sodium.crypto_generichash(32, params.providerPubKey, null);
  const sealKey = getProviderNetworkSealKey();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plainJson = enc.encode(JSON.stringify(params.endpoint));
  const sealedEndpoint = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plainJson,
    providerId,
    null,
    nonce,
    sealKey,
  );

  const unsigned: Omit<ProviderLeaseSet, 'signature'> = {
    version: 2,
    flags: params.flags ?? 0,
    providerPubKey: new Uint8Array(params.providerPubKey),
    providerId,
    backendId: params.endpoint.backendId,
    expiresAtSec: params.expiresAtSec,
    freeDataSlots: params.freeDataSlots,
    nonce,
    sealedEndpoint,
  };
  const unsignedBytes = serializeProviderUnsigned(unsigned);
  const signature = sodium.crypto_sign_detached(unsignedBytes, params.providerPrivKey);
  return { ...unsigned, signature };
}

/** ProviderLeaseSet の署名を検証する */
export async function verifyProviderLeaseSet(lease: ProviderLeaseSet, nowSec: number = Math.floor(Date.now() / 1000)): Promise<boolean> {
  await sodiumReady;
  if (lease.version !== 2) return false;
  if (lease.providerPubKey.length !== 32 || lease.providerId.length !== 32 || lease.signature.length !== 64) return false;
  if (lease.expiresAtSec <= nowSec) return false;
  const expectedPid = sodium.crypto_generichash(32, lease.providerPubKey, null);
  if (!bytesEqual(expectedPid, lease.providerId)) return false;
  try {
    const unsignedBytes = serializeProviderUnsigned(lease);
    return sodium.crypto_sign_verify_detached(lease.signature, unsignedBytes, lease.providerPubKey);
  } catch {
    return false;
  }
}

/** ProviderLeaseSet から Worker エンドポイント情報を開封し、SSRF 検査を行う */
export async function unsealProviderEndpoint(lease: ProviderLeaseSet): Promise<ProviderEndpointPayload | null> {
  await sodiumReady;
  try {
    const sealKey = getProviderNetworkSealKey();
    const plainBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      lease.sealedEndpoint,
      lease.providerId,
      lease.nonce,
      sealKey,
    );
    const parsed = JSON.parse(dec.decode(plainBytes)) as ProviderEndpointPayload;
    if (!parsed || typeof parsed.workerUrl !== 'string' || !isSafeExternalHttpsUrl(parsed.workerUrl)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function serializeSlabUnsigned(s: Omit<SlabLeaseSet, 'signature'>): Uint8Array {
  return new ByteWriter()
    .u8(OZZY_MSG_SLAB_LEASESET)
    .u8(s.version)
    .u16(s.slabChunkCount)
    .raw(s.leaseSetId)
    .u16((s.migrationSeq >>> 16) & 0xffff)
    .u16(s.migrationSeq & 0xffff)
    .u64(BigInt(s.expiresAtSec))
    .raw(s.leaseSignPubKey)
    .raw(s.nonce)
    .varint(s.sealedLockerUrl.length)
    .raw(s.sealedLockerUrl)
    .finish();
}

/**
 * Tier 2 ロッカー Slab (またはヤドカリ移設先) の URL を K_lease で暗号化封印し、SlabLeaseSet を作成する。
 */
export async function createSlabLeaseSet(params: {
  kLease: Uint8Array;
  slabChunkCount: number;
  migrationSeq: number;
  expiresAtSec: number;
  endpoint: SlabEndpointPayload;
}): Promise<SlabLeaseSet> {
  await sodiumReady;
  if (!isSafeExternalHttpsUrl(params.endpoint.downloadUrl)) {
    throw new Error(`Unsafe or non-HTTPS downloadUrl rejected: ${params.endpoint.downloadUrl}`);
  }
  const leaseSetId = await computeLeaseSetId(params.kLease);
  const signKp = await deriveLeaseSignKeypair(params.kLease);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  // ★ authToken は封印しない (常に空)。Lease はリンクを持つ全員が開けるので、ここに削除トークン・API キー・
  //   IA の秘密鍵を入れると、受け取った全員が Slab を消せる (旧版はロッカーの deleteToken をそのまま入れていた)。
  //   読み出しに資格情報が要るロッカー (Gofile) は、読む側がその都度使い捨てのゲスト ID を作る。
  const endpoint: SlabEndpointPayload = {
    lockerId: params.endpoint.lockerId,
    downloadUrl: params.endpoint.downloadUrl,
    authToken: '',
    supportsRange: params.endpoint.supportsRange,
    chunkMap: params.endpoint.chunkMap,
  };
  const plainBytes = enc.encode(JSON.stringify(endpoint));
  const sealedLockerUrl = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plainBytes,
    leaseSetId,
    null,
    nonce,
    params.kLease,
  );

  const unsigned: Omit<SlabLeaseSet, 'signature'> = {
    version: 2,
    slabChunkCount: params.slabChunkCount,
    leaseSetId,
    migrationSeq: params.migrationSeq,
    expiresAtSec: params.expiresAtSec,
    leaseSignPubKey: signKp.publicKey,
    nonce,
    sealedLockerUrl,
  };
  const unsignedBytes = serializeSlabUnsigned(unsigned);
  const signature = sodium.crypto_sign_detached(unsignedBytes, signKp.privateKey);
  signKp.privateKey.fill(0);
  return { ...unsigned, signature };
}

/**
 * SlabLeaseSet の署名を検証する (Gossip 中継ノードは K_lease を知らなくても署名と有効期限を検証できる!)
 */
export async function verifySlabLeaseSet(lease: SlabLeaseSet, nowSec: number = Math.floor(Date.now() / 1000)): Promise<boolean> {
  await sodiumReady;
  if (lease.version !== 2) return false;
  if (lease.leaseSetId.length !== 16 || lease.leaseSignPubKey.length !== 32 || lease.signature.length !== 64) {
    return false;
  }
  if (lease.expiresAtSec <= nowSec || lease.expiresAtSec > nowSec + OZZY_MAX_LEASE_LIFETIME_SEC) return false;
  try {
    // ★ 識別子が署名鍵に縛られているか (K_lease を知らない相手が同じ識別子へ Lease を積めない)
    if (!bytesEqual(lease.leaseSetId, leaseSetIdFromSignPubKey(lease.leaseSignPubKey))) return false;
    const unsignedBytes = serializeSlabUnsigned(lease);
    return sodium.crypto_sign_verify_detached(lease.signature, unsignedBytes, lease.leaseSignPubKey);
  } catch {
    return false;
  }
}

/**
 * Fetcher ノードが Reader から渡された K_lease を使って SlabLeaseSet の URL を開封する。
 * 同時に leaseSignPubKey が真の K_lease から導出されたものであることを検証し、偽造 Lease および SSRF URL を完全に弾く。
 */
export async function unsealSlabEndpoint(lease: SlabLeaseSet, kLease: Uint8Array): Promise<SlabEndpointPayload | null> {
  await sodiumReady;
  try {
    const expectedId = await computeLeaseSetId(kLease);
    if (!bytesEqual(expectedId, lease.leaseSetId)) return null;
    const expectedSignKp = await deriveLeaseSignKeypair(kLease);
    if (!bytesEqual(expectedSignKp.publicKey, lease.leaseSignPubKey)) return null;

    const plainBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      lease.sealedLockerUrl,
      lease.leaseSetId,
      lease.nonce,
      kLease,
    );
    const parsed = JSON.parse(dec.decode(plainBytes)) as SlabEndpointPayload;
    if (!parsed || typeof parsed.downloadUrl !== 'string' || !isSafeExternalHttpsUrl(parsed.downloadUrl)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * プロバイダの一貫性ハッシュリング上の仮想ノード位置 pos_{p, v} (v = 0..15) を計算する。
 */
export function computeProviderVnodePositions(providerId: Uint8Array): bigint[] {
  const positions: bigint[] = [];
  const prefix = enc.encode('ozzy-vnode-v2');
  for (let v = 0; v < OZZY_VNODES_PER_PROVIDER; v++) {
    const buf = new Uint8Array(prefix.length + providerId.length + 4);
    buf.set(prefix, 0);
    buf.set(providerId, prefix.length);
    new DataView(buf.buffer).setUint32(prefix.length + providerId.length, v, true);
    const h = sodium.crypto_generichash(16, buf, null);
    positions.push(new DataView(h.buffer, h.byteOffset, 8).getBigUint64(0, false));
  }
  return positions;
}

/**
 * ストライプ s の 32 チャンクを担当するプロバイダ集合を決定論的に選出する。
 *   - 制約 1: 同一 providerId は 1 ストライプにつき最大 1 回のみ選出。
 *   - 制約 2 (Provider Diversity Cap): 同一 backendId (例: "cloudflare-r2") は最大 maxPerBackend (既定 12) まで。
 *     ただし候補プロバイダ全体の他バックエンド数が不足している場合は、まず多様性キャップ内で選出し、
 *     足りない枠を残りプロバイダまたは Tier 2 スピルオーバー枠として補完する。
 */
export function selectStripeProviders(
  kLoc: Uint8Array,
  stripeIndex: number,
  providers: readonly ProviderLeaseSet[],
  targetCount: number = OZZY_RS_N,
  maxPerBackend: number = OZZY_MAX_SHARES_PER_BACKEND,
): ProviderLeaseSet[] {
  if (providers.length === 0) return [];
  const targetPos = computeStripeRingPosition(kLoc, stripeIndex);

  // 全プロバイダの仮想ノードを展開して targetPos からのリング距離順にソート
  const vnodes: { provider: ProviderLeaseSet; pos: bigint; dist: bigint; pidHex: string }[] = [];
  for (const p of providers) {
    const pidHex = Encoding.toHex(p.providerId);
    for (const pos of computeProviderVnodePositions(p.providerId)) {
      vnodes.push({
        provider: p,
        pos,
        dist: ringDistance(targetPos, pos),
        pidHex,
      });
    }
  }

  vnodes.sort((a, b) => {
    if (a.dist !== b.dist) return a.dist < b.dist ? -1 : 1;
    if (a.pos !== b.pos) return a.pos < b.pos ? -1 : 1;
    return a.pidHex.localeCompare(b.pidHex);
  });

  const chosen: ProviderLeaseSet[] = [];
  const usedPid = new Set<string>();
  const backendCounts = new Map<string, number>();
  const deferredByCap: ProviderLeaseSet[] = [];

  for (const vn of vnodes) {
    if (chosen.length >= targetCount) break;
    if (usedPid.has(vn.pidHex)) continue;

    const currentCount = backendCounts.get(vn.provider.backendId) ?? 0;
    if (currentCount >= maxPerBackend) {
      usedPid.add(vn.pidHex);
      deferredByCap.push(vn.provider);
      continue;
    }

    usedPid.add(vn.pidHex);
    backendCounts.set(vn.provider.backendId, currentCount + 1);
    chosen.push(vn.provider);
  }

  // 単一バックエンドしか登録されていない初期環境でも 32 チャンク選出できるようフォールバック補完
  for (const p of deferredByCap) {
    if (chosen.length >= targetCount) break;
    chosen.push(p);
  }

  return chosen;
}

export interface RemoteLeaseSetDirectoryBridge {
  publishSlabLease(leaseSetIdHex: string, leaseBase64: string): Promise<void>;
  fetchSlabLeases(leaseSetIdHex: string): Promise<string[]>;
}

/** SlabLeaseSet をバイト列にする (署名対象 ‖ 署名 64 B)。ディレクトリ (Worker) と同じ形式 */
export function encodeSlabLeaseSet(lease: SlabLeaseSet): Uint8Array {
  const unsigned = serializeSlabUnsigned(lease);
  const out = new Uint8Array(unsigned.length + 64);
  out.set(unsigned, 0);
  out.set(lease.signature, unsigned.length);
  return out;
}

/** encodeSlabLeaseSet の逆。形が壊れていれば null (署名の検証は verifySlabLeaseSet) */
export function decodeSlabLeaseSet(bytes: Uint8Array): SlabLeaseSet | null {
  try {
    const r = new ByteReader(bytes);
    if (r.u8() !== OZZY_MSG_SLAB_LEASESET) return null;
    const version = r.u8();
    const slabChunkCount = r.u16();
    const leaseSetId = r.bytes(16).slice();
    const migrationSeq = ((r.u16() << 16) | r.u16()) >>> 0;
    const expiresAtSec = Number(r.u64());
    const leaseSignPubKey = r.bytes(32).slice();
    const nonce = r.bytes(24).slice();
    const sealedLen = r.varint();
    if (sealedLen > 16 * 1024) return null;
    const sealedLockerUrl = r.bytes(sealedLen).slice();
    const signature = r.bytes(64).slice();
    r.end();
    if (!Number.isSafeInteger(expiresAtSec)) return null;
    return { version, slabChunkCount, leaseSetId, migrationSeq, expiresAtSec, leaseSignPubKey, nonce, sealedLockerUrl, signature };
  } catch {
    return null;
  }
}

export function serializeSlabLeaseSetToBase64(lease: SlabLeaseSet): string {
  return Encoding.toBase64(encodeSlabLeaseSet(lease));
}

export function deserializeSlabLeaseSetFromBase64(b64: string): SlabLeaseSet | null {
  if (typeof b64 !== 'string' || b64.length > 24 * 1024 || !/^[A-Za-z0-9_-]+$/.test(b64)) return null;
  try {
    return decodeSlabLeaseSet(Encoding.fromBase64(b64));
  } catch {
    return null;
  }
}

// ★ 旧 createWorkerLeaseSetDirectoryBridge (共通の Worker の /ozzy/v2/leaseset へ Lease を出し入れする) は廃止。
//   Ozzy の置き場所は Manifest v4 に入れ、Manifest は P2P のファイル保管に置く (OzzyManifestStore)。

/**
 * 全 P2P ノードがメモリ上に保持する CloudLeaseSet Gossip ストア。
 * remoteBridge を渡すと、アップロード時に暗号化済み SlabLeaseSet をネットワークへ自動 Publish し、
 * 別端末でのダウンロード時に `resolveSlabLeases()` で自動取得・署名検証を行う。
 */
export class CloudLeaseSetStore {
  private readonly providers = new Map<string, ProviderLeaseSet>();
  private readonly slabs = new Map<string, SlabLeaseSet[]>();

  constructor(private readonly remoteBridge?: RemoteLeaseSetDirectoryBridge) {}

  async upsertProvider(lease: ProviderLeaseSet, nowSec: number = Math.floor(Date.now() / 1000)): Promise<boolean> {
    if (!(await verifyProviderLeaseSet(lease, nowSec))) return false;
    const key = Encoding.toHex(lease.providerId);
    const existing = this.providers.get(key);
    if (existing && existing.expiresAtSec >= lease.expiresAtSec) {
      return false;
    }
    this.providers.set(key, lease);
    return true;
  }

  /**
   * SlabLeaseSet を加える。署名・識別子と鍵の結び付き・期限を確かめ、同じ署名の重複は入れない。
   * ★ 先着順に OZZY_MULTIHOME_LEASE_LIMIT 件まで (期限切れは先に捨てる)。満杯なら新しいものを入れない。
   */
  async upsertSlab(
    lease: SlabLeaseSet,
    nowSec: number = Math.floor(Date.now() / 1000),
    skipRemotePublish: boolean = false,
  ): Promise<boolean> {
    if (!(await verifySlabLeaseSet(lease, nowSec))) return false;
    const key = Encoding.toHex(lease.leaseSetId);
    const list = (this.slabs.get(key) ?? []).filter(item => item.expiresAtSec > nowSec);
    if (list.some(item => bytesEqual(item.signature, lease.signature))) {
      this.slabs.set(key, list);
      return false;
    }
    if (list.length >= OZZY_MULTIHOME_LEASE_LIMIT) {
      this.slabs.set(key, list);
      return false;
    }
    list.push(lease);
    this.slabs.set(key, list);

    if (this.remoteBridge && !skipRemotePublish) {
      await this.remoteBridge.publishSlabLease(key, serializeSlabLeaseSetToBase64(lease));
    }
    return true;
  }

  getActiveProviders(nowSec: number = Math.floor(Date.now() / 1000)): ProviderLeaseSet[] {
    const out: ProviderLeaseSet[] = [];
    for (const p of this.providers.values()) {
      if (p.expiresAtSec > nowSec) out.push(p);
    }
    return out;
  }

  /** 期限内の Lease。ヤドカリ移設の新しい世代 (migrationSeq の大きい順) を先に */
  getSlabLeases(leaseSetId: Uint8Array, nowSec: number = Math.floor(Date.now() / 1000)): SlabLeaseSet[] {
    const key = Encoding.toHex(leaseSetId);
    const list = this.slabs.get(key) ?? [];
    return list.filter(item => item.expiresAtSec > nowSec).sort((a, b) => b.migrationSeq - a.migrationSeq);
  }

  /**
   * ローカルストアに SlabLeaseSet が無い場合 (別端末からリンク `[[ozzy:v2:...]]` だけを受け取った場合など)、
   * 外部ディレクトリ / Gossip ブリッジから暗号化済み SlabLeaseSet を自動取得し、署名と識別子の結び付きを検証した上で返す。
   */
  async resolveSlabLeases(leaseSetId: Uint8Array, nowSec: number = Math.floor(Date.now() / 1000)): Promise<SlabLeaseSet[]> {
    const local = this.getSlabLeases(leaseSetId, nowSec);
    if (local.length > 0 || !this.remoteBridge) {
      return local;
    }
    const key = Encoding.toHex(leaseSetId);
    const remoteB64List = await this.remoteBridge.fetchSlabLeases(key);
    for (const b64 of remoteB64List.slice(0, OZZY_MULTIHOME_LEASE_LIMIT * 2)) {
      const decoded = deserializeSlabLeaseSetFromBase64(b64);
      if (decoded && bytesEqual(decoded.leaseSetId, leaseSetId)) {
        await this.upsertSlab(decoded, nowSec, true);
      }
    }
    return this.getSlabLeases(leaseSetId, nowSec);
  }
}

export { ByteReader };
