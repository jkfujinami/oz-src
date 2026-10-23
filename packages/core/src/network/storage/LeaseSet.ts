import sodium from '../../crypto/sodium';
import { ByteReader, ByteWriter } from '../../common/ByteIO';
import { Encoding } from '../../common/Encoding';
import { EQUIX_SOLUTION_BYTES } from '../../crypto/equix/EquiX';
import { MINUTE_MS, POW_POLICY, minutesToMs } from '../../crypto/PowPolicy';
import { MAX_SLOTS, SLOT_EFFORT, verifySlotSolution, type SlotSolution } from './SlotPow';

/**
 * LeaseSet — 「この保存用の身元 (SID) は、この位置の枠を持ち、この Guard の受け口で受け付ける」という署名つきの宣言
 * (history v2 §4.2)。全員が flood で受け取り、手元に持つ (問い合わせない = 誰が何に関心があるかが漏れない)。
 *
 *   offset  size   field
 *   0       1      version (= 1)
 *   1       32     SID_pub (Ed25519)
 *   33      1      slotCount (1..16)
 *   34      20 × n 各枠: nonce u32be ‖ Equi-X の解 16
 *   …       16     受け口 (gateway) の peerId (生の 16 バイト)
 *   …       8      tunnelId (SID と gateway の組ごとの乱数。B-b2 で gateway に登録する)
 *   …       3      expires: u24。OZ_EPOCH からの分
 *   …       64     署名: Ed25519 (SID) が、ここまでの全バイトに対して
 *   サイズ = 145 + 20 × (n − 1)。1 枠で 145、4 枠で 205、16 枠で 445。
 *
 * ★ IP は載せない。載るのは SID・枠・受け口の Guard の peerId だけ。監視ノードが全 leaseSet を集めても、
 *   「SID が Guard G の受け口を使っている」までしか分からず、保持者の IP には辿り着けない。
 * ★ SID は中継の peerId とは別の鍵。leaseSet から peerId (= 接続している相手) は引けない。
 */
export const LEASESET_VERSION = 1;
const SID_BYTES = 32;
const SLOT_ENTRY_BYTES = 4 + EQUIX_SOLUTION_BYTES;
const PEER_ID_BYTES = 16;
const TUNNEL_ID_BYTES = 8;
const SIGNATURE_BYTES = 64;
const FIXED_BYTES = 1 + SID_BYTES + 1 + PEER_ID_BYTES + TUNNEL_ID_BYTES + 3 + SIGNATURE_BYTES;
export const LEASESET_MIN_BYTES = FIXED_BYTES + SLOT_ENTRY_BYTES;
export const LEASESET_MAX_BYTES = FIXED_BYTES + MAX_SLOTS * SLOT_ENTRY_BYTES;

/** 期限の上限 (発行から) と更新の間隔 */
export const LEASESET_LIFETIME_MS = 6 * 60 * MINUTE_MS;
export const LEASESET_REPUBLISH_MS = 2 * 60 * MINUTE_MS;
/**
 * 同じ SID の leaseSet を置き換えてよい最短間隔 (受け手が、最後に受け付けた時刻から数える)。
 * ★ 期限が遅ければ置き換わる規則だけだと、保持者が分単位で署名し直して (オープンの網では受け口も毎回変えて)
 *   全員に flood し続けられる。置き換えは 10 分に 1 回までにして、flood の量に上限を付ける。
 *   最初の 1 件は常に受け付ける。
 */
export const LEASESET_MIN_REPLACE_MS = 10 * MINUTE_MS;
/**
 * 保持者が自分の leaseSet を出し直す最短間隔。受け手の規則 (10 分) にちょうど合わせると、
 * 配送の揺れ・時計の誤差で受け手に「早すぎる」と落とされるので、余裕を 30 秒足す。
 * 受け口の変更 (Guard の交代) もこの間隔に従う: 待つ間、読み手は古い受け口を試して失敗し、別の保持者へ回る (hedge)。
 */
export const LEASESET_PUBLISH_GAP_MS = LEASESET_MIN_REPLACE_MS + 30_000;

export interface LeaseSet {
  sid: Uint8Array;
  slots: SlotSolution[];
  /** 受け口の Guard の peerId (hex 32 文字) */
  gateway: string;
  tunnelId: Uint8Array;
  /** OZ_EPOCH からの分 */
  expiresMin: number;
  signature: Uint8Array;
  /** ワイヤ上のバイト列そのもの (id・再配布に使う) */
  bytes: Uint8Array;
}

export interface LeaseSetFields {
  sid: Uint8Array;
  slots: SlotSolution[];
  gateway: string;
  tunnelId: Uint8Array;
  expiresMin: number;
}

function body(f: LeaseSetFields): Uint8Array {
  if (f.sid.length !== SID_BYTES) throw new RangeError('LeaseSet: bad sid');
  if (f.slots.length < 1 || f.slots.length > MAX_SLOTS) throw new RangeError('LeaseSet: bad slot count');
  if (f.tunnelId.length !== TUNNEL_ID_BYTES) throw new RangeError('LeaseSet: bad tunnelId');
  if (!/^[0-9a-f]{32}$/.test(f.gateway)) throw new RangeError('LeaseSet: bad gateway');
  if (!Number.isInteger(f.expiresMin) || f.expiresMin < 0 || f.expiresMin > 0xffffff) throw new RangeError('LeaseSet: bad expiry');
  const w = new ByteWriter().u8(LEASESET_VERSION).raw(f.sid).u8(f.slots.length);
  for (const s of f.slots) {
    if (s.solution.length !== EQUIX_SOLUTION_BYTES) throw new RangeError('LeaseSet: bad solution');
    if (!Number.isInteger(s.nonce) || s.nonce < 0 || s.nonce > 0xffffffff) throw new RangeError('LeaseSet: bad nonce');
    w.u16(Math.floor(s.nonce / 0x10000)).u16(s.nonce % 0x10000).raw(s.solution);
  }
  return w
    .raw(Encoding.fromHex(f.gateway))
    .raw(f.tunnelId)
    .u8(f.expiresMin >>> 16).u8((f.expiresMin >>> 8) & 0xff).u8(f.expiresMin & 0xff)
    .finish();
}

/** 署名して、ワイヤのバイト列を作る。sign は SID の秘密鍵での Ed25519 署名 (64 バイト) */
export function signLeaseSet(f: LeaseSetFields, sign: (msg: Uint8Array) => Uint8Array): Uint8Array {
  const b = body(f);
  const sig = sign(b);
  if (sig.length !== SIGNATURE_BYTES) throw new RangeError('LeaseSet: bad signature size');
  const out = new Uint8Array(b.length + SIGNATURE_BYTES);
  out.set(b, 0);
  out.set(sig, b.length);
  return out;
}

/** 構造だけ読む (署名・PoW・期限は見ない)。壊れていれば null */
export function decodeLeaseSet(bytes: Uint8Array): LeaseSet | null {
  if (!(bytes instanceof Uint8Array) || bytes.length < LEASESET_MIN_BYTES || bytes.length > LEASESET_MAX_BYTES) return null;
  try {
    const r = new ByteReader(bytes);
    if (r.u8() !== LEASESET_VERSION) return null;
    const sid = r.bytes(SID_BYTES).slice();
    const n = r.u8();
    if (n < 1 || n > MAX_SLOTS) return null;
    const slots: SlotSolution[] = [];
    for (let i = 0; i < n; i++) {
      const nonce = r.u16() * 0x10000 + r.u16();
      slots.push({ nonce, solution: r.bytes(EQUIX_SOLUTION_BYTES).slice() });
    }
    const gateway = Encoding.toHex(r.bytes(PEER_ID_BYTES));
    const tunnelId = r.bytes(TUNNEL_ID_BYTES).slice();
    const expiresMin = (r.u8() << 16) | (r.u8() << 8) | r.u8();
    const signature = r.bytes(SIGNATURE_BYTES).slice();
    r.end();
    return { sid, slots, gateway, tunnelId, expiresMin, signature, bytes: bytes.slice() };
  } catch {
    return null;
  }
}

export type LeaseSetRejection = 'slot-count' | 'expired' | 'too-far' | 'untrusted-gateway' | 'bad-signature' | 'bad-slot-pow';

export interface LeaseSetVerifyContext {
  nowMs: number;
  /**
   * 受け口として認めてよい peerId か。信頼 Guard のリストが有効な間は「リストの Guard」だけ、
   * リストが無い網 (open) では全員を認める。判定は呼び出し側 (OzNode が GuardManager から作る)。
   */
  gatewayAllowed: (peerId: string) => boolean;
  /** ★ テスト専用。本番は SLOT_EFFORT 固定 (全ノードで同じでなければならない) */
  slotEffort?: number;
}

export type LeaseSetVerdict = { ok: true } | { ok: false; reason: LeaseSetRejection };

/**
 * leaseSet の検証。安い検査から順に行い、落とすなら早く落とす (flood で受け取る全員がやるため)。
 *   1. 枠の数 (1..16)  2. 期限が (now, now + 6 時間 + 時計のずれ]  3. 受け口  4. 署名  5. 各枠の PoW
 */
export function verifyLeaseSet(ls: LeaseSet, ctx: LeaseSetVerifyContext): LeaseSetVerdict {
  if (ls.slots.length < 1 || ls.slots.length > MAX_SLOTS) return { ok: false, reason: 'slot-count' };
  const expiresMs = minutesToMs(ls.expiresMin);
  if (expiresMs <= ctx.nowMs) return { ok: false, reason: 'expired' };
  // ★ 遠い未来の期限は拒否する。許すと、期限切れで消える仕組みが効かず、SID が居座れる
  if (expiresMs > ctx.nowMs + LEASESET_LIFETIME_MS + POW_POLICY.MAX_TIME_DRIFT) return { ok: false, reason: 'too-far' };
  if (!ctx.gatewayAllowed(ls.gateway)) return { ok: false, reason: 'untrusted-gateway' };

  const signed = ls.bytes.subarray(0, ls.bytes.length - SIGNATURE_BYTES);
  let sigOk = false;
  try {
    sigOk = sodium.crypto_sign_verify_detached(ls.signature, signed, ls.sid);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: 'bad-signature' };

  const effort = ctx.slotEffort ?? SLOT_EFFORT;
  for (let i = 0; i < ls.slots.length; i++) {
    if (!verifySlotSolution(ls.sid, i, ls.slots[i], effort)) return { ok: false, reason: 'bad-slot-pow' };
  }
  return { ok: true };
}

/** 重複排除用の id (バイト列全体のハッシュ。署名まで含むので、同じ内容でも署名が違えば別物) */
export function leaseSetId(bytes: Uint8Array): string {
  return Encoding.toHex(sodium.crypto_generichash(16, bytes, null));
}
