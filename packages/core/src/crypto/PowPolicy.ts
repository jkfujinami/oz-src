import sodium from './sodium';
import { equixSolve, equixVerify, EQUIX_SOLUTION_BYTES } from './equix/EquiX';

/**
 * PowPolicy — パケット v5 の PoW (Tor 式の Equi-X) と、網が受理する範囲の定数。
 *
 * ★ 申告値を信用しない。難易度 (effort) はヘッダに載るが、中継は「最低 effort」を自分で計算して
 *   それ未満を拒否する。effort はヘッダの 1 バイト (指数 e) で、PoW の challenge に入るので、
 *   解を使い回して高い effort を名乗ることはできない (名乗り直すと challenge が変わる)。
 *
 * PoW (Tor の Equi-X と同じ構成):
 *   C = BLAKE2b-256("OZ/v5/pow" ‖ version ‖ time ‖ tag ‖ age ‖ e ‖ SHA-256(payload))
 *   Equi-X の challenge = C ‖ nonce (u32be)
 *   解 s (16 バイト) が有効 ⇔ equixVerify(challenge, s) かつ
 *     u32be(BLAKE2b-256(C ‖ nonce ‖ s)[0..4]) * effort ≤ 0xFFFFFFFF
 *   solver は nonce を 0, 1, 2, … と試す。Equi-X は 1 試行で解が 0 個以上 (平均 1.47 個) 出る。
 *
 * ★ SHA-256 の hashcash (meetsDifficulty ほか) は NodeId PoW が使うので残してある。
 *   ゴシップのパケットでは使わない。
 */
export const POW_POLICY = {
  /**
   * 投稿本文の上限 (UTF-8 バイト)。5ch と同じ 2048。
   * 超える投稿は送る前に PacketBuilder が拒否する (UI はバイト数を見せる)。
   */
  MAX_CONTENT_BYTES: 2048,

  /** DAG の親の上限。固定長セルに収めるため (ThreadDAGManager.getTips も同じ値で絞る) */
  MAX_PARENTS: 2,

  /** スレ立ての thread_id の上限 (UTF-8 バイト)。返信には載らない */
  MAX_ID_BYTES: 32,

  /** 親 (packet_id) のバイト長。SHA-256 の先頭 16 バイト */
  PACKET_ID_BYTES: 16,

  /** 外側ヘッダのバイト数 (PacketCodec のレイアウト参照) */
  HEADER_BYTES: 28,

  /** SIV 暗号のタグ兼 nonce のバイト数 (PostCodec / CryptoEngine) */
  SIV_BYTES: 16,

  /**
   * 1 セル (= 1000 バイトまで) あたりの最低 effort。
   * 長い投稿は枚数に比例して払う (分割で網に掛ける負荷に見合う分だけ、フラッドが高くつく)。
   */
  MIN_EFFORT_PER_CELL: 1,
  /** 最低 effort を数えるセルの大きさ (パケットのバイト数) */
  EFFORT_CELL_BYTES: 1000,

  /** effort の指数 e の上限 (effort = floor(2^(e/4)) なので e=80 で 2^20) */
  MAX_EFFORT_EXP: 80,

  /** age (スレ立てからの日数) の上限。これを超えるパケットは中継が拒否する */
  MAX_AGE_DAYS: 90,

  /** tag は 12 ビット */
  TAG_BITS: 12,

  /** 許容する時刻ドリフト (ms)。SeenCache の TTL と揃える二重防御 */
  MAX_TIME_DRIFT: 15 * 60 * 1000,

  /**
   * ペイロード (= SIV 暗号文) の上限 (bytes)。
   *
   * ★ 「2048 バイトの本文 + 親 2 つ + スレ立ての最長 thread_id + 署名ブロック」がちょうど入る値。
   *   内訳 (PostCodec): siv 16 + flags 1 + (thread_id 1+32) + 親 2*16 + 署名ブロック 96 + 本文 2048 = 2226。
   *   トリップ有りでも署名ブロックは 96 (トリップ鍵 + 署名だけでセッション鍵は載らない)。
   */
  MAX_PAYLOAD_SIZE: 16 + 1 + (1 + 32) + 2 * 16 + 96 + 2048,
} as const;

/** パケットのバージョン (外側ヘッダの先頭 1 バイト)。v1 の SHA-256 形式は 1、v5 は 2 */
export const PACKET_VERSION = 2;

/** 時刻の起点 (分単位の u24 の 0)。2025-01-01T00:00:00Z */
export const OZ_EPOCH_MS = Date.UTC(2025, 0, 1);
export const MINUTE_MS = 60_000;
export const DAY_MS = 24 * 60 * 60 * 1000;

const enc = new TextEncoder();
export const POW_DOMAIN = enc.encode('OZ/v5/pow');
export const ID_DOMAIN = enc.encode('OZ/v5/id');

/** ms → 起点からの分 (u24)。範囲外は例外 */
export function msToMinutes(ms: number): number {
  const m = Math.floor((ms - OZ_EPOCH_MS) / MINUTE_MS);
  if (!Number.isSafeInteger(m) || m < 0 || m > 0xffffff) throw new RangeError(`time out of range: ${ms}`);
  return m;
}

export function minutesToMs(minutes: number): number {
  return OZ_EPOCH_MS + minutes * MINUTE_MS;
}

/** effort = floor(2^(e/4))。e=0 → 1 */
export function effortFromExp(e: number): number {
  if (!Number.isInteger(e) || e < 0 || e > POW_POLICY.MAX_EFFORT_EXP) throw new RangeError(`effort exponent out of range: ${e}`);
  return Math.floor(Math.pow(2, e / 4));
}

/** effort 以上を満たす最小の指数 e。量子化は 2^(1/4) ≒ 19% 刻み */
export function effortExpAtLeast(effort: number): number {
  const target = Math.max(1, Math.ceil(effort));
  for (let e = 0; e <= POW_POLICY.MAX_EFFORT_EXP; e++) {
    if (effortFromExp(e) >= target) return e;
  }
  return POW_POLICY.MAX_EFFORT_EXP;
}

/** パケット (ヘッダ込み) が何セル分か。最低 effort・推奨 effort・中継の予算のすべてがこの数え方を使う */
export function cellsFor(packetBytes: number): number {
  return Math.max(1, Math.ceil(packetBytes / POW_POLICY.EFFORT_CELL_BYTES));
}

/**
 * 長さ packetBytes (ヘッダ込み) のパケットに中継が要求する最低 effort。
 * 1000 バイトごとに MIN_EFFORT_PER_CELL (長い投稿は枚数分だけ払う)。
 */
export function minEffortFor(packetBytes: number): number {
  return POW_POLICY.MIN_EFFORT_PER_CELL * cellsFor(packetBytes);
}

/**
 * 作者が使う effort の指数。最低 effort を満たす最小の量子化値。
 * @param suggested 推奨 effort の**パケット全体の値** (= EffortAdvisor の 1 セルあたりの推奨 × セル数)。
 *   最低値より高ければそちらに合わせる。
 *   ★ 推奨は全員が同じ flood から手元で計算する (EffortAdvisor)。申告ではなく、各自が自分の都合で上乗せする値。
 *   中継が強制するのは最低値だけで、推奨に満たない投稿も (優先度が低いだけで) 受理される。
 */
export function effortFor(packetBytes: number, suggested?: number): { exp: number; effort: number } {
  const want = Math.max(minEffortFor(packetBytes), suggested ?? 0);
  const exp = effortExpAtLeast(want);
  return { exp, effort: effortFromExp(exp) };
}

/**
 * effort を解くのにかかる時間の目安 (ms、デスクトップの 1 スレッド)。
 * ★ Equi-X は 1 試行 ≒ 60ms で解が平均 1.47 個、effort E なら解の採用率は 1/E。よって 60 / 1.47 ≒ 41ms × E。
 *   UI が「時間がかかります」を出す判断と、推奨 effort の上限 (約 40 秒 / セル) の根拠。端末で数倍は違う。
 */
export const EQUIX_MS_PER_EFFORT = 41;
export function estimateSolveMs(effort: number): number {
  return effort * EQUIX_MS_PER_EFFORT;
}

/** PoW がコミットするヘッダの項目 (ワイヤのバイト表現と 1 対 1) */
export interface PowCommitted {
  version: number;
  /** 起点からの分 (u24) */
  time: number;
  /** 12 ビット */
  tag: number;
  /** スレ立てからの日数 */
  age: number;
  /** effort の指数 */
  effort_exp: number;
  payload: Uint8Array;
}

export interface PowSolution {
  /** Equi-X の challenge に付ける u32 */
  nonce: number;
  /** Equi-X の解 (16 バイト) */
  solution: Uint8Array;
}

export function u64be(value: number | bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), false);
  return buf;
}

export function u32be(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value >>> 0, false);
  return buf;
}

export function u16be(value: number): Uint8Array {
  const buf = new Uint8Array(2);
  new DataView(buf.buffer).setUint16(0, value & 0xffff, false);
  return buf;
}

export function u24be(value: number): Uint8Array {
  return Uint8Array.of((value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** 外側ヘッダの先頭 7 バイト (version ‖ time ‖ tag ‖ age)。SIV の AAD と packet_id の入力 */
export function headerPrefix(h: Pick<PowCommitted, 'version' | 'time' | 'tag' | 'age'>): Uint8Array {
  return concat([Uint8Array.of(h.version), u24be(h.time), u16be(h.tag), Uint8Array.of(h.age)]);
}

/** PoW の C。ヘッダ全体 (effort 込み) とペイロードのハッシュにコミットする */
export function powSeed(h: PowCommitted): Uint8Array {
  return sodium.crypto_generichash(
    32,
    concat([POW_DOMAIN, headerPrefix(h), Uint8Array.of(h.effort_exp), sodium.crypto_hash_sha256(h.payload)]),
    null,
  );
}

/** packet_id (16 バイト) の hex。effort / nonce / 解を含めないので、解き直しても変わらない */
export function derivePacketId(h: Pick<PowCommitted, 'version' | 'time' | 'tag' | 'age' | 'payload'>): string {
  const digest = sodium.crypto_hash_sha256(concat([ID_DOMAIN, headerPrefix(h), h.payload]));
  return sodium.to_hex(digest.slice(0, POW_POLICY.PACKET_ID_BYTES));
}

function challengeOf(seed: Uint8Array, nonce: number): Uint8Array {
  return concat([seed, u32be(nonce)]);
}

/** u32be(BLAKE2b-256(C ‖ nonce ‖ s)[0..4]) * effort ≤ 0xFFFFFFFF (積は 2^52 未満なので Number で正確) */
function meetsEffort(seed: Uint8Array, nonce: number, solution: Uint8Array, effort: number): boolean {
  const r = sodium.crypto_generichash(32, concat([seed, u32be(nonce), solution]), null);
  const v = ((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]) >>> 0;
  return v * effort <= 0xffffffff;
}

/**
 * PoW の検証。同期。申告された effort の指数 (e ≤ MAX_EFFORT_EXP) と解を確かめる。
 * 最低 effort (長さに応じた下限) は呼び出し側 (PacketValidator) が別に強制する。
 */
export function verifyPow(h: PowCommitted, sol: PowSolution): boolean {
  if (!Number.isInteger(h.effort_exp) || h.effort_exp < 0 || h.effort_exp > POW_POLICY.MAX_EFFORT_EXP) return false;
  if (!Number.isInteger(sol.nonce) || sol.nonce < 0 || sol.nonce > 0xffffffff) return false;
  if (sol.solution.length !== EQUIX_SOLUTION_BYTES) return false;
  const seed = powSeed(h);
  if (!equixVerify(challengeOf(seed, sol.nonce), sol.solution)) return false;
  return meetsEffort(seed, sol.nonce, sol.solution, effortFromExp(h.effort_exp));
}

/**
 * PoW の探索 (同期)。nonce を 0, 1, 2, … と試す。Worker からも Node からも呼ぶ。
 * @param maxAttempts 打ち切り (nonce の個数)。到達したら null
 */
export function solvePow(h: PowCommitted, maxAttempts: number = 0x1_0000_0000): PowSolution | null {
  if (!Number.isInteger(h.effort_exp) || h.effort_exp < 0 || h.effort_exp > POW_POLICY.MAX_EFFORT_EXP) {
    throw new RangeError(`solvePow: effort exponent out of range: ${h.effort_exp}`);
  }
  const effort = effortFromExp(h.effort_exp);
  const seed = powSeed(h);
  for (let nonce = 0; nonce < maxAttempts; nonce++) {
    for (const solution of equixSolve(challengeOf(seed, nonce))) {
      if (meetsEffort(seed, nonce, solution, effort)) return { nonce, solution };
    }
  }
  return null;
}

// ── SHA-256 hashcash (NodeId PoW が使う。ゴシップのパケットでは使わない) ──

/** ハッシュの先頭ゼロビット数が difficulty 以上かを判定する */
export function meetsDifficulty(hash: Uint8Array, difficulty: number): boolean {
  if (difficulty <= 0) return true;
  if (difficulty > hash.length * 8) return false;

  const fullBytes = difficulty >> 3;
  for (let i = 0; i < fullBytes; i++) {
    if (hash[i] !== 0) return false;
  }
  const remainBits = difficulty & 7;
  if (remainBits > 0) {
    const mask = (0xff << (8 - remainBits)) & 0xff;
    if ((hash[fullBytes] & mask) !== 0) return false;
  }
  return true;
}

/**
 * JSON や IndexedDB を経由したバイト列は Uint8Array / Array / Buffer / {data:[...]}
 * のいずれの形にもなり得るため、正規化してから正準化に掛ける。
 */
export function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  if (value && typeof value === 'object' && Array.isArray((value as any).data)) {
    return Uint8Array.from((value as any).data as number[]);
  }
  return new Uint8Array(0);
}
