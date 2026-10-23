/**
 * Ring — 64 ビットのリング上の位置と距離 (過去ログの担当ゾーンと大容量ファイルの置き場所で共有する)。
 *
 * ★ 位置は「ハッシュの先頭 8 バイト (ビッグエンディアン)」を bigint にしたもの。
 *   number だと 2^53 を超えて丸まり、距離の比較が狂う。
 * ★ 同順位の決め方まで固定する (距離 → 位置 → id)。担当の選び方が端末ごとにずれると、
 *   置いた先と取りに行く先が食い違い、ファイルが「あるのに見つからない」になる。
 */
import sodium from '../crypto/sodium';

export const RING_SIZE = 1n << 64n;

export interface RingEntry {
  id: Uint8Array;
  position: bigint;
}

/** ハッシュの先頭 8 バイトを 64 ビット位置にする */
export function positionFromHash(hash: Uint8Array): bigint {
  if (hash.length < 8) throw new RangeError('hash too short');
  return new DataView(hash.buffer, hash.byteOffset, 8).getBigUint64(0, false);
}

/** リング上の最短距離 (2^64 を回り込む) */
export function ringDistance(a: bigint, b: bigint): bigint {
  const d = (a >= b ? a - b : b - a) % RING_SIZE;
  return d <= RING_SIZE - d ? d : RING_SIZE - d;
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

/**
 * BLAKE2b-256(len(domain) ‖ domain ‖ (len(part) ‖ part)...) の先頭 8 バイト。
 * ★ 可変長の部品には長さを前置する。前置しないと ("ab","c") と ("a","bc") が同じ位置になる。
 * ★ 呼ぶ前に sodiumReady を await しておくこと。
 */
export function positionOf(domain: string, ...parts: Uint8Array[]): bigint {
  const d = new TextEncoder().encode(domain);
  const chunks: Uint8Array[] = [u32be(d.length), d];
  for (const p of parts) chunks.push(u32be(p.length), p);
  let total = 0;
  for (const c of chunks) total += c.length;
  const buf = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    buf.set(c, o);
    o += c.length;
  }
  return positionFromHash(sodium.crypto_generichash(32, buf, null));
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** target に近い順に k 個。距離 → 位置 → id の順で決定的に並べる (入力順に依存しない) */
export function closest<T extends RingEntry>(target: bigint, candidates: readonly T[], k: number): T[] {
  if (k <= 0) return [];
  const keyed = candidates.map(c => ({ c, d: ringDistance(target, c.position) }));
  keyed.sort((x, y) => {
    if (x.d !== y.d) return x.d < y.d ? -1 : 1;
    if (x.c.position !== y.c.position) return x.c.position < y.c.position ? -1 : 1;
    return compareBytes(x.c.id, y.c.id);
  });
  return keyed.slice(0, k).map(x => x.c);
}
