import { EQUIX_WASM_BASE64 } from './equixWasm';

/**
 * EquiX — Tor の PoW (Equi-X) を Wasm で呼ぶ薄い層。
 *
 * ★ Equi-X は「解くのは重く (約 60ms / 試行・解は平均 1.47 個)、検証は軽い (約 20µs)」ように作られた
 *   メモリ・計算ハードな PoW。SHA-256 の hashcash は ASIC / GPU で桁違いに安く解けるが、Equi-X は
 *   汎用 CPU 向けなので、攻撃者の有利が小さい。Tor が onion service の DoS 対策に使っているものと同じ。
 * ★ Wasm は packages/pow-wasm (Rust の `equix` crate) を `npm run build:pow-wasm` でビルドし、
 *   base64 の文字列として埋め込んである (equixWasm.ts)。バンドラの設定なしに、ブラウザ・Worker・
 *   Node・Electron のどこでも同じ方法で読める。
 * ★ 読み込みは非同期 (WebAssembly.instantiate)。ブラウザのメインスレッドは大きな Wasm の
 *   同期コンパイルを禁じているため。呼び出し側は起動時に `await equixReady` する
 *   (OzNode.create / PoW Worker / テストの setup)。その後の solve / verify は同期。
 */

/** 解 (Equi-X の proof) のバイト長 */
export const EQUIX_SOLUTION_BYTES = 16;

interface EquixExports {
  memory: WebAssembly.Memory;
  buf_ptr: () => number;
  solve: (len: number) => number;
  verify: (len: number) => number;
}

let wasm: EquixExports | null = null;

function decodeBase64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Wasm の読み込みが終われば解決する。何度 await しても同じ Promise (instantiate は 1 回) */
export const equixReady: Promise<void> = WebAssembly.instantiate(decodeBase64(EQUIX_WASM_BASE64), {}).then(
  ({ instance }) => {
    wasm = instance.exports as unknown as EquixExports;
  },
);

function ready(): EquixExports {
  // ★ 黙って false を返さない。読み込み前の verify が「不正」に見えると、正規の投稿が捨てられる
  if (!wasm) throw new Error('Equi-X wasm is not ready: await equixReady first');
  return wasm;
}

/**
 * challenge を解く。解は 0 個以上 (平均 1.47 個)。0 個なら、呼び出し側が challenge を変えて再試行する。
 * 失敗 (challenge の長さが範囲外など) は例外。
 */
export function equixSolve(challenge: Uint8Array): Uint8Array[] {
  const w = ready();
  if (challenge.length === 0 || challenge.length > 1024) throw new RangeError('equixSolve: bad challenge length');
  // memory.buffer は grow で入れ替わることがあるので、呼ぶたびに取り直す
  const base = w.buf_ptr();
  new Uint8Array(w.memory.buffer, base, challenge.length).set(challenge);
  const n = w.solve(challenge.length);
  if (n === 0xffffffff) throw new Error('equixSolve: wasm error');
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    out.push(new Uint8Array(w.memory.buffer, base + challenge.length + i * EQUIX_SOLUTION_BYTES, EQUIX_SOLUTION_BYTES).slice());
  }
  return out;
}

/** challenge に対する解 (16 バイト) が正しいか。長さが違えば false */
export function equixVerify(challenge: Uint8Array, solution: Uint8Array): boolean {
  const w = ready();
  if (solution.length !== EQUIX_SOLUTION_BYTES) return false;
  if (challenge.length === 0 || challenge.length > 1024) return false;
  const base = w.buf_ptr();
  const mem = new Uint8Array(w.memory.buffer, base, challenge.length + EQUIX_SOLUTION_BYTES);
  mem.set(challenge, 0);
  mem.set(solution, challenge.length);
  return w.verify(challenge.length) === 1;
}
