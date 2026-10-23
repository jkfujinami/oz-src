/**
 * ReedSolomon — GF(2^8) 上の組織的 (Systematic) Reed-Solomon (k=16, n=32) 符号エンジン。
 *
 * 設計仕様 (docs/design/03_storage_format.md §3.2):
 *   - データチャンク数 k = 16 (shareIndex 0..15)
 *   - パリティチャンク数 n - k = 16 (shareIndex 16..31)
 *   - 総チャンク数 n = 32
 *   - 任意の 16 チャンク (データ・パリティ問わず) から元の 16 データチャンクを完全復元する。
 *   - 64 KiB の事前計算乗算テーブル (MUL_TABLE) により、4 MiB チャンク群を高速にストリーム処理する。
 */

export const OZZY_RS_K = 16;
export const OZZY_RS_N = 32;
export const OZZY_RS_PARITY = OZZY_RS_N - OZZY_RS_K; // 16

// GF(2^8) 原始多項式: x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
const PRIM_POLY = 0x11d;
const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);
const MUL_TABLE = new Uint8Array(256 * 256);

let tablesInitialized = false;
// 生成行列 G (32 行 × 16 列): 上半分 16×16 は単位行列、下半分 16×16 は Cauchy 行列
const GEN_MATRIX = new Uint8Array(OZZY_RS_N * OZZY_RS_K);

function initTables(): void {
  if (tablesInitialized) return;
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x;
    LOG_TABLE[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= PRIM_POLY;
  }
  LOG_TABLE[0] = 0;

  for (let a = 0; a < 256; a++) {
    const rowOffset = a << 8;
    if (a === 0) continue;
    const logA = LOG_TABLE[a];
    for (let b = 1; b < 256; b++) {
      MUL_TABLE[rowOffset | b] = EXP_TABLE[logA + LOG_TABLE[b]];
    }
  }

  // 生成行列 G の構築
  tablesInitialized = true;
  // 行 0..15: 単位行列 I_16 (Systematic)
  for (let r = 0; r < OZZY_RS_K; r++) {
    GEN_MATRIX[r * OZZY_RS_K + r] = 1;
  }
  // 行 16..31: Cauchy 行列 C_{i, j} = 1 / (x_i ^ y_j) in GF(2^8)
  // x_i = i (i = 16..31), y_j = j (j = 0..15) => x_i ^ y_j != 0 for all i, j
  for (let r = OZZY_RS_K; r < OZZY_RS_N; r++) {
    for (let c = 0; c < OZZY_RS_K; c++) {
      const diff = r ^ c;
      GEN_MATRIX[r * OZZY_RS_K + c] = EXP_TABLE[255 - LOG_TABLE[diff]];
    }
  }
}

export function gfMul(a: number, b: number): number {
  initTables();
  return MUL_TABLE[(a << 8) | b];
}

export function gfInv(a: number): number {
  initTables();
  if (a === 0) throw new RangeError('GF(2^8) division by zero');
  return EXP_TABLE[255 - LOG_TABLE[a]];
}

/**
 * k × k 行列 (Uint8Array(k * k)) の GF(2^8) 逆行列をガウス・ジョルダン法で求める。
 */
export function invertMatrixGF256(mat: Uint8Array, k: number): Uint8Array {
  initTables();
  const work = new Uint8Array(mat);
  const inv = new Uint8Array(k * k);
  for (let i = 0; i < k; i++) inv[i * k + i] = 1;

  for (let col = 0; col < k; col++) {
    // ピボット選択
    let pivotRow = col;
    while (pivotRow < k && work[pivotRow * k + col] === 0) {
      pivotRow++;
    }
    if (pivotRow === k) {
      throw new Error('Matrix is singular in GF(2^8)');
    }
    // 行入れ替え
    if (pivotRow !== col) {
      for (let c = 0; c < k; c++) {
        const tmpW = work[col * k + c];
        work[col * k + c] = work[pivotRow * k + c];
        work[pivotRow * k + c] = tmpW;

        const tmpI = inv[col * k + c];
        inv[col * k + c] = inv[pivotRow * k + c];
        inv[pivotRow * k + c] = tmpI;
      }
    }
    // ピボット行を 1 に正規化
    const pivotVal = work[col * k + col];
    if (pivotVal !== 1) {
      const invPivot = gfInv(pivotVal);
      const mulRow = invPivot << 8;
      for (let c = 0; c < k; c++) {
        work[col * k + c] = MUL_TABLE[mulRow | work[col * k + c]];
        inv[col * k + c] = MUL_TABLE[mulRow | inv[col * k + c]];
      }
    }
    // 他の行を消去
    for (let row = 0; row < k; row++) {
      if (row === col) continue;
      const factor = work[row * k + col];
      if (factor !== 0) {
        const mulRow = factor << 8;
        for (let c = 0; c < k; c++) {
          work[row * k + c] ^= MUL_TABLE[mulRow | work[col * k + c]];
          inv[row * k + c] ^= MUL_TABLE[mulRow | inv[col * k + c]];
        }
      }
    }
  }
  return inv;
}

/**
 * 16 個のデータチャンク body (すべて同じバイト長 L) から 16 個のパリティチャンク body (shareIndex 16..31) を生成する。
 * ★ PARITY_JOB 支援ノード上でもそのまま実行可能 (データチャンクは暗号化済みのため平文は一切露出しない)。
 */
export function encodeRsParity(dataBodies: readonly Uint8Array[]): Uint8Array[] {
  initTables();
  if (dataBodies.length !== OZZY_RS_K) {
    throw new RangeError(`Expected ${OZZY_RS_K} data chunks, got ${dataBodies.length}`);
  }
  const bodyLen = dataBodies[0].length;
  for (let i = 1; i < OZZY_RS_K; i++) {
    if (dataBodies[i].length !== bodyLen) {
      throw new RangeError('All data chunk bodies must have identical byte length');
    }
  }

  const parityBodies: Uint8Array[] = [];
  for (let p = 0; p < OZZY_RS_PARITY; p++) {
    const out = new Uint8Array(bodyLen);
    const genRowOffset = (OZZY_RS_K + p) * OZZY_RS_K;

    for (let c = 0; c < OZZY_RS_K; c++) {
      const coeff = GEN_MATRIX[genRowOffset + c];
      if (coeff === 0) continue;
      const src = dataBodies[c];
      if (coeff === 1) {
        for (let i = 0; i < bodyLen; i++) {
          out[i] ^= src[i];
        }
      } else {
        const mulOffset = coeff << 8;
        for (let i = 0; i < bodyLen; i++) {
          out[i] ^= MUL_TABLE[mulOffset | src[i]];
        }
      }
    }
    parityBodies.push(out);
  }
  return parityBodies;
}

export interface RsShareInput {
  /** 0..31 のシェア番号 (0..15: データ, 16..31: パリティ) */
  shareIndex: number;
  /** チャンクの body 部分 (tag 16B を除いたバイト列) */
  body: Uint8Array;
}

/**
 * 任意の 16 個以上の利用可能なシェア (0..31) から、元の 16 個のデータチャンク body (0..15) を復元する。
 * 既にデータチャンク (0..15) に含まれているシェアはコピーのみで計算をスキップし、欠損しているデータチャンクのみ逆行列積で再構築する。
 */
export function reconstructRsData(availableShares: readonly RsShareInput[]): Uint8Array[] {
  initTables();
  if (availableShares.length < OZZY_RS_K) {
    throw new RangeError(`Need at least ${OZZY_RS_K} shares to reconstruct, got ${availableShares.length}`);
  }

  // 重複を排除し、shareIndex < 16 (データチャンク) を優先して先頭 16 個を選ぶ
  const seen = new Set<number>();
  const uniqueShares: RsShareInput[] = [];
  const sorted = [...availableShares].sort((a, b) => a.shareIndex - b.shareIndex);
  for (const s of sorted) {
    if (!Number.isInteger(s.shareIndex) || s.shareIndex < 0 || s.shareIndex >= OZZY_RS_N) {
      throw new RangeError(`Invalid shareIndex: ${s.shareIndex}`);
    }
    if (!seen.has(s.shareIndex)) {
      seen.add(s.shareIndex);
      uniqueShares.push(s);
      if (uniqueShares.length === OZZY_RS_K) break;
    }
  }
  if (uniqueShares.length < OZZY_RS_K) {
    throw new RangeError(`Need ${OZZY_RS_K} distinct shares, got ${uniqueShares.length}`);
  }

  const bodyLen = uniqueShares[0].body.length;
  for (let i = 1; i < OZZY_RS_K; i++) {
    if (uniqueShares[i].body.length !== bodyLen) {
      throw new RangeError('All share bodies must have identical length');
    }
  }

  // 高速パス: 0..15 のデータチャンクがすべて揃っている場合は逆行列計算不要
  const directMap = new Map<number, Uint8Array>();
  for (const s of uniqueShares) {
    if (s.shareIndex < OZZY_RS_K) {
      directMap.set(s.shareIndex, s.body);
    }
  }
  if (directMap.size === OZZY_RS_K) {
    const out: Uint8Array[] = [];
    for (let i = 0; i < OZZY_RS_K; i++) {
      out.push(new Uint8Array(directMap.get(i)!));
    }
    return out;
  }

  // 選ばれた 16 個のシェアに対応する生成部分行列 G_sub (16 × 16) を取り出し、逆行列 D = G_sub^{-1} を計算
  const subMat = new Uint8Array(OZZY_RS_K * OZZY_RS_K);
  for (let r = 0; r < OZZY_RS_K; r++) {
    const shareIdx = uniqueShares[r].shareIndex;
    for (let c = 0; c < OZZY_RS_K; c++) {
      subMat[r * OZZY_RS_K + c] = GEN_MATRIX[shareIdx * OZZY_RS_K + c];
    }
  }
  const decMat = invertMatrixGF256(subMat, OZZY_RS_K);

  // データチャンク d = 0..15 を復元 (既に手元にあるデータチャンクはそのまま使い、欠損分のみ行列積を実行)
  const reconstructed: Uint8Array[] = [];
  for (let d = 0; d < OZZY_RS_K; d++) {
    if (directMap.has(d)) {
      reconstructed.push(new Uint8Array(directMap.get(d)!));
      continue;
    }
    const out = new Uint8Array(bodyLen);
    const decRowOffset = d * OZZY_RS_K;
    for (let c = 0; c < OZZY_RS_K; c++) {
      const coeff = decMat[decRowOffset + c];
      if (coeff === 0) continue;
      const src = uniqueShares[c].body;
      if (coeff === 1) {
        for (let i = 0; i < bodyLen; i++) {
          out[i] ^= src[i];
        }
      } else {
        const mulOffset = coeff << 8;
        for (let i = 0; i < bodyLen; i++) {
          out[i] ^= MUL_TABLE[mulOffset | src[i]];
        }
      }
    }
    reconstructed.push(out);
  }

  return reconstructed;
}
