/**
 * パスワードの強度の目安と、覚えやすい長いパスワードの生成。すべて端末内で完結する。
 */

/** 乱数 [0, max) を偏りなく引く (剰余の偏りを棄却法で避ける) */
function randomBelow(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

/**
 * 発音しやすい音節 (ローマ字のかな)。60 個なので 1 音節あたり約 5.9 bit。
 * 辞書の単語ではなく音節の組み合わせなので、単語リストを持ち歩かずに済む。
 */
const SYLLABLES = [
  'ka', 'ki', 'ku', 'ke', 'ko', 'sa', 'shi', 'su', 'se', 'so',
  'ta', 'chi', 'tsu', 'te', 'to', 'na', 'ni', 'nu', 'ne', 'no',
  'ha', 'hi', 'fu', 'he', 'ho', 'ma', 'mi', 'mu', 'me', 'mo',
  'ya', 'yu', 'yo', 'ra', 'ri', 'ru', 're', 'ro', 'wa', 'ga',
  'gi', 'gu', 'ge', 'go', 'za', 'ji', 'zu', 'ze', 'zo', 'da',
  'de', 'do', 'ba', 'bi', 'bu', 'be', 'bo', 'pa', 'pi', 'pu',
];

export const GENERATED_WORDS = 4;
export const SYLLABLES_PER_WORD = 3;

/**
 * 4 つの「語」(3 音節ずつ) をハイフンでつないだパスワードを作る。
 * 例: `kemiro-sunoha-tagupi-rebuzo`。60^12 通り (約 71 bit)、27 文字。
 */
export function generatePassphrase(): string {
  const words: string[] = [];
  for (let w = 0; w < GENERATED_WORDS; w++) {
    let word = '';
    for (let s = 0; s < SYLLABLES_PER_WORD; s++) word += SYLLABLES[randomBelow(SYLLABLES.length)];
    words.push(word);
  }
  return words.join('-');
}

export type StrengthLevel = 'empty' | 'short' | 'weak' | 'fair' | 'strong';

export interface PassphraseStrength {
  level: StrengthLevel;
  /** 画面に出す短い説明 */
  label: string;
  /** 推定ビット数 (目安。実際の総当たりの難しさを保証するものではない) */
  bits: number;
}

/**
 * 強度の目安。使われている文字種の数と長さから見積もり、
 * 同じ文字の繰り返し・連番・よくある並びは割り引く。
 * あくまで目安で、辞書攻撃への強さまでは見ていない。
 */
export function estimateStrength(passphrase: string, minLength: number): PassphraseStrength {
  if (passphrase.length === 0) return { level: 'empty', label: '', bits: 0 };

  let pool = 0;
  if (/[a-z]/.test(passphrase)) pool += 26;
  if (/[A-Z]/.test(passphrase)) pool += 26;
  if (/[0-9]/.test(passphrase)) pool += 10;
  if (/[^A-Za-z0-9]/.test(passphrase)) pool += 32;
  if (/[^\x00-\x7f]/.test(passphrase)) pool += 100; // かな・漢字など

  // 重複する文字は新しい情報を足さないので、異なる文字の数で数える (繰り返しの割引)
  const distinct = new Set(passphrase).size;
  // 0.6 は「人が選んだ文字列は一様な乱数より推測しやすい」ことの割引
  let bits = Math.log2(Math.max(pool, 2)) * Math.min(passphrase.length, distinct * 2) * 0.6;

  // 連番・キーボード順は大きく割り引く
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv|password|パスワード)/i.test(passphrase)) {
    bits = Math.min(bits, 28);
  }

  if (passphrase.length < minLength) {
    return { level: 'short', label: `短すぎます (あと ${minLength - passphrase.length} 文字)`, bits };
  }
  if (bits < 40) return { level: 'weak', label: '弱い: 長さや文字の種類を増やしてください', bits };
  if (bits < 60) return { level: 'fair', label: 'まずまず: もう少し長いとより安全です', bits };
  return { level: 'strong', label: '強い', bits };
}
