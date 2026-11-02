import fs from 'node:fs';
import path from 'node:path';

const JA = /[぀-ヿ㐀-鿿！-｠]/;

/**
 * 画面のコードで、日本語の文字列が直書きされている行 (コメントを除く) を探す。
 * ★ コメント (//・/* … *\/・{/* … *\/}) の日本語は数えない。行末に `i18n-ignore` と書いた行も数えない
 *   (画面に出さない文字列だけに使う)。src/i18n/ (文言そのもの) は見ない。
 */
export function scanJapaneseLiterals(srcDir: string): Map<string, number[]> {
  const out = new Map<string, number[]>();
  const walk = (dir: string) => {
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      if (fs.statSync(p).isDirectory()) {
        if (path.relative(srcDir, p) === 'i18n') continue;
        walk(p);
        continue;
      }
      if (!/\.(tsx?|mts)$/.test(name)) continue;
      const lines = fs.readFileSync(p, 'utf8').split('\n');
      let inBlock = false;
      const hits: number[] = [];
      lines.forEach((raw, i) => {
        let line = raw;
        if (line.includes('i18n-ignore')) return;
        // ブロックコメントを除く (行をまたぐものも)
        let code = '';
        let j = 0;
        while (j < line.length) {
          if (inBlock) {
            const end = line.indexOf('*/', j);
            if (end < 0) { j = line.length; break; }
            inBlock = false;
            j = end + 2;
            continue;
          }
          const start = line.indexOf('/*', j);
          const lineComment = findLineComment(line, j);
          if (lineComment >= 0 && (start < 0 || lineComment < start)) {
            code += line.slice(j, lineComment);
            j = line.length;
            break;
          }
          if (start < 0) { code += line.slice(j); break; }
          code += line.slice(j, start);
          inBlock = true;
          j = start + 2;
        }
        line = code;
        if (JA.test(line)) hits.push(i + 1);
      });
      if (hits.length > 0) out.set(path.relative(srcDir, p).split(path.sep).join('/'), hits);
    }
  };
  walk(srcDir);
  return out;
}

/** 文字列の外にある // の位置 (無ければ -1)。https:// などを文字列の中と見なす簡易版 */
function findLineComment(line: string, from: number): number {
  let quote: string | null = null;
  for (let i = from; i < line.length - 1; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '/' && line[i + 1] === '/') return i;
  }
  return -1;
}
