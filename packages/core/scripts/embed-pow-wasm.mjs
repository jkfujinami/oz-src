// packages/pow-wasm でビルドした Wasm を、base64 の文字列として TS モジュールに埋め込む。
// ★ 生成物 (src/crypto/equix/equixWasm.ts) はコミットする。Rust の環境が無くても
//   `npm run build:core` が通り、ブラウザ・Worker・Node・Electron のどこでも
//   バンドラの設定なしで同じ方法 (base64 → WebAssembly.instantiate) で読める。
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = resolve(here, '../../pow-wasm/target/wasm32-unknown-unknown/release/oz_pow_wasm.wasm');
const outPath = resolve(here, '../src/crypto/equix/equixWasm.ts');

const bytes = readFileSync(wasmPath);
const b64 = bytes.toString('base64');
const lines = b64.match(/.{1,120}/g) ?? [];
const body = [
  '// 自動生成: `npm run build:pow-wasm` (packages/pow-wasm の Rust を Wasm にして埋め込む)。手で編集しない。',
  `// ${bytes.length} バイト`,
  'export const EQUIX_WASM_BASE64 =',
  ...lines.map((l, i) => `  '${l}'${i === lines.length - 1 ? ';' : ' +'}`),
  '',
].join('\n');
writeFileSync(outPath, body);
console.log(`wrote ${outPath} (${bytes.length} bytes wasm)`);
