/**
 * プロトコル適合ベクタの生成器 (テストではない)。
 *
 * ★ これを走らせるのは「ワイヤ形式・暗号の符号化を意図的に変えたとき」だけ。
 *   ProtocolConformance.test.ts が落ちたからといって安易に再生成しないこと。
 *   落ちたということは、既存ノードとの互換性が壊れたということである。
 *
 * 実行方法 (packages/core で):
 *
 *   npx esbuild tests/protocol/generateVectors.ts --bundle --platform=node --format=cjs \
 *     --outfile=node_modules/.cache/oz-generate-vectors.cjs --log-level=warning \
 *   && node node_modules/.cache/oz-generate-vectors.cjs tests/protocol/vectors/core_protocol_vectors.json
 *
 * 出力先は第 1 引数 (既定: tests/protocol/vectors/core_protocol_vectors.json, cwd 基準)。
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { buildGoldenVectors } from './goldenInputs';

async function main() {
  const out = resolve(process.cwd(), process.argv[2] ?? 'tests/protocol/vectors/core_protocol_vectors.json');
  const vectors = await buildGoldenVectors();
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n');
  console.log(`wrote ${out}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
