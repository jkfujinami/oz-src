// 利用規約 (packages/ui/src/lib/terms.ts) から TERMS.md を書き出す: npm run terms
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { termsMarkdown } from '../packages/ui/src/lib/terms';

writeFileSync(fileURLToPath(new URL('../TERMS.md', import.meta.url)), termsMarkdown());
