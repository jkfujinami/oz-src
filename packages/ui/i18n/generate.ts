/// <reference path="./js-yaml.d.ts" />
/**
 * 画面の文言 (packages/ui/locales/*.yaml) を検査して、型付きの TypeScript (src/i18n/messages.gen.ts) にする。
 *
 *   npm run i18n -w @oz/ui      (YAML を直したら実行する。生成物は commit する)
 *
 * ★ YAML は組み立て時にだけ読む。利用者の端末には YAML の読み取り部品を載せず、実行時に何も取りに行かない。
 * ★ 検査 (どれかに当たれば生成しない):
 *   - キーは英数字と _ の段を . でつないだもの。値は文字列か、複数形の表 ({ one, other } など。other は必須)
 *   - 既定の言語 (ja) に無いキーを、ほかの言語に書かない
 *   - 同じキーの差し込み ({count}) と部品の印 (<link>…</link>) は、どの言語でも同じ組
 *   ほかの言語で訳していないキーは警告だけ (実行時は ja を出す)。
 */
import { load } from 'js-yaml';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BASE_LOCALE = 'ja';
/** 載せる言語 (先頭が既定)。増やすときは locales/<言語>.yaml を足してここに書く */
export const LOCALES = ['ja', 'en'] as const;

const PLURAL_CATEGORIES = new Set(['zero', 'one', 'two', 'few', 'many', 'other']);
const KEY_SEGMENT = /^[a-zA-Z][a-zA-Z0-9_]*$/;
const PLACEHOLDER = /\{(\w+)\}/g;
const TAG = /<(\w+)>|<\/(\w+)>|<(\w+)\/>/g;

export type CompiledMessage = string | Record<string, string>;

interface Entry {
  message: CompiledMessage;
  params: Set<string>;
  tags: Set<string>;
  plural: boolean;
}

export interface CompileResult {
  code: string;
  warnings: string[];
}

export class I18nError extends Error {}

/** YAML の文 (言語 → 中身) から、生成する TypeScript を作る。おかしければ I18nError */
export function compile(sources: Record<string, string>): CompileResult {
  if (!(BASE_LOCALE in sources)) throw new I18nError(`${BASE_LOCALE}.yaml が無い`);
  const catalogs = new Map<string, Map<string, Entry>>();
  for (const [locale, text] of Object.entries(sources)) {
    let doc: unknown;
    try {
      doc = load(text);
    } catch (e) {
      throw new I18nError(`${locale}.yaml を読めない: ${(e as Error).message}`);
    }
    const flat = new Map<string, Entry>();
    if (doc !== null && doc !== undefined) flatten(locale, doc, [], flat);
    catalogs.set(locale, flat);
  }

  const base = catalogs.get(BASE_LOCALE)!;
  const warnings: string[] = [];
  for (const [locale, flat] of catalogs) {
    if (locale === BASE_LOCALE) continue;
    for (const [key, entry] of flat) {
      const b = base.get(key);
      if (!b) throw new I18nError(`${locale}.yaml: ${key} は ${BASE_LOCALE}.yaml に無い`);
      if (!sameSet(b.params, entry.params)) throw new I18nError(`${locale}.yaml: ${key} の差し込み {…} が ${BASE_LOCALE} と違う`);
      if (!sameSet(b.tags, entry.tags)) throw new I18nError(`${locale}.yaml: ${key} の部品の印 <…> が ${BASE_LOCALE} と違う`);
    }
    const missing = [...base.keys()].filter(k => !flat.has(k));
    if (missing.length > 0) warnings.push(`${locale}.yaml: 訳していないキー ${missing.length} 件 (${BASE_LOCALE} を出す)`);
  }
  return { code: render(catalogs, base), warnings };
}

function flatten(locale: string, node: unknown, trail: string[], out: Map<string, Entry>): void {
  const key = trail.join('.');
  if (typeof node === 'string') {
    out.set(key, entryOf(locale, key, node, false));
    return;
  }
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    throw new I18nError(`${locale}.yaml: ${key || '(先頭)'} は文字列か表にする`);
  }
  const obj = node as Record<string, unknown>;
  const names = Object.keys(obj);
  // 複数形の表: 中身が全部 複数形の区分 (one / other …) の文字列で、other がある
  if (trail.length > 0 && names.length > 0 && names.every(n => PLURAL_CATEGORIES.has(n)) && names.every(n => typeof obj[n] === 'string')) {
    if (!names.includes('other')) throw new I18nError(`${locale}.yaml: ${key} の複数形に other が無い`);
    const forms = obj as Record<string, string>;
    const entry = entryOf(locale, key, forms.other, true);
    // other 以外の形は差し込みを省いてよい (英語の one: "1 new line" など)。部品の印は揃える
    for (const n of names) {
      const e = entryOf(locale, key, forms[n], true);
      if (![...e.params].every(p => entry.params.has(p)) || !sameSet(e.tags, entry.tags)) throw new I18nError(`${locale}.yaml: ${key} の複数形 ${n} の差し込みか部品の印が other と合わない`);
    }
    if (!entry.params.has('count')) throw new I18nError(`${locale}.yaml: ${key} は複数形なのに {count} が無い`);
    out.set(key, { ...entry, message: { ...forms } });
    return;
  }
  for (const n of names) {
    if (!KEY_SEGMENT.test(n)) throw new I18nError(`${locale}.yaml: ${[...trail, n].join('.')} は使えない名前 (英数字と _ だけ)`);
    flatten(locale, obj[n], [...trail, n], out);
  }
}

function entryOf(locale: string, key: string, text: string, plural: boolean): Entry {
  const params = new Set<string>();
  for (const m of text.matchAll(PLACEHOLDER)) params.add(m[1]);
  const tags = new Set<string>();
  const open: string[] = [];
  for (const m of text.matchAll(TAG)) {
    if (m[1]) {
      open.push(m[1]);
      tags.add(m[1]);
    } else if (m[2]) {
      if (open.pop() !== m[2]) throw new I18nError(`${locale}.yaml: ${key} の部品の印 </${m[2]}> の対応がおかしい`);
    } else if (m[3]) {
      tags.add(m[3]);
    }
  }
  if (open.length > 0) throw new I18nError(`${locale}.yaml: ${key} の部品の印 <${open[0]}> が閉じていない`);
  return { message: text, params, tags, plural };
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  return a.size === b.size && [...a].every(x => b.has(x));
}

function render(catalogs: Map<string, Map<string, Entry>>, base: Map<string, Entry>): string {
  const keys = [...base.keys()].sort();
  const lit = (s: string) => JSON.stringify(s);
  const lines: string[] = [];
  lines.push('/* 自動生成: npm run i18n -w @oz/ui (packages/ui/i18n/generate.ts)。直接書き換えない。元は packages/ui/locales/*.yaml */');
  lines.push('');
  lines.push(`export const LOCALES = [${LOCALES.map(lit).join(', ')}] as const;`);
  lines.push('export type Locale = (typeof LOCALES)[number];');
  lines.push(`export const BASE_LOCALE: Locale = ${lit(BASE_LOCALE)};`);
  lines.push('');
  lines.push('/** 文 (複数形の表は 区分 → 文) */');
  lines.push('export type Message = string | Readonly<Record<string, string>>;');
  lines.push('');
  lines.push(`export type MessageKey =${keys.length === 0 ? ' never' : ''}`);
  for (const k of keys) lines.push(`  | ${lit(k)}`);
  lines.push(';');
  lines.push('');
  lines.push('/** 差し込み ({name}) のあるキー → 渡す値。複数形のキーは count が数 */');
  lines.push('export interface MessageParams {');
  for (const k of keys) {
    const e = base.get(k)!;
    if (e.params.size === 0) continue;
    const fields = [...e.params].sort().map(p => `${p}: ${e.plural && p === 'count' ? 'number' : 'string | number'}`);
    lines.push(`  ${lit(k)}: { ${fields.join('; ')} };`);
  }
  lines.push('}');
  lines.push('');
  lines.push('/** 部品の印 (<link>…</link>・<br/>) のあるキー → 印の名前 */');
  lines.push('export interface MessageTags {');
  for (const k of keys) {
    const e = base.get(k)!;
    if (e.tags.size === 0) continue;
    lines.push(`  ${lit(k)}: ${[...e.tags].sort().map(lit).join(' | ')};`);
  }
  lines.push('}');
  lines.push('');
  lines.push('export const MESSAGES: Readonly<Record<Locale, Readonly<Partial<Record<MessageKey, Message>>>>> = {');
  for (const locale of LOCALES) {
    const flat = catalogs.get(locale) ?? new Map<string, Entry>();
    lines.push(`  ${lit(locale)}: {`);
    for (const k of keys) {
      const e = flat.get(k);
      if (!e) continue;
      const v = typeof e.message === 'string'
        ? lit(e.message)
        : `{ ${Object.entries(e.message).map(([c, s]) => `${c}: ${lit(s)}`).join(', ')} }`;
      lines.push(`    ${lit(k)}: ${v},`);
    }
    lines.push('  },');
  }
  lines.push('};');
  lines.push('');
  return lines.join('\n');
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const LOCALES_DIR = path.resolve(HERE, '../locales');
export const OUTPUT_FILE = path.resolve(HERE, '../src/i18n/messages.gen.ts');

/** locales/*.yaml を読む (無い言語は空) */
export function readSources(dir: string = LOCALES_DIR): Record<string, string> {
  const out: Record<string, string> = {};
  for (const locale of LOCALES) {
    const file = path.join(dir, `${locale}.yaml`);
    if (fs.existsSync(file)) out[locale] = fs.readFileSync(file, 'utf8');
  }
  return out;
}

// npm run i18n で直接動かしたとき
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { code, warnings } = compile(readSources());
    fs.writeFileSync(OUTPUT_FILE, code);
    for (const w of warnings) console.warn(`[i18n] ${w}`);
    console.log(`[i18n] ${path.relative(process.cwd(), OUTPUT_FILE)} を書き出した`);
  } catch (e) {
    console.error(`[i18n] ${(e as Error).message}`);
    process.exit(1);
  }
}
