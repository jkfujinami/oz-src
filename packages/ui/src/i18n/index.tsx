/**
 * 画面の文言 (i18n)。文は packages/ui/locales/<言語>.yaml にだけ書き、ここで言語に合わせて出す。
 *
 *   const t = useT();                                   // 部品の中 (言語が変わると描き直す)
 *   t('status.title')                                   // 文
 *   t('status.peers', { connected: 5, verified: 4, max: 64 })   // 差し込み {name}
 *   t('status.newRows', { count: 3 })                   // 複数形 ({ one, other } の表。ja は other だけでよい)
 *   tRich('vault.workerHint', { link: (c) => <a onClick={…}>{c}</a> })   // 部品の印 <link>…</link>・<br/>
 *
 * ★ YAML を直したら `npm run i18n -w @oz/ui` で messages.gen.ts を作り直す (テストが食い違いを見つける)。
 * ★ 訳文に HTML は書かない。リンクや強調は部品の印 (<name>…</name>) で書き、tRich に部品を渡す (差し込みの事故を防ぐ)。
 * ★ 訳していないキーは既定の言語 (ja) を出す。
 * ★ core は画面の文を返さない (状態は 種類 + 数 で返し、ここで文にする)。
 *
 * 言語の選び方: 保存された選択 (setLocale) → OS の言語 (navigator.languages) → ja。
 *   選択は端末の localStorage に置く (利用規約とロック画面は暗号化 DB を開く前に出るため)。どの言語で使っているかだけが端末に残る。
 */
import { Fragment, useSyncExternalStore, type ReactNode } from 'react';
import { BASE_LOCALE, LOCALES, MESSAGES, type Locale, type Message, type MessageKey, type MessageParams, type MessageTags } from './messages.gen';

export { LOCALES, BASE_LOCALE, type Locale, type MessageKey } from './messages.gen';

const STORAGE_KEY = 'oz.locale';

function isLocale(v: unknown): v is Locale {
  return typeof v === 'string' && (LOCALES as readonly string[]).includes(v);
}

function initialLocale(): Locale {
  try {
    const saved = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
    if (isLocale(saved)) return saved;
  } catch {
    // 使えない環境 (プライベートモードなど)
  }
  const prefs = typeof navigator !== 'undefined' ? (navigator.languages ?? [navigator.language]) : [];
  for (const p of prefs) {
    const lang = String(p).toLowerCase().split('-')[0];
    if (isLocale(lang)) return lang;
  }
  return BASE_LOCALE;
}

let current: Locale = initialLocale();
const listeners = new Set<() => void>();

export function getLocale(): Locale {
  return current;
}

/** 言語を変える (端末に覚える)。部品は useT / useLocale で描き直す */
export function setLocale(locale: Locale): void {
  if (!isLocale(locale) || locale === current) return;
  current = locale;
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    // 覚えられないだけ
  }
  for (const l of listeners) l();
}

export function subscribeLocale(fn: () => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

/** 部品の印のない文のキー */
export type PlainKey = Exclude<MessageKey, keyof MessageTags>;
/** 部品の印のある文のキー */
type RichKey = Extract<MessageKey, keyof MessageTags>;
/** 差し込みのあるキーは値が必須、無いキーは渡さない */
type ParamArgs<K extends MessageKey> = K extends keyof MessageParams ? [params: MessageParams[K]] : [params?: undefined];

const pluralRules = new Map<Locale, Intl.PluralRules>();

function lookup(key: MessageKey): Message | undefined {
  return MESSAGES[current][key] ?? MESSAGES[BASE_LOCALE][key];
}

function pick(message: Message, params: Record<string, unknown> | undefined): string {
  if (typeof message === 'string') return message;
  const count = Number(params?.count);
  let rules = pluralRules.get(current);
  if (!rules) {
    rules = new Intl.PluralRules(current);
    pluralRules.set(current, rules);
  }
  return message[rules.select(Number.isFinite(count) ? count : 0)] ?? message.other;
}

function interpolate(text: string, params: Record<string, unknown> | undefined): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (all, name: string) => (name in params ? String(params[name]) : all));
}

/** 文を出す。キーが無ければキーをそのまま出す (型で防いでいるので、ふつうは起きない) */
export function t<K extends PlainKey>(key: K, ...args: ParamArgs<K>): string {
  const m = lookup(key);
  if (m === undefined) return key;
  const params = args[0] as Record<string, unknown> | undefined;
  return interpolate(pick(m, params), params);
}

/**
 * 部品の印 (<name>…</name>・<name/>) を含む文を、部品の並びにして出す。印の中の文は部品の関数に渡す (印の入れ子は無し)。
 * ★ 文そのものは文字として出す (HTML として解釈しない)。
 */
export function tRich<K extends RichKey>(
  key: K,
  parts: Record<MessageTags[K], (children: string) => ReactNode>,
  ...args: ParamArgs<K>
): ReactNode {
  const m = lookup(key);
  if (m === undefined) return key;
  const params = args[0] as Record<string, unknown> | undefined;
  const text = pick(m, params);
  const out: ReactNode[] = [];
  const re = /<(\w+)>([\s\S]*?)<\/\1>|<(\w+)\/>/g;
  let last = 0;
  for (const match of text.matchAll(re)) {
    const at = match.index ?? 0;
    if (at > last) out.push(interpolate(text.slice(last, at), params));
    const name = (match[1] ?? match[3]) as MessageTags[K];
    const render = (parts as Record<string, (children: string) => ReactNode>)[name];
    const inner = match[1] ? interpolate(match[2], params) : '';
    out.push(render ? render(inner) : inner);
    last = at + match[0].length;
  }
  if (last < text.length) out.push(interpolate(text.slice(last), params));
  return out.map((n, i) => <Fragment key={i}>{n}</Fragment>);
}

/**
 * 日時・日付 (今の言語の書き方)。Date.toLocaleString / toLocaleDateString に言語を渡しただけ。
 * ★ 書式の指定は足さない: 日本語では移す前の表示 (2026/11/1 22:56:00) と同じ文字になる
 */
export function formatDateTime(ms: number): string {
  return new Date(ms).toLocaleString(current);
}

export function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString(current);
}

/** 今の言語 (変わると描き直す) */
export function useLocale(): Locale {
  return useSyncExternalStore(subscribeLocale, getLocale, getLocale);
}

/** 部品の中で使う t。言語が変わると描き直す */
export function useT(): typeof t {
  useLocale();
  return t;
}
