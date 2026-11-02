/**
 * 利用規約。アプリの同意画面・「仕組みと安全性」・リポジトリの TERMS.md はすべてこれから作る。
 *
 * ★ 文面を変えたら TERMS_VERSION を上げ、`npm run terms` で TERMS.md を作り直すこと
 *   (テストで TERMS.md と一致しているかを確かめている)。版が変わると、全員にもう一度同意を求める。
 * ★ 同意したことは localStorage に版だけを残す。データベース (IndexedDB) と同じく、
 *   この端末で OZ を使ったことは分かるが、それ以上のことは残さない。全消去・緊急消去で一緒に消す。
 *
 * ★ 文面は locales/ja.yaml の legal.* にある。条・項・号の数を変えるときは、下の ARTICLE_SHAPE も直す。
 */
import { t } from '../i18n';

/** 規約の版 (制定・改定の日付) */
export const TERMS_VERSION = '2026-10-24';

export function termsTitle(): string {
  return t('legal.title');
}

export interface TermsArticle {
  heading: string;
  /** 項。2 つ以上あるときは番号を付けて表示する */
  paragraphs: string[];
  /** 号。最後の項に続けて、番号を付けて並べる */
  items?: string[];
}

/** 前文 */
export function termsPreamble(): string {
  return t('legal.preamble');
}

/** 条の並び: [条の番号, 項の数, 号の数]。文面は locales/ja.yaml の legal.a<番号>.* */
const ARTICLE_SHAPE: ReadonlyArray<readonly [number, number, number]> = [
  [1, 4, 0],
  [2, 4, 0],
  [3, 1, 8],
  [4, 2, 0],
  [5, 3, 0],
  [6, 1, 0],
  [7, 1, 0],
  [8, 3, 0],
  [9, 1, 0],
  [10, 2, 0],
  [11, 2, 0],
];

/** 各条の文面 (今の言語で引く) */
export function termsArticles(): TermsArticle[] {
  return ARTICLE_SHAPE.map(([n, paragraphs, items]) => {
    const get = (part: string) => t(`legal.a${n}.${part}` as Parameters<typeof t>[0]);
    const article: TermsArticle = {
      heading: get('heading'),
      paragraphs: Array.from({ length: paragraphs }, (_, i) => get(`p${i + 1}`)),
    };
    if (items > 0) article.items = Array.from({ length: items }, (_, i) => get(`item${i + 1}`));
    return article;
  });
}

/** 制定・改定の表記 (例: 2026年10月24日 制定) */
export function termsDateLabel(version = TERMS_VERSION): string {
  const [y, m, d] = version.split('-').map(Number);
  return t('legal.dateLabel', { year: y, month: m, day: d });
}

/** TERMS.md の本文。`npm run terms` で書き出す */
export function termsMarkdown(): string {
  const out: string[] = [`# ${termsTitle()}`, '', termsPreamble(), ''];
  for (const a of termsArticles()) {
    out.push(`## ${a.heading}`, '');
    if (a.paragraphs.length > 1) {
      a.paragraphs.forEach((p, i) => out.push(`${i + 1}. ${p}`));
      out.push('');
    } else {
      out.push(a.paragraphs[0], '');
    }
    if (a.items) {
      a.items.forEach((item, i) => out.push(`${i + 1}. ${item}`));
      out.push('');
    }
  }
  out.push(termsDateLabel(), '');
  return out.join('\n');
}

const ACCEPTED_KEY = 'oz.termsAccepted';

function storage(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

/** 同意済みの版。まだ同意していなければ null */
export function loadAcceptedTermsVersion(): string | null {
  try {
    return storage()?.getItem(ACCEPTED_KEY) ?? null;
  } catch {
    return null;
  }
}

/** 今の版に同意したことを残す。残せない環境 (保存が禁止されたブラウザなど) では、次回もう一度尋ねる */
export function saveTermsAccepted(): void {
  try {
    storage()?.setItem(ACCEPTED_KEY, TERMS_VERSION);
  } catch {
    // 残せなくても、この起動中は同意済みとして進める
  }
}

/** 全消去・緊急消去のときに、同意の記録も消す */
export function clearTermsAccepted(): void {
  try {
    storage()?.removeItem(ACCEPTED_KEY);
  } catch {
    // 消せなくても続ける
  }
}
