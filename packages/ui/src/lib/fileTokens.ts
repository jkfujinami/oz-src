import { parseFileLinks, type FileLink } from '@oz/core';

export type BodyPart =
  | { type: 'text'; text: string }
  | { type: 'file'; token: string; link: FileLink };

/**
 * 本文を「ただの文字列」と「添付トークン」に分ける。
 *
 * ★ トークンは本文の文字列から parseFileLinks で厳密に読む。形式の合わないものは分けずに
 *   そのまま文字列として残る (core が黙って無視する)。HTML には一切しない。
 */
export function splitFileTokens(content: string): BodyPart[] {
  const parts: BodyPart[] = [];
  let at = 0;
  for (const m of parseFileLinks(content)) {
    if (m.start > at) parts.push({ type: 'text', text: content.slice(at, m.start) });
    parts.push({ type: 'file', token: content.slice(m.start, m.end), link: m.link });
    at = m.end;
  }
  if (at < content.length) parts.push({ type: 'text', text: content.slice(at) });
  return parts;
}

/** 一覧など、カードを置けない所で使う: トークンを短い表記に置き換える */
export function replaceFileTokens(content: string, label = '[添付ファイル]'): string {
  return splitFileTokens(content).map(p => (p.type === 'text' ? p.text : label)).join('');
}

/** 欄の末尾にトークンを足す (空でなければ改行で区切る) */
export function appendToken(text: string, token: string): string {
  if (!text) return token;
  return text.endsWith('\n') ? text + token : `${text}\n${token}`;
}
