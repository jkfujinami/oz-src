/**
 * 書き込み欄の末尾にアンカー (>>番号) を足す (レス番を押したとき)。
 * 空ならそのまま、末尾が改行でなければ改行をはさむ。アンカーのあとに改行を付けて、続けて本文を書けるようにする
 */
export function appendAnchor(text: string, n: number): string {
  const anchor = `>>${n}\n`;
  if (text === '') return anchor;
  return text.endsWith('\n') ? text + anchor : `${text}\n${anchor}`;
}
