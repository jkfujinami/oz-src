import { splitFileTokens } from '../lib/fileTokens';
import { FileCard } from './FileCard';

/**
 * 本文の表示。添付トークンはカードにし、残りは呼び出し側の整形 (HTML エスケープ済み) で出す。
 * ★ トークンは文字列から厳密に読んだものだけをカードにする。トークンの中身を HTML に入れることはない。
 */
export function PostBody({ content, format }: { content: string; format: (text: string) => string }) {
  return (
    <>
      {splitFileTokens(content).map((p, i) =>
        p.type === 'text'
          ? <span key={i} dangerouslySetInnerHTML={{ __html: format(p.text) }} />
          : <FileCard key={`${i}:${p.token}`} token={p.token} link={p.link} />,
      )}
    </>
  );
}
