import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { describeGuardStatus, importFailureText } from '../lib/guardStatus';

function formatTime(ms: number): string {
  return new Date(ms).toLocaleString('ja-JP', { dateStyle: 'medium', timeStyle: 'short' });
}

type ImportMessage =
  | { kind: 'ok'; text: string }
  | { kind: 'error'; text: string };

/**
 * Guard (1 ホップ目) の状態を説明する panel。
 *
 * ★ 表示しないもの: Guard の peerId。これは「この端末がどの Guard を使っているか」を
 *   示すので、画面にも書かない (スクリーンショットや画面共有で漏れるため)。
 */
export function GuardPanel({ onClose }: { onClose?: () => void }) {
  const { guardStatus, guardTrustConfigured, importGuardList } = useP2P();
  const view = describeGuardStatus(guardStatus);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<ImportMessage | null>(null);

  const handleImport = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await importGuardList(text);
      if (result.ok) {
        setMessage({ kind: 'ok', text: `取り込みました (版 ${result.version}・期限 ${formatTime(result.expiresAt)})` });
        setText('');
      } else {
        setMessage({ kind: 'error', text: importFailureText(result.reason) });
      }
    } catch {
      // 停止中のノードへの取り込みは例外になる
      setMessage({ kind: 'error', text: 'リストを取り込めませんでした (ノードが停止しています)' });
    } finally {
      setBusy(false);
    }
  };

  const messageColor = message?.kind === 'error' ? 'var(--danger)' : 'var(--success)';

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>匿名経路の状態</div>
      <div style={{ color: view.tone === 'warn' ? 'var(--warn)' : 'var(--text-dim)', fontWeight: view.tone === 'warn' ? 700 : 400 }}>
        {view.headline}
      </div>
      {view.details.map((line) => (
        <div key={line} style={{ color: 'var(--text-dim)' }}>{line}</div>
      ))}

      {guardStatus.listVersion !== null && (
        <div style={{ marginTop: '6px' }}>
          信頼リスト: 版 {guardStatus.listVersion}
          {guardStatus.listExpiresAt !== null && <>・期限 {formatTime(guardStatus.listExpiresAt)}</>}
        </div>
      )}

      {guardTrustConfigured ? (
        <div style={{ marginTop: '10px' }}>
          <div style={{ fontWeight: 700 }}>信頼リストの取り込み</div>
          <div style={{ color: 'var(--text-dim)', marginBottom: '6px' }}>
            メンテナが署名した Guard リストの文字列を貼り付けてください。署名と期限を確認してから保存します。
          </div>
          <div className="input-group">
            <textarea
              aria-label="信頼リストの文字列"
              placeholder="oz-guards:..."
              value={text}
              spellCheck={false}
              autoComplete="off"
              rows={3}
              onChange={(e) => setText(e.target.value)}
              style={{ width: '100%', fontFamily: 'monospace', fontSize: '11px' }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
              <button className="btn" disabled={busy || !text.trim()} onClick={() => void handleImport()}>
                取り込む
              </button>
            </div>
            {message && (
              <div
                role={message.kind === 'error' ? 'alert' : 'status'}
                style={{ color: messageColor, fontSize: '11px', marginTop: '6px' }}
              >
                {message.text}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div style={{ marginTop: '10px', color: 'var(--text-dim)' }}>
          この版のアプリには信頼リストの公開鍵が組み込まれていないため、リストは取り込めません。
        </div>
      )}

      {onClose && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
      )}
    </div>
  );
}
