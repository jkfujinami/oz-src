import { WEAK_ROUTE_CONFIRM_TEXT as T } from '../lib/guardStatus';

/**
 * 警告状態 (信頼 Guard に未接続 / 未設定) で投稿する前の確認。
 * 既定のフォーカスは「やめる」側: 勢いで Enter を押しても送られないように。
 */
export function WeakRouteConfirm({ onConfirm, onCancel }: { onConfirm: () => void; onCancel: () => void }) {
  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="weak-route-title"
      aria-describedby="weak-route-body"
      className="card"
      style={{ border: '1px solid var(--warn-line)', marginTop: '10px', padding: '12px' }}
    >
      <div id="weak-route-title" style={{ fontWeight: 700, color: 'var(--warn)', marginBottom: '6px' }}>
        {T.title}
      </div>
      <div id="weak-route-body" style={{ fontSize: '12px', lineHeight: 1.6 }}>
        {T.body.map((line) => <p key={line} style={{ margin: '0 0 4px' }}>{line}</p>)}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
        <button className="btn" autoFocus onClick={onCancel}>{T.cancel}</button>
        <button className="btn" onClick={onConfirm}>{T.proceed}</button>
      </div>
    </div>
  );
}
