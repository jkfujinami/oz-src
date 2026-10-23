import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { formatBytes, maxSlots, SLOT_BYTES } from '../lib/fileLimits';

/**
 * 保管の容量。他の人の暗号化されたデータ (投稿の過去ログ・添付ファイル) をいくつ預かるか。
 *
 * ★ 預かるのは暗号化された断片だけで、中身は預かる側にも読めない。1 枠 = 256MiB。
 */
export function StorageSettings({ onClose }: { onClose?: () => void }) {
  const { node } = useP2P();
  const max = maxSlots();
  const [slots, setSlots] = useState(node?.storageCapacity ?? 1);
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const apply = async (n: number) => {
    if (!node) return;
    setBusy(true);
    setMessage(null);
    try {
      await node.setStorageCapacity(n);
      setSlots(n);
      setMessage({ error: false, text: '保存しました' });
    } catch {
      setMessage({ error: true, text: '変更できませんでした' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>保管の容量</div>
      <div style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
        ほかの人の暗号化されたデータを預かると、網が安定します。預かったデータの中身は、あなたにも読めません。
      </div>
      <label className="field">
        <span className="field-label">預かる枠の数 (1 枠 = {formatBytes(SLOT_BYTES)})</span>
        <select
          aria-label="預かる枠の数"
          value={slots}
          disabled={busy || !node}
          onChange={(e) => void apply(Number(e.target.value))}
        >
          {Array.from({ length: Math.max(max, slots) }, (_, i) => i + 1).map((n) => (
            <option key={n} value={n}>{n} 枠 ({formatBytes(n * SLOT_BYTES)})</option>
          ))}
        </select>
      </label>
      {message && (
        <div role={message.error ? 'alert' : 'status'} style={{ color: message.error ? 'var(--danger)' : 'var(--success)', fontSize: '11px', marginTop: '6px' }}>
          {message.text}
        </div>
      )}
      {onClose && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
          <button className="btn" onClick={onClose}>閉じる</button>
        </div>
      )}
    </div>
  );
}
