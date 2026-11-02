import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { useT } from '../i18n';
import { formatBytes, maxSlots, SLOT_BYTES } from '../lib/fileLimits';

/**
 * 保管の容量。他の人の暗号化されたデータ (投稿の過去ログ・添付ファイル) をいくつ預かるか。
 *
 * ★ 預かるのは暗号化された断片だけで、中身は預かる側にも読めない。1 枠 = 256MiB。
 */
export function StorageSettings({ onClose }: { onClose?: () => void }) {
  const t = useT();
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
      setMessage({ error: false, text: t('storage.saved') });
    } catch {
      setMessage({ error: true, text: t('storage.failed') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>{t('storage.title')}</div>
      <div style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
        {t('storage.desc')}
      </div>
      <label className="field">
        <span className="field-label">{t('storage.slotsLabel', { size: formatBytes(SLOT_BYTES) })}</span>
        <select
          aria-label={t('storage.slotsAria')}
          value={slots}
          disabled={busy || !node}
          onChange={(e) => void apply(Number(e.target.value))}
        >
          {Array.from({ length: Math.max(max, slots) }, (_, i) => i + 1).map((n) => (
            <option key={n} value={n}>{t('storage.option', { n, size: formatBytes(n * SLOT_BYTES) })}</option>
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
          <button className="btn" onClick={onClose}>{t('storage.close')}</button>
        </div>
      )}
    </div>
  );
}
