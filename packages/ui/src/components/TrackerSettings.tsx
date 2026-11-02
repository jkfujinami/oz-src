import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { StunSettings } from './StunSettings';
import { useT } from '../i18n';
import { STANDARD_TRACKERS } from '../lib/trackerSetting';

/**
 * トラッカー (参加者同士を最初に引き合わせるサーバ) の設定。
 *
 * ★ 公式のトラッカーは無い。運営者には接続時の IP アドレスとノード ID が見えるので、
 *   信頼できる配布元から受け取った URL だけを設定してもらう。
 */
export function TrackerSettings({ onClose }: { onClose?: () => void }) {
  const t = useT();
  const { trackerUrl, setTrackerUrl } = useP2P();
  const [input, setInput] = useState(trackerUrl ?? '');
  const [message, setMessage] = useState<{ kind: 'error' | 'notice' | 'ok'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const apply = async (value: string | null) => {
    setBusy(true);
    setMessage(null);
    try {
      const r = await setTrackerUrl(value);
      if (!r.ok) setMessage({ kind: 'error', text: r.error });
      else if (r.notice) setMessage({ kind: 'notice', text: r.notice });
      else setMessage({ kind: 'ok', text: value === null ? t('settings.tracker.reset') : t('settings.tracker.saved') });
      if (r.ok && value === null) setInput('');
    } finally {
      setBusy(false);
    }
  };

  const color = message?.kind === 'error' ? 'var(--danger)' : message?.kind === 'notice' ? 'var(--warn)' : 'var(--success)';

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>{t('settings.tracker.title')}</div>
      <div style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
        {t('settings.tracker.desc')}
      </div>
      <div style={{ marginBottom: '6px' }}>
        {t('settings.tracker.current')}{trackerUrl
          ? <code style={{ wordBreak: 'break-all' }}>{trackerUrl}</code>
          : <span style={{ color: 'var(--warn)' }}>{t('settings.tracker.unset')}</span>}
      </div>
      <div className="input-group">
        <input
          aria-label={t('settings.tracker.urlLabel')}
          placeholder={t('settings.tracker.placeholder')}
          value={input}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setInput(e.target.value)}
        />
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px', marginBottom: '8px' }}>
          <button
            type="button"
            className="btn"
            style={{ fontSize: '11px', padding: '3px 8px', borderColor: 'var(--line-strong)', color: 'var(--text-2)' }}
            onClick={() => setInput(STANDARD_TRACKERS.cloudflare)}
          >
            {t('settings.tracker.cloudflare')}
          </button>
          <button
            type="button"
            className="btn"
            style={{ fontSize: '11px', padding: '3px 8px', borderColor: 'var(--line-strong)', color: 'var(--text-2)' }}
            onClick={() => setInput(STANDARD_TRACKERS.deno)}
          >
            {t('settings.tracker.deno')}
          </button>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
          {onClose && <button className="btn" onClick={onClose}>{t('settings.tracker.close')}</button>}
          {trackerUrl && (
            <button className="btn" disabled={busy} onClick={() => void apply(null)}>{t('settings.tracker.clear')}</button>
          )}
          <button className="btn" disabled={busy || !input.trim()} onClick={() => void apply(input)}>{t('settings.tracker.save')}</button>
        </div>
        {message && (
          <div role={message.kind === 'error' ? 'alert' : 'status'} style={{ color, fontSize: '11px', marginTop: '6px' }}>
            {message.text}
          </div>
        )}
      </div>
      <StunSettings />
    </div>
  );
}
