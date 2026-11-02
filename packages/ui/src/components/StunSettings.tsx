import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { useT } from '../i18n';

/**
 * STUN サーバー (自分の外向きのアドレスを知るためのサーバ) の設定。
 *
 * ★ 既定は Google と Cloudflare の公開 STUN (core の DEFAULT_PUBLIC_STUN_SERVERS。トラッカーは UDP を受けないため)。
 *   STUN の運営者には IP と接続の時刻が伝わる。画面ではそのことを実装どおりに書く。
 */
export function StunSettings() {
  const t = useT();
  const { iceServers, effectiveIceServers, defaultStunServer, setIceServers } = useP2P();
  const [input, setInput] = useState(iceServers.join(', '));
  const [message, setMessage] = useState<{ kind: 'error' | 'notice' | 'ok'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const usingDefault = iceServers.length === 0;

  const apply = async (value: string | null) => {
    setBusy(true);
    setMessage(null);
    try {
      const r = await setIceServers(value);
      if (!r.ok) setMessage({ kind: 'error', text: r.error });
      else setMessage({ kind: r.notice ? 'notice' : 'ok', text: value === null ? t('stun.reset') : (r.notice ?? t('stun.saved')) });
      if (r.ok && value === null) setInput('');
    } finally {
      setBusy(false);
    }
  };

  const color = message?.kind === 'error' ? 'var(--danger)' : message?.kind === 'notice' ? 'var(--text-dim)' : 'var(--success)';

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6, marginTop: '16px' }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>{t('stun.title')}</div>
      <div style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
        {t('stun.desc')}
      </div>
      <div style={{ marginBottom: '6px' }}>
        {t('stun.inUse')}{effectiveIceServers.length > 0
          ? <code style={{ wordBreak: 'break-all' }}>{effectiveIceServers.join(', ')}</code>
          : <span style={{ color: 'var(--warn)' }}>{t('stun.none')}</span>}
        {usingDefault && effectiveIceServers.length > 0 && <span style={{ color: 'var(--text-dim)' }}>{t('stun.default')}</span>}
      </div>
      <div className="input-group">
        <input
          aria-label={t('stun.title')}
          placeholder={defaultStunServer ?? t('stun.placeholder')}
          value={input}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setInput(e.target.value)}
        />
        <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginTop: '4px' }}>
          {t('stun.format')}
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
          {!usingDefault && (
            <button className="btn" disabled={busy} onClick={() => void apply(null)}>{t('stun.resetButton')}</button>
          )}
          <button className="btn" disabled={busy || !input.trim()} onClick={() => void apply(input)}>{t('stun.save')}</button>
        </div>
        {message && (
          <div role={message.kind === 'error' ? 'alert' : 'status'} style={{ color, fontSize: '11px', marginTop: '6px' }}>
            {message.text}
          </div>
        )}
      </div>
    </div>
  );
}
