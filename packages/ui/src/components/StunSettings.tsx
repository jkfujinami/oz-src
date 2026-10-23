import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';

/**
 * STUN サーバー (自分の外向きのアドレスを知るためのサーバ) の設定。
 *
 * ★ 既定は Google と Cloudflare の公開 STUN (core の DEFAULT_PUBLIC_STUN_SERVERS。トラッカーは UDP を受けないため)。
 *   STUN の運営者には IP と接続の時刻が伝わる。画面ではそのことを実装どおりに書く。
 */
export function StunSettings() {
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
      else setMessage({ kind: r.notice ? 'notice' : 'ok', text: value === null ? '既定に戻しました' : (r.notice ?? '保存しました') });
      if (r.ok && value === null) setInput('');
    } finally {
      setBusy(false);
    }
  };

  const color = message?.kind === 'error' ? 'var(--danger)' : message?.kind === 'notice' ? 'var(--text-dim)' : 'var(--success)';

  return (
    <div style={{ fontSize: '12px', lineHeight: 1.6, marginTop: '16px' }}>
      <div style={{ fontWeight: 700, marginBottom: '4px' }}>STUN サーバー</div>
      <div style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
        接続を張るときに、自分の外向きのアドレスを調べるためのサーバです。既定では Google と Cloudflare の公開 STUN を使います。
        STUN の運営者には、あなたの IP アドレスと接続の時刻が伝わります。自分で用意した STUN に変えることもできます。
      </div>
      <div style={{ marginBottom: '6px' }}>
        使用中: {effectiveIceServers.length > 0
          ? <code style={{ wordBreak: 'break-all' }}>{effectiveIceServers.join(', ')}</code>
          : <span style={{ color: 'var(--warn)' }}>なし (同じネットワーク内の相手としか繋がりません)</span>}
        {usingDefault && effectiveIceServers.length > 0 && <span style={{ color: 'var(--text-dim)' }}> (既定)</span>}
      </div>
      <div className="input-group">
        <input
          aria-label="STUN サーバー"
          placeholder={defaultStunServer ?? 'stun:ホスト名:3478'}
          value={input}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setInput(e.target.value)}
        />
        <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginTop: '4px' }}>
          stun:ホスト名:ポート の形。複数ならカンマで区切ります (4 つまで)。
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
          {!usingDefault && (
            <button className="btn" disabled={busy} onClick={() => void apply(null)}>既定に戻す</button>
          )}
          <button className="btn" disabled={busy || !input.trim()} onClick={() => void apply(input)}>STUN を保存</button>
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
