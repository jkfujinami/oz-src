import { useEffect, useState } from 'react';
import { copySecret } from '../lib/clipboard';
import { desktopGuardApi, type DesktopGuardStatus } from '../lib/desktopGuard';

const SLOT_CHOICES = [1, 2, 4, 8, 16, 32];

/**
 * 設定の「この端末で Guard を動かす」(デスクトップ版だけ)。
 *
 * ★ Guard は画面のノードとは別の身元・別の DB で、見えないウィンドウで動く。画面をロックしても止まらない。
 * ★ 表示するのは Guard 自身の peerId・Guard 文字列・件数だけ (つながっている利用者の peerId や IP は出さない)。
 */
export function DesktopGuardSettings() {
  const api = desktopGuardApi();
  const [status, setStatus] = useState<DesktopGuardStatus | null>(null);
  const [slots, setSlots] = useState<number>(4);
  const [trackerPortInput, setTrackerPortInput] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedTracker, setCopiedTracker] = useState(false);

  useEffect(() => {
    if (!api) return;
    let alive = true;
    void api.get().then((s) => {
      if (!alive || !s) return;
      setStatus(s);
      setSlots(s.slots);
      if (s.trackerPort) setTrackerPortInput(String(s.trackerPort));
    });
    const off = api.onStatus((s) => { if (alive) setStatus(s); });
    return () => { alive = false; off(); };
  }, [api]);

  if (!api) return null;
  if (!status) return <div className="msg msg-info">読み込んでいます...</div>;

  const run = async (fn: () => Promise<DesktopGuardStatus | null>) => {
    setBusy(true);
    try {
      const s = await fn();
      if (s) setStatus(s);
    } finally {
      setBusy(false);
    }
  };

  const copyGuardString = async () => {
    if (!status.report) return;
    try {
      await copySecret(status.report.guardString);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };

  const copyTrackerString = async () => {
    if (!status.trackerString) return;
    try {
      await copySecret(status.trackerString);
      setCopiedTracker(true);
      setTimeout(() => setCopiedTracker(false), 2000);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };

  const handleEnable = () => {
    const trimmed = trackerPortInput.trim();
    const parsedPort = trimmed.length > 0 ? Number(trimmed) : null;
    const validPort = parsedPort !== null && Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535 ? parsedPort : undefined;
    void run(() => api.enable(validPort !== undefined ? { slots, trackerPort: validPort } : { slots }));
  };

  const r = status.report;
  const state = status.running ? '動いています' : status.starting ? '起動しています...' : status.enabled ? '止まっています' : '使っていません';

  return (
    <div className="stack">
      <p className="panel-desc">
        この端末を、他の利用者の 1 ホップ目 (信頼 Guard) として動かします。画面のノードとは別の身元で、画面をロックしても動き続けます。
        <strong> Guard にはつながってきた利用者の IP が見え、この端末の IP は Guard として利用者に見えます。</strong>
      </p>

      {!status.available ? (
        <div className="alert alert-warn">{status.unavailableReason}</div>
      ) : (
        <>
          <div className="row row-wrap" style={{ gap: 8, alignItems: 'center' }}>
            <span className={`badge ${status.running ? 'badge-ok' : status.error ? 'badge-warn' : 'badge-neutral'}`}>{state}</span>
            {r && (
              <span className="xsmall muted">
                接続 {r.counts.degree} (利用者 {r.counts.clients} / 他の Guard {r.counts.backbone})・トンネル {r.counts.tunnels} 本
              </span>
            )}
          </div>

          {status.error && <div role="alert" className="alert alert-warn">{status.error}</div>}

          {!status.enabled ? (
            <div className="row row-wrap" style={{ gap: 8, alignItems: 'center' }}>
              <label className="field-label" htmlFor="guard-slots">預かる枠</label>
              <select id="guard-slots" value={slots} onChange={(e) => setSlots(Number(e.target.value))} style={{ width: 'auto' }}>
                {SLOT_CHOICES.map((n) => <option key={n} value={n}>{n} 枠 ({n * 256} MiB)</option>)}
              </select>
              <label className="field-label" htmlFor="guard-tracker-port">トラッカー開放ポート (任意)</label>
              <input
                id="guard-tracker-port"
                type="number"
                min={1}
                max={65535}
                placeholder="例: 8787"
                value={trackerPortInput}
                onChange={(e) => setTrackerPortInput(e.target.value)}
                style={{ width: 110 }}
              />
              <button className="btn btn-primary" disabled={busy} onClick={handleEnable}>
                Guard として動かす
              </button>
            </div>
          ) : (
            <div className="row row-wrap" style={{ gap: 8 }}>
              <button className="btn" disabled={busy} onClick={() => void run(() => api.disable())}>Guard を止める</button>
            </div>
          )}

          {status.trackerString && (
            <div className="subpanel stack stack-sm">
              <div className="subpanel-title">ポート開放トラッカー (ポート {status.trackerPort})</div>
              <div className="small">
                この文字列をトラッカー設定に入力すると、IP アドレスとポート番号を直接晒さずにこの端末のトラッカーへ接続できます。
              </div>
              <div className="field">
                <div className="row row-between row-wrap" style={{ gap: 8 }}>
                  <span className="field-label">トラッカー文字列</span>
                  <button className="btn btn-sm btn-ghost" onClick={() => void copyTrackerString()}>
                    {copiedTracker ? 'コピーしました' : 'コピー'}
                  </button>
                </div>
                <code className="code-block">{status.trackerString}</code>
              </div>
            </div>
          )}

          <label className="check">
            <input
              id="guard-open-at-login"
              type="checkbox"
              checked={status.openAtLogin}
              disabled={busy}
              onChange={(e) => void run(() => api.setOpenAtLogin(e.target.checked))}
            />
            <span>
              <strong>ログイン時に起動する</strong>
              <span className="muted"> (画面は出さず、トレイと Guard だけで動きます)</span>
            </span>
          </label>

          {r && (
            <div className="subpanel stack stack-sm">
              <div className="subpanel-title">信頼リスト</div>
              <div className="small">
                {r.listed
                  ? `この Guard は信頼リスト (v${r.listVersion ?? '?'}) に載っています。`
                  : r.hasList
                    ? `信頼リスト (v${r.listVersion ?? '?'}) にはまだ載っていません。下の Guard 文字列をメンテナに渡してください。`
                    : 'このアプリには信頼リストがありません。下の Guard 文字列をメンテナに渡してください。'}
              </div>
              <div className="field">
                <div className="row row-between row-wrap" style={{ gap: 8 }}>
                  <span className="field-label">Guard 文字列</span>
                  <button className="btn btn-sm btn-ghost" onClick={() => void copyGuardString()}>{copied ? 'コピーしました' : 'コピー'}</button>
                </div>
                <code className="code-block">{r.guardString}</code>
              </div>
              <div className="xsmall muted">peerId: <span className="mono">{r.peerId}</span></div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
