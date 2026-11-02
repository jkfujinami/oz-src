import { useEffect, useState } from 'react';
import { copySecret } from '../lib/clipboard';
import { tRich, useT } from '../i18n';
import { desktopGuardApi, type DesktopGuardStatus } from '../lib/desktopGuard';

const SLOT_CHOICES = [1, 2, 4, 8, 16, 32];

/**
 * 設定の「この端末で Guard を動かす」(デスクトップ版だけ)。
 *
 * ★ Guard は画面のノードとは別の身元・別の DB で、見えないウィンドウで動く。画面をロックしても止まらない。
 * ★ 表示するのは Guard 自身の peerId・Guard 文字列・件数だけ (つながっている利用者の peerId や IP は出さない)。
 */
export function DesktopGuardSettings() {
  const t = useT();
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
  if (!status) return <div className="msg msg-info">{t('hostGuard.loading')}</div>;

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
  const state = status.running ? t('hostGuard.stateRunning') : status.starting ? t('hostGuard.stateStarting') : status.enabled ? t('hostGuard.stateStopped') : t('hostGuard.stateOff');

  return (
    <div className="stack">
      <p className="panel-desc">
        {tRich('hostGuard.intro', { strong: (c) => <strong>{c}</strong> })}
      </p>

      {!status.available ? (
        <div className="alert alert-warn">{status.unavailableReason}</div>
      ) : (
        <>
          <div className="row row-wrap" style={{ gap: 8, alignItems: 'center' }}>
            <span className={`badge ${status.running ? 'badge-ok' : status.error ? 'badge-warn' : 'badge-neutral'}`}>{state}</span>
            {r && (
              <span className="xsmall muted">
                {t('hostGuard.counts', { degree: r.counts.degree, clients: r.counts.clients, backbone: r.counts.backbone, tunnels: r.counts.tunnels })}
              </span>
            )}
          </div>

          {status.error && <div role="alert" className="alert alert-warn">{status.error}</div>}

          {!status.enabled ? (
            <div className="row row-wrap" style={{ gap: 8, alignItems: 'center' }}>
              <label className="field-label" htmlFor="guard-slots">{t('hostGuard.slots')}</label>
              <select id="guard-slots" value={slots} onChange={(e) => setSlots(Number(e.target.value))} style={{ width: 'auto' }}>
                {SLOT_CHOICES.map((n) => <option key={n} value={n}>{t('hostGuard.slotOption', { n, size: n * 256 })}</option>)}
              </select>
              <label className="field-label" htmlFor="guard-tracker-port">{t('hostGuard.trackerPortLabel')}</label>
              <input
                id="guard-tracker-port"
                type="number"
                min={1}
                max={65535}
                placeholder={t('hostGuard.trackerPortPlaceholder')}
                value={trackerPortInput}
                onChange={(e) => setTrackerPortInput(e.target.value)}
                style={{ width: 110 }}
              />
              <button className="btn btn-primary" disabled={busy} onClick={handleEnable}>
                {t('hostGuard.enable')}
              </button>
            </div>
          ) : (
            <div className="row row-wrap" style={{ gap: 8 }}>
              <button className="btn" disabled={busy} onClick={() => void run(() => api.disable())}>{t('hostGuard.disable')}</button>
            </div>
          )}

          {status.trackerString && (
            <div className="subpanel stack stack-sm">
              <div className="subpanel-title">{t('hostGuard.trackerTitle', { port: status.trackerPort ?? '' })}</div>
              <div className="small">
                {t('hostGuard.trackerDesc')}
              </div>
              <div className="field">
                <div className="row row-between row-wrap" style={{ gap: 8 }}>
                  <span className="field-label">{t('hostGuard.trackerString')}</span>
                  <button className="btn btn-sm btn-ghost" onClick={() => void copyTrackerString()}>
                    {copiedTracker ? t('hostGuard.copied') : t('hostGuard.copy')}
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
              <strong>{t('hostGuard.openAtLogin')}</strong>
              <span className="muted">{t('hostGuard.openAtLoginNote')}</span>
            </span>
          </label>

          {r && (
            <div className="subpanel stack stack-sm">
              <div className="subpanel-title">{t('hostGuard.listTitle')}</div>
              <div className="small">
                {r.listed
                  ? t('hostGuard.listed', { version: r.listVersion ?? '?' })
                  : r.hasList
                    ? t('hostGuard.notListed', { version: r.listVersion ?? '?' })
                    : t('hostGuard.noList')}
              </div>
              <div className="field">
                <div className="row row-between row-wrap" style={{ gap: 8 }}>
                  <span className="field-label">{t('hostGuard.guardString')}</span>
                  <button className="btn btn-sm btn-ghost" onClick={() => void copyGuardString()}>{copied ? t('hostGuard.copied') : t('hostGuard.copy')}</button>
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
