import { useState, type FormEvent } from 'react';
import { useP2P, MIN_PASSPHRASE_LENGTH } from '../providers/P2PProvider';
import { SecurityInfo } from './SecurityInfo';
import { estimateStrength, generatePassphrase } from '../lib/passphrase';
import { BrandMark } from './BrandMark';
import { useT } from '../i18n';

/**
 * パスワード画面。
 *
 * 端末の全データはこのパスワードで暗号化される。忘れた場合の復元手段は無く、
 * 全データを消して作り直すしかない (復元手段を作ると、その分だけ押収に弱くなる)。
 */
export function UnlockScreen() {
  const t = useT();
  const { lockState, unlock, unlockError, resetAll } = useP2P();
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  /** 「パスワードを作る」で生成したもの。控えてもらうために一度だけ画面に出す */
  const [generated, setGenerated] = useState<string | null>(null);

  const isSetup = lockState === 'setup';
  const busy = lockState === 'starting' || lockState === 'checking';

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    if (isSetup) {
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        setLocalError(t('unlock.tooShort', { min: MIN_PASSPHRASE_LENGTH }));
        return;
      }
      if (passphrase !== confirm) {
        setLocalError(t('unlock.mismatch'));
        return;
      }
    }
    if (passphrase.length === 0) return;
    const value = passphrase;
    setPassphrase('');
    setConfirm('');
    setGenerated(null);
    await unlock(value);
  };

  const onGenerate = () => {
    const value = generatePassphrase();
    setGenerated(value);
    setPassphrase(value);
    setConfirm(value);
    setLocalError(null);
  };

  const strength = estimateStrength(passphrase, MIN_PASSPHRASE_LENGTH);
  const STRENGTH_COLOR: Record<string, string> = {
    short: 'var(--danger)',
    weak: 'var(--danger)',
    fair: 'var(--warn)',
    strong: 'var(--ok)',
  };

  const onReset = async () => {
    if (!confirmReset) {
      setConfirmReset(true);
      return;
    }
    setConfirmReset(false);
    await resetAll();
  };

  return (
    <div className="unlock-wrap">
      <div className="unlock-card">
        <div className="unlock-brand">
          <BrandMark />
          <span className="brand-name">OZ</span>
          <span className="badge">{t('unlock.badge')}</span>
        </div>

        <h2 className="unlock-title">
          {isSetup ? t('unlock.setupTitle') : t('unlock.unlockTitle')}
        </h2>
        <p className="unlock-lead">
          {isSetup
            ? t('unlock.setupLead')
            : t('unlock.unlockLead')}
        </p>

        <form onSubmit={onSubmit} className="stack">
          <div className="field">
            <input
              type="password"
              aria-label={t('unlock.password')}
              placeholder={t('unlock.password')}
              autoComplete={isSetup ? 'new-password' : 'current-password'}
              value={passphrase}
              onChange={(e) => { setPassphrase(e.target.value); setGenerated(null); }}
              disabled={busy}
              autoFocus
            />
          </div>

          {isSetup && (
            <div className="field">
              <input
                type="password"
                aria-label={t('unlock.confirm')}
                placeholder={t('unlock.confirm')}
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => { setConfirm(e.target.value); setGenerated(null); }}
                disabled={busy}
              />
            </div>
          )}

          {isSetup && strength.level !== 'empty' && (
            <div
              role="status"
              className="strength"
              style={{ color: STRENGTH_COLOR[strength.level] }}
            >
              <span>{t('unlock.strength', { label: strength.label })}</span>
            </div>
          )}

          {isSetup && (
            <div className="row row-wrap" style={{ gap: 10 }}>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={onGenerate}
                disabled={busy}
              >
                {t('unlock.generate')}
              </button>
              <span className="field-hint">
                {t('unlock.generateHint')}
              </span>
            </div>
          )}

          {isSetup && generated && (
            <div className="alert alert-info">
              <div className="stack stack-sm grow">
                <div className="xsmall text-2">
                  {t('unlock.noteDown')}
                </div>
                <code aria-label={t('unlock.generatedLabel')} className="code-block is-gold">
                  {generated}
                </code>
              </div>
            </div>
          )}

          <button
            className="btn btn-primary btn-block"
            type="submit"
            disabled={busy || passphrase.length === 0}
            style={{ marginTop: 8 }}
          >
            {busy ? t('unlock.starting') : isSetup ? t('unlock.setupSubmit') : t('unlock.submit')}
          </button>
        </form>

        {(localError || unlockError) && (
          <div role="alert" className="alert alert-danger" style={{ marginTop: 14 }}>
            {localError || unlockError}
          </div>
        )}

        {isSetup && (
          <details className="disclosure" open>
            <summary>{t('unlock.securityTitle')}</summary>
            <div className="disclosure-body">
              <SecurityInfo compact />
            </div>
          </details>
        )}

        {!isSetup && (
          <div style={{ marginTop: 24, textAlign: 'center' }}>
            <button
              type="button"
              className="btn-link small"
              onClick={onReset}
              disabled={busy}
            >
              {confirmReset
                ? t('unlock.resetAgain')
                : t('unlock.forgot')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
