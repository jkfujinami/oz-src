import { useState, type FormEvent } from 'react';
import { useP2P, MIN_PASSPHRASE_LENGTH } from '../providers/P2PProvider';
import { SecurityInfo } from './SecurityInfo';
import { estimateStrength, generatePassphrase } from '../lib/passphrase';
import { BrandMark } from './BrandMark';

/**
 * パスワード画面。
 *
 * 端末の全データはこのパスワードで暗号化される。忘れた場合の復元手段は無く、
 * 全データを消して作り直すしかない (復元手段を作ると、その分だけ押収に弱くなる)。
 */
export function UnlockScreen() {
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
        setLocalError(`パスワードは ${MIN_PASSPHRASE_LENGTH} 文字以上にしてください`);
        return;
      }
      if (passphrase !== confirm) {
        setLocalError('確認用のパスワードが一致しません');
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
          <span className="badge">端点暗号化</span>
        </div>

        <h2 className="unlock-title">
          {isSetup ? 'パスワードを設定' : 'ロックを解除'}
        </h2>
        <p className="unlock-lead">
          {isSetup
            ? 'この端末に保存されるすべてのデータ (投稿履歴・板の鍵など) をこのパスワードで暗号化します。忘れると復元できません。'
            : 'この端末のデータは暗号化されています。パスワードを入力してください。'}
        </p>

        <form onSubmit={onSubmit} className="stack">
          <div className="field">
            <input
              type="password"
              aria-label="パスワード"
              placeholder="パスワード"
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
                aria-label="パスワード (確認)"
                placeholder="パスワード (確認)"
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
              <span>強さの目安: {strength.label}</span>
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
                パスワードを作る
              </button>
              <span className="field-hint">
                読みやすい長いパスワードを自動で作ります
              </span>
            </div>
          )}

          {isSetup && generated && (
            <div className="alert alert-info">
              <div className="stack stack-sm grow">
                <div className="xsmall text-2">
                  このパスワードを、端末の外 (紙など) に控えてください。忘れると復元できません。
                </div>
                <code aria-label="作成したパスワード" className="code-block is-gold">
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
            {busy ? '起動中...' : isSetup ? '設定して開始' : '解除'}
          </button>
        </form>

        {(localError || unlockError) && (
          <div role="alert" className="alert alert-danger" style={{ marginTop: 14 }}>
            {localError || unlockError}
          </div>
        )}

        {isSetup && (
          <details className="disclosure" open>
            <summary>OZ で守れること・守れないこと</summary>
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
                ? 'もう一度押すと、この端末の全データを消去して作り直します (元に戻せません)'
                : 'パスワードを忘れた場合'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
