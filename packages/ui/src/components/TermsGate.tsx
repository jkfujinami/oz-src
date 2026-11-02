import { useState, type ReactNode } from 'react';
import { BrandMark } from './BrandMark';
import { TermsText } from './TermsText';
import { useT } from '../i18n';
import { TERMS_VERSION, termsTitle, loadAcceptedTermsVersion, saveTermsAccepted } from '../lib/terms';

/**
 * 利用規約への同意を求める。同意するまでは中身 (データベースもネットワークも) を始めない。
 *
 * 同意したのが前の版なら、更新されたことを伝えてもう一度尋ねる。
 */
export function TermsGate({ children }: { children: ReactNode }) {
  const t = useT();
  const [accepted, setAccepted] = useState<string | null>(() => loadAcceptedTermsVersion());
  const [checked, setChecked] = useState(false);
  const [declined, setDeclined] = useState(false);

  if (accepted === TERMS_VERSION) return <>{children}</>;

  const updated = accepted !== null;

  const agree = () => {
    saveTermsAccepted();
    setAccepted(TERMS_VERSION);
  };

  return (
    <div className="unlock-wrap">
      <div className="unlock-card terms-card">
        <div className="unlock-brand">
          <BrandMark />
          <span className="brand-name">OZ</span>
        </div>

        <h2 className="unlock-title">{termsTitle()}</h2>
        <p className="unlock-lead">
          {updated
            ? t('terms.gate.updated')
            : t('terms.gate.first')}
        </p>

        <div className="terms-box" tabIndex={0} role="region" aria-label={t('terms.gate.bodyLabel')}>
          <TermsText />
        </div>

        {declined ? (
          <div role="alert" className="alert alert-warn" style={{ marginTop: 16 }}>
            {t('terms.gate.declined')}
          </div>
        ) : null}

        <div className="stack" style={{ marginTop: 16 }}>
          <label className="check">
            <input type="checkbox" checked={checked} onChange={(e) => { setChecked(e.target.checked); setDeclined(false); }} />
            <span>{t('terms.gate.check')}</span>
          </label>
          <div className="row row-wrap" style={{ gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="btn" onClick={() => { setDeclined(true); setChecked(false); }}>
              {t('terms.gate.decline')}
            </button>
            <button type="button" className="btn btn-primary" disabled={!checked} onClick={agree}>
              {t('terms.gate.agree')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
