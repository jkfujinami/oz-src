import { useState, type ReactNode } from 'react';
import { BrandMark } from './BrandMark';
import { TermsText } from './TermsText';
import { TERMS_TITLE, TERMS_VERSION, loadAcceptedTermsVersion, saveTermsAccepted } from '../lib/terms';

/**
 * 利用規約への同意を求める。同意するまでは中身 (データベースもネットワークも) を始めない。
 *
 * 同意したのが前の版なら、更新されたことを伝えてもう一度尋ねる。
 */
export function TermsGate({ children }: { children: ReactNode }) {
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

        <h2 className="unlock-title">{TERMS_TITLE}</h2>
        <p className="unlock-lead">
          {updated
            ? '利用規約が更新されました。引き続きご利用いただくには、更新後の内容をお読みのうえ、同意してください。'
            : 'OZ をご利用いただく前に、以下の利用規約をお読みください。'}
        </p>

        <div className="terms-box" tabIndex={0} role="region" aria-label="利用規約の本文">
          <TermsText />
        </div>

        {declined ? (
          <div role="alert" className="alert alert-warn" style={{ marginTop: 16 }}>
            利用規約に同意いただけない場合、OZ はご利用いただけません。このウィンドウ (Web 版ではタブ) を閉じてください。
          </div>
        ) : null}

        <div className="stack" style={{ marginTop: 16 }}>
          <label className="check">
            <input type="checkbox" checked={checked} onChange={(e) => { setChecked(e.target.checked); setDeclined(false); }} />
            <span>利用規約を読み、内容に同意します</span>
          </label>
          <div className="row row-wrap" style={{ gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" className="btn" onClick={() => { setDeclined(true); setChecked(false); }}>
              同意しない
            </button>
            <button type="button" className="btn btn-primary" disabled={!checked} onClick={agree}>
              同意して始める
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
