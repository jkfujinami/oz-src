import { TERMS_ARTICLES, TERMS_PREAMBLE, termsDateLabel } from '../lib/terms';

/** 利用規約の本文 (同意画面と「仕組みと安全性」で使う) */
export function TermsText() {
  return (
    <div className="prose terms">
      <p>{TERMS_PREAMBLE}</p>
      {TERMS_ARTICLES.map((a) => (
        <section key={a.heading}>
          <h3 className="terms-heading">{a.heading}</h3>
          {a.paragraphs.length > 1 ? (
            <ol>
              {a.paragraphs.map((p) => <li key={p}>{p}</li>)}
            </ol>
          ) : (
            <p>{a.paragraphs[0]}</p>
          )}
          {a.items && (
            <ol className="terms-items">
              {a.items.map((item) => <li key={item}>{item}</li>)}
            </ol>
          )}
        </section>
      ))}
      <p className="terms-date">{termsDateLabel()}</p>
    </div>
  );
}
