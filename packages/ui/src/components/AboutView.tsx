import { SecurityInfo } from './SecurityInfo';
import { TermsText } from './TermsText';
import { termsTitle } from '../lib/terms';
import { tRich, useT } from '../i18n';

/**
 * 仕組みと安全性の説明をまとめた画面。各画面には短い案内だけを置き、詳しい説明はここに集める。
 *
 * ★ 書く内容は実装と一致させること (誇張しない。守れない範囲を具体的に書く)。
 */
export function AboutView() {
  const t = useT();
  const code = { code: (c: string) => <code>{c}</code> };
  return (
    <div className="column-content about">
      <div className="page-head">
        <div>
          <div className="eyebrow">About</div>
          <h1 className="page-title">{t('about.title')}</h1>
        </div>
      </div>

      <div className="stack">
        <section className="panel" aria-labelledby="a-safety">
          <h2 id="a-safety" className="panel-title">{t('about.safetyTitle')}</h2>
          <SecurityInfo />
        </section>

        <section className="panel" aria-labelledby="a-route">
          <h2 id="a-route" className="panel-title">{t('about.route.title')}</h2>
          <div className="prose">
            <p>{t('about.route.intro')}</p>
            <ul>
              <li>{t('about.route.li1')}</li>
              <li>{t('about.route.li2')}</li>
              <li>{t('about.route.li3')}</li>
              <li>{t('about.route.li4')}</li>
              <li>{t('about.route.li5')}</li>
            </ul>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-ozzy">
          <h2 id="a-ozzy" className="panel-title">{t('about.ozzy.title')}</h2>
          <div className="prose">
            <p>{t('about.ozzy.intro')}</p>
            <ul>
              <li>{t('about.ozzy.li1')}</li>
              <li>{t('about.ozzy.li2')}</li>
              <li>{tRich('about.ozzy.li3', code)}</li>
              <li>{t('about.ozzy.li4')}</li>
              <li>{t('about.ozzy.li5')}</li>
              <li>{t('about.ozzy.li6')}</li>
              <li>{t('about.ozzy.li7')}</li>
            </ul>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-worker">
          <h2 id="a-worker" className="panel-title">{t('about.worker.title')}</h2>
          <div className="prose">
            <p>{t('about.worker.intro')}</p>
            <ol>
              <li>{t('about.worker.step1')}</li>
              <li>{tRich('about.worker.step2', code)}</li>
              <li>{tRich('about.worker.step3', code)}</li>
            </ol>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-terms">
          <h2 id="a-terms" className="panel-title">{termsTitle()}</h2>
          <TermsText />
        </section>
      </div>
    </div>
  );
}
