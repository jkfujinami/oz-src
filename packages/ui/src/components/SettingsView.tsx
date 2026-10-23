import { useEffect } from 'react';
import { TrackerSettings } from './TrackerSettings';
import { GuardPanel } from './GuardPanel';
import { StorageSettings } from './StorageSettings';
import { OzzySettings } from './OzzySettings';
import { DesktopGuardSettings } from './DesktopGuardSettings';
import { desktopGuardApi } from '../lib/desktopGuard';

export type SettingsSection = 'connection' | 'guard' | 'host-guard' | 'storage' | 'ozzy';

const SECTIONS: ReadonlyArray<{ id: SettingsSection; title: string; desktopOnly?: boolean }> = [
  { id: 'connection', title: '接続' },
  { id: 'guard', title: '匿名経路' },
  { id: 'host-guard', title: 'この端末の Guard', desktopOnly: true },
  { id: 'storage', title: 'データの保管' },
  { id: 'ozzy', title: 'ファイル共有' },
];

/**
 * 設定をまとめた画面。サイドバーの状態表示 (匿名経路・トラッカー) から開くときは、その節へ移る。
 * `focusNonce` は同じ節をもう一度選んだときにも移るためのもの。
 */
export function SettingsView({ focus, focusNonce = 0 }: { focus?: SettingsSection; focusNonce?: number }) {
  useEffect(() => {
    if (!focus) return;
    document.getElementById(`settings-${focus}`)?.scrollIntoView?.({ block: 'start' });
  }, [focus, focusNonce]);

  const desktop = desktopGuardApi() !== null;

  return (
    <div className="column-content">
      <div className="page-head">
        <div>
          <div className="eyebrow">Settings</div>
          <h1 className="page-title">設定</h1>
        </div>
        <nav className="row row-wrap" aria-label="設定の節">
          {SECTIONS.filter(s => desktop || !s.desktopOnly).map(s => (
            <a key={s.id} className="btn btn-sm btn-ghost" href={`#settings-${s.id}`} onClick={(e) => {
              e.preventDefault();
              document.getElementById(`settings-${s.id}`)?.scrollIntoView?.({ block: 'start' });
            }}>
              {s.title}
            </a>
          ))}
        </nav>
      </div>

      <div className="stack">
        <section id="settings-connection" className="panel settings-block" aria-labelledby="h-connection">
          <h2 id="h-connection" className="panel-title">接続</h2>
          <TrackerSettings />
        </section>

        <section id="settings-guard" className="panel settings-block" aria-labelledby="h-guard">
          <h2 id="h-guard" className="panel-title">匿名経路</h2>
          <GuardPanel />
        </section>

        {desktop && (
          <section id="settings-host-guard" className="panel settings-block" aria-labelledby="h-host-guard">
            <h2 id="h-host-guard" className="panel-title">この端末の Guard</h2>
            <DesktopGuardSettings />
          </section>
        )}

        <section id="settings-storage" className="panel settings-block" aria-labelledby="h-storage">
          <h2 id="h-storage" className="panel-title">データの保管</h2>
          <StorageSettings />
        </section>

        <section id="settings-ozzy" className="panel settings-block" aria-labelledby="h-ozzy">
          <h2 id="h-ozzy" className="panel-title">ファイル共有</h2>
          <OzzySettings />
        </section>
      </div>
    </div>
  );
}
