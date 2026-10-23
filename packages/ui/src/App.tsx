import { useEffect, useState, useRef } from 'react';
import { P2PProvider, useP2P } from './providers/P2PProvider';
import { AppConfigContext } from './providers/AppConfig';
import { Sidebar, type MainSection } from './components/Sidebar';
import { UnlockScreen } from './components/UnlockScreen';
import BoardView from './components/BoardView';
import ThreadView from './components/ThreadView';
import { OzzyVaultView } from './components/OzzyVaultView';
import { SettingsView, type SettingsSection } from './components/SettingsView';
import { AboutView } from './components/AboutView';
import { TermsGate } from './components/TermsGate';
import { useRoute, absorbLocationHash, dismissKeyLinkNotice } from './lib/route';
import { resetOzzyPrefs } from './lib/ozzyPrefs';
import type { GuardTrustConfig } from './lib/guardSetting';
import { installConsoleHandle } from '@oz/core';

export type { MainSection } from './components/Sidebar';

export function RouterView({ initialSection = 'board' }: { initialSection?: MainSection } = {}) {
  const { route, droppedKeyLink } = useRoute();
  const [mainSection, setMainSection] = useState<MainSection>(initialSection);
  const [settingsFocus, setSettingsFocus] = useState<{ section?: SettingsSection; nonce: number }>({ nonce: 0 });

  // ★ 経路は URL ではなくメモリに持つ (lib/route.ts)。ここで残る URL の入口は
  //   `location.hash` を書き換える画面部品 (ThreadView / BoardView が移行されるまで) だけで、
  //   hashchange で経路に取り込んだ直後に URL を素のパスへ置き換える。
  //   鍵つきのリンクの鍵は読まずに捨てる。
  useEffect(() => {
    const onHashChange = () => absorbLocationHash(true);
    window.addEventListener('hashchange', onHashChange);
    absorbLocationHash(false);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // ファイル共有の設定はメモリだけ。ロック (この画面が消える) で既定に戻す
  useEffect(() => () => resetOzzyPrefs(), []);

  // 板やスレッドへ移動した (保存済みの板を選んだ・板を作った等) ときは掲示板の画面に切り替える
  const routeKey = `${route.board}/${route.thread ?? ''}`;
  const firstRoute = useRef(routeKey);
  useEffect(() => {
    if (routeKey !== firstRoute.current) {
      firstRoute.current = routeKey;
      setMainSection('board');
    }
  }, [routeKey]);

  const select = (section: MainSection, focus?: SettingsSection) => {
    setMainSection(section);
    if (section === 'settings') setSettingsFocus(f => ({ section: focus, nonce: f.nonce + 1 }));
  };

  return (
    <div id="app" className="shell">
      <Sidebar section={mainSection} onSelect={select} />
      <main>
        {droppedKeyLink && (
          <div role="note" className="alert alert-warn" style={{ marginBottom: 16, justifyContent: 'space-between', alignItems: 'center' }}>
            <span>
              リンクに含まれていた板の鍵は受け付けていません (閲覧履歴に残るため)。
              共有コードを受け取っている場合は、サイドバーの「共有コードで参加」に貼り付けてください。
            </span>
            <button className="btn btn-sm" onClick={dismissKeyLinkNotice}>
              閉じる
            </button>
          </div>
        )}
        {mainSection === 'vault' ? (
          <OzzyVaultView onOpenSettings={() => select('settings', 'ozzy')} onOpenAbout={() => select('about')} />
        ) : mainSection === 'settings' ? (
          <SettingsView focus={settingsFocus.section} focusNonce={settingsFocus.nonce} />
        ) : mainSection === 'about' ? (
          <AboutView />
        ) : route.thread ? (
          <ThreadView boardId={route.board} threadId={route.thread} />
        ) : (
          <BoardView boardId={route.board} />
        )}
      </main>
    </div>
  );
}

/** ロック解除が済むまでは、パスワード画面だけを出す */
function LockGate({ defaultSection = 'vault' }: { defaultSection?: MainSection }) {
  const { lockState } = useP2P();
  if (lockState !== 'ready') return <UnlockScreen />;
  return <RouterView initialSection={defaultSection} />;
}

export interface OzAppProps {
  /** ヘッダーのラベル (例: 'Desktop Full Node' / 'Web') */
  badge?: string;
  /** 利用者がトラッカーを設定していないときの既定値。P2PProvider を参照 */
  defaultTrackerUrl?: string | null;
  /** 信頼 Guard の設定 (メンテナの公開鍵)。無ければオープン動作 (警告表示) */
  trust?: GuardTrustConfig | null;
  /** STUN サーバ (`stun:` の URL の列)。無ければ Google と Cloudflare の公開 STUN */
  iceServers?: string[] | null;
}

/**
 * Desktop と Web で共通のアプリ本体。
 *
 * ★ 両アプリはこれと @oz/core だけを使う。プロトコルや端末データの扱いを
 *   アプリ側に複製しないことで、Desktop と Web の挙動が食い違わないようにする。
 */
export default function App({ badge = 'Desktop Full Node', defaultTrackerUrl = null, trust = null, iceServers = null }: OzAppProps = {}) {
  // 起動時に URL のハッシュを取り除き、コンソール用 ozLog ハンドルを公開する
  useEffect(() => {
    absorbLocationHash(false);
    installConsoleHandle();
  }, []);
  return (
    <AppConfigContext.Provider value={{ badge }}>
      {/* 利用規約に同意するまでは、データベースもネットワークも始めない */}
      <TermsGate>
        <P2PProvider defaultTrackerUrl={defaultTrackerUrl} trust={trust} iceServers={iceServers}>
          <LockGate />
        </P2PProvider>
      </TermsGate>
    </AppConfigContext.Provider>
  );
}
