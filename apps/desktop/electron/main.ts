// ★ ws のネイティブ拡張 (bufferutil / utf-8-validate) の誤解決によるクラッシュを防止
//   Vite でバンドルすると bufferutil が空モジュールとして解決され、t.unmask is not a function で落ちる
process.env.WS_NO_BUFFER_UTIL = '1';
process.env.WS_NO_UTF_8_VALIDATE = '1';

import { app, BrowserWindow, Menu, Tray, nativeImage, dialog, Notification, ipcMain, powerMonitor, session, safeStorage, powerSaveBlocker } from 'electron';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { clearVolatileData, removeDirContents, wipeDeviceData } from './wipe';
import { GuardHost } from './guardHost';
import { createLocalTrackerService } from './localTracker';

/**
 * ★ 端末に残る痕跡を減らす設定 (app が ready になる前に決める)
 *
 *   - ウィンドウ・トレイ・通知の文言には投稿内容などを出さない。アプリ名は OZ をそのまま出す
 *     (以前は「メモ」に偽装していたが、配布するアプリとして名前とアイコンを出すことにした)。
 *   - HTTP キャッシュは実質使わない。ロック・終了時にも消す。
 *   - クラッシュレポートは有効にしない (crashReporter は起動しない)。Breakpad も切る
 *     (ダンプにはメモリ上の情報が入り得る)。
 *
 *   「IndexedDB の origin 以外を in-memory パーティションにする」ことはしない。
 *   この UI は 1 つの origin / 1 つのセッションで動いており、IndexedDB の永続化と
 *   他の保存領域は同じパーティションに載る。メモリ上のパーティションにすると
 *   IndexedDB も終了で消え、暗号化データを持ち越せなくなる。代わりに、IndexedDB 以外の
 *   保存領域 (Cookie・Local Storage・キャッシュ等) をロックのたびに消す。
 */
const APP_NAME = 'OZ';
app.commandLine.appendSwitch('disk-cache-size', '1');
app.commandLine.appendSwitch('disable-breakpad');
// ★ WebRTC は LAN 内のアドレスを出さない ('default_public_interface_only'。UDP は使える)。
//   旧版は force-webrtc-ip-handling-policy=disable_non_proxied_udp をプロセス全体に掛けていて、ピアとの UDP が止まり
//   P2P (掲示板の網・Ozzy のオニオン回路での取得) がつながらなかった。
app.commandLine.appendSwitch('enforce-webrtc-ip-permission-check');

const APP_ROOT = app.getAppPath();
const RENDERER_DIST = path.join(APP_ROOT, 'dist');
const VITE_DEV_SERVER_URL = process.env.VITE_DEV_SERVER_URL;

app.setName(APP_NAME);
/**
 * 端末のデータ (暗号化 DB など) の置き場所。
 * ★ 開発中 (配布版でない) は配布版とは別のプロファイルを使う。開発用に起動しただけで、普段使っている
 *   データ (投稿履歴・板の鍵) に触れないように。試験では OZ_USER_DATA_DIR (絶対パス) で別の場所を指せる。
 *   単一起動のロックも userData に作られるので、ロックを取る前に決める。
 */
const PROFILE_OVERRIDE = process.env.OZ_USER_DATA_DIR;
if (PROFILE_OVERRIDE && path.isAbsolute(PROFILE_OVERRIDE)) {
  app.setPath('userData', PROFILE_OVERRIDE);
} else if (!app.isPackaged) {
  app.setPath('userData', path.join(app.getPath('appData'), `${APP_NAME}-dev`));
}

/** アプリの画面の URL か (開発サーバか、同梱した dist/ の中のファイル) */
function isAppUrl(url: string): boolean {
  if (VITE_DEV_SERVER_URL) return url.startsWith(VITE_DEV_SERVER_URL);
  return url.startsWith(pathToFileURL(RENDERER_DIST).href);
}

/** 画面が求めてよい権限。それ以外 (カメラ・マイク・位置・通知など) は聞かずに断る */
const ALLOWED_PERMISSIONS = new Set(['clipboard-sanitized-write', 'fullscreen']);

let mainWindow: BrowserWindow | null = null;
/** この端末で動かす信頼 Guard (見えないウィンドウ。画面のノードとは別)。app の準備ができてから作る */
let guardHost: GuardHost | null = null;
/** ログイン時に起動されたとき (画面を出さず、トレイと Guard だけで動く) */
const LOGIN_LAUNCH_ARG = '--oz-hidden';
let tray: Tray | null = null;
let isQuitting = false;
let hideNoticeShown = false;
let cachesCleared = false;
/** 緊急消去を実行した (終了後にもう一度 userData を掃除する) */
let wiping = false;

/** レンダラーへ操作を依頼する (preload の onCommand で受ける) */
function sendCommand(command: 'lock' | 'panic-wipe') {
  mainWindow?.webContents.send('oz:command', command);
}

/**
 * 緊急消去。誤操作を防ぐため、既定の選択を「キャンセル」にした確認を挟む。
 * 通知や確認文に投稿内容などは含めない。
 */
async function confirmPanicWipe() {
  const { response } = await dialog.showMessageBox({
    type: 'warning',
    buttons: ['キャンセル', '全消去する'],
    defaultId: 0,
    cancelId: 0,
    title: '緊急消去',
    message: 'この端末のデータをすべて消去します。',
    detail: '通信を止め、データを読めなくしてから削除します。元に戻せません。',
  });
  if (response === 1) sendCommand('panic-wipe');
}

function createTrayIcon(): Electron.NativeImage {
  // OZ のアイコン (build/tray.png と tray@2x.png。配布版は resources に同梱)
  const dir = app.isPackaged ? process.resourcesPath : path.join(APP_ROOT, 'build');
  const icon = nativeImage.createFromPath(path.join(dir, 'tray.png'));
  if (!icon.isEmpty()) return icon;
  // 見つからないときはグレーの四角
  const size = 16;
  const buffer = Buffer.alloc(size * size * 4, 0);
  for (let i = 0; i < size * size; i++) {
    // 中立のグレー (Google Grey 500)。アプリの色・ロゴは出さない (トレイからアプリが分からないように)
    buffer[i * 4] = 154;     // R
    buffer[i * 4 + 1] = 160; // G
    buffer[i * 4 + 2] = 166; // B
    buffer[i * 4 + 3] = 255; // A
  }
  return nativeImage.createFromBuffer(buffer, { width: size, height: size });
}

function createTray() {
  const icon = createTrayIcon();
  tray = new Tray(icon);
  tray.setToolTip(APP_NAME);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'ウィンドウを表示',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    {
      label: 'バックグラウンドで動作中',
      enabled: false,
    },
    { type: 'separator' },
    {
      label: 'ロック (通信を止めてパスワード画面へ)',
      click: () => sendCommand('lock'),
    },
    {
      label: '緊急消去...',
      click: () => { void confirmPanicWipe(); },
    },
    { type: 'separator' },
    {
      label: '終了 (Quit)',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show();
    }
  });
}

/** Guard を動かす見えないウィンドウ。画面のウィンドウと同じ制限 (外部への遷移・新しいウィンドウを断る) を掛ける */
function createGuardWindow(): BrowserWindow {
  const win = new BrowserWindow({
    show: false,
    width: 480,
    height: 320,
    title: `${APP_NAME} Guard`,
    webPreferences: {
      preload: path.join(__dirname, 'guardPreload.js'),
      backgroundThrottling: false, // 見えないまま動き続ける (タイマー・WebRTC を止めない)
      nodeIntegration: false,
      contextIsolation: true,
      devTools: !app.isPackaged,
    },
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });
  if (typeof win.webContents.setWebRTCIPHandlingPolicy === 'function') {
    win.webContents.setWebRTCIPHandlingPolicy('default_public_interface_only');
  }
  win.webContents.on('render-process-gone', (_event, details) => guardHost?.onWindowGone(details.reason));
  win.on('closed', () => guardHost?.onWindowGone('closed'));
  if (VITE_DEV_SERVER_URL) {
    void win.loadURL(new URL('guard.html', VITE_DEV_SERVER_URL).href);
  } else {
    void win.loadFile(path.join(RENDERER_DIST, 'guard.html'));
  }
  return win;
}

function createWindow({ show = true }: { show?: boolean } = {}) {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    show,
    title: APP_NAME,
    // 配布版は実行ファイルに埋めたアイコンを使う。開発中だけ build/icon.png を指す
    icon: app.isPackaged ? undefined : path.join(APP_ROOT, 'build', 'icon.png'),
    backgroundColor: '#202124', // 画面の地の色 (styles.css の --bg。Google Grey 900)。読み込み前に白く光らない
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      backgroundThrottling: false, // バックグラウンドでもWebRTC/タイマーを維持
      nodeIntegration: false,
      contextIsolation: true,
      // ★ 配布版では DevTools を開けない (ログや通信内容を画面から読めてしまうため)
      devTools: !app.isPackaged,
    },
  });

  // ページの <title> でウィンドウ名が書き換わらないようにする
  mainWindow.on('page-title-updated', (event) => event.preventDefault());
  // ★ このウィンドウはアプリの画面だけを表示する。外部のページへの遷移も、新しいウィンドウも開かない
  //   (画面の中のリンクや、取り込んだ文字列に仕込まれた URL で、外のページに連れ出されないように)
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });
  if (typeof mainWindow.webContents.setWebRTCIPHandlingPolicy === 'function') {
    mainWindow.webContents.setWebRTCIPHandlingPolicy('default_public_interface_only');
  }

  // レンダラーのコンソール出力をターミナルへ流すのは開発時だけ。
  //
  // ★ 配布版では転送しない。メインプロセスの標準出力は OS のセッションログ
  //   (Linux の ~/.xsession-errors など) に平文で残ることがあり、経路や ID を含む
  //   ログが押収時の痕跡になる。
  if (VITE_DEV_SERVER_URL) {
    mainWindow.webContents.on('console-message', (_event, _level, message, line, sourceId) => {
      console.log(`[Renderer] ${message} (${sourceId}:${line})`);
    });
  }

  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription) => {
    console.error(`[Load Error] ${errorCode}: ${errorDescription}`);
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
      // ★ 閉じてもノードは動き続ける (cover traffic を流し続けることで、
      //   オンラインの時間帯と投稿の相関を弱める)。終了したと誤解されないよう
      //   最初の 1 回だけ知らせる。文面には投稿内容などを含めない。
      if (!hideNoticeShown && Notification.isSupported()) {
        hideNoticeShown = true;
        new Notification({
          title: APP_NAME,
          body: 'バックグラウンドで動作しています。終了はトレイのメニューから行えます。',
          silent: true,
        }).show();
      }
    }
  });

  const indexPath = path.join(RENDERER_DIST, 'index.html');
  console.log('[Main] Loading UI from:', VITE_DEV_SERVER_URL || indexPath);

  if (VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(indexPath);
  }

  // macOS で確実に前面に表示 (ログイン時に起動したときは出さない)
  if (show) {
    mainWindow.show();
    mainWindow.focus();
  } else {
    mainWindow.hide();
  }
}

// Single Instance Lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  /** レンダラー (自分のウィンドウ) からの呼び出しだけを受ける */
  const fromMainWindow = (event: Electron.IpcMainInvokeEvent) => {
    if (!mainWindow || event.sender !== mainWindow.webContents) {
      throw new Error('untrusted sender');
    }
  };

  ipcMain.handle('oz:clear-caches', async (event) => {
    fromMainWindow(event);
    await clearVolatileData(session.defaultSession);
  });

  // ── この端末の Guard ──
  // 画面からの操作は画面のウィンドウからだけ、起動の設定と状態は Guard のウィンドウからだけ受ける
  ipcMain.handle('oz-guard:get', (event) => {
    fromMainWindow(event);
    return guardHost?.status() ?? null;
  });
  ipcMain.handle('oz-guard:enable', (event, opts: unknown) => {
    fromMainWindow(event);
    const o = typeof opts === 'object' && opts !== null ? (opts as { slots?: unknown; trackerPort?: unknown }) : {};
    return guardHost?.enable({
      slots: typeof o.slots === 'number' ? o.slots : undefined,
      trackerPort: typeof o.trackerPort === 'number' ? o.trackerPort : o.trackerPort === null ? null : undefined,
    }) ?? null;
  });
  ipcMain.handle('oz-guard:disable', async (event) => {
    fromMainWindow(event);
    return (await guardHost?.disable()) ?? null;
  });
  ipcMain.handle('oz-guard:set-login', (event, on: unknown) => {
    fromMainWindow(event);
    return guardHost?.setOpenAtLogin(on === true) ?? null;
  });
  ipcMain.handle('oz-guard:set-tracker-url', (event, url: unknown) => {
    fromMainWindow(event);
    return guardHost?.setTrackerUrl(typeof url === 'string' ? url : null) ?? null;
  });
  ipcMain.handle('oz-guard:start-config', (event) => {
    if (!guardHost) throw new Error('guard not ready');
    return guardHost.startConfigFor(event.sender.id);
  });
  ipcMain.on('oz-guard:report', (event, report: unknown) => guardHost?.onReport(event.sender.id, report));
  ipcMain.on('oz-guard:error', (event, message: unknown) => guardHost?.onError(event.sender.id, message));
  ipcMain.on('oz-guard:stopped', (event) => guardHost?.onStopped(event.sender.id));

  ipcMain.handle('oz:wipe-device-data', async (event) => {
    fromMainWindow(event);
    wiping = true;
    // Guard の身元 (DB と封印したパスフレーズ) も消す。書き戻されないよう、待たずにウィンドウを壊す
    guardHost?.destroyNow();
    await wipeDeviceData({
      session: session.defaultSession,
      userDataPath: app.getPath('userData'),
      fs,
      quit: () => { isQuitting = true; app.quit(); },
    });
  });

  // <webview> は使わない (埋め込みで別のページを開かせない)
  app.on('web-contents-created', (_event, contents) => {
    contents.on('will-attach-webview', (event) => event.preventDefault());
  });

  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => {
      callback(ALLOWED_PERMISSIONS.has(permission));
    });
    session.defaultSession.setPermissionCheckHandler((_wc, permission) => ALLOWED_PERMISSIONS.has(permission));

    // ★ 配布版にはアプリケーションメニュー (開発者ツールや再読み込みの入口) を置かない。
    //   macOS はメニューが無いとコピー・貼り付けのショートカットも効かないので、編集だけ残す。
    if (app.isPackaged) {
      Menu.setApplicationMenu(
        process.platform === 'darwin'
          ? Menu.buildFromTemplate([{ label: APP_NAME, submenu: [{ role: 'quit' }] }, { role: 'editMenu' }])
          : null,
      );
    }

    if (process.platform === 'darwin' && !app.isPackaged) app.dock?.setIcon(path.join(APP_ROOT, 'build', 'icon.png'));
    const launchedAtLogin = process.argv.includes(LOGIN_LAUNCH_ARG) || app.getLoginItemSettings().wasOpenedAsHidden;
    createWindow({ show: !launchedAtLogin });
    createTray();

    guardHost = new GuardHost({
      dir: path.join(app.getPath('userData'), 'guard'),
      fs,
      safeStorage,
      platform: process.platform,
      randomBytes,
      openWindow: createGuardWindow,
      setLoginItem: (openAtLogin) => {
        app.setLoginItemSettings({ openAtLogin, openAsHidden: true, args: [LOGIN_LAUNCH_ARG] });
      },
      notify: (status) => {
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('oz-guard:status', status);
        tray?.setToolTip(status.running ? `${APP_NAME} (Guard 稼働中)` : APP_NAME);
      },
      trackerService: createLocalTrackerService(),
    });
    // ★ OS によるバックグラウンド凍結・App Nap・スリープによる通信遮断を強力に防止
    powerSaveBlocker.start('prevent-app-suspension');

    // ★ 画面のロックとは関係なく動かす (画面のノードが止まっていても、Guard は利用者を受け入れ続ける)
    guardHost.startIfEnabled();

    // ★ 画面ロック時に P2P 接続を切断させないため、自動ロックは行わない。
    //   スリープからの復帰時にはネットワーク再接続を促す。
    powerMonitor.on('resume', () => {
      mainWindow?.webContents.send('oz:system-resume');
    });

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      } else {
        mainWindow?.show();
        mainWindow?.focus();
      }
    });
  });

  app.on('before-quit', (event) => {
    isQuitting = true;
    // 終了前にキャッシュ等を消す (非同期なので、済むまで終了を保留して呼び直す)
    if (!cachesCleared && !wiping) {
      event.preventDefault();
      cachesCleared = true;
      // Guard を止めて書き残しを終えてから (上限あり)、キャッシュ等を消して終了する
      void (async () => {
        await guardHost?.stop().catch(() => {});
        await clearVolatileData(session.defaultSession);
      })().finally(() => app.quit());
    }
  });

  // 緊急消去後は、終了処理で Chromium が書き戻した分をもう一度消す (best effort)
  app.on('quit', () => {
    if (wiping) removeDirContents(app.getPath('userData'), fs);
  });
}
