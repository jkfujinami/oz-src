import { contextBridge, ipcRenderer } from 'electron';

/**
 * Guard のウィンドウ (guard.html) とメインプロセスの間の窓口。
 * 画面のウィンドウの preload とは別にし、Guard のウィンドウにだけ読み込む。
 */
contextBridge.exposeInMainWorld('ozGuard', {
  /** 起動に要るもの (パスフレーズ・枠の数)。メインは Guard のウィンドウからの要求にだけ答える */
  getStartConfig: (): Promise<unknown> => ipcRenderer.invoke('oz-guard:start-config'),
  reportStatus: (report: unknown): void => ipcRenderer.send('oz-guard:report', report),
  reportError: (message: string): void => ipcRenderer.send('oz-guard:error', message),
  /** 止める指示を受ける (書き残しを終えたら stopped を呼ぶ) */
  onStop: (cb: () => void): void => {
    ipcRenderer.on('oz-guard:stop', () => cb());
  },
  stopped: (): void => ipcRenderer.send('oz-guard:stopped'),
});
