import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';

type Command = 'lock' | 'panic-wipe';

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  isElectron: true,
  /**
   * トレイからの操作 (ロック / 緊急消去) を受け取る。解除関数を返す。
   * 受け付けるのは決まった 2 種類だけ (それ以外の文字列は捨てる)。
   */
  onCommand: (cb: (command: Command) => void) => {
    const listener = (_event: IpcRendererEvent, command: unknown) => {
      if (command === 'lock' || command === 'panic-wipe') cb(command);
    };
    ipcRenderer.on('oz:command', listener);
    return () => { ipcRenderer.removeListener('oz:command', listener); };
  },
  /**
   * 緊急消去の仕上げ: ブラウザ側の保存領域・キャッシュ・userData を消してアプリを終了する。
   * レンダラーが IndexedDB を消した後に呼ぶ。引数は取らない (渡せるのは「やる」ことだけ)。
   */
  wipeDeviceData: (): Promise<void> => ipcRenderer.invoke('oz:wipe-device-data'),
  /** ロック時: キャッシュなど、IndexedDB 以外の保存領域を消す */
  clearCaches: (): Promise<void> => ipcRenderer.invoke('oz:clear-caches'),
  /**
   * この端末で動かす信頼 Guard (画面のノードとは別に、見えないウィンドウで動く)。
   * 状態は件数と Guard 文字列だけ (利用者の peerId や IP は来ない)。
   */
  guard: {
    get: (): Promise<unknown> => ipcRenderer.invoke('oz-guard:get'),
    enable: (opts: { slots: number }): Promise<unknown> => ipcRenderer.invoke('oz-guard:enable', { slots: opts.slots }),
    disable: (): Promise<unknown> => ipcRenderer.invoke('oz-guard:disable'),
    setOpenAtLogin: (on: boolean): Promise<unknown> => ipcRenderer.invoke('oz-guard:set-login', on === true),
    onStatus: (cb: (status: unknown) => void) => {
      const listener = (_event: IpcRendererEvent, status: unknown) => cb(status);
      ipcRenderer.on('oz-guard:status', listener);
      return () => { ipcRenderer.removeListener('oz-guard:status', listener); };
    },
  },
});
