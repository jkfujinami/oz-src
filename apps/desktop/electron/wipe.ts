/**
 * デスクトップ版の端末データの消去。Electron のモジュールには依存せず、
 * 必要なものを引数で受ける (メインプロセスから使い、テストでは差し替える)。
 *
 * ★ レンダラーの緊急消去は IndexedDB の DEK を消して DB を削除するところまでしか
 *   できない。Chromium はそれ以外にも、キャッシュ・Cookie・Local Storage・
 *   Service Worker・コードキャッシュ・シェーダキャッシュを userData に書く。
 *   メインプロセス側で保存領域を消し、userData の中身を削除してから終了する。
 *
 * ★ これは「アプリから見える範囲」の消去であって、物理的な消去ではない。SSD の
 *   ウェアレベリングやファイルシステムのジャーナル、OS のバックアップ (Time Machine 等) に
 *   削除前の内容が残る可能性を、アプリは排除できない。だから IndexedDB の中身は
 *   最初から DEK で暗号化してあり、DEK の封印を消す (crypto-shredding) ことが本体の防御で、
 *   ここでの削除はその補助である。
 */

/** Electron の Session のうち使う部分 */
export interface SessionLike {
  clearStorageData(options?: { storages?: string[] }): Promise<void>;
  clearCache(): Promise<void>;
  clearCodeCaches?(options: object): Promise<void>;
}

export interface FsLike {
  readdirSync(path: string): string[];
  rmSync(path: string, options: { recursive: boolean; force: boolean }): void;
}

/**
 * IndexedDB 以外の保存領域。ロックのたびに消す (IndexedDB は暗号化済みで、
 * 次回のロック解除で要るので残す)。
 */
export const VOLATILE_STORAGES = [
  'cookies',
  'localstorage',
  'cachestorage',
  'serviceworkers',
  'filesystem',
  'shadercache',
  'websql',
];

/** ロック・終了時: キャッシュと IndexedDB 以外の保存領域を消す。失敗しても続ける */
export async function clearVolatileData(session: SessionLike): Promise<void> {
  await session.clearCache().catch(() => undefined);
  await session.clearStorageData({ storages: VOLATILE_STORAGES }).catch(() => undefined);
  await session.clearCodeCaches?.({}).catch(() => undefined);
}

/** dir の直下を全て消す (dir 自体は残す)。消せなかったものの数を返す */
export function removeDirContents(dir: string, fs: FsLike): number {
  let failed = 0;
  let names: string[] = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  for (const name of names) {
    try {
      fs.rmSync(`${dir}/${name}`, { recursive: true, force: true });
    } catch {
      failed++;
    }
  }
  return failed;
}

export interface WipeDeps {
  session: SessionLike;
  userDataPath: string;
  fs: FsLike;
  /** アプリを終了する */
  quit: () => void;
}

/**
 * 緊急消去: 全ての保存領域とキャッシュを消し、userData の中身を削除して終了する。
 * 終了処理で Chromium が書き戻すものがあるので、呼び出し側は終了後にもう一度
 * {@link removeDirContents} を呼ぶこと (main.ts の quit イベント)。
 */
export async function wipeDeviceData(deps: WipeDeps): Promise<void> {
  await deps.session.clearStorageData().catch(() => undefined); // 引数なし = 全ての保存領域
  await deps.session.clearCache().catch(() => undefined);
  await deps.session.clearCodeCaches?.({}).catch(() => undefined);
  removeDirContents(deps.userDataPath, deps.fs);
  deps.quit();
}
