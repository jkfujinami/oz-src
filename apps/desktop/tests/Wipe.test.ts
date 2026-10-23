import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { clearVolatileData, removeDirContents, wipeDeviceData, VOLATILE_STORAGES } from '../electron/wipe';

function fakeSession() {
  return {
    calls: [] as string[],
    storages: undefined as string[] | undefined,
    async clearStorageData(opts?: { storages?: string[] }) { this.calls.push('storage'); this.storages = opts?.storages; },
    async clearCache() { this.calls.push('cache'); },
    async clearCodeCaches() { this.calls.push('code'); },
  };
}

describe('デスクトップ版の消去 (Electron のメインプロセス側)', () => {
  it('緊急消去: 全保存領域・キャッシュを消し、userData の中身を削除して、最後に終了する', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oz-wipe-'));
    fs.mkdirSync(path.join(dir, 'IndexedDB', 'x'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'IndexedDB', 'x', 'data'), 'secret');
    fs.writeFileSync(path.join(dir, 'Preferences'), '{}');
    const session = fakeSession();
    const order: string[] = [];
    await wipeDeviceData({
      session,
      userDataPath: dir,
      fs,
      quit: () => order.push(`quit:${fs.readdirSync(dir).length}`),
    });
    expect(session.calls).toEqual(['storage', 'cache', 'code']);
    expect(session.storages).toBeUndefined(); // 絞り込まない = 全ての保存領域 (IndexedDB を含む)
    expect(fs.readdirSync(dir)).toEqual([]); // userData の直下は空 (ディレクトリ自体は残る)
    expect(order).toEqual(['quit:0']); // 削除が済んでから終了する
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('一部の削除が失敗しても、残りを消して終了まで進む', async () => {
    const rm = vi.fn((p: string) => { if (p.endsWith('/locked')) throw new Error('EBUSY'); });
    const fsLike = { readdirSync: () => ['locked', 'ok'], rmSync: rm };
    const quit = vi.fn();
    const session = { ...fakeSession(), clearCache: async () => { throw new Error('boom'); } };
    await wipeDeviceData({ session, userDataPath: '/u', fs: fsLike, quit });
    expect(rm.mock.calls.map((c) => c[0])).toEqual(['/u/locked', '/u/ok']);
    expect(quit).toHaveBeenCalledTimes(1);
  });

  it('removeDirContents: 無いディレクトリは何もせず 0、消せなかった数を返す', () => {
    expect(removeDirContents('/definitely/not/here', fs)).toBe(0);
    const fsLike = { readdirSync: () => ['a', 'b'], rmSync: () => { throw new Error('x'); } };
    expect(removeDirContents('/u', fsLike)).toBe(2);
  });

  it('ロック時の削除は IndexedDB を残す (暗号化済みで、次回のロック解除で要る)', async () => {
    const session = fakeSession();
    await clearVolatileData(session);
    expect(session.calls).toEqual(['cache', 'storage', 'code']);
    expect(session.storages).toEqual(VOLATILE_STORAGES);
    expect(VOLATILE_STORAGES).not.toContain('indexdb');
  });
});

describe('メインプロセスの設定 (静的な確認)', () => {
  const main = fs.readFileSync(path.resolve(__dirname, '../electron/main.ts'), 'utf8');
  const html = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');

  it('アプリ名は 1 か所 (APP_NAME = OZ) で決め、ウィンドウ・トレイ・通知・ページの題はそれを使う', () => {
    expect(main).toMatch(/const APP_NAME = 'OZ';/);
    expect(main).toMatch(/title: APP_NAME/);
    expect(main).toMatch(/tray\.setToolTip\(APP_NAME\)/);
    expect(html).toMatch(/<title>OZ<\/title>/);
  });

  it('外部のページへの遷移・新しいウィンドウ・webview・権限 (カメラ・マイク・位置など) を断る', () => {
    expect(main).toMatch(/setWindowOpenHandler\(\(\) => \(\{ action: 'deny' \}\)\)/);
    expect(main).toMatch(/'will-navigate'[\s\S]*isAppUrl\(url\)[\s\S]*preventDefault/);
    expect(main).toMatch(/'will-attach-webview'[\s\S]*preventDefault/);
    expect(main).toMatch(/setPermissionRequestHandler/);
    expect(main).toMatch(/setPermissionCheckHandler/);
    expect(main).toMatch(/ALLOWED_PERMISSIONS = new Set\(\['clipboard-sanitized-write', 'fullscreen'\]\)/);
  });

  it('開発中は配布版とは別のプロファイルを使う (普段のデータに触らない)', () => {
    expect(main).toMatch(/!app\.isPackaged\)[\s\S]*setPath\('userData'[\s\S]*-dev/);
  });

  it('配布版では DevTools とアプリメニューを出さず、キャッシュを最小にし、クラッシュレポートを起動しない', () => {
    expect(main).toMatch(/devTools:\s*!app\.isPackaged/);
    expect(main).toMatch(/app\.isPackaged[\s\S]*Menu\.setApplicationMenu/);
    expect(main).not.toMatch(/openDevTools/);
    expect(main).toMatch(/disk-cache-size/);
    expect(main).not.toMatch(/crashReporter\.start/);
  });

  it('スリープ・画面ロックでレンダラーへ lock を送る', () => {
    expect(main).toMatch(/powerMonitor\.on\('suspend'/);
    expect(main).toMatch(/powerMonitor\.on\('lock-screen'/);
  });
});
