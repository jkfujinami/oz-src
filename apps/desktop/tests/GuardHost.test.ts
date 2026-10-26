import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GuardHost, type GuardHostDeps, type GuardWindowLike, type SafeStorageLike } from '../electron/guardHost';
import type { DesktopGuardStatus, GuardReport } from '../src/guardProtocol';

/** OS の鍵の保管庫の代わり (平文を逆順にして印を付けるだけ。平文がファイルに出ないことを確かめるため) */
function fakeSafeStorage(over: Partial<SafeStorageLike> = {}): SafeStorageLike {
  return {
    isEncryptionAvailable: () => true,
    encryptString: (p) => Buffer.from('ENC:' + [...p].reverse().join('')),
    decryptString: (b) => [...b.toString().slice(4)].reverse().join(''),
    getSelectedStorageBackend: () => 'keychain',
    ...over,
  };
}

function fakeWindow(id: number) {
  const sent: string[] = [];
  let destroyed = false;
  const win: GuardWindowLike & { sent: string[] } = {
    sent,
    webContents: { id, send: (ch) => { sent.push(ch); } },
    destroy: () => { destroyed = true; },
    isDestroyed: () => destroyed,
  };
  return win;
}

const REPORT: GuardReport = {
  peerId: 'ab'.repeat(16),
  guardString: 'oz-guard:abc',
  hasList: true,
  listed: false,
  listVersion: 3,
  counts: { degree: 5, clients: 4, backbone: 1, tunnels: 2 },
};

describe('GuardHost (この端末の Guard の世話)', () => {
  let dir: string;
  let windows: ReturnType<typeof fakeWindow>[];
  let notified: DesktopGuardStatus[];
  let loginItems: boolean[];

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oz-guardhost-'));
    windows = [];
    notified = [];
    loginItems = [];
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  function host(over: Partial<GuardHostDeps> = {}) {
    return new GuardHost({
      dir: path.join(dir, 'guard'),
      fs,
      safeStorage: fakeSafeStorage(),
      platform: 'darwin',
      randomBytes: (n) => Buffer.alloc(n, 7),
      openWindow: () => {
        const w = fakeWindow(100 + windows.length);
        windows.push(w);
        return w;
      },
      setLoginItem: (on) => { loginItems.push(on); },
      notify: (s) => { notified.push(s); },
      ...over,
    });
  }

  it('既定では動かさない。有効にすると見えないウィンドウを開き、設定を残す (再起動しても有効のまま)', () => {
    const h = host();
    h.startIfEnabled();
    expect(windows).toHaveLength(0);
    expect(h.status()).toMatchObject({ available: true, enabled: false, running: false });

    const s = h.enable({ slots: 8 });
    expect(s).toMatchObject({ enabled: true, starting: true, running: false, slots: 8 });
    expect(windows).toHaveLength(1);

    const again = host();
    expect(again.status()).toMatchObject({ enabled: true, slots: 8 });
    again.startIfEnabled();
    expect(windows).toHaveLength(2);
  });

  it('★パスフレーズは Guard のウィンドウにだけ渡し、ディスクには鍵の保管庫で暗号化したものだけを置く (権限 600)', () => {
    const h = host();
    h.enable();
    const guardId = windows[0].webContents.id;
    expect(() => h.startConfigFor(1)).toThrow(/untrusted/); // 画面のウィンドウなど、他の送り手には渡さない
    const cfg = h.startConfigFor(guardId);
    expect(cfg.passphrase.length).toBeGreaterThanOrEqual(32);
    expect(cfg.slots).toBe(4);
    const file = path.join(dir, 'guard', 'passphrase.bin');
    const onDisk = fs.readFileSync(file).toString();
    expect(onDisk.startsWith('ENC:')).toBe(true);
    expect(onDisk).not.toContain(cfg.passphrase);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    // 次に起動しても同じパスフレーズ (= 同じ身元の DB を開ける)
    const h2 = host();
    h2.enable();
    expect(h2.startConfigFor(windows[1].webContents.id).passphrase).toBe(cfg.passphrase);
  });

  it('★OS の鍵の保管庫が使えない端末 (Linux の平文 basic_text など) では動かさない', () => {
    const none = host({ safeStorage: fakeSafeStorage({ isEncryptionAvailable: () => false }) });
    expect(none.status()).toMatchObject({ available: false });
    expect(none.enable().enabled).toBe(false);
    expect(windows).toHaveLength(0);

    const plain = host({ platform: 'linux', safeStorage: fakeSafeStorage({ getSelectedStorageBackend: () => 'basic_text' }) });
    expect(plain.status().available).toBe(false);
    expect(plain.status().unavailableReason).toMatch(/平文/);
    plain.enable();
    expect(windows).toHaveLength(0);
  });

  it('状態は Guard のウィンドウから届いた正しい形のものだけを受け、画面へ知らせる', () => {
    const h = host();
    h.enable();
    const id = windows[0].webContents.id;
    h.onReport(999, REPORT); // 他の送り手
    h.onReport(id, { ...REPORT, peerId: 'not-hex' }); // 形が違う
    expect(h.status().running).toBe(false);
    h.onReport(id, REPORT);
    expect(h.status()).toMatchObject({ running: true, starting: false, report: { counts: { clients: 4 } } });
    expect(notified.at(-1)?.running).toBe(true);
  });

  it('止めるときは書き残しを待ってからウィンドウを閉じる (応答が無くても上限で閉じる)', async () => {
    const h = host();
    h.enable();
    const w = windows[0];
    h.onReport(w.webContents.id, REPORT);
    const stopping = h.disable();
    expect(w.sent).toContain('oz-guard:stop');
    h.onStopped(w.webContents.id);
    const s = await stopping;
    expect(s).toMatchObject({ enabled: false, running: false });
    expect(w.isDestroyed()).toBe(true);

    // 応答が無いときは上限で閉じる
    h.enable();
    vi.useFakeTimers();
    const p = h.stop(1000);
    vi.advanceTimersByTime(1000);
    await p;
    vi.useRealTimers();
    expect(windows[1].isDestroyed()).toBe(true);
  });

  it('起動に失敗したら理由を出してウィンドウを閉じる。勝手に消えたら止まったと知らせる', () => {
    const h = host();
    h.enable();
    h.onError(windows[0].webContents.id, 'トラッカーが設定されていません');
    expect(h.status()).toMatchObject({ running: false, starting: false, error: 'トラッカーが設定されていません' });
    expect(windows[0].isDestroyed()).toBe(true);

    h.enable();
    h.onReport(windows[1].webContents.id, REPORT);
    h.onWindowGone('crashed');
    expect(h.status()).toMatchObject({ running: false, error: expect.stringMatching(/crashed/) });
  });

  it('ログイン時の起動を切り替える', () => {
    const h = host();
    expect(h.setOpenAtLogin(true).openAtLogin).toBe(true);
    expect(loginItems).toEqual([true]);
    expect(host().status().openAtLogin).toBe(true);
  });

  it('★緊急消去: 待たずにウィンドウを壊し、設定と封印したパスフレーズを消し、ログイン時の起動も外す', () => {
    const h = host();
    h.enable();
    h.setOpenAtLogin(true);
    h.startConfigFor(windows[0].webContents.id);
    h.destroyNow();
    expect(windows[0].isDestroyed()).toBe(true);
    expect(fs.existsSync(path.join(dir, 'guard'))).toBe(false);
    expect(loginItems.at(-1)).toBe(false);
    expect(host().status().enabled).toBe(false);
  });

  it('ポート開放トラッカー (trackerPort) を指定すると trackerService を起動して oz-tracker:... を返し、トラッカー URL 同期も行う', async () => {
    const startMock = vi.fn().mockResolvedValue({ trackerString: 'oz-tracker:TEST_TOKEN', port: 18787 });
    const stopMock = vi.fn().mockResolvedValue(undefined);
    const h = host({ trackerService: { start: startMock, stop: stopMock } });

    h.setTrackerUrl('wss://custom-tracker.example/ws');
    h.enable({ slots: 4, trackerPort: 18787 });
    expect(startMock).toHaveBeenCalledWith(18787);
    await vi.waitFor(() => expect(h.status().trackerString).toBe('oz-tracker:TEST_TOKEN'));
    expect(h.status().trackerPort).toBe(18787);

    // ポート開放トラッカー稼働時は Guard 自身はそのローカルポートへ接続する
    const cfg = h.startConfigFor(windows[0].webContents.id);
    expect(cfg.trackerUrl).toBe('ws://127.0.0.1:18787/ws');

    // 無効化で trackerService も停止する
    const stopping = h.disable();
    h.onStopped(windows[0].webContents.id);
    await stopping;
    expect(stopMock).toHaveBeenCalled();
    expect(h.status().trackerString).toBeNull();
  });
});
