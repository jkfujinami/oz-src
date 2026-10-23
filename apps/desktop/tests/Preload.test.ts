import { describe, it, expect, vi, beforeEach } from 'vitest';

/** electron モジュールの代わり。preload が公開したものと登録したリスナを記録する */
const exposed: Record<string, any> = {};
const invoked: unknown[][] = [];
const listeners = new Map<string, Set<(...args: any[]) => void>>();

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: (key: string, api: unknown) => { exposed[key] = api; },
  },
  ipcRenderer: {
    invoke: (channel: string, ...args: unknown[]) => { invoked.push([channel, ...args]); return Promise.resolve(); },
    on: (channel: string, fn: (...args: any[]) => void) => {
      if (!listeners.has(channel)) listeners.set(channel, new Set());
      listeners.get(channel)!.add(fn);
    },
    removeListener: (channel: string, fn: (...args: any[]) => void) => {
      listeners.get(channel)?.delete(fn);
    },
  },
}));

function emit(channel: string, ...args: unknown[]) {
  for (const fn of listeners.get(channel) ?? []) fn({}, ...args);
}

describe('Electron preload', () => {
  beforeEach(async () => {
    vi.resetModules();
    for (const k of Object.keys(exposed)) delete exposed[k];
    listeners.clear();
    invoked.length = 0;
    await import('../electron/preload');
  });

  it('レンダラーへ公開するのは electronAPI だけで、ipcRenderer そのものは渡さない', () => {
    expect(Object.keys(exposed)).toEqual(['electronAPI']);
    const api = exposed.electronAPI;
    expect(Object.keys(api).sort()).toEqual(['clearCaches', 'guard', 'isElectron', 'onCommand', 'platform', 'wipeDeviceData']);
    expect(Object.keys(api.guard).sort()).toEqual(['disable', 'enable', 'get', 'onStatus', 'setOpenAtLogin']);
    for (const v of [...Object.values(api), ...Object.values(api.guard)]) {
      expect(v).not.toHaveProperty('send');
      expect(v).not.toHaveProperty('invoke');
    }
  });

  it('トレイからの操作は lock と panic-wipe の 2 種類だけを通す', () => {
    const cb = vi.fn();
    exposed.electronAPI.onCommand(cb);
    emit('oz:command', 'lock');
    emit('oz:command', 'panic-wipe');
    emit('oz:command', 'rm -rf');
    emit('oz:command', { toString: () => 'lock' });
    emit('oz:command');
    expect(cb.mock.calls).toEqual([['lock'], ['panic-wipe']]);
  });

  it('解除関数を呼ぶと以後は受け取らない', () => {
    const cb = vi.fn();
    const off = exposed.electronAPI.onCommand(cb);
    off();
    emit('oz:command', 'lock');
    expect(cb).not.toHaveBeenCalled();
    expect(listeners.get('oz:command')?.size ?? 0).toBe(0);
  });

  it('消去・キャッシュ削除は引数なしで、決まった 2 つのチャンネルにだけ送る', async () => {
    await exposed.electronAPI.wipeDeviceData('ignored', { path: '/' });
    await exposed.electronAPI.clearCaches('ignored');
    expect(invoked).toEqual([['oz:wipe-device-data'], ['oz:clear-caches']]);
  });

  it('Guard の操作は決まったチャンネルにだけ送り、余計な引数は渡さない', async () => {
    const g = exposed.electronAPI.guard;
    await g.get('x');
    await g.enable({ slots: 8, passphrase: 'steal' });
    await g.disable('x');
    await g.setOpenAtLogin('yes');
    expect(invoked).toEqual([
      ['oz-guard:get'],
      ['oz-guard:enable', { slots: 8 }],
      ['oz-guard:disable'],
      ['oz-guard:set-login', false],
    ]);
    const cb = vi.fn();
    const off = g.onStatus(cb);
    emit('oz-guard:status', { running: true });
    off();
    emit('oz-guard:status', { running: false });
    expect(cb.mock.calls).toEqual([[{ running: true }]]);
  });
});
