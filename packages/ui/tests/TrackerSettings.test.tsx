// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';
import { IndexedDBStore, VAULT_PARAMS_FAST } from '@oz/core';

import { Sidebar } from '../src/components/Sidebar';
import { TrackerSettings } from '../src/components/TrackerSettings';
import { P2PContextForTest, NO_GUARD_STATUS } from '../src/providers/P2PProvider';
import { loadTrackerUrl, saveTrackerUrl, loadIceServers, saveIceServers } from '../src/lib/trackerSetting';

function context(over: Record<string, unknown> = {}): any {
  return {
    node: null,
    boardOrchestrator: null,
    threadOrchestrator: null,
    pm: null,
    identity: null,
    db: null,
    isReady: true,
    lockState: 'ready',
    unlockError: null,
    unlock: async () => {},
    resetAll: async () => {},
    panicWipe: async () => {},
    lock: async () => {},
    trackerUrl: null,
    setTrackerUrl: vi.fn().mockResolvedValue({ ok: true }),
    iceServers: [],
    effectiveIceServers: [],
    defaultStunServer: null,
    setIceServers: vi.fn().mockResolvedValue({ ok: true }),
    guardStatus: NO_GUARD_STATUS,
    guardTrustConfigured: false,
    importGuardList: async () => ({ ok: false, reason: 'malformed' }),
    ...over,
  };
}

afterEach(() => cleanup());

describe('トラッカーの保存 (暗号化 DB)', () => {
  const unlocked = async () => {
    const db = new IndexedDBStore(`desktop-tracker-${Math.random()}`);
    await db.init();
    await db.unlock('test-passphrase', VAULT_PARAMS_FAST);
    return db;
  };

  it('保存した URL を読み戻せる。保存が無ければ未設定 (既定のトラッカーは無い)', async () => {
    const db = await unlocked();
    expect(await loadTrackerUrl(db)).toBeNull();
    await saveTrackerUrl(db, 'wss://tracker.example.org/ws');
    expect(await loadTrackerUrl(db)).toBe('wss://tracker.example.org/ws');
  });

  it('明示的に消したら、ビルド時の既定値があっても未設定のまま', async () => {
    const fallback = 'wss://default.example.org/ws';
    const db = await unlocked();
    expect(await loadTrackerUrl(db, fallback)).toBe(fallback);
    await saveTrackerUrl(db, 'wss://tracker.example.org/ws');
    expect(await loadTrackerUrl(db, fallback)).toBe('wss://tracker.example.org/ws');
    await saveTrackerUrl(db, null);
    expect(await loadTrackerUrl(db, fallback)).toBeNull();
  });

  it('ビルド時の既定値も検証する (平文の ws:// は使わない)', async () => {
    expect(await loadTrackerUrl(await unlocked(), 'ws://default.example.org/ws')).toBeNull();
  });

  it('保存値が壊れていたら使わない', async () => {
    const db = await unlocked();
    await db.setSetting('trackerUrl', { url: 'ws://tracker.example.org/ws' });
    expect(await loadTrackerUrl(db)).toBeNull();
    await db.setSetting('trackerUrl', 'wss://tracker.example.org/ws'); // 形式違い
    expect(await loadTrackerUrl(db)).toBeNull();
  });

  it('ロック中は読めない (URL は暗号化して保存されている)', async () => {
    const db = await unlocked();
    await saveTrackerUrl(db, 'wss://tracker.example.org/ws');
    db.lock();
    await expect(loadTrackerUrl(db)).rejects.toThrow(/locked/);
  });
});

describe('トラッカーの設定画面', () => {
  it('未設定であることをサイドバーで知らせる', () => {
    render(
      <P2PContextForTest.Provider value={context({ node: { degree: 0 } })}>
        <Sidebar section="board" onSelect={() => {}} />
      </P2PContextForTest.Provider>,
    );
    expect(screen.getByText('トラッカー未設定')).toBeTruthy();
  });

  it('入力した URL を保存し、結果を表示する', async () => {
    const setTrackerUrl = vi.fn().mockResolvedValue({ ok: true });
    render(
      <P2PContextForTest.Provider value={context({ setTrackerUrl })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    expect(screen.getByText(/未設定/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('トラッカーの URL'), { target: { value: 'wss://tracker.example.org' } });
    fireEvent.click(screen.getByText('保存'));
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('保存しました'));
    expect(setTrackerUrl).toHaveBeenCalledWith('wss://tracker.example.org');
  });

  it('拒否された理由を表示する', async () => {
    const setTrackerUrl = vi.fn().mockResolvedValue({ ok: false, error: '暗号化されていない ws:// は使えません' });
    render(
      <P2PContextForTest.Provider value={context({ setTrackerUrl })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('トラッカーの URL'), { target: { value: 'ws://tracker.example.org' } });
    fireEvent.click(screen.getByText('保存'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/ws:\/\//));
  });

  it('設定済みなら現在の URL を表示し、消せる', async () => {
    const setTrackerUrl = vi.fn().mockResolvedValue({ ok: true });
    render(
      <P2PContextForTest.Provider value={context({ trackerUrl: 'wss://tracker.example.org/ws', setTrackerUrl })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    expect(screen.getAllByText('wss://tracker.example.org/ws').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText('設定を消す'));
    await waitFor(() => expect(setTrackerUrl).toHaveBeenCalledWith(null));
  });
});

describe('STUN の選択', () => {
  const unlocked = async () => {
    const db = new IndexedDBStore(`desktop-ice-${Math.random()}`);
    await db.init();
    await db.unlock('test-passphrase', VAULT_PARAMS_FAST);
    return db;
  };

  it('保存した STUN を読み戻せる。既定に戻すと null (= トラッカーの STUN)', async () => {
    const db = await unlocked();
    expect(await loadIceServers(db)).toBeNull();
    await saveIceServers(db, ['stun:stun.example.org:3478', 'stun:[2001:db8::1]:3478']);
    expect(await loadIceServers(db)).toEqual(['stun:stun.example.org:3478', 'stun:[2001:db8::1]:3478']);
    await saveIceServers(db, null);
    expect(await loadIceServers(db)).toBeNull();
  });

  it('既定のときは、トラッカーの STUN が「使用中 (既定)」と表示され、既定に戻すボタンは出ない', () => {
    render(
      <P2PContextForTest.Provider value={context({ effectiveIceServers: ['stun:tracker.example.org:3478'], defaultStunServer: 'stun:tracker.example.org:3478' })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    expect(screen.getByText('stun:tracker.example.org:3478')).toBeTruthy();
    expect(screen.getByText(/^\s*\(既定\)$/)).toBeTruthy();
    expect(screen.queryByText('既定に戻す')).toBeNull();
    expect((screen.getByLabelText('STUN サーバー') as HTMLInputElement).placeholder).toBe('stun:tracker.example.org:3478');
  });

  it('好きな STUN を入力して保存できる。既定に戻すこともできる', async () => {
    const setIceServers = vi.fn().mockResolvedValue({ ok: true, notice: '保存しました。次に張る接続から使います' });
    const { rerender } = render(
      <P2PContextForTest.Provider value={context({ setIceServers })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('STUN サーバー'), { target: { value: 'stun:stun.example.org:3478' } });
    fireEvent.click(screen.getByText('STUN を保存'));
    await waitFor(() => expect(setIceServers).toHaveBeenCalledWith('stun:stun.example.org:3478'));
    expect(await screen.findByText('保存しました。次に張る接続から使います')).toBeTruthy();

    rerender(
      <P2PContextForTest.Provider value={context({ setIceServers, iceServers: ['stun:stun.example.org:3478'], effectiveIceServers: ['stun:stun.example.org:3478'] })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    fireEvent.click(screen.getByText('既定に戻す'));
    await waitFor(() => expect(setIceServers).toHaveBeenCalledWith(null));
  });

  it('不正な入力はエラーを出して保存しない', async () => {
    const setIceServers = vi.fn().mockResolvedValue({ ok: false, error: 'TURN には対応していません (stun: で始まる URL だけ)' });
    render(
      <P2PContextForTest.Provider value={context({ setIceServers })}>
        <TrackerSettings />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('STUN サーバー'), { target: { value: 'turn:relay.example.org' } });
    fireEvent.click(screen.getByText('STUN を保存'));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('TURN');
  });
});
