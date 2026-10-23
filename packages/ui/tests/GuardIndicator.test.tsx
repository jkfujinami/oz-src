// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';

import { Sidebar } from '../src/components/Sidebar';
import { GuardPanel } from '../src/components/GuardPanel';
import { P2PContextForTest } from '../src/providers/P2PProvider';

const FULL_PEER_ID = '0123456789abcdef0123456789abcdef';

function context(over: Record<string, unknown> = {}): any {
  return {
    node: { degree: 0 },
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
    trackerUrl: 'wss://tracker.example.org/ws',
    setTrackerUrl: vi.fn().mockResolvedValue({ ok: true }),
    guardStatus: { mode: 'trusted', guardId: FULL_PEER_ID, listVersion: 3, listExpiresAt: Date.UTC(2030, 0, 1) },
    guardTrustConfigured: true,
    importGuardList: vi.fn().mockResolvedValue({ ok: false, reason: 'rollback' }),
    ...over,
  };
}

function renderHeader(value: any) {
  return render(
    <P2PContextForTest.Provider value={value}>
      <Sidebar section="board" onSelect={() => {}} />
    </P2PContextForTest.Provider>,
  );
}

afterEach(() => cleanup());

describe('匿名経路の状態表示 (サイドバー)', () => {
  it('信頼 Guard 経由なら落ち着いた表示にする (警告ではない)', () => {
    renderHeader(context({ guardStatus: { mode: 'trusted', guardId: null, listVersion: 1, listExpiresAt: null } }));
    const button = screen.getByText('信頼 Guard 経由');
    expect(button).toBeTruthy();
    expect(screen.queryByText(/警告/)).toBeNull();
  });

  it('信頼 Guard に未接続なら警告を出す', () => {
    renderHeader(context({ guardStatus: { mode: 'fallback', guardId: null, listVersion: 1, listExpiresAt: null, reason: 'no-trusted-guard-connected' } }));
    expect(screen.getByText('警告: 信頼 Guard に未接続')).toBeTruthy();
  });

  it('信頼リストが無ければ「未設定」の警告を出す', () => {
    renderHeader(context({ guardStatus: { mode: 'open', guardId: null, listVersion: null, listExpiresAt: null, reason: 'no-list' } }));
    expect(screen.getByText('警告: 信頼 Guard 未設定')).toBeTruthy();
  });

  it('起動直後の待ちは、エラーに見えない文言にする', () => {
    for (const reason of ['waiting-for-trusted-guard', 'waiting-for-candidates']) {
      cleanup();
      renderHeader(context({ guardStatus: { mode: 'none', guardId: null, listVersion: null, listExpiresAt: null, reason } }));
      expect(screen.getByText('匿名経路を準備中…')).toBeTruthy();
      expect(screen.queryByText(/警告/)).toBeNull();
    }
  });

  it('リストが期限切れなら警告にする (準備が整えば警告状態で送られる)', () => {
    renderHeader(context({ guardStatus: { mode: 'none', guardId: null, listVersion: 2, listExpiresAt: null, reason: 'list-expired' } }));
    expect(screen.getByText('警告: 信頼リストが期限切れ')).toBeTruthy();
  });

  it('ノードが無ければ状態表示を出さない', () => {
    renderHeader(context({ node: null }));
    expect(screen.queryByText(/信頼 Guard 経由|警告|準備中/)).toBeNull();
  });

  it('ボタンを押すと設定の「匿名経路」を開く。信頼設定が無ければ取り込み欄は出さない', () => {
    const value = context({
      guardTrustConfigured: false,
      guardStatus: { mode: 'open', guardId: null, listVersion: null, listExpiresAt: null, reason: 'no-list' },
    });
    const onSelect = vi.fn();
    render(
      <P2PContextForTest.Provider value={value}>
        <Sidebar section="board" onSelect={onSelect} />
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.click(screen.getByText('警告: 信頼 Guard 未設定'));
    expect(onSelect).toHaveBeenCalledWith('settings', 'guard');
    expect(screen.getByText('匿名経路の状態')).toBeTruthy();
    expect(screen.getByText(/審査されていない普通の隣人/)).toBeTruthy();
    expect(screen.queryByLabelText('信頼リストの文字列')).toBeNull();
  });
});

describe('信頼リストの取り込み (パネル)', () => {
  it('信頼設定があれば取り込み欄を出し、成功を表示する', async () => {
    const importGuardList = vi.fn().mockResolvedValue({
      ok: true, version: 4, issuedAt: 0, expiresAt: Date.UTC(2030, 0, 1), guards: [], revoked: [],
    });
    render(
      <P2PContextForTest.Provider value={context({ importGuardList })}>
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('信頼リストの文字列'), { target: { value: 'oz-guards:abc' } });
    fireEvent.click(screen.getByText('取り込む'));
    await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/取り込みました \(版 4/));
    expect(importGuardList).toHaveBeenCalledWith('oz-guards:abc');
  });

  it('失敗の理由を日本語で表示する (rollback は古い版)', async () => {
    const importGuardList = vi.fn().mockResolvedValue({ ok: false, reason: 'rollback' });
    render(
      <P2PContextForTest.Provider value={context({ importGuardList })}>
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('信頼リストの文字列'), { target: { value: 'oz-guards:old' } });
    fireEvent.click(screen.getByText('取り込む'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('手元のリストより古い版です'));
  });

  it('署名不足は専用の文言にする', async () => {
    const importGuardList = vi.fn().mockResolvedValue({ ok: false, reason: 'insufficient-signatures' });
    render(
      <P2PContextForTest.Provider value={context({ importGuardList })}>
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('信頼リストの文字列'), { target: { value: 'oz-guards:x' } });
    fireEvent.click(screen.getByText('取り込む'));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('メンテナの署名が足りません'));
  });

  it('ノードが停止中で取り込みが例外になっても落ちずに伝える', async () => {
    const importGuardList = vi.fn().mockRejectedValue(new Error('node is stopped'));
    render(
      <P2PContextForTest.Provider value={context({ importGuardList })}>
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.change(screen.getByLabelText('信頼リストの文字列'), { target: { value: 'oz-guards:x' } });
    fireEvent.click(screen.getByText('取り込む'));
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
  });
});

describe('Guard の peerId は画面に出さない', () => {
  it('サイドバーとパネルのどちらにも、完全な peerId もその先頭も出ない', () => {
    const value = context({
      guardStatus: { mode: 'trusted', guardId: FULL_PEER_ID, listVersion: 3, listExpiresAt: Date.UTC(2030, 0, 1) },
    });
    const { container } = render(
      <P2PContextForTest.Provider value={value}>
        <Sidebar section="board" onSelect={() => {}} />
        <GuardPanel />
      </P2PContextForTest.Provider>,
    );
    fireEvent.click(screen.getByText('信頼 Guard 経由'));
    const text = container.textContent ?? '';
    expect(text).not.toContain(FULL_PEER_ID);
    expect(text).not.toContain(FULL_PEER_ID.slice(0, 8));
    expect(container.innerHTML).not.toContain(FULL_PEER_ID);
  });
});
