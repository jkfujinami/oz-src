// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';

import { DesktopGuardSettings } from '../src/components/DesktopGuardSettings';
import { SettingsView } from '../src/components/SettingsView';
import { P2PProvider } from '../src/providers/P2PProvider';
import type { DesktopGuardStatus } from '../src/lib/desktopGuard';

const BASE: DesktopGuardStatus = {
  available: true,
  unavailableReason: null,
  enabled: false,
  starting: false,
  running: false,
  openAtLogin: false,
  slots: 4,
  report: null,
  error: null,
};

const RUNNING: DesktopGuardStatus = {
  ...BASE,
  enabled: true,
  running: true,
  report: {
    peerId: 'ab'.repeat(16),
    guardString: 'oz-guard:EXAMPLE',
    hasList: true,
    listed: false,
    listVersion: 3,
    counts: { degree: 5, clients: 4, backbone: 1, tunnels: 2 },
  },
};

function installGuardApi(initial: DesktopGuardStatus) {
  let listener: ((s: DesktopGuardStatus) => void) | null = null;
  const api = {
    get: vi.fn().mockResolvedValue(initial),
    enable: vi.fn().mockResolvedValue({ ...initial, enabled: true, starting: true }),
    disable: vi.fn().mockResolvedValue({ ...initial, enabled: false, running: false, report: null }),
    setOpenAtLogin: vi.fn().mockImplementation(async (on: boolean) => ({ ...initial, openAtLogin: on })),
    onStatus: vi.fn((cb: (s: DesktopGuardStatus) => void) => { listener = cb; return () => { listener = null; }; }),
  };
  (window as any).electronAPI = { guard: api };
  return { api, push: (s: DesktopGuardStatus) => listener?.(s) };
}

afterEach(() => {
  cleanup();
  delete (window as any).electronAPI;
});

describe('この端末の Guard (デスクトップ版の設定)', () => {
  it('Web 版 (electronAPI が無い) では設定に出さない', () => {
    render(<P2PProvider><SettingsView /></P2PProvider>);
    expect(screen.queryByRole('heading', { name: 'この端末の Guard' })).toBeNull();
  });

  it('有効にすると、選んだ枠の数で起動を頼む。IP が見えることを明示する', async () => {
    const { api } = installGuardApi(BASE);
    render(<DesktopGuardSettings />);
    await waitFor(() => expect(screen.getByText('使っていません')).toBeTruthy());
    expect(screen.getByText(/利用者の IP が見え、この端末の IP は Guard として利用者に見えます/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('預かる枠'), { target: { value: '8' } });
    fireEvent.click(screen.getByText('Guard として動かす'));
    await waitFor(() => expect(api.enable).toHaveBeenCalledWith({ slots: 8 }));
    await waitFor(() => expect(screen.getByText('起動しています...')).toBeTruthy());
  });

  it('動いていれば件数・Guard 文字列・リストへの掲載状況を出し、止められる', async () => {
    const { api, push } = installGuardApi(BASE);
    render(<DesktopGuardSettings />);
    await waitFor(() => expect(screen.getByText('使っていません')).toBeTruthy());
    push(RUNNING);
    await waitFor(() => expect(screen.getByText('動いています')).toBeTruthy());
    expect(screen.getByText(/利用者 4/)).toBeTruthy();
    expect(screen.getByText('oz-guard:EXAMPLE')).toBeTruthy();
    expect(screen.getByText(/まだ載っていません/)).toBeTruthy();
    fireEvent.click(screen.getByText('Guard を止める'));
    await waitFor(() => expect(api.disable).toHaveBeenCalled());
  });

  it('OS の鍵の保管庫が使えない端末では理由を出し、起動のボタンを出さない', async () => {
    installGuardApi({ ...BASE, available: false, unavailableReason: '鍵の保管庫がありません' });
    render(<DesktopGuardSettings />);
    await waitFor(() => expect(screen.getByText('鍵の保管庫がありません')).toBeTruthy());
    expect(screen.queryByText('Guard として動かす')).toBeNull();
  });

  it('ログイン時の起動を切り替える', async () => {
    const { api } = installGuardApi(BASE);
    render(<DesktopGuardSettings />);
    await waitFor(() => expect(screen.getByText('使っていません')).toBeTruthy());
    fireEvent.click(screen.getByLabelText(/ログイン時に起動する/));
    await waitFor(() => expect(api.setOpenAtLogin).toHaveBeenCalledWith(true));
  });
});
