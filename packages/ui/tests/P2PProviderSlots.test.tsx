// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, waitFor, act } from '@testing-library/react';
import { OzNode } from '@oz/core';
import { P2PProvider, useP2P, DESKTOP_DEFAULT_SLOTS, WEB_DEFAULT_SLOTS } from '../src/providers/P2PProvider';

/** 保管担当の既定の容量: デスクトップ (Electron のプリロードあり) は 4 枠、ブラウザは 1 枠 */
function Unlocker() {
  const { unlock, lockState } = useP2P();
  React.useEffect(() => {
    if (lockState === 'setup' || lockState === 'locked') void unlock('a-long-enough-passphrase');
  }, [lockState, unlock]);
  return null;
}

async function configPassedToCreate(): Promise<any> {
  const spy = vi.spyOn(OzNode, 'create').mockRejectedValue(new Error('stop here'));
  render(<P2PProvider><Unlocker /></P2PProvider>);
  await waitFor(() => expect(spy).toHaveBeenCalled());
  await act(async () => {});
  return spy.mock.calls[0][0];
}

describe('P2PProvider: 保管担当の既定の容量', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete (window as any).electronAPI;
  });

  it('ブラウザ版は 1 枠', async () => {
    const cfg = await configPassedToCreate();
    expect(cfg.storage).toEqual({ defaultSlots: WEB_DEFAULT_SLOTS });
    expect(WEB_DEFAULT_SLOTS).toBe(1);
  });

  it('デスクトップ版 (electronAPI あり) は 4 枠', async () => {
    (window as any).electronAPI = {};
    const cfg = await configPassedToCreate();
    expect(cfg.storage).toEqual({ defaultSlots: DESKTOP_DEFAULT_SLOTS });
    expect(DESKTOP_DEFAULT_SLOTS).toBe(4);
  });
});
