// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';
import sodium from 'libsodium-wrappers-sumo';
import { KeyManager } from '@oz/core';

import { Sidebar } from '../src/components/Sidebar';
import { P2PContextForTest, NO_GUARD_STATUS } from '../src/providers/P2PProvider';
import {
  DEFAULT_BOARD_ID, PUBLIC_BOARDS, boardDisplayName, isPublicBoardId, publicBoardKey, resolveBoardKey, shareCode,
} from '../src/lib/boardKeys';
import { getRoute, resetRoute } from '../src/lib/route';

/** ロック解除済みの最小のコンテキスト (ノード無し) */
function readyContext(db: any): any {
  return {
    node: null, boardOrchestrator: null, threadOrchestrator: null, pm: null, identity: null, db,
    isReady: false, lockState: 'ready', unlockError: null,
    unlock: async () => {}, resetAll: async () => {}, panicWipe: async () => {}, lock: async () => {},
    guardStatus: NO_GUARD_STATUS, guardTrustConfigured: false,
    importGuardList: async () => ({ ok: false, reason: 'malformed' }),
  };
}

beforeAll(async () => {
  await sodium.ready;
});

afterEach(() => {
  cleanup();
  resetRoute();
});

describe('公開板', () => {
  it('公開板は「雑談」と「ファイル共有スレッド」の 2 つで、起動時は雑談を開く。vip はもう無い', () => {
    expect(PUBLIC_BOARDS.map(b => b.name)).toEqual(['雑談', 'ファイル共有スレッド']);
    expect(DEFAULT_BOARD_ID).toBe('zatsudan');
    expect(getRoute()).toEqual({ board: 'zatsudan' });
    expect(isPublicBoardId('vip')).toBe(false);
    expect(boardDisplayName('files')).toBe('ファイル共有スレッド');
    expect(boardDisplayName('0123456789ab')).toBe('0123456789ab');
  });

  it('鍵は ID から決まり (全員が同じ鍵)、板ごとに違う', () => {
    const a = publicBoardKey('zatsudan')!;
    expect(a).toHaveLength(32);
    expect(publicBoardKey('zatsudan')).toEqual(a);
    expect(publicBoardKey('files')).not.toEqual(a);
    expect(publicBoardKey('0123456789ab')).toBeNull();
  });

  it('★公開板は、端末に同じ ID の鍵が保存されていても公開の鍵を使う (共有コードによるすり替えを防ぐ)', async () => {
    const spoofed = KeyManager.generateBoardKey();
    const db: any = { getBoardKey: vi.fn().mockResolvedValue(spoofed) };
    expect(await resolveBoardKey('zatsudan', db)).toEqual(publicBoardKey('zatsudan'));
    // 秘密の板は保存した鍵
    expect(await resolveBoardKey('0123456789ab', db)).toEqual(spoofed);
    expect(await resolveBoardKey('0123456789ab', null)).toBeNull();
  });

  it('サイドバーには公開板を名前で並べ、公開板の ID を持つ共有コードは受け付けない', async () => {
    const saveBoard = vi.fn().mockResolvedValue(undefined);
    const db: any = { saveBoard, listBoards: vi.fn().mockResolvedValue([]) };
    render(
      <P2PContextForTest.Provider value={readyContext(db)}>
        <Sidebar section="board" onSelect={() => {}} />
      </P2PContextForTest.Provider>,
    );
    expect(screen.getByRole('button', { name: '雑談' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'ファイル共有スレッド' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'vip' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'ファイル共有スレッド' }));
    expect(getRoute()).toEqual({ board: 'files' });

    fireEvent.click(screen.getByText('共有コードで参加'));
    fireEvent.change(screen.getByLabelText('共有コード'), {
      target: { value: shareCode('zatsudan', KeyManager.generateBoardKey()) },
    });
    fireEvent.click(screen.getByRole('button', { name: '追加' }));
    await waitFor(() => expect(screen.getByText(/公開板の共有コードは使えません/)).toBeTruthy());
    expect(saveBoard).not.toHaveBeenCalled();
  });
});
