// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor, act } from '@testing-library/react';
import sodium from 'libsodium-wrappers-sumo';

import { Sidebar } from '../src/components/Sidebar';
import { AboutView } from '../src/components/AboutView';
import BoardView from '../src/components/BoardView';
import ThreadView from '../src/components/ThreadView';
import App, { RouterView } from '../src/App';
import { P2PProvider, P2PContextForTest, NO_GUARD_STATUS } from '../src/providers/P2PProvider';
import { getRoute, navigate, resetRoute } from '../src/lib/route';
import { saveTermsAccepted } from '../src/lib/terms';

/** ロック解除済みの最小のコンテキスト (ノード無し) */
function readyContext(): any {
  return {
    node: null,
    boardOrchestrator: null,
    threadOrchestrator: null,
    pm: null,
    identity: null,
    db: null,
    isReady: false,
    lockState: 'ready',
    unlockError: null,
    unlock: async () => {},
    resetAll: async () => {},
    panicWipe: async () => {},
    lock: async () => {},
    guardStatus: NO_GUARD_STATUS,
    guardTrustConfigured: false,
    importGuardList: async () => ({ ok: false, reason: 'malformed' }),
  };
}
import { KeyManager, Identity } from '@oz/core';

describe('Desktop UI Rendering & Workflows (OZ Specification)', () => {
  beforeAll(async () => {
    await sodium.ready;
  });

  afterEach(() => {
    cleanup();
    window.location.hash = '';
    resetRoute();
  });

  describe('サイドバー', () => {
    it('ロゴ、Desktop Full Node バッジ、秘密の板作成ボタン、つながりの状態が描画される', () => {
      render(
        <P2PProvider>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PProvider>,
      );

      expect(screen.getByText('OZ')).toBeTruthy();
      expect(screen.getByText('Desktop Full Node')).toBeTruthy();
      expect(screen.getByText('+ 秘密の板を作る')).toBeTruthy();
      expect(screen.getByText(/Peers:/)).toBeTruthy();
    });

    it('秘密の板を作ると、鍵は暗号化 DB に保存され、URL には何も載らない (経路はメモリだけ)', async () => {
      const saveBoard = vi.fn().mockResolvedValue(undefined);
      const db: any = { saveBoard, listBoards: vi.fn().mockResolvedValue([]) };
      render(
        <P2PContextForTest.Provider value={{ ...readyContext(), db }}>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PContextForTest.Provider>,
      );

      fireEvent.click(screen.getByText('+ 秘密の板を作る'));

      await waitFor(() => expect(getRoute().board).toMatch(/^[0-9a-f]+$/));
      expect(saveBoard).toHaveBeenCalledTimes(1);
      const [boardId, key] = saveBoard.mock.calls[0];
      expect(getRoute()).toEqual({ board: boardId });
      expect(window.location.hash).toBe('');
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it('ロック解除前 (DB が無い) は秘密の板を作れない', () => {
      render(
        <P2PProvider>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PProvider>,
      );
      expect((screen.getByText('+ 秘密の板を作る') as HTMLButtonElement).disabled).toBe(true);
    });

    it('トリップ使用中は「投稿同士が紐付く」警告を出す', () => {
      const identity: any = { hasTrip: true, tripDisplay: '◆abcdefg' };
      render(
        <P2PContextForTest.Provider value={{ ...readyContext(), identity }}>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PContextForTest.Provider>,
      );
      expect(screen.getByRole('note').textContent).toMatch(/投稿同士が紐付きます/);
    });

    it('「仕組みと安全性」を開くと、守れないことを明示する', () => {
      const onSelect = vi.fn();
      render(
        <P2PContextForTest.Provider value={readyContext()}>
          <Sidebar section="board" onSelect={onSelect} />
        </P2PContextForTest.Provider>,
      );
      fireEvent.click(screen.getByText('仕組みと安全性'));
      expect(onSelect).toHaveBeenCalledWith('about');
      cleanup();
      render(<AboutView />);
      expect(screen.getByText('守れないこと')).toBeTruthy();
      expect(screen.getByText(/国全体の通信を監視できる相手/)).toBeTruthy();
      expect(screen.getByText(/IP アドレスは接続先の端末、トラッカーの運営者、通信事業者/)).toBeTruthy();
    });

    it('サイドバーから設定と説明の画面に切り替わる (設定は 1 つの画面にまとまっている)', () => {
      render(<P2PProvider><RouterView /></P2PProvider>);
      fireEvent.click(screen.getByRole('button', { name: /設定/ }));
      for (const name of ['接続', '匿名経路', 'データの保管', 'ファイル共有']) {
        expect(screen.getByRole('heading', { name })).toBeTruthy();
      }
      fireEvent.click(screen.getByRole('button', { name: /仕組みと安全性/ }));
      expect(screen.getByRole('heading', { name: '仕組みと安全性' })).toBeTruthy();
      expect(screen.getByText('守れないこと')).toBeTruthy();
    });

    it('ロックボタンで lock が呼ばれる (データは消さない)', async () => {
      const lock = vi.fn().mockResolvedValue(undefined);
      const panicWipe = vi.fn();
      render(
        <P2PContextForTest.Provider value={{ ...readyContext(), lock, panicWipe }}>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PContextForTest.Provider>,
      );
      fireEvent.click(screen.getByText('ロック'));
      await waitFor(() => expect(lock).toHaveBeenCalledTimes(1));
      expect(panicWipe).not.toHaveBeenCalled();
    });

    it('緊急消去は 2 回押さないと実行されない', async () => {
      const panicWipe = vi.fn().mockResolvedValue(undefined);
      render(
        <P2PContextForTest.Provider value={{ ...readyContext(), panicWipe }}>
          <Sidebar section="board" onSelect={() => {}} />
        </P2PContextForTest.Provider>,
      );

      fireEvent.click(screen.getByText('緊急消去'));
      expect(panicWipe).not.toHaveBeenCalled();
      fireEvent.click(screen.getByText('もう一度押すと全消去'));
      await waitFor(() => expect(panicWipe).toHaveBeenCalledTimes(1));
    });
  });

  describe('BoardView Component', () => {
    it('初期状態で板タイトルと新スレを立てるボタンが表示される', () => {
      render(
        <P2PProvider>
          <BoardView boardId="vip" />
        </P2PProvider>,
      );

      expect(screen.getByText('板: vip')).toBeTruthy();
      const newThreadBtn = screen.getByText('新スレを立てる');
      expect(newThreadBtn).toBeTruthy();
    });

    it('新スレを立てるボタンをクリックするとフォームが展開され、中止で閉じることができる', () => {
      render(
        <P2PProvider>
          <BoardView boardId="vip" />
        </P2PProvider>,
      );

      const newThreadBtn = screen.getByText('新スレを立てる');
      fireEvent.click(newThreadBtn);

      expect(screen.getByText('新規スレッド作成')).toBeTruthy();
      const textarea = screen.getByPlaceholderText('スレッドタイトル...');
      expect(textarea).toBeTruthy();

      const cancelBtn = screen.getByText('中止');
      fireEvent.click(cancelBtn);

      expect(screen.queryByText('新規スレッド作成')).toBeNull();
    });

    it('スレッドタイトルが空の場合は作成ボタンが無効化される', () => {
      render(
        <P2PProvider>
          <BoardView boardId="vip" />
        </P2PProvider>,
      );

      fireEvent.click(screen.getByText('新スレを立てる'));
      const submitBtn = screen.getByText('作成') as HTMLButtonElement;
      expect(submitBtn.disabled).toBe(true);

      const textarea = screen.getByPlaceholderText('スレッドタイトル...');
      fireEvent.change(textarea, { target: { value: 'テストスレッドです' } });
      expect(submitBtn.disabled).toBe(false);
    });
  });

  describe('ThreadView Component', () => {
    it('スレッド画面で戻るボタン、スレッドタイトル、返信フォームが表示される', () => {
      const threadId = 'abcdef1234567890';
      render(
        <P2PProvider>
          <ThreadView boardId="vip" threadId={threadId} />
        </P2PProvider>,
      );

      expect(screen.getByText('← 板に戻る')).toBeTruthy();
      expect(screen.getByText(`スレッド: ${threadId.substring(0, 8)}`)).toBeTruthy();
      expect(screen.getByPlaceholderText('>>レスを入力... (Ctrl+Enterで送信)')).toBeTruthy();
    });

    it('板に戻るボタンを押すと該当の板へ戻る (URL には板 ID を書かない)', () => {
      const threadId = 'abcdef1234567890';
      window.location.hash = `#board=vip&thread=${threadId}`;

      render(
        <P2PProvider>
          <ThreadView boardId="vip" threadId={threadId} />
        </P2PProvider>,
      );

      const backBtn = screen.getByText('← 板に戻る');
      fireEvent.click(backBtn);

      expect(getRoute()).toEqual({ board: 'vip' });
      expect(window.location.hash).toBe('');
    });

    it('レス入力欄でCtrl+Enterが入力可能であり空のときは送信されない', () => {
      const threadId = 'abcdef1234567890';
      render(
        <P2PProvider>
          <ThreadView boardId="vip" threadId={threadId} />
        </P2PProvider>,
      );

      const textarea = screen.getByPlaceholderText('>>レスを入力... (Ctrl+Enterで送信)');
      fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true });
      // 例外なく安全にスルーされる
    });
  });

  describe('Desktop App Whole Integration', () => {
    // 利用規約の同意画面は Terms.test.tsx で確かめる。ここでは同意済みから始める
    beforeEach(() => saveTermsAccepted());

    it('起動するとまずパスワード画面が出て、ロック解除まで板は表示されない', async () => {
      render(<App />);

      await waitFor(() => {
        expect(screen.getByText('パスワードを設定')).toBeTruthy();
      });
      expect(screen.queryByText('板: vip')).toBeNull();
      // 初回設定の画面で、守れないことを先に読めるようにしてある
      expect(screen.getByText('守れないこと')).toBeTruthy();
    });

    it('トレイからのロック命令でパスワード画面に戻る', async () => {
      let send: ((c: string) => void) | null = null;
      (window as any).electronAPI = {
        onCommand: (cb: (c: string) => void) => { send = cb; return () => { send = null; }; },
      };
      try {
        render(<App />);
        await waitFor(() => screen.getByText('パスワードを設定'));
        expect(send).not.toBeNull();

        await act(async () => { send!('lock'); });
        await waitFor(() => expect(screen.getByText('ロックを解除')).toBeTruthy());
      } finally {
        delete (window as any).electronAPI;
      }
    });

    it('ロックすると経路が既定に戻り、URL も素のパスになる (どの板を開いていたかを残さない)', async () => {
      let send: ((c: string) => void) | null = null;
      (window as any).electronAPI = {
        onCommand: (cb: (c: string) => void) => { send = cb; return () => { send = null; }; },
        clearCaches: vi.fn().mockResolvedValue(undefined),
      };
      try {
        render(<App />);
        await waitFor(() => screen.getByText('パスワードを設定'));
        act(() => { navigate({ board: 'abc123', thread: 'deadbeef' }); });
        window.history.replaceState(null, '', '/#board=abc123');
        await act(async () => { send!('lock'); });
        expect(getRoute()).toEqual({ board: 'vip' });
        expect(window.location.hash).toBe('');
        expect((window as any).electronAPI.clearCaches).toHaveBeenCalled();
      } finally {
        delete (window as any).electronAPI;
      }
    });

    it('初回設定で「パスワードを作る」を押すと、確認欄にも入り、強さの目安が出る', async () => {
      render(<App />);
      await waitFor(() => screen.getByText('パスワードを設定'));
      fireEvent.click(screen.getByText('パスワードを作る'));
      const shown = screen.getByLabelText('作成したパスワード').textContent!;
      expect(shown.length).toBeGreaterThanOrEqual(12);
      expect((screen.getByLabelText('パスワード') as HTMLInputElement).value).toBe(shown);
      expect((screen.getByLabelText('パスワード (確認)') as HTMLInputElement).value).toBe(shown);
      expect(screen.getByRole('status').textContent).toMatch(/強い/);
    });

    it('初回設定では短いパスワードと確認の不一致を弾く', async () => {
      render(<App />);
      await waitFor(() => screen.getByText('パスワードを設定'));

      fireEvent.change(screen.getByLabelText('パスワード'), { target: { value: 'short' } });
      fireEvent.change(screen.getByLabelText('パスワード (確認)'), { target: { value: 'short' } });
      fireEvent.click(screen.getByText('設定して開始'));
      await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/12 文字以上/));

      fireEvent.change(screen.getByLabelText('パスワード'), { target: { value: 'long enough passphrase' } });
      fireEvent.change(screen.getByLabelText('パスワード (確認)'), { target: { value: 'different passphrase!!' } });
      fireEvent.click(screen.getByText('設定して開始'));
      await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/一致しません/));
    });

    it('初期URLハッシュなしで開くと既定の板が描画され、URL には何も書かれない', async () => {
      window.location.hash = '';

      render(<P2PProvider><RouterView /></P2PProvider>);

      expect(screen.getByText('OZ')).toBeTruthy();
      expect(screen.getByText('板: vip')).toBeTruthy();
      expect(window.location.hash).toBe('');
    });

    it('鍵付きのリンクで開いても鍵は取り込まず、URL から消して、貼り付けを案内する', async () => {
      window.location.hash = '#board=abc123&key=AAAA';
      render(<P2PProvider><RouterView /></P2PProvider>);

      await waitFor(() => expect(window.location.hash).toBe(''));
      expect(window.location.href).not.toContain('AAAA');
      expect(screen.getByText(/共有コードを受け取っている場合/)).toBeTruthy();
      expect(screen.getByText('板: vip')).toBeTruthy(); // 鍵付きリンクの板へは飛ばない
    });

    it('ハッシュ変更により BoardView と ThreadView の切り替えが正しく反映される', async () => {
      window.location.hash = '#board=vip';
      render(<P2PProvider><RouterView /></P2PProvider>);

      expect(screen.getByText('板: vip')).toBeTruthy();

      // 移行前の画面部品が location.hash を書き換えても、経路に取り込んで URL は素に戻す
      window.location.hash = '#board=vip&thread=9876543210abcdef';
      window.dispatchEvent(new HashChangeEvent('hashchange'));

      await waitFor(() => {
        expect(screen.getByText('スレッド: 98765432')).toBeTruthy();
      });
      expect(window.location.hash).toBe('');
    });

    it('navigate で板・スレッドが切り替わる', async () => {
      render(<P2PProvider><RouterView /></P2PProvider>);
      await act(async () => { navigate({ board: 'vip', thread: '1234567890abcdef' }); });
      expect(screen.getByText('スレッド: 12345678')).toBeTruthy();
      await act(async () => { navigate({ board: 'vip' }); });
      expect(screen.getByText('板: vip')).toBeTruthy();
    });
  });
});
