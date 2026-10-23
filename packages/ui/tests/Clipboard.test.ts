// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { copySecret, SECRET_CLIPBOARD_MS } from '../src/lib/clipboard';

describe('copySecret: 板の共有コードをクリップボードから消す', () => {
  let content = '';
  beforeEach(() => {
    vi.useFakeTimers();
    content = '';
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: vi.fn(async (t: string) => { content = t; }),
        readText: vi.fn(async () => content),
      },
    });
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it('30 秒後、まだ同じコードなら空にする (画面を離れても動く: タイマーはモジュールにある)', async () => {
    await copySecret('BOARD-KEY');
    expect(content).toBe('BOARD-KEY');
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_MS);
    expect(content).toBe('');
  });

  it('利用者が別のものをコピーしていたら消さない', async () => {
    await copySecret('BOARD-KEY');
    content = '別のメモ';
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_MS);
    expect(content).toBe('別のメモ');
  });

  it('フォーカスが無ければ、戻ったときに確かめて消す', async () => {
    (document.hasFocus as any).mockReturnValue(false);
    await copySecret('BOARD-KEY');
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_MS);
    expect(content).toBe('BOARD-KEY');
    (document.hasFocus as any).mockReturnValue(true);
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(content).toBe('');
  });
});
