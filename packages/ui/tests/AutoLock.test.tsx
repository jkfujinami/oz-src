// @vitest-environment jsdom
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { renderHook, cleanup } from '@testing-library/react';
import { useAutoLock, AUTO_LOCK_MS } from '../src/hooks/useAutoLock';

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe('useAutoLock', () => {
  it('既定は 15 分', () => {
    expect(AUTO_LOCK_MS).toBe(15 * 60 * 1000);
  });

  it('操作が無いまま期限が過ぎるとロックを 1 回だけ呼ぶ', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: true, onLock, limitMs: 60_000 }));
    vi.advanceTimersByTime(59_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(20_000);
    expect(onLock).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(300_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it('操作があれば期限が延びる', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: true, onLock, limitMs: 60_000 }));
    vi.advanceTimersByTime(45_000);
    window.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(45_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it('隠れている間に期限が過ぎたら、戻った瞬間にロックする (タイマーが止められていても)', () => {
    const onLock = vi.fn();
    let state: DocumentVisibilityState = 'visible';
    vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => state);
    renderHook(() => useAutoLock({ enabled: true, onLock, limitMs: 60_000 }));
    state = 'hidden';
    document.dispatchEvent(new Event('visibilitychange'));
    // タイマーを進めずに時刻だけ進める (バックグラウンドで間引かれた状況)
    vi.setSystemTime(Date.now() + 120_000);
    state = 'visible';
    document.dispatchEvent(new Event('visibilitychange'));
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it('無効のとき (ロック中) は何もしない', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: false, onLock, limitMs: 1000 }));
    vi.advanceTimersByTime(600_000);
    expect(onLock).not.toHaveBeenCalled();
  });
});
