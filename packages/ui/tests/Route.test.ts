// @vitest-environment jsdom
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { getRoute, navigate, resetRoute, absorbLocationHash, subscribeRoute } from '../src/lib/route';

let pushState: ReturnType<typeof vi.spyOn>;
let replaceState: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetRoute();
  window.location.hash = '';
  pushState = vi.spyOn(window.history, 'pushState');
  replaceState = vi.spyOn(window.history, 'replaceState');
});

afterEach(() => {
  vi.restoreAllMocks();
  resetRoute();
});

describe('route: 経路は URL に出さない', () => {
  it('navigate は pushState を呼ばず、location.hash も書かず、replaceState で素のパスにするだけ', () => {
    const before = window.history.length;
    navigate({ board: 'secretboard', thread: 'abc123' });
    expect(getRoute()).toEqual({ board: 'secretboard', thread: 'abc123' });
    expect(pushState).not.toHaveBeenCalled();
    expect(window.location.hash).toBe('');
    expect(window.history.length).toBe(before);
    for (const call of replaceState.mock.calls) {
      expect(String(call[2])).not.toContain('secretboard');
      expect(String(call[2])).not.toContain('#');
    }
  });

  it('不正な板 ID は既定の板に戻る。購読者に通知される', () => {
    const seen: string[] = [];
    const off = subscribeRoute(() => seen.push(getRoute().board));
    navigate({ board: '../evil' });
    expect(getRoute()).toEqual({ board: 'zatsudan' });
    navigate({ board: 'abc' });
    off();
    navigate({ board: 'zzz' });
    expect(seen).toEqual(['zatsudan', 'abc']);
  });

  it('resetRoute (ロック・消去) は経路を既定に戻し、URL を素のパスに置き換える', () => {
    navigate({ board: 'abc', thread: 't1' });
    window.history.replaceState(null, '', '/#board=abc&thread=t1');
    replaceState.mockClear();
    resetRoute();
    expect(getRoute()).toEqual({ board: 'zatsudan' });
    expect(replaceState).toHaveBeenCalledWith(null, '', window.location.pathname);
    expect(window.location.hash).toBe('');
    expect(pushState).not.toHaveBeenCalled();
  });

  it('absorbLocationHash: 鍵つきのハッシュは鍵を読まずに捨て、板へも飛ばない', () => {
    window.history.replaceState(null, '', '/#board=abc&key=SECRETKEY');
    absorbLocationHash(true);
    expect(window.location.href).not.toContain('SECRETKEY');
    expect(window.location.hash).toBe('');
    expect(getRoute()).toEqual({ board: 'abc' });
    expect(pushState).not.toHaveBeenCalled();
  });

  it('absorbLocationHash(true): 鍵の無いハッシュは経路に取り込んで URL から消す', () => {
    window.history.replaceState(null, '', '/#board=abc&thread=t9');
    absorbLocationHash(true);
    expect(getRoute()).toEqual({ board: 'abc', thread: 't9' });
    expect(window.location.hash).toBe('');
  });
});
