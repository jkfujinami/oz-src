// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const keys: Record<string, Uint8Array> = { zatsudan: new Uint8Array([1]), files: new Uint8Array([2]) };
vi.mock('../src/lib/boardKeys', () => ({
  resolveBoardKey: (id: string) => new Promise<Uint8Array | null>((r) => setTimeout(() => r(keys[id] ?? null), 5)),
}));

const { useBoardKey } = await import('../src/hooks/useBoardKey');

describe('useBoardKey (板の鍵は板 ID と組で返す)', () => {
  it('★板を切り替えた直後の描画で、前の板の鍵を返さない (新しい板の鍵が解決するまで null)', async () => {
    const seen: Array<[string, number | null]> = [];
    const { result, rerender } = renderHook(({ id }) => {
      const key = useBoardKey(id, null);
      seen.push([id, key ? key[0] : null]);
      return key;
    }, { initialProps: { id: 'zatsudan' } });
    await waitFor(() => expect(result.current?.[0]).toBe(1));

    rerender({ id: 'files' });
    expect(result.current).toBeNull();
    await waitFor(() => expect(result.current?.[0]).toBe(2));
    // どの描画でも「files の ID に zatsudan の鍵」の組は出ない
    expect(seen.filter(([id, k]) => id === 'files' && k === 1)).toHaveLength(0);
  });
});
