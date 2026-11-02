import { describe, it, expect } from 'vitest';
import { appendAnchor } from '../src/lib/anchor';

describe('appendAnchor (レス番を押したときのアンカー)', () => {
  it('空ならそのまま、末尾が改行ならそのあと、そうでなければ改行をはさむ', () => {
    expect(appendAnchor('', 5)).toBe('>>5\n');
    expect(appendAnchor('>>5\n', 6)).toBe('>>5\n>>6\n');
    expect(appendAnchor('こんにちは', 7)).toBe('こんにちは\n>>7\n');
  });
});
