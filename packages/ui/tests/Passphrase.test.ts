import { describe, it, expect } from 'vitest';
import { generatePassphrase, estimateStrength } from '../src/lib/passphrase';
import { MIN_PASSPHRASE_LENGTH } from '../src/providers/P2PProvider';

describe('パスワードの生成と強度の目安', () => {
  it('最小長は 12 文字', () => {
    expect(MIN_PASSPHRASE_LENGTH).toBe(12);
  });

  it('生成したパスワードは最小長を超え、毎回異なり、強いと判定される', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const p = generatePassphrase();
      expect(p).toMatch(/^[a-z]+(-[a-z]+){3}$/);
      expect(p.length).toBeGreaterThanOrEqual(MIN_PASSPHRASE_LENGTH);
      expect(estimateStrength(p, MIN_PASSPHRASE_LENGTH).level).toBe('strong');
      seen.add(p);
    }
    expect(seen.size).toBe(50);
  });

  it('短い・繰り返し・よくある並びは弱いと判定される', () => {
    expect(estimateStrength('', 12).level).toBe('empty');
    expect(estimateStrength('abc', 12).level).toBe('short');
    expect(estimateStrength('aaaaaaaaaaaaaaaa', 12).level).toBe('weak');
    expect(estimateStrength('password12345678', 12).level).toBe('weak');
    expect(estimateStrength('Tanaka19900101', 12).level).not.toBe('strong');
  });
});
