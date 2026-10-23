/**
 * crypto / common / storage の単体テスト用の小道具。
 * (他領域のヘルパとは独立させてある)
 */
import { setSink, type Sink } from '../../src/common/Logger';
import type { SealedStore } from '../../src/crypto/Identity';

export interface MemorySealedStore extends SealedStore {
  slots: Map<string, { secret: Uint8Array; meta?: any }>;
}

/** SealedStore のメモリ実装。失敗を注入できる。 */
export function memorySealedStore(opts: {
  failGet?: boolean;
  failSave?: boolean;
  failDelete?: boolean;
} = {}): MemorySealedStore {
  const slots = new Map<string, { secret: Uint8Array; meta?: any }>();
  return {
    slots,
    async getSecret(slot) {
      if (opts.failGet) throw new Error('get failed');
      return slots.get(slot);
    },
    async saveSecret(slot, secret, meta) {
      if (opts.failSave) throw new Error('save failed');
      slots.set(slot, { secret, meta });
    },
    async deleteSecret(slot) {
      if (opts.failDelete) throw new Error('delete failed');
      slots.delete(slot);
    },
  };
}

export interface CapturedLine {
  method: keyof Sink;
  args: unknown[];
}

/** Logger の出力先を差し替えて捕まえる。restore() で console に戻す。 */
export function captureLogSink(): { lines: CapturedLine[]; text: () => string; restore: () => void } {
  const lines: CapturedLine[] = [];
  const push = (method: keyof Sink) => (...args: unknown[]) => { lines.push({ method, args }); };
  setSink({ error: push('error'), warn: push('warn'), info: push('info'), log: push('log'), debug: push('debug') });
  return {
    lines,
    text: () => lines.map((l) => l.args.map(String).join(' ')).join('\n'),
    restore: () => setSink(console),
  };
}

/** haystack の中に needle がそのまま含まれるか (平文残存の検査用) */
export function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
