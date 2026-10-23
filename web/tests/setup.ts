import { webcrypto } from 'node:crypto';
import { TextEncoder as NodeTextEncoder, TextDecoder as NodeTextDecoder } from 'node:util';
import sodium from 'libsodium-wrappers-sumo';
import { beforeAll } from 'vitest';
import 'fake-indexeddb/auto';

class RealmSafeTextEncoder extends NodeTextEncoder {
  encode(input?: string) {
    const src = super.encode(input);
    const out = new Uint8Array(src.length);
    out.set(src);
    return out;
  }
}

Object.defineProperty(globalThis, 'TextEncoder', {
  value: RealmSafeTextEncoder,
  configurable: true,
  writable: true,
});

Object.defineProperty(globalThis, 'TextDecoder', {
  value: NodeTextDecoder,
  configurable: true,
  writable: true,
});

if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.getRandomValues !== 'function') {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
}

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length() { return this.map.size; }
  clear() { this.map.clear(); }
  getItem(key: string) { return this.map.has(key) ? this.map.get(key)! : null; }
  key(index: number) { return Array.from(this.map.keys())[index] ?? null; }
  removeItem(key: string) { this.map.delete(key); }
  setItem(key: string, value: string) { this.map.set(key, String(value)); }
}

if (typeof globalThis.localStorage === 'undefined') {
  Object.defineProperty(globalThis, 'localStorage', {
    value: new MemoryStorage(),
    configurable: true,
  });
}

if (typeof globalThis.btoa === 'undefined') {
  globalThis.btoa = (s: string) => Buffer.from(s, 'binary').toString('base64');
}
if (typeof globalThis.atob === 'undefined') {
  globalThis.atob = (s: string) => Buffer.from(s, 'base64').toString('binary');
}

beforeAll(async () => {
  await sodium.ready;
});
