/**
 * アンロックの Argon2 は 1 回 (F2b) と、低メモリ端末への縮退。
 *   - trip / node 鍵は DEK 配下で、独自のパスワード KDF を持たない
 *   - 旧形式 (SecretVault 封印) の行は、次のアンロックで DEK 配下へ移す
 *   - 256 MiB の確保に失敗したら 64 MiB / ops 4 で新しい封印を作り、パラメータは封印と一緒に保存する
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import 'fake-indexeddb/auto';
import { openDB } from 'idb';
import sodium, { sodiumReady } from '../../src/crypto/sodium';
import { IndexedDBStore } from '../../src/storage/IndexedDBStore';
import { WrongPassphraseError } from '../../src/storage/DataVault';
import { SecretVault, VAULT_PARAMS, VAULT_PARAMS_FAST, VAULT_PARAMS_LOW_MEMORY } from '../../src/storage/SecretVault';
import { captureLogSink } from '../helpers/cryptoStorageFixtures';

const PASS = 'single kdf passphrase one';
const PASS2 = 'single kdf passphrase two';

let seq = 0;
const freshName = () => `singlekdf_${process.pid}_${seq++}`;

async function open(name: string, pass = PASS, params = VAULT_PARAMS_FAST): Promise<IndexedDBStore> {
  const store = new IndexedDBStore(name);
  await store.init();
  await store.unlock(pass, params);
  return store;
}

async function dekRow(name: string): Promise<any> {
  const db = await openDB(name);
  try {
    return await db.get('identity', '__dek__');
  } finally {
    db.close();
  }
}

/** crypto_pwhash の呼び出しを数える (実体はそのまま走らせる) */
function spyPwhash() {
  return vi.spyOn(sodium, 'crypto_pwhash');
}

beforeAll(async () => {
  await sodiumReady;
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('アンロックの Argon2 は 1 回', () => {
  it('trip / node 鍵があっても、既存のストアを開く Argon2 は 1 回だけ', async () => {
    const name = freshName();
    const first = await open(name);
    await first.saveSecret('trip', new Uint8Array(96).fill(1), { t: 1 });
    await first.saveSecret('node', new Uint8Array(96).fill(2), { powCounter: 3 });
    first.lock();

    const spy = spyPwhash();
    const again = await open(name);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(Array.from((await again.getSecret('trip'))!.secret)).toEqual(Array.from(new Uint8Array(96).fill(1)));
    expect((await again.getSecret('node'))!.meta).toEqual({ powCounter: 3 });
    // 読み書きでも KDF は走らない
    await again.saveSecret('trip', new Uint8Array(96).fill(4));
    await again.getSecret('trip');
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('新規作成も 1 回', async () => {
    const spy = spyPwhash();
    await open(freshName());
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

describe('旧形式の trip / node 行の移行', () => {
  it('次のアンロックで DEK 配下へ移り、旧い行は残らず、その次のアンロックは 1 回に戻る', async () => {
    const name = freshName();
    const store = await open(name);
    const trip = new Uint8Array(96).fill(7);
    const node = new Uint8Array(96).fill(8);
    // 旧形式: 秘密ごとにパスワードで封印した行 (保護なしだった旧データも混ぜる)
    await store.saveSealed('trip', SecretVault.seal(trip, PASS, VAULT_PARAMS_FAST), { n: 1 });
    await store.saveSealed('node', SecretVault.seal(node, '', VAULT_PARAMS_FAST), { powCounter: 9 });
    expect(await store.getSecret('trip')).toBeUndefined(); // 旧形式のままでは新 API から見えない
    store.lock();

    const spy = spyPwhash();
    const migrated = await open(name);
    // DEK を開く 1 回 + 旧い封印 (パスワード付き) を開く 1 回。保護なしの行は空パスワードで開く 1 回
    expect(spy).toHaveBeenCalledTimes(3);
    expect(await migrated.getSealed('trip')).toBeUndefined();
    expect(await migrated.getSealed('node')).toBeUndefined();
    const t = (await migrated.getSecret('trip'))!;
    expect(t.meta).toEqual({ n: 1 });
    expect(Array.from(t.secret)).toEqual(Array.from(trip));
    const n = (await migrated.getSecret('node'))!;
    expect(n.meta).toEqual({ powCounter: 9 });
    expect(Array.from(n.secret)).toEqual(Array.from(node));
    migrated.lock();

    spy.mockClear();
    await open(name);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('別のパスワードで封印された旧い行は開けないので触らない', async () => {
    const name = freshName();
    const store = await open(name);
    await store.saveSealed('trip', SecretVault.seal(new Uint8Array(96), 'someone else', VAULT_PARAMS_FAST));
    store.lock();
    const again = await open(name);
    expect(await again.getSecret('trip')).toBeUndefined();
    expect((await again.getSealed('trip'))!.sealed.protected).toBe(true);
  });
});

describe('パスワード変更', () => {
  it('trip / node 鍵が新しいパスワードで往復する。Argon2 は 旧 DEK を開く 1 + 新 DEK の封印 1', async () => {
    const name = freshName();
    const store = await open(name);
    const trip = new Uint8Array(96).fill(3);
    await store.saveSecret('trip', trip, { a: 1 });
    await store.saveSecret('node', trip, { b: 2 });
    store.lock();

    const spy = spyPwhash();
    await store.changePassphrase(PASS, PASS2, VAULT_PARAMS_FAST);
    expect(spy).toHaveBeenCalledTimes(2);

    await expect(open(name, PASS)).rejects.toBeInstanceOf(WrongPassphraseError);
    const again = await open(name, PASS2);
    expect(Array.from((await again.getSecret('trip'))!.secret)).toEqual(Array.from(trip));
    expect((await again.getSecret('node'))!.meta).toEqual({ b: 2 });
  });
});

describe('低メモリ端末への縮退', () => {
  /** 256 MiB (VAULT_PARAMS.memLimit) の確保だけ失敗させる */
  function failBigAllocation() {
    const real = sodium.crypto_pwhash.bind(sodium);
    return vi.spyOn(sodium, 'crypto_pwhash').mockImplementation(((...args: any[]) => {
      if (args[4] >= VAULT_PARAMS.memLimit) throw new RangeError('WebAssembly.Memory(): could not allocate memory');
      return (real as any)(...args);
    }) as any);
  }

  it('確保に失敗したら 64 MiB / ops 4 で封印を作り、パラメータを保存し、WARN を出す (秘密は書かない)', async () => {
    const log = captureLogSink();
    try {
      const name = freshName();
      failBigAllocation();
      const store = await open(name, PASS, VAULT_PARAMS);
      expect(store.isUnlocked).toBe(true);

      const row = await dekRow(name);
      expect(row.sealed.opsLimit).toBe(VAULT_PARAMS_LOW_MEMORY.opsLimit);
      expect(row.sealed.memLimit).toBe(VAULT_PARAMS_LOW_MEMORY.memLimit);
      expect(log.lines.some((l) => l.method === 'warn' && /falling back/.test(log.text()))).toBe(true);
      expect(log.text()).not.toContain(PASS);
      store.lock();
      vi.restoreAllMocks();

      // 開く側は保存されたパラメータを使う (既定の 256 MiB を試さない)。包み直しも試みない
      const spy = spyPwhash();
      const again = await open(name, PASS, VAULT_PARAMS);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][3]).toBe(VAULT_PARAMS_LOW_MEMORY.opsLimit);
      expect(spy.mock.calls[0][4]).toBe(VAULT_PARAMS_LOW_MEMORY.memLimit);
      expect(await dekRow(name)).toEqual(row);
      again.lock();

      // 間違ったパスワードは改竄と区別できない
      await expect(open(name, 'wrong')).rejects.toBeInstanceOf(WrongPassphraseError);
    } finally {
      log.restore();
    }
  });

  it('SecretVault.seal 単体でも縮退し、すでに 64 MiB 以下の指定なら縮退せずに失敗を伝える', () => {
    const log = captureLogSink();
    try {
      failBigAllocation();
      const sealed = SecretVault.seal(new Uint8Array(32).fill(1), PASS, VAULT_PARAMS);
      expect(sealed.memLimit).toBe(VAULT_PARAMS_LOW_MEMORY.memLimit);
      expect(Array.from(SecretVault.open(sealed, PASS)!)).toEqual(Array.from(new Uint8Array(32).fill(1)));

      vi.restoreAllMocks();
      vi.spyOn(sodium, 'crypto_pwhash').mockImplementation(() => { throw new RangeError('oom'); });
      expect(() => SecretVault.seal(new Uint8Array(32), PASS, VAULT_PARAMS_LOW_MEMORY)).toThrow(RangeError);
    } finally {
      log.restore();
    }
  });

  it('通常の端末では縮退しない', async () => {
    const name = freshName();
    const store = await open(name, PASS, VAULT_PARAMS_FAST);
    expect((await dekRow(name)).sealed.memLimit).toBe(VAULT_PARAMS_FAST.memLimit);
    store.lock();
  });
});

describe('パスワード違いは改竄と区別できない', () => {
  it('間違ったパスワードと壊れた DEK の封印は、同じ例外・同じ文言になる', async () => {
    const name = freshName();
    const s = await open(name);
    s.lock();
    const errOf = async (fn: () => Promise<unknown>) => fn().then(() => null, (e) => e);
    const wrong = await errOf(() => open(name, 'definitely wrong'));

    const db = await openDB(name);
    const row = await db.get('identity', '__dek__');
    row.sealed.ciphertext[0] ^= 1;
    await db.put('identity', row);
    db.close();
    const tampered = await errOf(() => open(name, PASS));

    expect(wrong).toBeInstanceOf(WrongPassphraseError);
    expect(tampered).toBeInstanceOf(WrongPassphraseError);
    expect(tampered.message).toBe(wrong.message);
    expect(tampered.name).toBe(wrong.name);
  });
});
