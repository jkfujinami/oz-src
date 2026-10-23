import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config';

const KEY = Buffer.alloc(32, 7).toString('base64url');
const KEY2 = Buffer.alloc(32, 9).toString('base64url');

describe('loadConfig', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oz-guard-cfg-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const base = ['--tracker', 'wss://tracker.example.org/ws', '--data', '/tmp/x'];
  const env = { OZ_GUARD_PASSPHRASE: 'correct horse battery staple' };

  function ok(argv: string[], e: Record<string, string | undefined> = env) {
    const r = loadConfig(argv, e);
    if (r.help) throw new Error('unexpected help');
    return r.config;
  }

  it('引数と環境変数から読める。既定は枠 1・スナップショット 10 分', () => {
    const c = ok(base);
    expect(c.trackerUrl).toMatch(/^wss:\/\/tracker\.example\.org/);
    expect(c.dataDir).toBe('/tmp/x');
    expect(c.passphrase).toBe(env.OZ_GUARD_PASSPHRASE);
    expect(c.storageSlots).toBe(1);
    expect(c.snapshotIntervalMs).toBe(10 * 60_000);
    expect(c.trust).toBeNull();
  });

  it('トラッカー・保存先は環境変数でも渡せる。引数が優先', () => {
    const c = ok([], { ...env, OZ_TRACKER_URL: 'wss://a.example.org/ws', OZ_GUARD_DATA: '/tmp/y' });
    expect(c.dataDir).toBe('/tmp/y');
    expect(ok(['--tracker', 'wss://b.example.org/ws', '--data', '/tmp/z'], { ...env, OZ_TRACKER_URL: 'wss://a.example.org/ws' }).trackerUrl)
      .toMatch(/b\.example\.org/);
  });

  it('パスフレーズは引数で渡せない (どの書き方でも拒否し、値は設定に入らない)', () => {
    for (const argv of [
      [...base, '--passphrase', 'secret-value'],
      [...base, '--passphrase=secret-value'],
    ]) {
      expect(() => loadConfig(argv, {})).toThrow(ConfigError);
      expect(() => loadConfig(argv, {})).toThrow(/コマンドライン引数では渡せません/);
    }
  });

  it('パスフレーズが無ければ拒否する (空文字も同じ)', () => {
    expect(() => loadConfig(base, {})).toThrow(/パスフレーズがありません/);
    expect(() => loadConfig(base, { OZ_GUARD_PASSPHRASE: '' })).toThrow(/パスフレーズがありません/);
  });

  it('--passphrase-file: 末尾の改行を 1 つ落として読む。権限が広いと拒否', () => {
    const f = join(dir, 'pass');
    writeFileSync(f, 'file-secret\n', { mode: 0o600 });
    chmodSync(f, 0o600);
    expect(ok([...base, '--passphrase-file', f], {}).passphrase).toBe('file-secret');

    chmodSync(f, 0o644);
    expect(() => loadConfig([...base, '--passphrase-file', f], {})).toThrow(/権限が広すぎます/);
    expect(() => loadConfig([...base, '--passphrase-file', join(dir, 'none')], {})).toThrow(/読めません/);
  });

  it('不正なトラッカー URL・知らないオプション・値の欠落を拒否', () => {
    expect(() => loadConfig(['--tracker', 'http://x.example.org', '--data', '/tmp/x'], env)).toThrow(/トラッカー/);
    expect(() => loadConfig(['--data', '/tmp/x'], env)).toThrow(/トラッカーの URL がありません/);
    expect(() => loadConfig(['--tracker', 'wss://x.example.org/ws'], env)).toThrow(/保存先/);
    expect(() => loadConfig([...base, '--nope', '1'], env)).toThrow(/知らないオプション/);
    expect(() => loadConfig([...base, '--storage-slots'], env)).toThrow(/値がありません/);
    expect(() => loadConfig([...base, '--storage-slots', '0'], env)).toThrow(/1〜64/);
  });

  it('--help は設定なしで返る', () => {
    expect(loadConfig(['--help'], {})).toEqual({ help: true });
  });

  it('メンテナ鍵・閾値・Guard リスト (デスクトップの VITE_OZ_* と同じ形式)', () => {
    const listFile = join(dir, 'list');
    writeFileSync(listFile, 'LISTTEXT\n');
    const c = ok(
      [...base, '--guard-list-file', listFile],
      { ...env, OZ_MAINTAINER_KEYS: `${KEY},${KEY2}`, OZ_MAINTAINER_THRESHOLD: '2' },
    );
    expect(c.trust?.maintainerKeys.threshold).toBe(2);
    expect(c.trust?.maintainerKeys.keys.map((k) => k.length)).toEqual([32, 32]);
    expect(c.trust?.guardList).toBe('LISTTEXT');

    // 環境変数に中身を直接
    expect(ok(base, { ...env, OZ_MAINTAINER_KEYS: KEY, OZ_GUARD_LIST: ' L2 ' }).trust?.guardList).toBe('L2');
  });

  it('信頼設定が壊れていれば黙って落とさず拒否する', () => {
    expect(() => loadConfig(base, { ...env, OZ_MAINTAINER_KEYS: 'not-a-key!' })).toThrow(/公開鍵の形式/);
    expect(() => loadConfig(base, { ...env, OZ_MAINTAINER_KEYS: Buffer.alloc(16).toString('base64url') })).toThrow(/公開鍵の形式/);
    expect(() => loadConfig(base, { ...env, OZ_MAINTAINER_KEYS: KEY, OZ_MAINTAINER_THRESHOLD: '2' })).toThrow(/閾値/);
    expect(() => loadConfig(base, { ...env, OZ_MAINTAINER_THRESHOLD: '1' })).toThrow(/maintainer-keys/);
    expect(() => loadConfig(base, { ...env, OZ_GUARD_LIST: 'L' })).toThrow(/公開鍵がありません/);
  });

  it('--trust-dir でリポジトリの trust/ をまとめて読む。個別の指定があればそちらが優先', () => {
    writeFileSync(join(dir, 'trust.json'), JSON.stringify({ maintainerKeys: [KEY, KEY2], threshold: 2 }));
    writeFileSync(join(dir, 'guard-list.txt'), 'LIST-FROM-DIR\n');
    const c = ok([...base, '--trust-dir', dir]);
    expect(c.trust?.maintainerKeys.threshold).toBe(2);
    expect(c.trust?.maintainerKeys.keys).toHaveLength(2);
    expect(c.trust?.guardList).toBe('LIST-FROM-DIR');
    // 環境変数でも指せる
    expect(ok(base, { ...env, OZ_TRUST_DIR: dir }).trust?.guardList).toBe('LIST-FROM-DIR');
    // 個別の指定が優先
    expect(ok([...base, '--trust-dir', dir], { ...env, OZ_MAINTAINER_KEYS: KEY, OZ_MAINTAINER_THRESHOLD: '1', OZ_GUARD_LIST: 'L3' }).trust)
      .toMatchObject({ guardList: 'L3', maintainerKeys: { threshold: 1 } });
    // 公開鍵がまだ無い trust/ (リストも無い) なら信頼設定なし
    const empty = mkdtempSync(join(tmpdir(), 'oz-guard-trust-'));
    writeFileSync(join(empty, 'trust.json'), JSON.stringify({ maintainerKeys: [], threshold: 1 }));
    expect(ok([...base, '--trust-dir', empty]).trust).toBeNull();
    rmSync(empty, { recursive: true, force: true });
  });

  it('--trust-dir が読めない・壊れているなら起動を止める', () => {
    expect(() => ok([...base, '--trust-dir', join(dir, 'none')])).toThrow(/trust.json を読めません/);
    writeFileSync(join(dir, 'trust.json'), JSON.stringify({ maintainerKeys: 'x' }));
    expect(() => ok([...base, '--trust-dir', dir])).toThrow(/文字列の配列/);
    writeFileSync(join(dir, 'trust.json'), JSON.stringify({ maintainerKeys: ['bad!'] }));
    expect(() => ok([...base, '--trust-dir', dir])).toThrow(/公開鍵の形式/);
  });

  it('--ice-servers は stun: のみ。既定は空 (= トラッカーのホスト)。turn: は拒否', () => {
    expect(ok(base).iceServers).toEqual([]);
    expect(ok([...base, '--ice-servers', 'stun:a.example.org:3478,stun:b.example.org']).iceServers)
      .toEqual(['stun:a.example.org:3478', 'stun:b.example.org']);
    expect(() => ok([...base, '--ice-servers', 'turn:u:p@t.example.org'])).toThrow(/turn/);
    expect(() => ok([...base, '--ice-servers', 'http://x'])).toThrow();
  });
});
