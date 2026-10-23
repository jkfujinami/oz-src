import { mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { VAULT_PARAMS_FAST } from '@oz/core';
import { startGuard, type GuardHandle } from '../src/GuardApp';
import type { GuardConfig } from '../src/config';
import { SNAPSHOT_FILE } from '../src/snapshot';

describe('Guard の身元の永続化', () => {
  let dir: string;
  const handles: GuardHandle[] = [];
  beforeEach(() => {
    dir = join(mkdtempSync(join(tmpdir(), 'oz-guard-id-')), 'data');
  });
  afterEach(async () => {
    for (const h of handles.splice(0)) await h.stop().catch(() => undefined);
    rmSync(join(dir, '..'), { recursive: true, force: true });
  });

  // トラッカーへは届かない URL (接続は試みて失敗するだけ。ここでは通信しない)
  const config = (passphrase = 'identity-test-passphrase'): GuardConfig => ({
    trackerUrl: 'ws://127.0.0.1:9/ws',
    iceServers: [],
    dataDir: dir,
    passphrase,
    trust: null,
    storageSlots: 1,
    snapshotIntervalMs: 3_600_000,
  });
  const opts = { print: () => undefined, nodeOverrides: { vaultParams: VAULT_PARAMS_FAST, storage: { defaultSlots: 1, slotEffort: 1, chunkEffort: 1 } } };

  async function start(passphrase?: string): Promise<GuardHandle> {
    const h = await startGuard(config(passphrase), opts);
    handles.push(h);
    return h;
  }

  it('停止 → 再起動で同じ peerId・同じ Guard 文字列の元になる公開鍵', async () => {
    const a = await start();
    expect(a.createdIdentity).toBe(true);
    const { peerId } = a.node;
    const pubkey = Buffer.from(a.node.nodeIdentity.pubkey).toString('hex');
    await a.stop();
    handles.length = 0;

    const b = await start();
    expect(b.createdIdentity).toBe(false);
    expect(b.node.peerId).toBe(peerId);
    expect(Buffer.from(b.node.nodeIdentity.pubkey).toString('hex')).toBe(pubkey);
  });

  it('★ 身元は作った直後に書かれる: 停止処理が走らなくても (クラッシュ相当) 再起動で同じ peerId', async () => {
    const a = await start();
    // a.stop() を呼ばない。この時点のディスクの内容だけから起動し直す
    expect(readdirSync(dir)).toEqual([SNAPSHOT_FILE]);
    if (process.platform !== 'win32') {
      expect(statSync(dir).mode & 0o777).toBe(0o700);
      expect(statSync(join(dir, SNAPSHOT_FILE)).mode & 0o777).toBe(0o600);
    }
    const b = await start();
    expect(b.createdIdentity).toBe(false);
    expect(b.node.peerId).toBe(a.node.peerId);
  });

  it('パスフレーズが違えば起動を拒否し、新しい身元は作らない', async () => {
    const a = await start();
    const { peerId } = a.node;
    await a.stop();
    handles.length = 0;
    await expect(start('another-passphrase')).rejects.toThrow(/passphrase/i);
    // 正しいパスフレーズなら元の peerId のまま
    expect((await start()).node.peerId).toBe(peerId);
  });

  it('スナップショットはパスフレーズ無しでは読めない (平文の peerId を含まない)', async () => {
    const a = await start();
    await a.snapshotNow();
    const raw = (await import('node:fs')).readFileSync(join(dir, SNAPSHOT_FILE));
    expect(raw.includes(Buffer.from(a.node.peerId))).toBe(false);
    expect(raw.includes(Buffer.from(a.node.nodeIdentity.pubkey))).toBe(false);
    expect(raw.includes(Buffer.from('identity-test-passphrase'))).toBe(false);
  });
});
