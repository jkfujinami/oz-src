import { describe, it, expect, beforeAll } from 'vitest';
import { sodiumReady } from '../../src/crypto/sodium';
import { NodeIdentity } from '../../src/crypto/NodeIdentity';
import { VAULT_PARAMS_FAST } from '../../src/storage/SecretVault';
import { runGuardMaintainer, parseKeySetJson, type CliIO } from '../../src/cli/guardMaintainer';
import { createGuardString, verifyGuardList } from '../../src/trust/TrustedGuards';

const FAST = { difficulty: 0, opsLimit: 1, memLimit: 8192 };
const OPTS = { vaultParams: VAULT_PARAMS_FAST, powParams: FAST };

/** メモリ上のファイルと、順に答えるパスワード入力 */
function memoryIO(answers: string[] = []) {
  const files = new Map<string, string>();
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIO = {
    readFile: async (p) => {
      if (!files.has(p)) throw new Error(`ENOENT ${p}`);
      return files.get(p)!;
    },
    writeFile: async (p, c) => { files.set(p, c); },
    promptSecret: async () => answers.shift() ?? '',
    print: (l) => out.push(l),
    error: (l) => err.push(l),
    now: () => Date.now(),
  };
  return { io, files, out, err, answers };
}

function pubkeyFrom(out: string[]): string {
  return out.find((l) => l.startsWith('公開鍵'))!.split(': ')[1];
}

describe('メンテナ用 CLI', () => {
  let guardStrings: string[];

  beforeAll(async () => {
    await sodiumReady;
    const gs = await Promise.all([1, 2].map(() => NodeIdentity.mine(FAST)));
    guardStrings = gs.map((g) => createGuardString(g));
  });

  it('鍵の生成 → リストへの署名 → 検査、が通しでできる', async () => {
    const env = memoryIO(['long enough pass', 'long enough pass', 'long enough pass']);
    expect(await runGuardMaintainer(['keygen', '--out', 'm1.key'], env.io, OPTS)).toBe(0);
    const pubkey = pubkeyFrom(env.out);
    // 鍵ファイルに秘密鍵が平文で入っていない
    expect(env.files.get('m1.key')).not.toMatch(/privateKey/);
    expect(JSON.parse(env.files.get('m1.key')!).sealed.protected).toBe(true);

    env.files.set('guards.txt', `# 審査済みの Guard\n${guardStrings.join('\n')}\n`);
    expect(await runGuardMaintainer(
      ['sign', '--key', 'm1.key', '--guards', 'guards.txt', '--version', '1', '--days', '90', '--out', 'list.txt'],
      env.io, OPTS,
    )).toBe(0);

    env.files.set('keys.json', JSON.stringify({ threshold: 1, keys: [pubkey] }));
    env.out.length = 0;
    expect(await runGuardMaintainer(['inspect', '--keys', 'keys.json', 'list.txt'], env.io, OPTS)).toBe(0);
    expect(env.out[0]).toMatch(/^OK {2}version=1/);
    expect(env.out.filter((l) => l.includes('guard '))).toHaveLength(2);

    // core の検証関数でも受け入れられる (アプリ側と同じ判定)
    const keyset = parseKeySetJson(env.files.get('keys.json')!);
    expect(verifyGuardList(env.files.get('list.txt')!.trim(), keyset, { powParams: FAST }).ok).toBe(true);
  });

  it('短いパスワード・確認の不一致では鍵を作らない', async () => {
    const short = memoryIO(['short', 'short']);
    expect(await runGuardMaintainer(['keygen', '--out', 'k'], short.io, OPTS)).toBe(1);
    expect(short.files.has('k')).toBe(false);

    const mismatch = memoryIO(['long enough pass', 'different pass!!']);
    expect(await runGuardMaintainer(['keygen', '--out', 'k'], mismatch.io, OPTS)).toBe(1);
    expect(mismatch.files.has('k')).toBe(false);
  });

  it('パスワードが違えば署名できない', async () => {
    const env = memoryIO(['long enough pass', 'long enough pass', 'wrong passphrase!']);
    await runGuardMaintainer(['keygen', '--out', 'm.key'], env.io, OPTS);
    env.files.set('guards.txt', guardStrings.join('\n'));
    expect(await runGuardMaintainer(
      ['sign', '--key', 'm.key', '--guards', 'guards.txt', '--version', '1', '--out', 'list.txt'], env.io, OPTS,
    )).toBe(1);
    expect(env.files.has('list.txt')).toBe(false);
    expect(env.err.join('\n')).toMatch(/wrong passphrase/);
  });

  it('不正な Guard 文字列が含まれていたら署名しない', async () => {
    const env = memoryIO(['long enough pass', 'long enough pass', 'long enough pass']);
    await runGuardMaintainer(['keygen', '--out', 'm.key'], env.io, OPTS);
    env.files.set('guards.txt', [...guardStrings, guardStrings[0].slice(0, -5) + 'AAAAA'].join('\n'));
    expect(await runGuardMaintainer(
      ['sign', '--key', 'm.key', '--guards', 'guards.txt', '--version', '1', '--out', 'list.txt'], env.io, OPTS,
    )).toBe(1);
    expect(env.files.has('list.txt')).toBe(false);
  });

  it('既存リストに 2 人目のメンテナが署名を足せる (2-of-2)', async () => {
    const env = memoryIO([
      'first maintainer', 'first maintainer',
      'second maintainer', 'second maintainer',
      'first maintainer', 'second maintainer',
    ]);
    await runGuardMaintainer(['keygen', '--out', 'a.key'], env.io, OPTS);
    const pubA = pubkeyFrom(env.out);
    env.out.length = 0;
    await runGuardMaintainer(['keygen', '--out', 'b.key'], env.io, OPTS);
    const pubB = pubkeyFrom(env.out);

    env.files.set('guards.txt', guardStrings.join('\n'));
    await runGuardMaintainer(['sign', '--key', 'a.key', '--guards', 'guards.txt', '--version', '2', '--out', 'one.txt'], env.io, OPTS);
    await runGuardMaintainer(
      ['sign', '--key', 'b.key', '--guards', 'guards.txt', '--version', '2', '--existing', 'one.txt', '--out', 'two.txt'],
      env.io, OPTS,
    );

    const keyset = { threshold: 2, keys: parseKeySetJson(JSON.stringify({ threshold: 2, keys: [pubA, pubB] })).keys };
    expect(verifyGuardList(env.files.get('one.txt')!.trim(), keyset, { powParams: FAST })).toMatchObject({ ok: false });
    expect(verifyGuardList(env.files.get('two.txt')!.trim(), keyset, { powParams: FAST }).ok).toBe(true);
  });

  it('知らないコマンドは使い方を表示して終了コード 2', async () => {
    const env = memoryIO();
    expect(await runGuardMaintainer(['nope'], env.io, OPTS)).toBe(2);
    expect(env.err[0]).toMatch(/usage/);
  });
});
