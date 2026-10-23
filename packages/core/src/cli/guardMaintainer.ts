import sodium, { sodiumReady } from '../crypto/sodium';
import { SecretVault, VAULT_PARAMS, type SealedSecret, type VaultParams } from '../storage/SecretVault';
import {
  parseGuardString,
  signGuardList,
  verifyGuardList,
  readGuardListUnverified,
  maintainerKeyId,
  keyFingerprint,
  TRUSTED_GUARD_LIMITS,
  type MaintainerKeySet,
} from '../trust/TrustedGuards';
import { NODE_ID_POW, type NodeIdPowParams } from '../crypto/NodeIdentity';

/**
 * メンテナ用 CLI — 信頼 Guard リストの管理。
 *
 *   keygen  --out <file>                       メンテナ鍵を作り、パスワードで封印して保存する
 *   pubkey  --key <file>                       公開鍵 (アプリに組み込む値) と指紋を表示する
 *   check   <guard 文字列>...                  運用者の Guard 文字列を検証する
 *   sign    --key <file> --guards <file> --version <n> [--days <n>] [--revoked <file>]
 *           [--existing <file>] --out <file>   リストに署名する (既存リストに署名を足すことも可)
 *   inspect --keys <file> <list file>          リストを検証して中身を表示する
 *
 * ★ 運用上の注意
 *   - メンテナ鍵は普段使いの機械に置かない (オフラインの機械で署名する)。
 *   - 作ったリストは全版をリポジトリにコミットし、追加の経緯を誰でも追えるようにする。
 *   - version は必ず前回より大きくする (利用者は古い版を受け付けない)。
 */

export interface CliIO {
  readFile(path: string): Promise<string>;
  writeFile(path: string, content: string): Promise<void>;
  /** 画面に表示しない入力 (パスワード) */
  promptSecret(question: string): Promise<string>;
  print(line: string): void;
  error(line: string): void;
  now(): number;
}

interface MaintainerKeyFile {
  v: 1;
  type: 'oz-maintainer-key';
  pubkey: string;
  sealed: { v: 1; protected: boolean; salt: string; nonce: string; ciphertext: string; opsLimit: number; memLimit: number };
}

const b64u = (b: Uint8Array) => sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);
const unb64u = (s: string) => sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);

const DAY_MS = 24 * 60 * 60 * 1000;
const MIN_PASSPHRASE_LENGTH = 12;

function parseArgs(argv: string[]): { positional: string[]; flags: Map<string, string> } {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`missing value for ${a}`);
      flags.set(a.slice(2), value);
      i++;
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function need(flags: Map<string, string>, name: string): string {
  const v = flags.get(name);
  if (!v) throw new Error(`--${name} is required`);
  return v;
}

/** 1 行 1 件のテキストを読む (空行と # 始まりは無視) */
function lines(text: string): string[] {
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));
}

async function loadSecretKey(io: CliIO, path: string): Promise<Uint8Array> {
  const file = JSON.parse(await io.readFile(path)) as MaintainerKeyFile;
  if (file?.type !== 'oz-maintainer-key' || file.v !== 1) throw new Error('not a maintainer key file');
  const sealed: SealedSecret = {
    v: 1,
    protected: file.sealed.protected,
    salt: unb64u(file.sealed.salt),
    nonce: unb64u(file.sealed.nonce),
    ciphertext: unb64u(file.sealed.ciphertext),
    opsLimit: file.sealed.opsLimit,
    memLimit: file.sealed.memLimit,
  };
  const passphrase = await io.promptSecret('メンテナ鍵のパスワード: ');
  const sk = SecretVault.open(sealed, passphrase);
  if (!sk || sk.length !== sodium.crypto_sign_SECRETKEYBYTES) throw new Error('wrong passphrase or corrupted key file');
  return sk;
}

/** 組み込み用の鍵の組 (JSON: { threshold, keys: [base64url...] }) */
export function parseKeySetJson(text: string): MaintainerKeySet {
  const raw = JSON.parse(text);
  if (!Number.isInteger(raw?.threshold) || !Array.isArray(raw?.keys)) throw new Error('invalid keyset file');
  return { threshold: raw.threshold, keys: raw.keys.map((k: string) => unb64u(k)) };
}

export async function runGuardMaintainer(
  argv: string[],
  io: CliIO,
  opts: { vaultParams?: VaultParams; powParams?: NodeIdPowParams } = {},
): Promise<number> {
  await sodiumReady;
  const [command, ...rest] = argv;
  try {
    const { positional, flags } = parseArgs(rest);
    switch (command) {
      case 'keygen': {
        const out = need(flags, 'out');
        const pass = await io.promptSecret(`新しいパスワード (${MIN_PASSPHRASE_LENGTH} 文字以上): `);
        const again = await io.promptSecret('もう一度: ');
        if (pass.length < MIN_PASSPHRASE_LENGTH) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
        if (pass !== again) throw new Error('passphrases do not match');
        const kp = sodium.crypto_sign_keypair();
        const sealed = SecretVault.seal(kp.privateKey, pass, opts.vaultParams ?? VAULT_PARAMS);
        sodium.memzero(kp.privateKey);
        const file: MaintainerKeyFile = {
          v: 1,
          type: 'oz-maintainer-key',
          pubkey: b64u(kp.publicKey),
          sealed: {
            v: 1,
            protected: sealed.protected,
            salt: b64u(sealed.salt),
            nonce: b64u(sealed.nonce),
            ciphertext: b64u(sealed.ciphertext),
            opsLimit: sealed.opsLimit,
            memLimit: sealed.memLimit,
          },
        };
        await io.writeFile(out, JSON.stringify(file, null, 2) + '\n');
        io.print(`公開鍵 (アプリに組み込む値): ${b64u(kp.publicKey)}`);
        io.print(`鍵 ID: ${maintainerKeyId(kp.publicKey)}`);
        io.print(`指紋: ${keyFingerprint(kp.publicKey)}`);
        return 0;
      }

      case 'pubkey': {
        const file = JSON.parse(await io.readFile(need(flags, 'key'))) as MaintainerKeyFile;
        const pk = unb64u(file.pubkey);
        io.print(`公開鍵: ${file.pubkey}`);
        io.print(`鍵 ID: ${maintainerKeyId(pk)}`);
        io.print(`指紋: ${keyFingerprint(pk)}`);
        return 0;
      }

      case 'check': {
        if (positional.length === 0) throw new Error('give at least one guard string');
        let bad = 0;
        for (const s of positional) {
          const g = parseGuardString(s, opts.powParams ?? NODE_ID_POW);
          if (g) io.print(`OK  ${g.peerId}`);
          else {
            io.print(`NG  ${s.slice(0, 32)}...`);
            bad++;
          }
        }
        return bad === 0 ? 0 : 1;
      }

      case 'sign': {
        const version = Number(need(flags, 'version'));
        const days = Number(flags.get('days') ?? '90');
        if (!Number.isSafeInteger(version) || version < 1) throw new Error('--version must be a positive integer');
        if (!Number.isFinite(days) || days <= 0 || days * DAY_MS > TRUSTED_GUARD_LIMITS.MAX_VALIDITY_MS) {
          throw new Error(`--days must be between 1 and ${TRUSTED_GUARD_LIMITS.MAX_VALIDITY_MS / DAY_MS}`);
        }
        const guards = lines(await io.readFile(need(flags, 'guards')));
        // 署名する前に、全員の Guard 文字列を検証する (不正なものを載せない)
        for (const g of guards) {
          if (!parseGuardString(g, opts.powParams ?? NODE_ID_POW)) throw new Error(`invalid guard string: ${g.slice(0, 32)}...`);
        }
        const revoked = flags.has('revoked') ? lines(await io.readFile(flags.get('revoked')!)) : [];
        const existing = flags.has('existing') ? (await io.readFile(flags.get('existing')!)).trim() : undefined;

        // 既存リストに署名を足す場合は、その中身 (発行・失効時刻) をそのまま使う
        let issuedAt = io.now();
        let expiresAt = issuedAt + Math.round(days * DAY_MS);
        if (existing) {
          // 署名は足す側では検証しない (利用者側の verifyGuardList が検証する)。
          // 中身が違えば signGuardList が拒否する。
          const prev = readGuardListUnverified(existing);
          if (!prev) throw new Error('existing list is malformed');
          ({ issuedAt, expiresAt } = prev);
        }

        const sk = await loadSecretKey(io, need(flags, 'key'));
        try {
          const list = signGuardList({ version, issuedAt, expiresAt, guards, revoked }, sk, existing);
          await io.writeFile(need(flags, 'out'), list + '\n');
          io.print(`署名しました: version=${version} guards=${guards.length} revoked=${revoked.length}`);
          io.print(`有効期限: ${new Date(expiresAt).toISOString()}`);
        } finally {
          sodium.memzero(sk);
        }
        return 0;
      }

      case 'inspect': {
        const keyset = parseKeySetJson(await io.readFile(need(flags, 'keys')));
        if (positional.length !== 1) throw new Error('give one list file');
        const text = (await io.readFile(positional[0])).trim();
        const r = verifyGuardList(text, keyset, { now: io.now(), powParams: opts.powParams });
        if (!r.ok) {
          io.print(`NG  ${r.reason}${r.detail ? ` (${r.detail})` : ''}`);
          return 1;
        }
        io.print(`OK  version=${r.version} 有効期限=${new Date(r.expiresAt).toISOString()}`);
        for (const g of r.guards) io.print(`    guard ${g.peerId}`);
        for (const p of r.revoked) io.print(`    revoked ${p}`);
        return 0;
      }

      default:
        io.error('usage: guard-maintainer <keygen|pubkey|check|sign|inspect> ...');
        return 2;
    }
  } catch (err) {
    io.error(`error: ${(err as Error).message}`);
    return 1;
  }
}
