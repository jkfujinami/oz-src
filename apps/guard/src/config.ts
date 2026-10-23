import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseIceServers, parseTrackerUrl, type MaintainerKeySet } from '@oz/core';

/**
 * 設定の読み取り (コマンドライン引数 + 環境変数)。副作用は passphrase-file / guard-list-file の読み込みだけ。
 *
 * ★ パスフレーズは **引数では受け取らない**。`--passphrase xxx` は `ps` や /proc/<pid>/cmdline から
 *   誰にでも見える (シェルの履歴にも残る)。環境変数か、権限 0600 のファイルで渡す。
 * ★ 信頼設定 (メンテナ鍵) が「あるのに壊れている」ときは起動を止める。デスクトップ版のように
 *   黙って信頼なし (オープン動作) に落とすと、Guard だと気付かないまま間違った網で動き続けるため。
 */

export interface GuardConfig {
  trackerUrl: string;
  /** STUN (`stun:` の URL)。空なら Google と Cloudflare の公開 STUN */
  iceServers: string[];
  /** 永続化先 (絶対パス) */
  dataDir: string;
  passphrase: string;
  trust: { maintainerKeys: MaintainerKeySet; guardList?: string } | null;
  storageSlots: number;
  /** 暗号化 DB のスナップショットを書く間隔 (ms) */
  snapshotIntervalMs: number;
}

export class ConfigError extends Error {}

export const DEFAULT_SNAPSHOT_INTERVAL_MIN = 10;

export const USAGE = `使い方: npm run guard -- --tracker <wss://...> --data <ディレクトリ> [オプション]

必須
  --tracker <url>             トラッカーの URL (wss://。localhost のみ ws:// 可)  [OZ_TRACKER_URL]
  --data <dir>                身元と履歴を保存するディレクトリ (無ければ 0700 で作る)  [OZ_GUARD_DATA]
  パスフレーズ                OZ_GUARD_PASSPHRASE か --passphrase-file <file> で渡す
                              (コマンドライン引数では渡せません。ps に見えてしまうため)

信頼 Guard の設定 (どれも任意。無ければ信頼リスト無しで動く)
  --maintainer-keys <k,k,..>  メンテナの公開鍵 (base64url、カンマ区切り)       [OZ_MAINTAINER_KEYS]
  --maintainer-threshold <n>  必要な署名の数 (既定 1)                           [OZ_MAINTAINER_THRESHOLD]
  --guard-list-file <file>    署名済みの Guard リスト                           [OZ_GUARD_LIST に中身を直接でも可]
  --trust-dir <dir>           リポジトリの trust/ (trust.json と guard-list.txt) をまとめて読む  [OZ_TRUST_DIR]
                              (上の個別の指定があればそちらが優先)

その他
  --ice-servers <url,url,..>  STUN サーバ (stun: のカンマ区切り。既定は Google と Cloudflare の公開 STUN。turn: 不可) [OZ_ICE_SERVERS]
  --storage-slots <n>         保管担当の枠の数 (1 枠 = 256MiB、既定 1)         [OZ_GUARD_STORAGE_SLOTS]
  --snapshot-interval <分>    スナップショットを書く間隔 (既定 ${DEFAULT_SNAPSHOT_INTERVAL_MIN})
  -h, --help                  このメッセージ
`;

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

function decodeBase64Url(text: string): Uint8Array | null {
  if (!BASE64URL_RE.test(text)) return null;
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

/**
 * メンテナ鍵の組を読む。形式が不正なら ConfigError (guardSetting.ts と同じ形式だが、こちらは黙って捨てない)。
 */
export function parseMaintainerKeys(keysText: string | undefined, thresholdText: string | undefined): MaintainerKeySet | null {
  const raw = keysText?.trim();
  if (!raw) {
    if (thresholdText?.trim()) throw new ConfigError('--maintainer-threshold だけ指定されています。--maintainer-keys も必要です');
    return null;
  }
  const keys: Uint8Array[] = [];
  for (const part of raw.split(',')) {
    const key = decodeBase64Url(part.trim());
    if (!key || key.length !== 32) {
      throw new ConfigError('メンテナの公開鍵の形式が不正です (base64url、32 バイト、カンマ区切り)');
    }
    keys.push(key);
  }
  const thresholdRaw = thresholdText?.trim();
  const threshold = thresholdRaw ? Number(thresholdRaw) : 1;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) {
    throw new ConfigError(`メンテナ署名の閾値が範囲外です (1〜${keys.length} の整数)`);
  }
  return { threshold, keys };
}

interface ParsedArgs {
  flags: Map<string, string>;
  help: boolean;
}

const VALUE_FLAGS = new Set([
  'tracker', 'data', 'passphrase-file', 'maintainer-keys', 'maintainer-threshold',
  'guard-list-file', 'storage-slots', 'snapshot-interval', 'ice-servers', 'trust-dir',
]);

function parseArgv(argv: string[]): ParsedArgs {
  const flags = new Map<string, string>();
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') {
      help = true;
      continue;
    }
    if (!a.startsWith('--')) throw new ConfigError(`解釈できない引数です: ${a}`);
    const eq = a.indexOf('=');
    const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
    // ★ 値を取る前に弾く: 「--passphrase=...」でも「--passphrase ...」でも、値は読まない
    if (name === 'passphrase') {
      throw new ConfigError(
        'パスフレーズはコマンドライン引数では渡せません (ps に見えてしまいます)。' +
        '環境変数 OZ_GUARD_PASSPHRASE か --passphrase-file <file> を使ってください',
      );
    }
    if (!VALUE_FLAGS.has(name)) throw new ConfigError(`知らないオプションです: --${name}`);
    let value: string | undefined;
    if (eq !== -1) value = a.slice(eq + 1);
    else {
      value = argv[i + 1];
      i++;
    }
    if (value === undefined || (eq === -1 && value.startsWith('--'))) throw new ConfigError(`--${name} に値がありません`);
    flags.set(name, value);
  }
  return { flags, help };
}

/** 引数・環境から設定を作る。`help` が true のときは設定は無い (usage を出して終わる) */
export function loadConfig(
  argv: string[],
  env: Record<string, string | undefined>,
): { help: true } | { help: false; config: GuardConfig } {
  const { flags, help } = parseArgv(argv);
  if (help) return { help: true };

  const pick = (flag: string, envName?: string): string | undefined => flags.get(flag) ?? (envName ? env[envName] : undefined);

  // トラッカー
  const trackerRaw = pick('tracker', 'OZ_TRACKER_URL')?.trim();
  if (!trackerRaw) throw new ConfigError('トラッカーの URL がありません (--tracker か OZ_TRACKER_URL)');
  const parsed = parseTrackerUrl(trackerRaw);
  if (!parsed.ok) throw new ConfigError(`トラッカーの URL が使えません: ${parsed.reason}`);

  // STUN (未指定なら Google と Cloudflare の公開 STUN。運営者には IP と時刻が伝わる)
  const ice = parseIceServers(pick('ice-servers', 'OZ_ICE_SERVERS'));
  if (!ice.ok) throw new ConfigError(ice.reason);

  // データディレクトリ
  const dataRaw = pick('data', 'OZ_GUARD_DATA')?.trim();
  if (!dataRaw) throw new ConfigError('保存先ディレクトリがありません (--data か OZ_GUARD_DATA)');

  // パスフレーズ: ファイルか環境変数のみ
  const passFile = flags.get('passphrase-file');
  let passphrase: string | undefined;
  if (passFile) {
    passphrase = readPassphraseFile(passFile);
  } else if (env.OZ_GUARD_PASSPHRASE) {
    passphrase = env.OZ_GUARD_PASSPHRASE;
  }
  if (!passphrase) {
    throw new ConfigError('パスフレーズがありません (環境変数 OZ_GUARD_PASSPHRASE か --passphrase-file)');
  }

  // 信頼設定 (個別の指定 > trust/ のまとめ)
  const trustDir = readTrustDir(pick('trust-dir', 'OZ_TRUST_DIR'));
  const keys = parseMaintainerKeys(
    pick('maintainer-keys', 'OZ_MAINTAINER_KEYS') ?? trustDir?.keys,
    pick('maintainer-threshold', 'OZ_MAINTAINER_THRESHOLD') ?? trustDir?.threshold,
  );
  let guardList: string | undefined;
  const listFile = flags.get('guard-list-file');
  if (listFile) {
    try {
      guardList = readFileSync(listFile, 'utf8').trim();
    } catch (err) {
      throw new ConfigError(`Guard リストのファイルを読めません: ${(err as Error).message}`);
    }
  } else if (env.OZ_GUARD_LIST?.trim()) {
    guardList = env.OZ_GUARD_LIST.trim();
  } else if (trustDir?.guardList) {
    guardList = trustDir.guardList;
  }
  if (guardList && !keys) {
    throw new ConfigError('Guard リストがありますが、メンテナの公開鍵がありません (署名を検証できないため使えません)');
  }
  const trust = keys ? (guardList ? { maintainerKeys: keys, guardList } : { maintainerKeys: keys }) : null;

  // 枠・間隔
  const slotsRaw = pick('storage-slots', 'OZ_GUARD_STORAGE_SLOTS');
  const storageSlots = slotsRaw === undefined || slotsRaw.trim() === '' ? 1 : Number(slotsRaw);
  if (!Number.isInteger(storageSlots) || storageSlots < 1 || storageSlots > 64) {
    throw new ConfigError('--storage-slots は 1〜64 の整数で指定してください');
  }
  const intervalRaw = flags.get('snapshot-interval');
  const intervalMin = intervalRaw === undefined ? DEFAULT_SNAPSHOT_INTERVAL_MIN : Number(intervalRaw);
  if (!Number.isFinite(intervalMin) || intervalMin < 1 || intervalMin > 24 * 60) {
    throw new ConfigError('--snapshot-interval は 1〜1440 (分) で指定してください');
  }

  return {
    help: false,
    config: {
      trackerUrl: parsed.url,
      iceServers: ice.servers,
      dataDir: resolve(dataRaw),
      passphrase,
      trust,
      storageSlots,
      snapshotIntervalMs: Math.round(intervalMin * 60_000),
    },
  };
}

/**
 * リポジトリの trust/ (trust.json と guard-list.txt) を読む。指定が無ければ null。
 * ★ 指定されたのに読めない・壊れているときは起動を止める (気付かないまま信頼なしで動かないように)。
 */
function readTrustDir(dir: string | undefined): { keys?: string; threshold?: string; guardList?: string } | null {
  if (!dir?.trim()) return null;
  let trust: { maintainerKeys?: unknown; threshold?: unknown };
  try {
    trust = JSON.parse(readFileSync(resolve(dir, 'trust.json'), 'utf8'));
  } catch (err) {
    throw new ConfigError(`trust.json を読めません: ${(err as Error).message}`);
  }
  if (!Array.isArray(trust.maintainerKeys) || !trust.maintainerKeys.every((k) => typeof k === 'string')) {
    throw new ConfigError('trust.json の maintainerKeys は文字列の配列にしてください');
  }
  let guardList: string | undefined;
  try {
    guardList = readFileSync(resolve(dir, 'guard-list.txt'), 'utf8').trim() || undefined;
  } catch {
    guardList = undefined; // リストはまだ無くてもよい
  }
  const keys = (trust.maintainerKeys as string[]).filter(Boolean).join(',');
  return {
    keys: keys || undefined,
    threshold: keys && trust.threshold !== undefined ? String(trust.threshold) : undefined,
    guardList,
  };
}

/** パスフレーズのファイルを読む。末尾の改行 1 つだけ落とす。他人に読める権限なら拒否する */
function readPassphraseFile(path: string): string {
  let text: string;
  try {
    const st = statSync(path);
    if (!st.isFile()) throw new ConfigError('パスフレーズのファイルが通常のファイルではありません');
    // ★ POSIX のみ: group / other に読めるファイルに置かれたパスフレーズは、秘密として扱えない
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      throw new ConfigError(`パスフレーズのファイルの権限が広すぎます。chmod 600 ${path} してください`);
    }
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError(`パスフレーズのファイルを読めません: ${(err as Error).message}`);
  }
  return text.replace(/\r?\n$/, '');
}
