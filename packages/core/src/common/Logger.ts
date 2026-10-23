/**
 * スコープ付きレベル制御ロガー
 *
 * ★ なぜ console.log を直接使わないか
 *
 *   1. **本番で漏れる。** これまで `[Dandelion] Stemming packet X to Y` のように
 *      Stem 先の peerId を平文で出していた。匿名性を扱う実装で、デバッグ出力が
 *      そのまま経路情報の漏洩源になる。レベルで落とせる形にする。
 *   2. **ホットパスで重い。** Gossip の受信は 1 パケットごとに走る。
 *      テンプレートリテラルは出力しなくても構築コストを払うため、
 *      レベル判定を通過するまで文字列を作らない仕組みが要る (下記の遅延評価)。
 *   3. **切り分けができない。** 「ゴシップ層だけ TRACE、他は WARN」が
 *      できないと、実網のログが読めない量になる。
 *
 * 使い方:
 *
 * ```ts
 * const log = createLogger('gossip');
 * log.info('peer connected', peerId);
 * log.trace(() => `expensive ${JSON.stringify(packet)}`);  // 遅延評価
 * ```
 *
 * 実行時の切り替え (ブラウザのコンソールから):
 *
 * ```js
 * ozLog.set('gossip', 'trace')   // このスコープだけ TRACE
 * ozLog.set('*', 'debug')        // 全体の既定
 * ozLog.show()                   // 現在の設定
 * ozLog.reset()
 * ```
 *
 * 起動時の指定:
 *   - ブラウザ: sessionStorage.oz_log = "*=info,gossip=trace"  (タブを閉じれば消える)
 *   - Node/テスト: OZ_LOG="*=warn,mailbox=trace"
 */

export const LogLevel = {
  SILENT: 0,
  ERROR: 1,
  WARN: 2,
  INFO: 3,
  DEBUG: 4,
  TRACE: 5,
} as const;

export type LogLevelName = keyof typeof LogLevel;
export type LogLevelValue = (typeof LogLevel)[LogLevelName];

const LEVEL_NAMES = Object.keys(LogLevel) as LogLevelName[];

/** 文字列/数値どちらでもレベルとして受ける。不正値は null */
export function parseLevel(v: unknown): LogLevelValue | null {
  if (typeof v === 'number') {
    return LEVEL_NAMES.some((n) => LogLevel[n] === v) ? (v as LogLevelValue) : null;
  }
  if (typeof v !== 'string') return null;
  const upper = v.trim().toUpperCase() as LogLevelName;
  return upper in LogLevel ? LogLevel[upper] : null;
}

export function levelName(v: LogLevelValue): LogLevelName {
  return LEVEL_NAMES.find((n) => LogLevel[n] === v) ?? 'SILENT';
}

/**
 * 既定レベルは常に WARN。詳しいログは明示的に有効化したときだけ出す。
 *
 * ★ 旧実装は `process.env.NODE_ENV` で本番かどうかを判定し、それ以外を DEBUG にしていた。
 *   ブラウザや Electron のレンダラー (nodeIntegration: false) には `process` が無いため、
 *   配布版でも DEBUG になっていた。DEBUG ログには経路の判断や
 *   隣人の peerId の一部が含まれ、コンソールの転送先 (OS のセッションログなど) に
 *   平文で残り得る。押収時の痕跡を増やさないよう、既定は静かにしておく。
 *
 *   開発時は環境変数 OZ_LOG か localStorage.oz_log で上げる
 *   (例: "*=debug,net.gossip=trace")。
 *
 * ★ 設定の保存先は sessionStorage。localStorage に置くと「詳細ログを出す」設定が
 *   端末に残り続け、次の起動からずっと経路や ID を出し続ける。押収された端末に残る
 *   設定が冗長ログのままだと、それ自体が使われ方の痕跡にもなる。タブ (セッション) を
 *   閉じれば消える sessionStorage にして、前の版が残した localStorage の値は起動時に消す。
 */
function defaultLevel(): LogLevelValue {
  return LogLevel.WARN;
}

/**
 * "*=info,gossip=trace" / "debug" のどちらの書式も受ける。
 * スコープ名を省いた単独のレベルは `*` への指定として扱う。
 */
function parseSpec(spec: string): Map<string, LogLevelValue> {
  const out = new Map<string, LogLevelValue>();
  for (const part of spec.split(/[,\s]+/)) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq === -1) {
      const lv = parseLevel(part);
      if (lv !== null) out.set('*', lv);
      continue;
    }
    const scope = part.slice(0, eq).trim();
    const lv = parseLevel(part.slice(eq + 1));
    if (scope && lv !== null) out.set(scope, lv);
  }
  return out;
}

function readEnvSpec(): string | null {
  try {
    // 前の版が localStorage に残した設定は使わず、消す
    if (typeof localStorage !== 'undefined') localStorage.removeItem('oz_log');
  } catch {
    // 使えない環境は無視
  }
  try {
    if (typeof sessionStorage !== 'undefined') {
      const v = sessionStorage.getItem('oz_log');
      if (v) return v;
    }
  } catch {
    // sessionStorage が使えない環境 (SSR / プライベートモード) は無視
  }
  try {
    if (typeof process !== 'undefined' && process.env?.OZ_LOG) {
      return process.env.OZ_LOG;
    }
  } catch {
    // noop
  }
  return null;
}

/** スコープごとの設定。`*` が全体の既定。 */
const levels = new Map<string, LogLevelValue>();
let initialized = false;

function ensureInit(): void {
  if (initialized) return;
  initialized = true;
  levels.set('*', defaultLevel());
  const spec = readEnvSpec();
  if (spec) for (const [k, v] of parseSpec(spec)) levels.set(k, v);
}

/**
 * スコープに適用されるレベルを解決する。
 *
 * `network.mailbox` のようなドット区切りは、長い方から順に前方一致で探す。
 * (`network.mailbox` → `network` → `*`)
 */
export function levelFor(scope: string): LogLevelValue {
  ensureInit();
  const exact = levels.get(scope);
  if (exact !== undefined) return exact;

  let idx = scope.lastIndexOf('.');
  while (idx > 0) {
    const parent = levels.get(scope.slice(0, idx));
    if (parent !== undefined) return parent;
    idx = scope.lastIndexOf('.', idx - 1);
  }
  return levels.get('*') ?? defaultLevel();
}

export function setLevel(scope: string, level: LogLevelName | LogLevelValue | string): boolean {
  ensureInit();
  const lv = parseLevel(level);
  if (lv === null) return false;
  levels.set(scope, lv);
  return true;
}

export function resetLevels(): void {
  levels.clear();
  initialized = false;
}

export function currentLevels(): Record<string, LogLevelName> {
  ensureInit();
  const out: Record<string, LogLevelName> = {};
  for (const [k, v] of levels) out[k] = levelName(v);
  return out;
}

/** 遅延評価用。出力しないと決まった時点で呼ばれない。 */
type Lazy = () => unknown;
type Arg = unknown | Lazy;

function resolve(args: Arg[]): unknown[] {
  return args.map((a) => (typeof a === 'function' ? (a as Lazy)() : a));
}

/**
 * WARN / ERROR の文字列中の長い 16 進列 (peerId・パケット ID・鍵など) を先頭 8 文字に縮める。
 *
 * ★ 既定レベルの WARN / ERROR は本番でも出る。エラー文に隣人の peerId の全体が入ると、
 *   コンソールの転送先 (OS のセッションログなど) に残る。8 文字なら切り分けには足りる。
 */
const LONG_HEX = /\b[0-9a-fA-F]{16,}\b/g;
export function redactIds(text: string): string {
  return text.replace(LONG_HEX, (m) => `${m.slice(0, 8)}…`);
}
function redactArgs(args: unknown[]): unknown[] {
  return args.map((a) => {
    if (typeof a === 'string') return redactIds(a);
    if (a instanceof Error) {
      const copy = new Error(redactIds(a.message));
      copy.name = a.name;
      if (a.stack) copy.stack = redactIds(a.stack);
      return copy;
    }
    return a;
  });
}

export interface Logger {
  readonly scope: string;
  error(...args: Arg[]): void;
  warn(...args: Arg[]): void;
  info(...args: Arg[]): void;
  debug(...args: Arg[]): void;
  trace(...args: Arg[]): void;
  /** 高コストな出力の前に使う。`if (log.enabled(LogLevel.TRACE)) { ... }` */
  enabled(level: LogLevelValue): boolean;
  /** 子スコープを作る。`createLogger('network').child('mailbox')` → `network.mailbox` */
  child(sub: string): Logger;
}

/** テストから差し替えられるようにしておく */
export interface Sink {
  error(...a: unknown[]): void;
  warn(...a: unknown[]): void;
  info(...a: unknown[]): void;
  log(...a: unknown[]): void;
  debug(...a: unknown[]): void;
}

let sink: Sink = console;

export function setSink(s: Sink): void {
  sink = s;
}

export function createLogger(scope: string): Logger {
  const emit = (level: LogLevelValue, method: keyof Sink, args: Arg[]) => {
    if (levelFor(scope) < level) return;
    const out = resolve(args);
    sink[method](`[${scope}]`, ...(level <= LogLevel.WARN ? redactArgs(out) : out));
  };

  return {
    scope,
    error: (...a) => emit(LogLevel.ERROR, 'error', a),
    warn: (...a) => emit(LogLevel.WARN, 'warn', a),
    info: (...a) => emit(LogLevel.INFO, 'info', a),
    // ★ DEBUG は console.log へ出す。
    //   Chrome DevTools は console.debug を "Verbose" 扱いにしており、
    //   既定のコンソールでは**表示されない**。レベルを上げたのに
    //   何も出ないように見える原因になる。
    debug: (...a) => emit(LogLevel.DEBUG, 'log', a),
    // TRACE だけ console.debug (= Verbose)。既定では隠れる量の細かさ。
    trace: (...a) => emit(LogLevel.TRACE, 'debug', a),
    enabled: (level: LogLevelValue) => levelFor(scope) >= level,
    child: (sub: string) => createLogger(`${scope}.${sub}`),
  };
}

/**
 * ブラウザのコンソールから触れるハンドルを生やす。
 * 実網のデバッグでは「今まさに動いている状態のまま」レベルを上げたいので、
 * 再読み込み不要で効くことが重要。
 */
export function installConsoleHandle(): void {
  if (typeof globalThis === 'undefined') return;
  if ((globalThis as any).ozLog) return;

  // 起動時に現在のレベルと操作方法を出す。
  // 「レベルを上げたのに何も出ない」ときに、まずここを見れば分かる。
  ensureInit();
  console.info(
    `[log] levels=${JSON.stringify(currentLevels())} — ` +
      `ozLog.set('net.gossip','trace') / ozLog.set('*','trace') / ozLog.show()`,
  );
  (globalThis as any).ozLog = {
    set: (scope: string, level: string) => {
      const ok = setLevel(scope, level);
      if (!ok) {
        console.warn(`[log] unknown level: ${level} (${LEVEL_NAMES.join('/')})`);
        return currentLevels();
      }
      try {
        // 同じタブの再読み込みには引き継ぐ (端末には残さない)
        if (typeof sessionStorage !== 'undefined') {
          const spec = Object.entries(currentLevels())
            .map(([k, v]) => `${k}=${v.toLowerCase()}`)
            .join(',');
          sessionStorage.setItem('oz_log', spec);
        }
      } catch {
        // noop
      }
      return currentLevels();
    },
    show: () => currentLevels(),
    levels: LEVEL_NAMES,
    reset: () => {
      resetLevels();
      try {
        if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem('oz_log');
      } catch {
        // noop
      }
      return currentLevels();
    },
  };
}

if (typeof window !== 'undefined') {
  installConsoleHandle();
}
