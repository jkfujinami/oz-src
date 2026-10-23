import path from 'node:path';
import type fsType from 'node:fs';
import {
  GUARD_SLOTS_MAX, GUARD_SLOTS_MIN, isGuardReport,
  type DesktopGuardStatus, type GuardReport, type GuardStartConfig,
} from '../src/guardProtocol';

/**
 * GuardHost — この端末で動かす信頼 Guard の世話をする (メインプロセス側)。
 *
 * ★ なぜ画面のノードと分けるのか
 *   画面のノード (自分の投稿・閲覧用) は起動のたびに身元を作り直し、ロック・自動ロック・スリープで止まる。
 *   Guard は信頼リストに載る固定の身元で、止まらずに動き続ける必要がある。同じノードにすると、自分の投稿の
 *   身元が公開の Guard の身元と同じになり、セッションをまたいで紐付く。そこで見えないウィンドウで別のノード
 *   (別の DB = OzGuardDB、別の身元) を動かし、画面がロック中でも Guard は動き続ける。
 *
 * ★ パスフレーズ
 *   Guard の DB (身元の秘密鍵) は乱数のパスフレーズで封印し、そのパスフレーズは OS の鍵の保管庫
 *   (macOS のキーチェーン / Windows の DPAPI / Linux の Secret Service。Electron の safeStorage) で暗号化して置く。
 *   利用者が何も入力しなくても起動でき、ディスクだけを抜かれても読めない。保管庫が使えない環境
 *   (Linux で平文の basic_text しか無いなど) では Guard を動かさない。
 */

interface GuardConfigFile {
  v: 1;
  enabled: boolean;
  slots: number;
  openAtLogin: boolean;
}

const DEFAULT_CONFIG: GuardConfigFile = { v: 1, enabled: false, slots: 4, openAtLogin: false };

/** 止めるときに、Guard のウィンドウが書き残しを終えるのを待つ上限 */
export const GUARD_STOP_TIMEOUT_MS = 8000;

/** Guard を動かすウィンドウ (BrowserWindow のうち使う部分だけ) */
export interface GuardWindowLike {
  webContents: { id: number; send(channel: string, ...args: unknown[]): void };
  destroy(): void;
  isDestroyed(): boolean;
}

export interface SafeStorageLike {
  isEncryptionAvailable(): boolean;
  encryptString(plain: string): Buffer;
  decryptString(enc: Buffer): string;
  getSelectedStorageBackend?(): string;
}

export interface GuardHostDeps {
  /** 設定と封印したパスフレーズを置く場所 (userData/guard) */
  dir: string;
  fs: Pick<typeof fsType, 'existsSync' | 'mkdirSync' | 'readFileSync' | 'writeFileSync' | 'rmSync'>;
  safeStorage: SafeStorageLike;
  platform: NodeJS.Platform;
  randomBytes(n: number): Buffer;
  /** 見えないウィンドウを作って guard.html を読む */
  openWindow(): GuardWindowLike;
  setLoginItem(openAtLogin: boolean): void;
  /** 状態が変わったら画面へ知らせる */
  notify(status: DesktopGuardStatus): void;
}

export class GuardHost {
  private config: GuardConfigFile;
  private window: GuardWindowLike | null = null;
  private starting = false;
  private report: GuardReport | null = null;
  private error: string | null = null;
  private stopWaiter: (() => void) | null = null;

  constructor(private readonly deps: GuardHostDeps) {
    this.config = this.readConfig();
  }

  private get configPath(): string {
    return path.join(this.deps.dir, 'config.json');
  }

  private get passPath(): string {
    return path.join(this.deps.dir, 'passphrase.bin');
  }

  private readConfig(): GuardConfigFile {
    try {
      const raw = JSON.parse(this.deps.fs.readFileSync(this.configPath, 'utf8')) as Partial<GuardConfigFile>;
      return {
        v: 1,
        enabled: raw.enabled === true,
        slots: clampSlots(raw.slots),
        openAtLogin: raw.openAtLogin === true,
      };
    } catch {
      return { ...DEFAULT_CONFIG };
    }
  }

  private writeConfig(): void {
    this.deps.fs.mkdirSync(this.deps.dir, { recursive: true, mode: 0o700 });
    this.deps.fs.writeFileSync(this.configPath, JSON.stringify(this.config), { mode: 0o600 });
  }

  /** この端末で Guard を動かせるか */
  availability(): { ok: true } | { ok: false; reason: string } {
    const s = this.deps.safeStorage;
    if (!s.isEncryptionAvailable()) {
      return { ok: false, reason: 'OS の鍵の保管庫が使えません (Guard の身元を安全に置けないため、動かせません)' };
    }
    if (this.deps.platform === 'linux' && s.getSelectedStorageBackend?.() === 'basic_text') {
      return { ok: false, reason: '鍵の保管庫 (Secret Service / KWallet) がありません。平文でしか置けないため、Guard は動かせません' };
    }
    return { ok: true };
  }

  status(): DesktopGuardStatus {
    const avail = this.availability();
    return {
      available: avail.ok,
      unavailableReason: avail.ok ? null : avail.reason,
      enabled: this.config.enabled,
      starting: this.starting,
      running: this.report !== null,
      openAtLogin: this.config.openAtLogin,
      slots: this.config.slots,
      report: this.report,
      error: this.error,
    };
  }

  private changed(): void {
    this.deps.notify(this.status());
  }

  /** パスフレーズを取り出す。無ければ乱数で作り、OS の鍵の保管庫で暗号化して置く */
  private passphrase(): string {
    const { fs, safeStorage } = this.deps;
    if (fs.existsSync(this.passPath)) {
      return safeStorage.decryptString(fs.readFileSync(this.passPath));
    }
    const pass = this.deps.randomBytes(32).toString('base64url');
    fs.mkdirSync(this.deps.dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(this.passPath, safeStorage.encryptString(pass), { mode: 0o600 });
    return pass;
  }

  /** 起動時: 有効にしてあれば動かす */
  startIfEnabled(): void {
    if (this.config.enabled && this.availability().ok) this.start();
  }

  enable(opts: { slots?: number } = {}): DesktopGuardStatus {
    const avail = this.availability();
    if (!avail.ok) {
      this.error = avail.reason;
      this.changed();
      return this.status();
    }
    this.config = { ...this.config, enabled: true, slots: clampSlots(opts.slots ?? this.config.slots) };
    this.writeConfig();
    this.error = null;
    this.start();
    return this.status();
  }

  async disable(): Promise<DesktopGuardStatus> {
    this.config = { ...this.config, enabled: false };
    this.writeConfig();
    await this.stop();
    return this.status();
  }

  setOpenAtLogin(on: boolean): DesktopGuardStatus {
    this.config = { ...this.config, openAtLogin: on };
    this.writeConfig();
    this.deps.setLoginItem(on);
    this.changed();
    return this.status();
  }

  private start(): void {
    if (this.window && !this.window.isDestroyed()) return;
    this.starting = true;
    this.report = null;
    this.window = this.deps.openWindow();
    this.changed();
  }

  private isGuardSender(senderId: number): boolean {
    return !!this.window && !this.window.isDestroyed() && this.window.webContents.id === senderId;
  }

  /** Guard のウィンドウが起動に要るもの (パスフレーズ・枠) を取りに来た。Guard のウィンドウ以外には渡さない */
  startConfigFor(senderId: number): GuardStartConfig {
    if (!this.isGuardSender(senderId)) throw new Error('untrusted sender');
    return { passphrase: this.passphrase(), slots: this.config.slots };
  }

  /** Guard のウィンドウから状態が届いた */
  onReport(senderId: number, report: unknown): void {
    if (!this.isGuardSender(senderId) || !isGuardReport(report)) return;
    this.report = report;
    this.starting = false;
    this.error = null;
    this.changed();
  }

  /** Guard のウィンドウが起動に失敗した */
  onError(senderId: number, message: unknown): void {
    if (!this.isGuardSender(senderId)) return;
    this.error = typeof message === 'string' ? message.slice(0, 300) : 'Guard を起動できませんでした';
    this.starting = false;
    this.report = null;
    this.destroyWindow();
    this.changed();
  }

  /** Guard のウィンドウが書き残しを終えて止まった */
  onStopped(senderId: number): void {
    if (!this.isGuardSender(senderId)) return;
    this.stopWaiter?.();
  }

  /** ウィンドウが勝手に消えた (描画のプロセスが落ちたなど) */
  onWindowGone(reason: string): void {
    if (!this.window) return;
    this.window = null;
    this.report = null;
    this.starting = false;
    if (this.config.enabled) this.error = `Guard が止まりました (${reason})`;
    this.changed();
  }

  /** 止める: ノードを止めて書き残しを終えるのを待ち (上限あり)、ウィンドウを閉じる */
  async stop(timeoutMs = GUARD_STOP_TIMEOUT_MS): Promise<void> {
    const win = this.window;
    if (!win || win.isDestroyed()) {
      this.window = null;
      return;
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, timeoutMs);
      this.stopWaiter = () => {
        clearTimeout(timer);
        resolve();
      };
      try {
        win.webContents.send('oz-guard:stop');
      } catch {
        clearTimeout(timer);
        resolve();
      }
    });
    this.stopWaiter = null;
    this.destroyWindow();
    this.report = null;
    this.starting = false;
    this.changed();
  }

  /** 緊急消去: 待たずにウィンドウを壊し、設定と封印したパスフレーズを消す */
  destroyNow(): void {
    this.destroyWindow();
    this.report = null;
    this.starting = false;
    try {
      this.deps.fs.rmSync(this.deps.dir, { recursive: true, force: true });
    } catch {
      // userData ごと消すので、ここで消せなくてもよい
    }
    this.config = { ...DEFAULT_CONFIG };
    this.deps.setLoginItem(false);
  }

  private destroyWindow(): void {
    const win = this.window;
    this.window = null;
    if (win && !win.isDestroyed()) win.destroy();
  }
}

function clampSlots(v: unknown): number {
  const n = typeof v === 'number' && Number.isInteger(v) ? v : DEFAULT_CONFIG.slots;
  return Math.min(GUARD_SLOTS_MAX, Math.max(GUARD_SLOTS_MIN, n));
}
