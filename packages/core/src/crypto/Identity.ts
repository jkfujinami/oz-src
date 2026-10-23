import sodium from './sodium';
import type { IIdentity, SignatureResult, SignContext } from '../types';
import { createLogger } from '../common/Logger';

const log = createLogger('crypto.identity');

/**
 * トリップ鍵・ノード鍵を保存できる最小のインターフェース。
 *
 * ★ 秘密は呼び出し側では封印しない。保存側 (IndexedDBStore) が DEK で暗号化する。
 *   以前は秘密ごとにパスワードの KDF (Argon2) を走らせていた。
 */
export interface SealedStore {
  getSecret(slot: string): Promise<{ secret: Uint8Array; meta?: any } | undefined>;
  saveSecret(slot: string, secret: Uint8Array, meta?: any): Promise<void>;
  deleteSecret(slot: string): Promise<void>;
}

const TRIP_SLOT = 'trip';
const DERIVED_CACHE_MAX = 8;
/** 文脈を渡されない呼び出し (テスト・旧い呼び出し元) の既定。本番の PacketBuilder は必ず渡す */
const DEFAULT_CTX: SignContext = { boardId: '', threadId: '', day: 0 };

/** u8 の長さ前置き */
function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + b.length);
  out[0] = b.length;
  out.set(b, 1);
  return out;
}
function u32be(n: number): Uint8Array {
  const o = new Uint8Array(4);
  new DataView(o.buffer).setUint32(0, n >>> 0, false);
  return o;
}

export class Identity implements IIdentity {
  /**
   * セッション鍵の元になる 32 バイトの乱数。メモリにだけ持ち、保存しない。
   *
   * ★ 1 つのセッション鍵で全スレ・全日の投稿に署名すると、鍵が同じことで投稿同士が紐付く
   *   (デスクトップ版は何日も起動しっぱなしになる)。そこで (板, スレ, 日) ごとに別の鍵を
   *   この master から導出する。同じスレ・同じ日なら同じ鍵 (= 同じ ID) なので 2ch 的な「その日の ID」は保てる。
   *   master は保存しない。ロック (dispose) で 0 埋めする。
   */
  private master: Uint8Array;
  /** 導出済みの鍵を少しだけ覚える (署名のたびに導出し直さない)。キーは文脈 */
  private derived = new Map<string, any>();
  /** トリップ（永続的、オプション） */
  private tripKeyPair: any | null = null;

  constructor() {
    this.master = sodium.randombytes_buf(32);
  }

  /** 文脈 (板・スレ・UTC 日) のセッション鍵。master からの決定的な導出 */
  private sessionKeyFor(ctx: SignContext): any {
    const id = `${ctx.day}\u0000${ctx.boardId}\u0000${ctx.threadId}`;
    const hit = this.derived.get(id);
    if (hit) return hit;
    const enc = new TextEncoder();
    const label = enc.encode('oz/v5/session');
    const parts = [label, lp(enc.encode(ctx.boardId)), lp(enc.encode(ctx.threadId)), u32be(ctx.day)];
    const msg = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let off = 0;
    for (const p of parts) { msg.set(p, off); off += p.length; }
    const seed = sodium.crypto_generichash(32, msg, this.master);
    const kp = sodium.crypto_sign_seed_keypair(seed);
    seed.fill(0);
    // 覚えるのは最近の数件だけ (古いものは秘密鍵を 0 埋めして捨てる)
    if (this.derived.size >= DERIVED_CACHE_MAX) {
      const oldest = this.derived.keys().next().value as string;
      this.derived.get(oldest)?.privateKey?.fill(0);
      this.derived.delete(oldest);
    }
    this.derived.set(id, kp);
    return kp;
  }

  /** ロック・破棄のとき。master と導出済みの秘密鍵を 0 埋めする (以後 sign は使えない) */
  public dispose(): void {
    this.master.fill(0);
    for (const kp of this.derived.values()) kp?.privateKey?.fill(0);
    this.derived.clear();
    this.disposed = true;
  }
  private disposed = false;

  /**
   * トリップの初期化（IndexedDB から封印を読み出して解く）
   * なければ／解けなければ名無しモード（tripKeyPair = null）のまま継続。
   *
   * ★ パスフレーズは要らない。store のロック解除 (DEK) が済んでいれば開ける。
   * @returns 復元できたか
   */
  public async initTrip(store: SealedStore): Promise<boolean> {
    const record = await store.getSecret(TRIP_SLOT);
    if (!record) return false;

    const secret = record.secret;
    if (secret.length !== sodium.crypto_sign_SECRETKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES) {
      log.warn(`Stored trip identity has an unexpected size; ignoring it.`);
      return false;
    }

    this.tripKeyPair = {
      publicKey: secret.slice(sodium.crypto_sign_SECRETKEYBYTES),
      privateKey: secret.slice(0, sodium.crypto_sign_SECRETKEYBYTES),
      keyType: 'ed25519',
    };
    log.debug(`Recovered persistent trip identity.`);
    return true;
  }

  /**
   * トリップを新規生成して封印・永続化する。
   *
   * 旧実装は秘密鍵を平文で IndexedDB に書いていた。押収されれば
   * 過去の全投稿がこのトリップで紐付く。
   */
  public async generateTrip(store: SealedStore): Promise<string> {
    this.tripKeyPair = sodium.crypto_sign_keypair();

    const secret = new Uint8Array(
      sodium.crypto_sign_SECRETKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES,
    );
    secret.set(this.tripKeyPair.privateKey, 0);
    secret.set(this.tripKeyPair.publicKey, sodium.crypto_sign_SECRETKEYBYTES);

    // ★ 保護なしでは永続化できない (H4) は、store 側が「ロック解除 = パスワード必須」で担保する
    await store.saveSecret(TRIP_SLOT, secret);
    log.debug(`[Identity] Generated and stored new trip identity.`);
    return this.tripDisplay;
  }

  /**
   * トリップを破棄する
   */
  public async deleteTrip(store: SealedStore): Promise<void> {
    this.tripKeyPair = null;
    await store.deleteSecret(TRIP_SLOT);
    log.debug(`Deleted trip identity.`);
  }

  /** トリップが設定されているか */
  public get hasTrip(): boolean {
    return this.tripKeyPair !== null;
  }

  /**
   * セッションIDの表示文字列（8文字）
   * 公開鍵のSHA256ハッシュの先頭4バイトをBase64化
   */
  get sessionDisplay(): string {
    const hash = sodium.crypto_hash(this.sessionKeyFor(DEFAULT_CTX).publicKey);
    return this.toBase64(hash.slice(0, 4));
  }

  /**
   * トリップの表示文字列（12文字）
   * 公開鍵のSHA256ハッシュの先頭5バイトをBase64化
   */
  get tripDisplay(): string {
    if (!this.tripKeyPair) return '';
    const hash = sodium.crypto_hash(this.tripKeyPair.publicKey);
    return '◆' + this.toBase64(hash.slice(0, 5));
  }

  /**
   * 投稿データにデジタル署名を行う
   */
  sign(postData: Uint8Array, ctx: SignContext = DEFAULT_CTX): SignatureResult {
    if (this.disposed) throw new Error('Identity.sign: disposed');
    const kp = this.sessionKeyFor(ctx);
    return {
      sessionPubkey: kp.publicKey,
      sessionSignature: sodium.crypto_sign_detached(postData, kp.privateKey),
      tripPubkey: this.tripKeyPair?.publicKey ?? null,
      tripSignature: this.tripKeyPair
        ? sodium.crypto_sign_detached(postData, this.tripKeyPair.privateKey)
        : null,
    };
  }

  /**
   * 署名検証
   */
  static verify(
    postData: Uint8Array,
    pubkey: Uint8Array,
    signature: Uint8Array,
  ): boolean {
    return sodium.crypto_sign_verify_detached(
      signature, postData, pubkey,
    );
  }

  private toBase64(buf: Uint8Array): string {
    return btoa(String.fromCharCode(...buf));
  }
}
