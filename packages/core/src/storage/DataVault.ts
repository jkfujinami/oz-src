import sodium from '../crypto/sodium';
import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { Encoding } from '../common/Encoding';
import { SecretVault, VAULT_PARAMS, type SealedSecret, type VaultParams } from './SecretVault';

/** パスワード違い (または封印の改竄)。どちらであるかは区別しない */
export class WrongPassphraseError extends Error {
  constructor() {
    super('Wrong passphrase (or the vault was tampered with)');
    this.name = 'WrongPassphraseError';
  }
}

const DEK_BYTES = 32;
const NONCE_BYTES = 24; // XChaCha20-Poly1305 IETF

/**
 * DataVault — 端末に保存するデータ全体の暗号化。
 *
 * ★ なぜ要るのか
 *
 *   旧実装は鍵だけを封印し、それ以外 (投稿・スレッド統計・保管中の Slot) は
 *   IndexedDB に平文のまま置いていた。投稿本文はスレッド鍵で暗号化されていても、
 *   「どの板・どのスレッドを、いつ読んで/書いていたか」がインデックスと統計に
 *   平文で残り、板の鍵は URL に載っていた。端末を押収されれば、そのまま
 *   閲覧・投稿の履歴になる。
 *
 * ★ 鍵の構成
 *
 *   KEK = Argon2id(パスワード)          … SecretVault (起動時に 1 回だけ。これ以外に Argon2 は走らせない)
 *   DEK = ランダム 32 バイト            … KEK で封印して保存する
 *   encKey / idxKey = KDF(DEK)          … 用途ごとに分ける
 *
 *   トリップ鍵・ノード鍵も DEK 配下の行として暗号化する (独自のパスワード KDF を持たない)。
 *   ★ 別々に封印すると、アンロックごとに Argon2 が数回走り (携帯で遅く、メモリも食う)、
 *     封印ごとにオフライン総当たりの的が増える。
 *
 *   パスワードの変更は DEK を包み直すだけで済む (データの再暗号化は要らない)。
 *   DEK の封印を消すだけで全データが読めなくなる (crypto-shredding)。
 *
 * ★ レコードの暗号化
 *
 *   XChaCha20-Poly1305 (nonce はレコードごとの乱数)。追加認証データに
 *   「どのストアのどのキーのレコードか」を入れ、別の場所へのすり替えを検出する。
 *
 * ★ インデックス
 *
 *   IndexedDB の検索キーは平文で保存される。板 ID やスレッド ID をそのまま
 *   キーにすると暗号化の意味が無いので、idxKey による鍵付きハッシュに置き換える。
 */
export class DataVault {
  private constructor(
    private encKey: Uint8Array,
    private idxKey: Uint8Array,
  ) {}

  /** 新しい DEK を作り、パスワードで封印したものと一緒に返す */
  static create(passphrase: string, params: VaultParams = VAULT_PARAMS): { vault: DataVault; sealed: SealedSecret } {
    DataVault.requirePassphrase(passphrase);
    const dek = sodium.randombytes_buf(DEK_BYTES);
    try {
      return { vault: DataVault.fromDek(dek), sealed: SecretVault.seal(dek, passphrase, params) };
    } finally {
      sodium.memzero(dek);
    }
  }

  /** 封印された DEK をパスワードで開く */
  static open(sealed: SealedSecret, passphrase: string): DataVault {
    const { vault, dek } = DataVault.openWithDek(sealed, passphrase);
    sodium.memzero(dek);
    return vault;
  }

  /**
   * DEK も一緒に返す版。
   *
   * ★ アンロックで Argon2 を 1 回しか走らせないための口。DEK の封印を強い設定に
   *   包み直す場面で、開き直さずに済む。呼び出し側は dek を必ず memzero すること。
   */
  static openWithDek(sealed: SealedSecret, passphrase: string): { vault: DataVault; dek: Uint8Array } {
    DataVault.requirePassphrase(passphrase);
    const dek = SecretVault.open(sealed, passphrase);
    if (!dek || dek.length !== DEK_BYTES) throw new WrongPassphraseError();
    try {
      return { vault: DataVault.fromDek(dek), dek };
    } catch (e) {
      sodium.memzero(dek);
      throw e;
    }
  }

  /** DEK を (新しい) パスワードで封印する。低メモリ端末では封印側が縮退する */
  static wrapDek(dek: Uint8Array, passphrase: string, params: VaultParams = VAULT_PARAMS): SealedSecret {
    DataVault.requirePassphrase(passphrase);
    return SecretVault.seal(dek, passphrase, params);
  }

  /** DEK を別のパスワードで包み直す (パスワード変更) */
  static rewrap(
    sealed: SealedSecret,
    oldPassphrase: string,
    newPassphrase: string,
    params: VaultParams = VAULT_PARAMS,
  ): SealedSecret {
    DataVault.requirePassphrase(newPassphrase);
    const dek = SecretVault.open(sealed, oldPassphrase);
    if (!dek || dek.length !== DEK_BYTES) throw new WrongPassphraseError();
    try {
      return SecretVault.seal(dek, newPassphrase, params);
    } finally {
      sodium.memzero(dek);
    }
  }

  private static requirePassphrase(passphrase: string): void {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new RangeError('DataVault: a non-empty passphrase is required');
    }
  }

  private static fromDek(dek: Uint8Array): DataVault {
    // ★ crypto_kdf の context はちょうど 8 バイト (違うと例外)
    return new DataVault(
      sodium.crypto_kdf_derive_from_key(32, 1, 'ozvltenc', dek),
      sodium.crypto_kdf_derive_from_key(32, 2, 'ozvltidx', dek),
    );
  }

  /**
   * 値を暗号化する。
   * @param ad このレコードがどこに置かれるか (ストア名とキー)。復号時に同じ値が要る
   */
  seal(value: unknown, ad: string): Uint8Array {
    this.assertOpen();
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      msgpackEncode(value),
      new TextEncoder().encode(ad),
      null,
      nonce,
      this.encKey,
    );
    const out = new Uint8Array(NONCE_BYTES + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_BYTES);
    return out;
  }

  /** 復号する。鍵違い・改竄・すり替えはいずれも null */
  open<T = any>(blob: unknown, ad: string): T | null {
    this.assertOpen();
    // IndexedDB から戻る値は別の realm の Uint8Array のことがある (テスト環境の jsdom など)。
    // instanceof では弾かれ、libsodium も受け付けないので、型タグで判定してこの realm に写す。
    if (Object.prototype.toString.call(blob) !== '[object Uint8Array]') return null;
    const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob as ArrayLike<number>);
    if (bytes.length <= NONCE_BYTES) return null;
    try {
      const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        bytes.subarray(NONCE_BYTES),
        new TextEncoder().encode(ad),
        bytes.subarray(0, NONCE_BYTES),
        this.encKey,
      );
      return msgpackDecode(pt) as T;
    } catch {
      return null;
    }
  }

  /** 検索キー。同じ (label, value) からは常に同じ値になるが、鍵を知らなければ逆算できない */
  index(label: string, value: string): string {
    this.assertOpen();
    const input = new TextEncoder().encode(`${label}\u0000${value}`);
    return Encoding.toHex(sodium.crypto_generichash(16, input, this.idxKey));
  }

  /** メモリ上の鍵をゼロで上書きする。以後は使えない */
  wipe(): void {
    sodium.memzero(this.encKey);
    sodium.memzero(this.idxKey);
    this.encKey = new Uint8Array(0);
    this.idxKey = new Uint8Array(0);
  }

  get isOpen(): boolean {
    return this.encKey.length === 32;
  }

  private assertOpen(): void {
    if (!this.isOpen) throw new Error('DataVault is locked');
  }
}
