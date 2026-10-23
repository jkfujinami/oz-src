import type { IDBPDatabase } from 'idb';
import sodium from '../crypto/sodium';
import { Encoding } from '../common/Encoding';
import { ByteReader, ByteWriter } from '../common/ByteIO';
import { createLogger } from '../common/Logger';
import { ChunkDB } from './ChunkDB';

const log = createLogger('storage.holder');

/** 保管担当の保存先 (IndexedDB のオブジェクトストア名)。IndexedDBStore の upgrade が作る */
export const HOLD_META_STORE = 'hold_meta';
export const HOLD_DATA_STORE = 'hold_data';
/** holder 専用の鍵 (32 バイト) を置く kv の名前 */
const HOLDER_KEY_NAME = 'holder.key';

const NONCE_BYTES = 24;

/** 暗号化 DB の kv (IndexedDBStore.getSetting / setSetting) */
export interface HolderSettings {
  getSetting<T = unknown>(name: string): Promise<T | undefined>;
  setSetting(name: string, value: unknown): Promise<void>;
}

/** バケット 1 つの控え (封印して hold_meta に置く) */
export interface BucketMeta {
  birthDay: number;
  tag: number;
  /** 保存している量 (封印後のバイト数の合計) */
  bytes: number;
  count: number;
}

/**
 * HolderVault — 保管担当のデータだけを封印する鍵。
 *
 * ★ DEK ではなく**専用の鍵**を使う理由: パスワード変更は DEK を作り直して全レコードを再暗号化する
 *   (IndexedDBStore.changePassphrase)。保管データは最大 数 GiB (枠 × 256MiB) になりうるので、パスワードを
 *   変えるたびに全部を再暗号化したくない。専用の鍵 (HK) を DEK 封印の kv に置けば、パスワード変更は
 *   kv の再暗号化 (32 バイト) だけで済み、保管データはそのまま読める。DEK の封印を消せば HK も読めなくなる
 *   (crypto-shredding は変わらない)。
 */
class HolderVault {
  private enc: Uint8Array;
  private idx: Uint8Array;
  private wiped = false;

  constructor(hk: Uint8Array) {
    // ★ crypto_kdf の context はちょうど 8 バイト (違うと例外)
    this.enc = sodium.crypto_kdf_derive_from_key(32, 1, 'ozhldenc', hk);
    this.idx = sodium.crypto_kdf_derive_from_key(32, 2, 'ozhldidx', hk);
  }

  private assertOpen(): void {
    if (this.wiped) throw new Error('HolderDB is locked');
  }

  seal(plain: Uint8Array, ad: string): Uint8Array {
    this.assertOpen();
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, new TextEncoder().encode(ad), null, nonce, this.enc);
    const out = new Uint8Array(NONCE_BYTES + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_BYTES);
    return out;
  }

  open(blob: unknown, ad: string): Uint8Array | null {
    this.assertOpen();
    // IndexedDB から戻る値は別の realm の Uint8Array のことがある (DataVault.open と同じ扱い)
    if (Object.prototype.toString.call(blob) !== '[object Uint8Array]') return null;
    const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob as ArrayLike<number>);
    if (bytes.length <= NONCE_BYTES) return null;
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, bytes.subarray(NONCE_BYTES), new TextEncoder().encode(ad), bytes.subarray(0, NONCE_BYTES), this.enc,
      );
    } catch {
      return null;
    }
  }

  index(label: string, value: string): string {
    this.assertOpen();
    return Encoding.toHex(sodium.crypto_generichash(16, new TextEncoder().encode(`${label}\u0000${value}`), this.idx));
  }

  wipe(): void {
    this.wiped = true;
    sodium.memzero(this.enc);
    sodium.memzero(this.idx);
  }
}

function encodeMeta(m: BucketMeta): Uint8Array {
  return new ByteWriter().u8(1).u16(Math.floor(m.birthDay / 0x10000)).u16(m.birthDay % 0x10000).u16(m.tag).u48(m.bytes).u48(m.count).finish();
}

function decodeMeta(b: Uint8Array): BucketMeta | null {
  try {
    const r = new ByteReader(b);
    if (r.u8() !== 1) return null;
    const birthDay = r.u16() * 0x10000 + r.u16();
    const tag = r.u16();
    const bytes = r.u48();
    const count = r.u48();
    r.end();
    return { birthDay, tag, bytes, count };
  } catch {
    return null;
  }
}

/**
 * HolderDB — 保管担当の IndexedDB 層 (hold_meta / hold_data)。
 *
 *   hold_meta  { k: bk, blob }         bk = 鍵付きハッシュ(birthDay, tag)。blob = 封印した BucketMeta
 *   hold_data  { k, b: bk, blob }      パケット 1 件 = 1 行。k = 鍵付きハッシュ(bk, packetId)。blob = 封印した encodePacket のバイト列
 *
 * ★ 平文で残るのは「行の数と大きさ」と、鍵付きハッシュの索引だけ。どの (日, tag) を持っているかも、
 *   パケット ID も、時刻も、パスワード無しでは読めない。
 * ★ 1 件ごとの行にしたのは、バケット全体を 1 レコードにすると、投稿が 1 件届くたびにバケット全体
 *   (1 スレで最大 数百 KB〜MB) を復号・再暗号化して書き直すことになるため。行の主キーが (bk, packetId) の
 *   鍵付きハッシュなので、同じパケットの二重保存は主キーの衝突で自然に弾かれる。
 */
export class HolderDB {
  private constructor(private readonly db: IDBPDatabase, private vault: HolderVault) {}

  public static async open(db: IDBPDatabase, settings: HolderSettings): Promise<HolderDB> {
    let hk = await settings.getSetting<Uint8Array>(HOLDER_KEY_NAME);
    if (!(hk instanceof Uint8Array) || hk.length !== 32) {
      hk = sodium.randombytes_buf(32);
      await settings.setSetting(HOLDER_KEY_NAME, hk);
    }
    const vault = new HolderVault(hk);
    sodium.memzero(hk);
    return new HolderDB(db, vault);
  }

  public bucketKey(birthDay: number, tag: number): string {
    return this.vault.index('bucket', `${birthDay}:${tag}`);
  }

  private packetKey(bk: string, packetIdHex: string): string {
    return this.vault.index('packet', `${bk}:${packetIdHex}`);
  }

  /** 全バケットの控えを読む (起動時に 1 回)。復号できないものは捨てる (別の鍵で書かれた残骸) */
  public async loadMeta(): Promise<Map<string, BucketMeta>> {
    const out = new Map<string, BucketMeta>();
    const orphan: string[] = [];
    for (const row of await this.db.getAll(HOLD_META_STORE)) {
      const plain = this.vault.open(row.blob, `${HOLD_META_STORE}:${row.k}`);
      const meta = plain ? decodeMeta(plain) : null;
      if (meta) out.set(row.k, meta);
      else orphan.push(row.k);
    }
    for (const k of orphan) await this.deleteBucket(k);
    if (orphan.length > 0) log.warn(`dropped ${orphan.length} unreadable bucket(s)`);
    return out;
  }

  /**
   * パケットを 1 件足し、控えを更新する (1 トランザクション)。既にあれば何もしない。
   * @param update 現在の控え (無ければ null) から新しい控えを作る。保存したバイト数が渡される
   * @returns 新しく保存したか、保存した封印後のバイト数
   */
  public async putPacket(
    bk: string, packetIdHex: string, bytes: Uint8Array, current: BucketMeta | null, fresh: { birthDay: number; tag: number },
  ): Promise<{ stored: boolean; sealedBytes: number; meta: BucketMeta }> {
    const k = this.packetKey(bk, packetIdHex);
    const tx = this.db.transaction([HOLD_META_STORE, HOLD_DATA_STORE], 'readwrite');
    const data = tx.objectStore(HOLD_DATA_STORE);
    if ((await data.getKey(k)) !== undefined) {
      await tx.done;
      return { stored: false, sealedBytes: 0, meta: current ?? { ...fresh, bytes: 0, count: 0 } };
    }
    const blob = this.vault.seal(bytes, `${HOLD_DATA_STORE}:${k}`);
    await data.add({ k, b: bk, blob });
    const meta: BucketMeta = current
      ? { ...current, bytes: current.bytes + blob.length, count: current.count + 1 }
      : { ...fresh, bytes: blob.length, count: 1 };
    await tx.objectStore(HOLD_META_STORE).put({ k: bk, blob: this.vault.seal(encodeMeta(meta), `${HOLD_META_STORE}:${bk}`) });
    await tx.done;
    return { stored: true, sealedBytes: blob.length, meta };
  }

  /** バケットのパケット (encodePacket のバイト列)。順序は不定 */
  public async getPackets(bk: string): Promise<Uint8Array[]> {
    const rows = await this.db.getAllFromIndex(HOLD_DATA_STORE, 'b', bk);
    const out: Uint8Array[] = [];
    for (const row of rows) {
      const plain = this.vault.open(row.blob, `${HOLD_DATA_STORE}:${row.k}`);
      if (plain) out.push(plain);
    }
    return out;
  }

  public async deleteBucket(bk: string): Promise<void> {
    const tx = this.db.transaction([HOLD_META_STORE, HOLD_DATA_STORE], 'readwrite');
    const data = tx.objectStore(HOLD_DATA_STORE);
    for (const key of await data.index('b').getAllKeys(bk)) await data.delete(key);
    await tx.objectStore(HOLD_META_STORE).delete(bk);
    await tx.done;
  }

  /**
   * 大容量ファイルのチャンクの保存先 (別のストア)。封印の鍵は同じ HK から派生した鍵を使い回し、用途はキーの接頭辞と AD で分ける。
   * ★ lock() 後は封印・開封が例外になる (同じ vault を共有しているため、鍵の消去が両方に効く)。
   */
  public openChunkDb(): ChunkDB {
    return new ChunkDB(this.db, this.vault);
  }

  /** 鍵をメモリから消す。以後は使えない */
  public lock(): void {
    this.vault.wipe();
  }
}
