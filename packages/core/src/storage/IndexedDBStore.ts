import { openDB, deleteDB, type IDBPDatabase } from 'idb';
import sodium from '../crypto/sodium';
import { BOARD_META_THREAD_ID } from '../logic/types';
import { createLogger } from '../common/Logger';
import { SecretVault, VAULT_PARAMS, VAULT_PARAMS_LOW_MEMORY, isWeakerThan, type SealedSecret, type VaultParams } from './SecretVault';
import { DataVault, WrongPassphraseError } from './DataVault';
import { HolderDB, HOLD_DATA_STORE, HOLD_META_STORE } from './HolderDB';
import { HOLD_CHUNK_META_STORE, HOLD_CHUNK_STORE } from './ChunkDB';

const log = createLogger('storage.idb');

export interface PostEntry {
  id?: number;
  boardId: string;
  threadId: string;
  payload: Uint8Array;
  timestamp: number;
  /**
   * 板のメタ (スレタイ) の持ち主のスレッド ID。
   * ★ 封印の中に置く (平文の索引には出さない)。メタは全スレ共通の threadId (BOARD_META_THREAD_ID) で
   *   保存するので、どのスレのものかは本来パケットを板の鍵で復号しないと分からない。期限切れの削除で
   *   毎回全件を復号しなくて済むように、保存時に控えておく。
   */
  metaFor?: string;
}

export interface BoardRecord {
  boardId: string;
  key: Uint8Array;
  /** 追加した日 (日単位に丸めてある) */
  addedAt: number;
  /** 追加順。時刻を細かく持たずに順序だけを保つための連番 */
  seq?: number;
}

const DB_VERSION = 10;

/** 封印された DEK の置き場所 (identity ストアの予約キー) */
const DEK_SLOT = '__dek__';

/** 1 日 (ms)。保管時刻はこの単位に丸めて平文に置く (期限切れ削除のためだけ) */
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * 保存する時刻は日単位に丸める。
 *
 * ★ 封印の中であっても、書き込み時刻をミリ秒で残すと、鍵を破られたとき (あるいは
 *   パスワードを強要されたとき) に「いつ何を読み書きしていたか」の時系列がそのまま出る。
 *   期限切れの判定は日単位で足りるので、そこまでの精度は持たない。
 */
function dayFloor(t: number = Date.now()): number {
  return Math.floor(t / DAY_MS) * DAY_MS;
}

/** kv 行の中身。復号した値だけでは検索キーを作り直せない (DEK の入れ替えで要る) ので、名前も封印の中に置く */
interface KvRecord { __kv: 1; n: string; v: unknown }

/**
 * DEK の封印 (identity ストアの __dek__ 行) の保存形。
 * ★ protected 欄は置かない (DEK は必ずパスワードで守られているので、平文に書く意味が無い)。
 *   開くのに要るのは salt / nonce / ciphertext / KDF パラメータだけで、これは平文で置くしかない。
 */
type DekWrap = Omit<SealedSecret, 'protected'>;
function toDekWrap(sealed: SealedSecret): DekWrap {
  const { v, salt, nonce, ciphertext, opsLimit, memLimit } = sealed;
  return { v, salt, nonce, ciphertext, opsLimit, memLimit };
}
function fromDekWrap(wrap: DekWrap): SealedSecret {
  return { ...wrap, protected: true };
}

/**
 * IndexedDBStore — 端末上の全データの置き場所。
 *
 * ★ v7 で全面暗号化した (パスワード必須)。
 *
 *   {@link unlock} でパスワードから DEK を開くまで、データの読み書きは一切できない
 *   (fail-closed)。各レコードは {@link DataVault} で暗号化され、検索キーも
 *   鍵付きハッシュに置き換えてある。平文で残るのは
 *     - レコードの件数と大きさ
 *   だけである。(identity ストアの行は、DEK の封印を除いて全体を封印してある。
 *   書き込み時刻・保護の有無といった欄も平文では持たない。)
 *
 *   v6 以前の平文データは、初回のロック解除時に暗号化して移し、平文側は消す。
 *   (IndexedDB の下層ストレージが削除済みページを即座に上書きする保証は無いので、
 *    移行前のデータの完全な消去までは保証できない。)
 */
export class IndexedDBStore {
  private db!: IDBPDatabase;
  private vault: DataVault | null = null;

  constructor(private readonly dbName: string = 'OzLiteDB') {}

  public async init() {
    if (this.db) return;
    this.db = await openDB(this.dbName, DB_VERSION, {
      upgrade(db: any, oldVersion: number) {
        // 封印済みの鍵 (トリップ・ノード・DEK)。v6 以前から引き継ぐ
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'key' });
        }
        // ── v7: 暗号化ストア ──
        if (!db.objectStoreNames.contains('eposts')) {
          const s = db.createObjectStore('eposts', { keyPath: 'id', autoIncrement: true });
          s.createIndex('bt', 'bt');
        }
        if (!db.objectStoreNames.contains('ethreads')) {
          const s = db.createObjectStore('ethreads', { keyPath: 'k' });
          s.createIndex('b', 'b');
        }
        if (!db.objectStoreNames.contains('boards')) {
          db.createObjectStore('boards', { keyPath: 'k' });
        }
        if (!db.objectStoreNames.contains('kv')) {
          db.createObjectStore('kv', { keyPath: 'k' });
        }
        // ── v8: 他人の Slot の保管庫 (Schrödinger Mailbox) を撤去した ──
        // ★ 中身は旧方式の Slot (投稿ごとの乱数スロット) で、新方式では読み手がいない。
        //   過去ログは Guard のバッファ (追いつき) と保管担当が担う (docs/design/history-v2.md)。
        //   暗号化済みの 'emailbox' も、v6 以前の平文の 'mailbox' も、移行せずに捨てる。
        if (oldVersion < 8) {
          if (db.objectStoreNames.contains('emailbox')) db.deleteObjectStore('emailbox');
          if (db.objectStoreNames.contains('mailbox')) db.deleteObjectStore('mailbox');
        }
        // ── v9: 保管担当の保存先 (network/storage の HolderStore。実装は HolderDB) ──
        // ★ 中身は HolderDB が専用の鍵で封印する。changePassphrase の再暗号化の対象には入れない
        //   (専用の鍵は DEK 封印の kv にあり、パスワード変更では kv だけが再暗号化される)。
        if (!db.objectStoreNames.contains(HOLD_META_STORE)) {
          db.createObjectStore(HOLD_META_STORE, { keyPath: 'k' });
        }
        if (!db.objectStoreNames.contains(HOLD_DATA_STORE)) {
          const s = db.createObjectStore(HOLD_DATA_STORE, { keyPath: 'k' });
          s.createIndex('b', 'b');
        }
        // ── v10: 大容量ファイルのチャンクの保存先 (storage/ChunkDB。封印は HolderDB の鍵) ──
        if (!db.objectStoreNames.contains(HOLD_CHUNK_STORE)) {
          db.createObjectStore(HOLD_CHUNK_STORE, { keyPath: 'k' });
        }
        if (!db.objectStoreNames.contains(HOLD_CHUNK_META_STORE)) {
          db.createObjectStore(HOLD_CHUNK_META_STORE, { keyPath: 'k' });
        }
        // v6 以前の平文ストア ('posts' / 'threads') はここでは消さない。
        // DEK が無いと暗号化して移せないので、unlock() で移行してから空にする。
      },
    });
  }

  // ── ロック / ロック解除 ──

  /** パスワードが設定済み (= DEK の封印がある) か。ロック解除前でも呼べる */
  public async hasVault(): Promise<boolean> {
    await this.init();
    return (await this.db.get('identity', DEK_SLOT)) !== undefined;
  }

  public get isUnlocked(): boolean {
    return this.vault !== null && this.vault.isOpen;
  }

  /**
   * パスワードでロックを解除する。初回はこのパスワードで新しい DEK を作る。
   *
   * @throws WrongPassphraseError パスワードが違う
   * @throws RangeError パスワードが空
   */
  public async unlock(passphrase: string, params: VaultParams = VAULT_PARAMS): Promise<void> {
    await this.init();
    const record = await this.db.get('identity', DEK_SLOT);
    if (this.isUnlocked) {
      // ★ 解除済みでもパスワードは照合する。旧実装はここで何もせず成功を返したので、
      //   同じインスタンスでの再認証 (画面のロック解除など) がどんなパスワードでも通った。
      if (!record?.sealed) throw new WrongPassphraseError();
      DataVault.open(fromDekWrap(record.sealed), passphrase).wipe();
      return;
    }

    // ★ ここで走る Argon2 は DEK の封印を開く 1 回だけ。トリップ・ノード鍵は DEK 配下なので
    //   追加の KDF は要らない。旧形式の行の移行 (行ごとに 1 回) は、移行が要るときだけ走る。
    let dek: Uint8Array | undefined;
    try {
      if (record?.sealed) {
        const opened = DataVault.openWithDek(fromDekWrap(record.sealed), passphrase);
        this.vault = opened.vault;
        dek = opened.dek;
      } else {
        const { vault, sealed } = DataVault.create(passphrase, params);
        await this.db.put('identity', { key: DEK_SLOT, sealed: toDekWrap(sealed) });
        this.vault = vault;
      }

      await this.migrateLegacy();
      await this.upgradeIdentityRows(passphrase, params, dek);
    } finally {
      if (dek) sodium.memzero(dek);
    }
  }

  /**
   * パスワードの変更。
   *
   * ★ DEK を包み直すだけにはしない。旧パスワードを知っている (または総当たりで破った)
   *   者が、変更前の封印のコピー (バックアップ・削除済みページの残骸) から旧 DEK を取り出せると、
   *   変更後に書かれたデータも読めてしまう。そこで新しい DEK を作り、全レコードを
   *   新しい鍵で暗号化し直す (保管量は小さいので 1 回で済ませる)。検索キーも DEK から
   *   派生しているので、すべて作り直す。
   *
   *   旧い封印は同じトランザクションで上書きされる。SSD / ファイルシステム上の
   *   旧ページが物理的に消える保証は無いが、旧 DEK で暗号化されたデータはもう
   *   DB のどこにも無いので、残骸の封印を開けても現在のデータは読めない。
   *   トランザクションは全体で 1 つ (途中で失敗すれば何も変わらない)。
   *
   * @throws WrongPassphraseError 旧パスワードが違う
   */
  public async changePassphrase(oldPassphrase: string, newPassphrase: string, params: VaultParams = VAULT_PARAMS): Promise<void> {
    await this.init();
    const record = await this.db.get('identity', DEK_SLOT);
    if (!record?.sealed) throw new Error('IndexedDBStore: no vault to rewrap');
    const oldVault = DataVault.open(fromDekWrap(record.sealed), oldPassphrase);
    let newVault: DataVault | undefined;
    try {
      const created = DataVault.create(newPassphrase, params);
      newVault = created.vault;
      const newWrap = created.sealed;
      // 重い KDF は、トランザクションを開く前に済ませる
      const identityRows = await this.db.getAll('identity');
      const identityOut: Array<{ key: string; e: Uint8Array }> = [];
      const identityDrop: string[] = [];
      for (const row of identityRows) {
        if (row.key === DEK_SLOT) continue;
        const loaded = this.readIdentityRow(oldVault, row);
        // 新形式は DEK 配下の平文の秘密なので、そのまま新しい DEK で包み直す。
        // 旧形式 (独自の KDF で封印) は、旧パスワードで 1 回開いて新形式に移す。
        const secret = loaded?.secret ?? (loaded?.sealed
          ? SecretVault.open(loaded.sealed, loaded.sealed.protected === false ? '' : oldPassphrase)
          : null);
        if (!loaded || !secret) {
          log.warn(`identity slot "${row.key}" could not be re-encrypted; dropping it`);
          identityDrop.push(row.key);
          continue;
        }
        identityOut.push({ key: row.key, e: newVault.seal({ v: 2, secret, meta: loaded.meta }, `identity:${row.key}`) });
        if (!loaded.secret) sodium.memzero(secret);
      }

      const tx = this.db.transaction(['identity', 'eposts', 'ethreads', 'boards', 'kv'], 'readwrite');
      let dropped = 0;

      // 投稿。id (挿入順) は保つ
      const posts = tx.objectStore('eposts');
      const postRows = await posts.getAll();
      await posts.clear();
      for (const row of postRows) {
        const rec = oldVault.open<PostEntry>(row.blob, `eposts:${row.bt}`);
        if (!rec) { dropped++; continue; }
        const bt = newVault.index('posts', `${rec.boardId}\u0000${rec.threadId}`);
        await posts.put({ id: row.id, bt, blob: newVault.seal(rec, `eposts:${bt}`) });
      }

      const threads = tx.objectStore('ethreads');
      const threadRows = await threads.getAll();
      await threads.clear();
      for (const row of threadRows) {
        const rec = oldVault.open<any>(row.blob, `ethreads:${row.k}`);
        if (!rec || typeof rec.threadId !== 'string' || typeof rec.boardId !== 'string') { dropped++; continue; }
        const k = newVault.index('thread', rec.threadId);
        await threads.put({ k, b: newVault.index('board', rec.boardId), blob: newVault.seal(rec, `ethreads:${k}`) });
      }

      const boards = tx.objectStore('boards');
      const boardRows = await boards.getAll();
      await boards.clear();
      for (const row of boardRows) {
        const rec = oldVault.open<BoardRecord>(row.blob, `boards:${row.k}`);
        if (!rec) { dropped++; continue; }
        const k = newVault.index('boardkey', rec.boardId);
        await boards.put({ k, blob: newVault.seal(rec, `boards:${k}`) });
      }

      const kv = tx.objectStore('kv');
      const kvRows = await kv.getAll();
      await kv.clear();
      for (const row of kvRows) {
        const rec = oldVault.open<KvRecord>(row.blob, `kv:${row.k}`);
        // 名前を持たない旧形式の行は、検索キーを作り直せない
        if (!rec || rec.__kv !== 1 || typeof rec.n !== 'string') { dropped++; continue; }
        const k = newVault.index('kv', rec.n);
        await kv.put({ k, blob: newVault.seal(rec, `kv:${k}`) });
      }

      const identity = tx.objectStore('identity');
      for (const key of identityDrop) await identity.delete(key);
      for (const row of identityOut) await identity.put(row);
      await identity.put({ key: DEK_SLOT, sealed: toDekWrap(newWrap) });

      await tx.done;
      if (dropped > 0) log.warn(`changePassphrase: ${dropped} record(s) could not be decrypted and were dropped`);
    } catch (e) {
      newVault?.wipe();
      throw e;
    } finally {
      oldVault.wipe();
    }

    // 成功: 解除中だったなら、新しい鍵に差し替える。ロック中ならロックのまま
    if (this.vault) {
      this.vault.wipe();
      this.vault = newVault!;
    } else {
      newVault!.wipe();
    }
  }

  /** メモリ上の鍵を消す。以後は unlock() し直すまで読み書きできない */
  public lock(): void {
    this.vault?.wipe();
    this.vault = null;
  }

  /**
   * 即時消去 (パニックワイプ)。
   *
   * まず DEK の封印を消す。これだけで残りのデータは誰にも (自分にも) 読めなくなる
   * (crypto-shredding)。その後でデータベースごと削除する。
   * パスワードを忘れた場合の「作り直し」もこれを使う (ロック解除は要らない)。
   */
  public async wipeAll(): Promise<void> {
    await this.init();
    try {
      await this.db.delete('identity', DEK_SLOT);
    } catch (e) {
      log.error('failed to delete sealed DEK', e);
    }
    this.lock();
    this.db.close();
    this.db = undefined as any;
    await deleteDB(this.dbName);
  }

  /**
   * 保管担当の保存先 (ロック解除後に呼ぶ)。専用の鍵は無ければここで作る。
   * @throws ロック中
   */
  public async openHolderDb(): Promise<HolderDB> {
    await this.init();
    this.requireVault();
    return HolderDB.open(this.db, this);
  }

  private requireVault(): DataVault {
    if (!this.vault || !this.vault.isOpen) {
      throw new Error('IndexedDBStore is locked; call unlock(passphrase) first');
    }
    return this.vault;
  }

  // ── 投稿とスレッド統計 ──

  private postIndex(boardId: string, threadId: string): string {
    return this.requireVault().index('posts', `${boardId}\u0000${threadId}`);
  }

  public async save(post: { boardId: string; threadId: string; payload: Uint8Array; dag?: any; metaFor?: string }): Promise<void> {
    if (!this.db) return;
    const vault = this.requireVault();
    const bt = this.postIndex(post.boardId, post.threadId);
    const record: PostEntry = {
      boardId: post.boardId,
      threadId: post.threadId,
      payload: post.payload,
      timestamp: dayFloor(),
      ...(post.metaFor !== undefined ? { metaFor: post.metaFor } : {}),
    };

    const tx = this.db.transaction(['eposts', 'ethreads'], 'readwrite');
    await tx.objectStore('eposts').add({ bt, blob: vault.seal(record, `eposts:${bt}`) });

    // スレッド統計の更新 (DAGメタデータがある場合)
    if (post.dag) {
      // 仮想トピック __board_meta__ ではなく、実際のスレッドルートをキーにする
      const targetThreadId = post.dag.thread_root || post.threadId;
      const k = vault.index('thread', targetThreadId);
      const store = tx.objectStore('ethreads');
      const row = await store.get(k);
      const existing = row ? vault.open<any>(row.blob, `ethreads:${k}`) : null;

      const currentMaxPow = existing ? (existing.max_pow || 0) : 0;
      const newMaxPow = Math.max(currentMaxPow, post.dag.cumulative_pow || 0);

      // created_at: 既存値が有効ならそれを保持、壊れていたら新しい値で上書き
      const existingCreatedAt = existing ? existing.created_at : null;
      const incomingCreatedAt = post.dag.created_at;
      const isExistingValid = typeof existingCreatedAt === 'number' && isFinite(existingCreatedAt) && existingCreatedAt > 0;
      const isIncomingValid = typeof incomingCreatedAt === 'number' && isFinite(incomingCreatedAt) && incomingCreatedAt > 0;
      const createdAt = isExistingValid ? existingCreatedAt : (isIncomingValid ? incomingCreatedAt : dayFloor());

      // スレ立て (板のメタ) の時刻だけを birth_at にする。レスが先に保存されても寿命の起点がずれないように
      const isMeta = post.threadId === BOARD_META_THREAD_ID;
      const birthAt = isMeta && isIncomingValid
        ? Math.min(typeof existing?.birth_at === 'number' ? existing.birth_at : Infinity, incomingCreatedAt)
        : existing?.birth_at;

      // 既存の欄 (birth_at / last_post_at) を落とさないよう、上書きする欄だけ差し替える
      const stats = {
        ...(existing ?? {}),
        threadId: targetThreadId,
        boardId: post.boardId,
        max_pow: newMaxPow,
        created_at: createdAt,
        last_updated: dayFloor(),
        ...(birthAt !== undefined ? { birth_at: birthAt } : {}),
      };
      await store.put({ k, b: vault.index('board', post.boardId), blob: vault.seal(stats, `ethreads:${k}`) });
    }

    await tx.done;
  }

  /**
   * スレッドの「最後に表示される書き込み」の時刻を記録する (過疎の判定に使う)。
   *
   * ★ 呼ぶのはスレを開いている ThreadOrchestrator だけ。上限の外で隠れた投稿の時刻は渡さない
   *   (隠れた投稿でスレを延命できないように)。値は大きくなる方向にだけ動く。
   */
  public async touchThread(boardId: string, threadId: string, lastPostAt: number): Promise<void> {
    if (!this.db || !Number.isFinite(lastPostAt) || lastPostAt <= 0) return;
    const vault = this.requireVault();
    const k = vault.index('thread', threadId);
    const tx = this.db.transaction('ethreads', 'readwrite');
    const store = tx.objectStore('ethreads');
    const row = await store.get(k);
    const existing = row ? vault.open<any>(row.blob, `ethreads:${k}`) : null;
    const prev = typeof existing?.last_post_at === 'number' ? existing.last_post_at : 0;
    if (lastPostAt > prev) {
      const stats = {
        ...(existing ?? { threadId, boardId, max_pow: 0, created_at: lastPostAt }),
        last_post_at: lastPostAt,
        last_updated: dayFloor(),
      };
      await store.put({ k, b: vault.index('board', boardId), blob: vault.seal(stats, `ethreads:${k}`) });
    }
    await tx.done;
  }

  // ── 期限切れスレッドの削除 (ThreadRetention が使う) ──
  //
  // ★ IndexedDB の削除は論理削除で、下層のストレージが旧ページを即座に上書きする保証は無い。
  //   それでも消すのは、DB 上に残さない (アプリ経由・通常の復元で見えない) ためと、
  //   全レコードが DEK で暗号化されているので、残骸も鍵が無ければ読めないため。

  /** そのスレッドのレス (と、同じキーで保存した板メタ) の行を全て消す。消した件数を返す */
  public async deleteThreadPosts(boardId: string, threadId: string): Promise<number> {
    if (!this.db) return 0;
    const bt = this.postIndex(boardId, threadId);
    const tx = this.db.transaction('eposts', 'readwrite');
    const keys = await tx.store.index('bt').getAllKeys(bt);
    for (const key of keys) await tx.store.delete(key);
    await tx.done;
    return keys.length;
  }

  /** getPosts が返した行の id を指定して消す (板メタのうち、期限切れのスレのものだけを消す用) */
  public async deletePostEntries(ids: number[]): Promise<void> {
    if (!this.db || ids.length === 0) return;
    this.requireVault();
    const tx = this.db.transaction('eposts', 'readwrite');
    for (const id of ids) await tx.store.delete(id);
    await tx.done;
  }

  /** スレッドの統計行を消す */
  public async deleteThreadStats(threadId: string): Promise<void> {
    if (!this.db) return;
    await this.db.delete('ethreads', this.requireVault().index('thread', threadId));
  }

  /**
   * 統計行から「読んだことに由来する欄」を落とす (残すのは threadId / boardId / created_at / birth_at)。
   * 行が無ければ何もしない。
   */
  public async resetThreadActivity(boardId: string, threadId: string): Promise<void> {
    if (!this.db) return;
    const vault = this.requireVault();
    const k = vault.index('thread', threadId);
    const tx = this.db.transaction('ethreads', 'readwrite');
    const row = await tx.store.get(k);
    const existing = row ? vault.open<any>(row.blob, `ethreads:${k}`) : null;
    if (existing) {
      const stats: any = { threadId, boardId: existing.boardId ?? boardId, max_pow: 0, created_at: existing.created_at };
      if (typeof existing.birth_at === 'number') stats.birth_at = existing.birth_at;
      await tx.store.put({ k, b: row!.b, blob: vault.seal(stats, `ethreads:${k}`) });
    }
    await tx.done;
  }

  public async getThreads(boardId: string): Promise<any[]> {
    if (!this.db) return [];
    const vault = this.requireVault();
    const rows = await this.db.getAllFromIndex('ethreads', 'b', vault.index('board', boardId));
    return rows
      .map(row => vault.open<any>(row.blob, `ethreads:${row.k}`))
      .filter((s): s is any => s !== null && s.boardId === boardId);
  }

  public async getPosts(boardId: string, threadId: string): Promise<PostEntry[]> {
    if (!this.db) return [];
    const vault = this.requireVault();
    const bt = this.postIndex(boardId, threadId);
    const rows = await this.db.getAllFromIndex('eposts', 'bt', bt);
    const posts: PostEntry[] = [];
    for (const row of rows) {
      const p = vault.open<PostEntry>(row.blob, `eposts:${bt}`);
      if (p && p.boardId === boardId && p.threadId === threadId) posts.push({ ...p, id: row.id });
    }
    // ★ timestamp は日単位なので同じ日の投稿は同順位になる。行 id (挿入順) で安定させる
    return posts.sort((a, b) => a.timestamp - b.timestamp || (a.id ?? 0) - (b.id ?? 0));
  }

  // ── 板の一覧 (板の鍵の保管) ──
  //
  // ★ 板の鍵を URL (#key=...) に載せない。URL は履歴・ログ・スクリーンショットに
  //   残りやすい。鍵は暗号化した DB にだけ置き、URL には板 ID だけを載せる。

  public async saveBoard(boardId: string, key: Uint8Array): Promise<void> {
    const vault = this.requireVault();
    const k = vault.index('boardkey', boardId);
    // ★ 追加順は時刻ではなく連番で保つ (時刻は日単位にしか残さない)
    const seq = (await this.listBoards()).reduce((m, b) => Math.max(m, b.seq ?? 0), 0) + 1;
    const record: BoardRecord = { boardId, key, addedAt: dayFloor(), seq };
    await this.db.put('boards', { k, blob: vault.seal(record, `boards:${k}`) });
  }

  public async getBoardKey(boardId: string): Promise<Uint8Array | null> {
    const vault = this.requireVault();
    const k = vault.index('boardkey', boardId);
    const row = await this.db.get('boards', k);
    if (!row) return null;
    const rec = vault.open<BoardRecord>(row.blob, `boards:${k}`);
    return rec && rec.boardId === boardId ? rec.key : null;
  }

  public async listBoards(): Promise<BoardRecord[]> {
    const vault = this.requireVault();
    const rows = await this.db.getAll('boards');
    return rows
      .map(row => vault.open<BoardRecord>(row.blob, `boards:${row.k}`))
      .filter((r): r is BoardRecord => r !== null)
      .sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0) || a.addedAt - b.addedAt || (a.boardId < b.boardId ? -1 : 1));
  }

  public async removeBoard(boardId: string): Promise<void> {
    const vault = this.requireVault();
    await this.db.delete('boards', vault.index('boardkey', boardId));
  }

  // ── 任意の設定値 ──

  public async getSetting<T = unknown>(name: string): Promise<T | undefined> {
    const vault = this.requireVault();
    const k = vault.index('kv', name);
    const row = await this.db.get('kv', k);
    if (!row) return undefined;
    const rec = vault.open<any>(row.blob, `kv:${k}`);
    if (rec === null) return undefined;
    if (rec && typeof rec === 'object' && rec.__kv === 1) return rec.v as T;
    // 名前を持たない旧形式の行。読めたついでに新しい形式で書き直す
    await this.setSetting(name, rec);
    return rec as T;
  }

  public async setSetting(name: string, value: unknown): Promise<void> {
    const vault = this.requireVault();
    const k = vault.index('kv', name);
    const rec: KvRecord = { __kv: 1, n: name, v: value };
    await this.db.put('kv', { k, blob: vault.seal(rec, `kv:${k}`) });
  }

  // ── Identity Storage (トリップ鍵・ノード鍵) ──
  //
  // 秘密は行ごと DEK で暗号化して置く ({v:2, secret, meta})。独自のパスワード KDF は持たない。
  //
  // ★ 以前は秘密鍵を SecretVault でパスワード封印し、その上で行全体を DEK で包んでいた。
  //   アンロックのたびに Argon2 が (DEK + 封印の数だけ) 走り、封印のぶんだけ総当たりの的が
  //   増えていた。DEK 自体が Argon2id(256 MiB) で守られているので、中身は DEK 配下で足りる。
  //
  // ★ 平文で残すと端末の素性が分かる欄は置かない。行に残るのはスロット名 (trip / node) と
  //   暗号文だけ。

  /**
   * 行を読む。新形式は secret、旧形式 (独自の KDF で封印 / 平文の sealed) は sealed を返す。
   * 旧形式は {@link upgradeIdentityRows} が次のアンロックで新形式にする。
   */
  private readIdentityRow(vault: DataVault, row: any): { secret?: Uint8Array; sealed?: SealedSecret; meta?: any } | null {
    if (row?.e !== undefined) {
      const inner = vault.open<{ v?: number; secret?: Uint8Array; sealed?: SealedSecret; meta?: any }>(row.e, `identity:${row.key}`);
      if (!inner) return null;
      // msgpack は undefined を null に変えて返すので、欄が無かったものとして揃える
      const meta = inner.meta ?? undefined;
      if (inner.v === 2 && inner.secret) return { secret: new Uint8Array(inner.secret), meta };
      return inner.sealed ? { sealed: inner.sealed, meta } : null;
    }
    if (!row?.sealed) return null;
    let meta = row.meta;
    if (row.emeta !== undefined) meta = vault.open(row.emeta, `identity:${row.key}`) ?? undefined;
    return { sealed: row.sealed as SealedSecret, meta };
  }

  /**
   * @param slot 'trip' = トリップ鍵 / 'node' = ノード identity
   * @returns 旧形式の行はアンロック時に移行済みのはずなので、ここでは「無い」扱い
   */
  public async getSecret(slot: string): Promise<{ secret: Uint8Array; meta?: any } | undefined> {
    if (!this.db || slot === DEK_SLOT) return undefined;
    const row = await this.db.get('identity', slot);
    if (!row) return undefined;
    const loaded = this.readIdentityRow(this.requireVault(), row);
    if (!loaded?.secret) {
      if (loaded?.sealed) log.warn(`identity slot "${slot}" is still in the legacy format (could not be migrated at unlock)`);
      return undefined;
    }
    return { secret: loaded.secret, meta: loaded.meta };
  }

  public async saveSecret(slot: string, secret: Uint8Array, meta?: any): Promise<void> {
    if (!this.db) return;
    if (slot === DEK_SLOT) throw new RangeError('reserved identity slot');
    const e = this.requireVault().seal({ v: 2, secret, meta }, `identity:${slot}`);
    await this.db.put('identity', { key: slot, e });
  }

  /** 旧形式の行 (SecretVault 封印) を読む。移行と、旧形式のテスト用 */
  public async getSealed(slot: string): Promise<{ sealed: SealedSecret; meta?: any } | undefined> {
    if (!this.db || slot === DEK_SLOT) return undefined;
    const row = await this.db.get('identity', slot);
    if (!row) return undefined;
    const loaded = this.readIdentityRow(this.requireVault(), row);
    return loaded?.sealed ? { sealed: loaded.sealed, meta: loaded.meta } : undefined;
  }

  /** 旧形式で書く。新規の書き込みには使わない (移行のテスト用) */
  public async saveSealed(slot: string, sealed: SealedSecret, meta?: any): Promise<void> {
    if (!this.db) return;
    if (slot === DEK_SLOT) throw new RangeError('reserved identity slot');
    const e = this.requireVault().seal({ sealed, meta }, `identity:${slot}`);
    await this.db.put('identity', { key: slot, e });
  }

  public async deleteSecret(slot: string): Promise<void> {
    if (!this.db || slot === DEK_SLOT) return;
    await this.db.delete('identity', slot);
  }

  /**
   * ロック解除のたびに、identity の行を最新の形に揃える。
   *
   *   - DEK の封印の KDF が今の既定より弱ければ、同じ DEK を今の強度で包み直す
   *     (封印にはパラメータが入っているので、旧い封印も開ける。ここで引き上げる)。
   *     ★ 低メモリ端末の縮退パラメータで作った封印は引き上げを試さない (毎回 256 MiB の
   *       確保に失敗して Argon2 を余計に走らせることになる)。強度はパスワード変更で再挑戦する。
   *   - DEK の行に残っていた旧形式の欄 (updatedAt / protected) を落とす
   *   - trip / node の行を旧形式 (独自の KDF で封印、または平文の行) から DEK 配下の
   *     新形式に移す。旧い封印をこのパスワードで開くのはここで 1 回だけ。
   *     開けたら新形式で書き直す (旧い行はその書き込みで置き換わる)。
   *
   * @param dek アンロックで既に開いた DEK (封印の包み直しに使う。無ければ初回作成直後)
   */
  private async upgradeIdentityRows(passphrase: string, params: VaultParams, dek?: Uint8Array): Promise<void> {
    const vault = this.requireVault();
    const row = await this.db.get('identity', DEK_SLOT);
    if (row?.sealed) {
      const lowMem = row.sealed.opsLimit === VAULT_PARAMS_LOW_MEMORY.opsLimit && row.sealed.memLimit === VAULT_PARAMS_LOW_MEMORY.memLimit;
      const weak = dek !== undefined && !lowMem && isWeakerThan(row.sealed, params);
      if (weak || 'updatedAt' in row || 'protected' in row.sealed) {
        const wrap = weak ? DataVault.wrapDek(dek!, passphrase, params) : fromDekWrap(row.sealed);
        await this.db.put('identity', { key: DEK_SLOT, sealed: toDekWrap(wrap) });
        if (weak) log.info('re-wrapped the data key with stronger KDF parameters');
      }
    }

    let migrated = 0;
    for (const r of await this.db.getAll('identity')) {
      if (r.key === DEK_SLOT) continue;
      const loaded = this.readIdentityRow(vault, r);
      if (!loaded?.sealed) continue; // 新形式 (または読めない行) は触らない

      const secret = SecretVault.open(loaded.sealed, loaded.sealed.protected === true ? passphrase : '');
      if (!secret) continue; // 開けないものは触らない (別のパスワードで封印されている等)
      await this.saveSecret(r.key, secret, loaded.meta);
      sodium.memzero(secret);
      migrated++;
    }
    if (migrated > 0) log.info(`upgraded ${migrated} identity record(s)`);
  }

  // ── v6 以前からの移行 ──

  private async migrateLegacy(): Promise<void> {
    const names = this.db.objectStoreNames;
    let migrated = 0;

    if (names.contains('posts')) {
      const vault = this.requireVault();
      const rows = (await this.db.getAll('posts')) as PostEntry[];
      for (const r of rows) {
        if (typeof r?.boardId !== 'string' || typeof r?.threadId !== 'string') continue;
        const bt = this.postIndex(r.boardId, r.threadId);
        const record: PostEntry = { boardId: r.boardId, threadId: r.threadId, payload: r.payload, timestamp: r.timestamp };
        await this.db.add('eposts', { bt, blob: vault.seal(record, `eposts:${bt}`) });
        migrated++;
      }
      await this.db.clear('posts');
    }

    if (names.contains('threads')) {
      const vault = this.requireVault();
      const rows = (await this.db.getAll('threads')) as any[];
      for (const r of rows) {
        if (typeof r?.threadId !== 'string' || typeof r?.boardId !== 'string') continue;
        const k = vault.index('thread', r.threadId);
        await this.db.put('ethreads', { k, b: vault.index('board', r.boardId), blob: vault.seal(r, `ethreads:${k}`) });
        migrated++;
      }
      await this.db.clear('threads');
    }

    if (migrated > 0) log.info(`migrated ${migrated} legacy plaintext record(s) into the encrypted store`);
  }
}

export { WrongPassphraseError };
