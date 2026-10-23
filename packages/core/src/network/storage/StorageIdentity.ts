import sodium from '../../crypto/sodium';
import { createLogger } from '../../common/Logger';
import { MAX_SLOTS, SLOT_EFFORT, solveSlot, slotPosition, verifySlotSolution, type SlotSolution } from './SlotPow';

const log = createLogger('net.storage.sid');

/** 暗号化 DB の kv に置く名前 (DEK で封印される。平文には出ない) */
export const STORAGE_IDENTITY_KEY = 'storage.sid';

export interface StorageIdentityStore {
  get(name: string): Promise<unknown>;
  set(name: string, value: unknown): Promise<void>;
}

export interface SolvedSlot extends SlotSolution {
  index: number;
  /** リング上の位置 (Ring.positionOf) */
  position: bigint;
}

interface Persisted {
  v: 1;
  /** Ed25519 の秘密鍵 (libsodium の 64 バイト形式) */
  sk: Uint8Array;
  slots: Array<{ nonce: number; solution: Uint8Array }>;
}

/**
 * StorageIdentity — 保管担当としての身元 SID (history v2 §4.1)。
 *
 * ★ 中継の peerId (NodeIdentity) とは**別の鍵**。leaseSet は全員に配られるので、SID から
 *   「いま誰と接続している端末か」を引けてはならない。SID と peerId を結ぶ情報はどこにも載せない。
 * ★ 暗号化 DB (DEK 封印の kv) に置く。パスワードを知らない者には、押収された端末から SID も枠の位置も読めない。
 *   (identity ストアの Argon2id 封印は使わない: 起動のたびに 2 回目の KDF が走るだけで、DEK の下という
 *   意味では防御が変わらないため。)
 * ★ 枠の PoW は SID につき 1 回だけ解いて、解を封印して保存する。枠の位置は SID が続く限り変わらない
 *   (起動のたびに数秒×枠数を払わない。位置が毎回変わると担当が揺れて、保持者が持つデータが無駄になる)。
 * ★ 枠を増やす (容量を上げる) のは裏で 1 枠ずつ解く。1 枠 約 2 秒 (SLOT_EFFORT)。1 枠解くたびに保存する。
 * ★ TODO(★ 後続): SID の 30 日ごとの作り直し (長期の追跡を断つ) は B-b1 の範囲外。入れるときは
 *   新しい SID で枠を解き直し、旧 SID の leaseSet は期限切れを待って捨てる。保持者のデータは位置が変わるので
 *   新しい枠へ移る (取り直し) ことになる点に注意。
 */
export class StorageIdentity {
  private solved: SolvedSlot[] = [];
  private solving: Promise<void> | null = null;
  private target = 0;
  private destroyed = false;
  private persistChain: Promise<void> = Promise.resolve();
  /** 要求の封印 (sealed box) を開ける X25519 の鍵。SID (Ed25519) から導出し、メモリだけに持つ */
  private curve: { pk: Uint8Array; sk: Uint8Array } | null = null;

  private constructor(
    private sk: Uint8Array,
    public readonly publicKey: Uint8Array,
    private readonly store: StorageIdentityStore | null,
    private readonly effort: number,
  ) {}

  /**
   * 保存済みの SID を読む。無ければ作って保存する (初回のロック解除)。
   * @param effort ★ テスト専用。本番は SLOT_EFFORT (全ノードで同じでなければならない)
   */
  public static async loadOrCreate(store: StorageIdentityStore | null, effort: number = SLOT_EFFORT): Promise<StorageIdentity> {
    // ★ 読めなかった (例外) ときは新しく作らず、そのまま失敗させる。一時的な読み出し失敗で
    //   既存の SID を新しい鍵で上書きすると、枠の解 (数秒×枠数) と位置を失う。
    const raw: any = store ? await store.get(STORAGE_IDENTITY_KEY) : undefined;
    if (raw && raw.v === 1 && raw.sk instanceof Uint8Array && raw.sk.length === sodium.crypto_sign_SECRETKEYBYTES) {
      const sk = raw.sk.slice();
      const pk = sodium.crypto_sign_ed25519_sk_to_pk(sk);
      const id = new StorageIdentity(sk, pk, store, effort);
      // 保存された解は信用せず検証し直す (壊れた分は捨てて解き直す。順番が飛んだら以降も捨てる)
      const slots: any[] = Array.isArray(raw.slots) ? raw.slots : [];
      for (let i = 0; i < slots.length && i < MAX_SLOTS; i++) {
        const s = slots[i];
        const sol: SlotSolution = { nonce: s?.nonce, solution: s?.solution };
        if (!verifySlotSolution(pk, i, sol, effort)) break;
        id.solved.push({ index: i, ...sol, position: slotPosition(pk, i, sol.solution) });
      }
      log.debug(() => `storage identity restored (${id.solved.length} slot(s) solved)`);
      return id;
    }
    const kp = sodium.crypto_sign_keypair();
    const id = new StorageIdentity(kp.privateKey, kp.publicKey, store, effort);
    await id.persist();
    log.debug(() => 'storage identity created');
    return id;
  }

  /** 解き終わった枠 (0 .. n−1 の連番)。位置はここから変わらない */
  public get slots(): readonly SolvedSlot[] {
    return this.solved;
  }

  /**
   * この SID 宛てに封印された (crypto_box_seal) 本文を開ける。H の X25519 鍵は SID から導出する (TunnelCrypto)。
   * 自分宛てでない・壊れている・停止後は null。
   */
  public openSealed(sealed: Uint8Array): Uint8Array | null {
    if (this.destroyed) return null;
    try {
      if (!this.curve) {
        this.curve = {
          pk: sodium.crypto_sign_ed25519_pk_to_curve25519(this.publicKey),
          sk: sodium.crypto_sign_ed25519_sk_to_curve25519(this.sk),
        };
      }
      return sodium.crypto_box_seal_open(sealed, this.curve.pk, this.curve.sk);
    } catch {
      return null;
    }
  }

  public sign(message: Uint8Array): Uint8Array {
    if (this.destroyed) throw new Error('StorageIdentity is destroyed');
    return sodium.crypto_sign_detached(message, this.sk);
  }

  /**
   * 枠を count 個まで解く (足りない分だけ、1 枠ずつ裏で)。解き終わったら解決する。
   * 並行して呼んでも解く処理は 1 本。より大きい count が来たら続けて解く。
   * @param onSolved 1 枠解くたびに呼ぶ (leaseSet の再発行・容量の反映に使う)
   */
  public ensureSlots(count: number, onSolved?: (slot: SolvedSlot) => void): Promise<void> {
    this.target = Math.max(this.target, Math.min(MAX_SLOTS, Math.max(0, Math.floor(count))));
    if (this.solving) return this.solving;
    this.solving = (async () => {
      try {
        while (!this.destroyed && this.solved.length < this.target) {
          const index = this.solved.length;
          const sol = await solveSlot(this.publicKey, index, { effort: this.effort, shouldStop: () => this.destroyed });
          if (!sol || this.destroyed) return;
          const slot: SolvedSlot = { index, ...sol, position: slotPosition(this.publicKey, index, sol.solution) };
          this.solved.push(slot);
          await this.persist();
          try { onSolved?.(slot); } catch (e) { log.warn('slot listener failed', e); }
        }
      } finally {
        this.solving = null;
      }
    })();
    return this.solving;
  }

  private persist(): Promise<void> {
    if (!this.store) return Promise.resolve();
    const record: Persisted = {
      v: 1,
      sk: this.sk.slice(),
      slots: this.solved.map(s => ({ nonce: s.nonce, solution: s.solution })),
    };
    this.persistChain = this.persistChain.then(async () => {
      try {
        await this.store!.set(STORAGE_IDENTITY_KEY, record);
      } catch (e) {
        log.warn('could not persist the storage identity', e);
      }
    });
    return this.persistChain;
  }

  /**
   * 解く処理を止め、鍵をメモリから消す。保存待ちは先に流す。
   * ★ 解いている最中の処理は待たない (次の試行の前に止まる)。待つと、タイマーが止まっている環境
   *   (テストの偽タイマー) で stop() が戻らなくなる。解けた直後の保存は destroyed の判定と同じ同期区間で
   *   persist() を呼ぶので、ここで待つ persistChain に必ず入っている。
   */
  public async destroy(): Promise<void> {
    this.destroyed = true;
    await this.persistChain;
    sodium.memzero(this.sk);
    if (this.curve) sodium.memzero(this.curve.sk);
    this.curve = null;
  }
}
