import sodium from './sodium';
import { Encoding } from '../common/Encoding';
import type { PeerId } from '../types';
import { createLogger } from '../common/Logger';

const log = createLogger('crypto.onion');

/** peerId は Bound Identity なので hex 32 文字に固定されている */
const PEER_ID_RE = /^[0-9a-f]{32}$/;

/** peerId のバイト長 (NodeIdentity.PEER_ID_BYTES と同じ。循環 import を避けて持つ) */
const PEER_ID_BYTES = 16;

/**
 * 回路の最後の層 (M1) に渡すもの。
 *
 * ★ 作者が網に出すものは**すべて** frag (断片) に包んで運ぶ。1 枚に収まるものも例外ではない
 *   (M1 が扱う形を 1 つにするため)。中身 (ExitItem: exit_fluff) は断片を
 *   連結した先にあり、M1 が再構成してから Stem で歩かせる。M1 は flood しない。
 *   旧実装は Gossip 本体だけをオニオンに載せ、同じパケットを
 *   DHT_PUT_STEM (Slot) と HINT_STEM (索引) で平文のまま並行に送っていたため、
 *   オニオンが丸ごと迂回されていた。
 *
 *   - frag : ExitItem の断片。同じ item の断片は id が同じ (idx 0..total-1, total ≤ MAX_FRAGMENTS)
 *   - drop : cover traffic。M1 で黙って捨てる
 *
 * 層の形はどれも位置固定のバイナリ (msgpack は使わない):
 *   中継層   [KIND_RELAY u8][次ホップの peerId 16 バイト (生)][内側の暗号文 (残り全部)]
 *   断片     [KIND_FRAG u8][id 8][idx u8][total u8][data (残り全部)]
 *   drop     [KIND_DROP u8]
 * 断片と drop は封印された出口層の内側 (padCell で固定長) なので Guard には見えない。
 */
export type ExitPayload =
  | { type: 'frag'; id: Uint8Array; idx: number; total: number; data: Uint8Array }
  | { type: 'drop' };

export type OnionPayload =
  | {
      type: 'relay';
      nextHop: PeerId;
      innerOnion: Uint8Array;
    }
  | ExitPayload;

export interface OnionHop {
  peerId: PeerId;
  pubkey: Uint8Array; // Ed25519 public key (32 bytes)
}

/** crypto_box_seal の付加長 (ephemeral pk 32 + MAC 16) */
const SEAL_OVERHEAD = 48;

/** X25519 変換キャッシュの上限 (他ノードの公開鍵は無限に流れてくる) */
const XPK_CACHE_LIMIT = 4096;

/**
 * 中継層 1 枚の付加バイト数: kind 1 + 次ホップの peerId 16 = 17。
 * (旧 msgpack 形式は 68。差の 51 バイトぶん、断片に載せられるデータが増えた)
 * OnionRouter.test が実際の符号化と突き合わせる。
 */
export const RELAY_LAYER_OVERHEAD = 1 + PEER_ID_BYTES;
const KIND_RELAY = 1;
const KIND_FRAG = 2;
const KIND_DROP = 3;

/** セルのヘッダ (マジック 2 + 実データ長 2) */
const CELL_HEADER = 4;

const CELL_SIZE_VALUE = 1200;

/** 1 つの item を運べる断片の最大数 (これを超える item は send で拒否される) */
export const MAX_FRAGMENTS = 3;
/** 断片 id の長さ (バイト) */
export const FRAG_ID_BYTES = 8;
/** 断片の付加: kind 1 + id 8 + idx 1 + total 1 = 11 */
const FRAG_OVERHEAD = 1 + FRAG_ID_BYTES + 1 + 1;

export class OnionRouter {
  /**
   * 固定長セルサイズ (1,200 バイト)。
   *
   * ★ 小さくした理由: 全員が平均 0.5 秒ごとにセルを出し続ける (cover traffic) ので、
   *   セルの大きさがそのまま常時の帯域になる。3,800 バイト / 平均 0.3 秒 (約 12.7 KB/s の上り)
   *   だったものが、1,200 バイト / 平均 0.5 秒で約 2.4 KB/s。代わりに本物の投稿は最大 3 枚に分割する
   *   (断片化。OnionCircuit の「3 スロット固定回路」を参照)。
   *   WebRTC DataChannel の単一フレーム上限 (CHUNK_SIZE = 4096B) に 1 枚で収まるので、
   *   SCTP 分割チャンキングは起きない。
   */
  public static readonly CELL_SIZE = CELL_SIZE_VALUE;

  /**
   * 出口層の平文長 (固定)。
   *
   * ★ 出口層も固定長にパディングする。
   *   しないと Guard が外殻を剥いた時点で innerOnion の長さが見え、
   *   cover traffic (drop) と本物 (frag) をサイズだけで区別できてしまう。
   *
   * ★ 2 層 (出口層を relay 層で包んだセル) がセルにちょうど収まるように導出する:
   *     CELL_SIZE - セルヘッダ 4 - seal 48 (relay 層) - 中継層の付加 17 - seal 48 (出口層) = 1083
   *   つまり CELL_SIZE の最外殻は**パディング無し**で埋まる。OnionRouter.test が
   *   wrapCircuit の実測でこの等式を確かめる (層の付加が変わればテストが落ちる)。
   */
  public static readonly EXIT_LAYER_SIZE =
    CELL_SIZE_VALUE - CELL_HEADER - SEAL_OVERHEAD - RELAY_LAYER_OVERHEAD - SEAL_OVERHEAD;

  /** 断片 1 枚に載せられるデータの最大長 = 出口層の容量 - padCell のヘッダ - 断片の付加 */
  public static readonly FRAG_DATA_MAX =
    OnionRouter.EXIT_LAYER_SIZE - CELL_HEADER - FRAG_OVERHEAD;

  /** 固定長セルのマジックヘッダ (0xA55A) */
  private static readonly CELL_MAGIC = 0xa55a;

  /** Ed25519 公開鍵 → X25519 公開鍵の変換キャッシュ */
  private static xPkCache = new Map<string, Uint8Array>();

  /**
   * 固定長セルパディング (Fixed Cell Size Padding)
   *
   * セル形式:
   * [0..1]: Magic (0xA55A)
   * [2..3]: 実データ長 L (Big Endian, 16bit)
   * [4..4+L-1]: 実データ
   * [4+L..cellSize-1]: 暗号論的擬似乱数パディング
   */
  public static padCell(payload: Uint8Array, cellSize: number = this.CELL_SIZE): Uint8Array {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError('OnionRouter: payload must be a Uint8Array');
    }
    if (payload.byteLength > cellSize - 4) {
      throw new Error(`OnionRouter: payload size (${payload.byteLength}) exceeds cell capacity (${cellSize - 4})`);
    }

    const cell = new Uint8Array(cellSize);
    cell[0] = (this.CELL_MAGIC >> 8) & 0xff;
    cell[1] = this.CELL_MAGIC & 0xff;
    cell[2] = (payload.byteLength >> 8) & 0xff;
    cell[3] = payload.byteLength & 0xff;
    cell.set(payload, 4);

    const padLen = cellSize - 4 - payload.byteLength;
    if (padLen > 0) {
      cell.set(sodium.randombytes_buf(padLen), 4 + payload.byteLength);
    }
    return cell;
  }

  /**
   * 固定長セルからパディングを剥離して実データを取り出す。
   *
   * ★ 形式が合わないものは null を返す。
   *   旧実装はマジック不一致のバイト列をそのまま「生の暗号文」として受け入れており、
   *   固定長でないセルが網を流れる余地を残していた。
   */
  public static unpadCell(cell: Uint8Array, expectedSize: number = this.CELL_SIZE): Uint8Array | null {
    if (!(cell instanceof Uint8Array) || cell.byteLength !== expectedSize) return null;
    if (cell[0] !== ((this.CELL_MAGIC >> 8) & 0xff) || cell[1] !== (this.CELL_MAGIC & 0xff)) return null;
    const len = (cell[2] << 8) | cell[3];
    if (len > cell.byteLength - 4) return null;
    return cell.subarray(4, 4 + len);
  }

  /**
   * Ed25519 公開鍵を X25519 (Curve25519) 公開鍵へ変換
   */
  public static toCurvePublicKey(edPubkey: Uint8Array): Uint8Array {
    const hex = Encoding.toHex(edPubkey);
    let xPk = this.xPkCache.get(hex);
    if (!xPk) {
      xPk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPubkey);
      if (this.xPkCache.size >= XPK_CACHE_LIMIT) {
        const oldest = this.xPkCache.keys().next().value;
        if (oldest !== undefined) this.xPkCache.delete(oldest);
      }
      this.xPkCache.set(hex, xPk);
    }
    return xPk;
  }

  /**
   * Ed25519 秘密鍵を X25519 (Curve25519) 秘密鍵へ変換
   */
  public static toCurvePrivateKey(edPrivkey: Uint8Array): Uint8Array {
    return sodium.crypto_sign_ed25519_sk_to_curve25519(edPrivkey);
  }

  /**
   * 多段オニオン暗号化 (Onion Wrap)
   *
   * 経路 hops: [Hop1 (Guard), ..., HopK (Exit)]
   * 出口層を固定長 (EXIT_LAYER_SIZE) にパディングしてから HopK → Hop1 の逆順に
   * 多重暗号化し、最外殻を固定長セル (CELL_SIZE) にパディングして返す。
   *
   * @returns Hop1 に送信する固定長セル
   */
  public static wrapCircuit(exit: ExitPayload, hops: OnionHop[]): Uint8Array {
    if (hops.length === 0) {
      throw new Error('OnionRouter: hops list cannot be empty');
    }

    const exitHop = hops[hops.length - 1];
    let currentCiphertext = sodium.crypto_box_seal(
      this.padCell(this.encodeExit(exit), this.EXIT_LAYER_SIZE),
      this.toCurvePublicKey(exitHop.pubkey),
    );

    for (let i = hops.length - 2; i >= 0; i--) {
      const nextHop = hops[i + 1].peerId;
      if (!PEER_ID_RE.test(nextHop)) throw new RangeError('OnionRouter: nextHop must be a 32-char hex peerId');
      const relay = new Uint8Array(RELAY_LAYER_OVERHEAD + currentCiphertext.length);
      relay[0] = KIND_RELAY;
      relay.set(Encoding.fromHex(nextHop), 1);
      relay.set(currentCiphertext, RELAY_LAYER_OVERHEAD);
      currentCiphertext = sodium.crypto_box_seal(relay, this.toCurvePublicKey(hops[i].pubkey));
    }

    return this.padCell(currentCiphertext);
  }

  /**
   * オニオンセルを復号して 1 枚剥く (Onion Unwrap)
   *
   * @param cell 受信した固定長セル (CELL_SIZE)
   * @returns 復号・形式検証済みのペイロード。失敗時は null
   */
  public static unwrap(
    cell: Uint8Array,
    myEdPubkey: Uint8Array,
    myEdPrivkey: Uint8Array,
  ): OnionPayload | null {
    return this.unwrapWithCurveKeys(
      cell,
      this.toCurvePublicKey(myEdPubkey),
      this.toCurvePrivateKey(myEdPrivkey),
    );
  }

  /** X25519 鍵を事前に変換済みの呼び出し側向け (受信ホットパスで毎回変換しない) */
  public static unwrapWithCurveKeys(
    cell: Uint8Array,
    myXPk: Uint8Array,
    myXSk: Uint8Array,
  ): OnionPayload | null {
    try {
      const rawCiphertext = this.unpadCell(cell);
      if (!rawCiphertext) return null;

      const plaintext = sodium.crypto_box_seal_open(rawCiphertext, myXPk, myXSk);

      // 出口層は固定長 (EXIT_LAYER_SIZE) にパディングされている。中継層は先頭が KIND_RELAY (1) で、
      // 出口層はマジック 0xA5 で始まるので衝突しない (長さとマジックの両方で判定する)。
      // ★ 出口層の中身は出口の種別 (断片 / drop) しか受け付けない。出口層に中継層を
      //   入れ子にして作者が M1 に「転送」させる経路を作らせない。
      if (plaintext.byteLength === this.EXIT_LAYER_SIZE) {
        const inner = this.unpadCell(plaintext, this.EXIT_LAYER_SIZE);
        if (inner) return this.parseExit(inner);
      }
      return this.parseRelay(plaintext);
    } catch (err) {
      log.trace(() => `Onion unwrap failed: ${err}`);
      return null;
    }
  }

  private static encodeExit(exit: ExitPayload): Uint8Array {
    if (exit.type === 'drop') return Uint8Array.of(KIND_DROP);
    if (exit.id.byteLength !== FRAG_ID_BYTES) throw new RangeError('OnionRouter: bad fragment id length');
    const out = new Uint8Array(FRAG_OVERHEAD + exit.data.byteLength);
    out[0] = KIND_FRAG;
    out.set(exit.id, 1);
    out[1 + FRAG_ID_BYTES] = exit.idx;
    out[2 + FRAG_ID_BYTES] = exit.total;
    out.set(exit.data, FRAG_OVERHEAD);
    return out;
  }

  /**
   * 復号結果の形を確定させる。
   *
   * 誰でも任意のノード宛てにオニオンを作れるので、復号できたことは
   * 中身が正しいことを何も保証しない。ここで種別と範囲を全部確かめる。
   */
  private static parseExit(b: Uint8Array): OnionPayload | null {
    if (b.byteLength === 0) return null;
    if (b[0] === KIND_DROP) return b.byteLength === 1 ? { type: 'drop' } : null;
    if (b[0] !== KIND_FRAG || b.byteLength < FRAG_OVERHEAD + 1) return null;
    const id = b.slice(1, 1 + FRAG_ID_BYTES);
    const idx = b[1 + FRAG_ID_BYTES];
    const total = b[2 + FRAG_ID_BYTES];
    if (total < 1 || total > MAX_FRAGMENTS) return null;
    if (idx >= total) return null;
    const data = b.slice(FRAG_OVERHEAD);
    if (data.byteLength < 1 || data.byteLength > this.FRAG_DATA_MAX) return null;
    return { type: 'frag', id, idx, total, data };
  }

  private static parseRelay(b: Uint8Array): OnionPayload | null {
    if (b.byteLength <= RELAY_LAYER_OVERHEAD || b[0] !== KIND_RELAY) return null;
    const innerOnion = b.slice(RELAY_LAYER_OVERHEAD);
    if (innerOnion.byteLength > this.CELL_SIZE - 4) return null;
    return { type: 'relay', nextHop: Encoding.toHex(b.subarray(1, RELAY_LAYER_OVERHEAD)), innerOnion };
  }
}

/** 封印された出口層の長さ (= Guard が外殻を剥いたときに見える innerOnion の長さ) */
export const SEALED_EXIT_LAYER_SIZE = OnionRouter.EXIT_LAYER_SIZE + SEAL_OVERHEAD;
