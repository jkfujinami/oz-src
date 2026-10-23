import sodium from './sodium';
import { NodeIdentity, NODE_ID_POW, type NodeIdPowParams } from './NodeIdentity';
import type { SealedStore } from './Identity';
import { createLogger } from '../common/Logger';

const log = createLogger('crypto.nodeid');

const NODE_SLOT = 'node';

/**
 * ノード identity の永続化。
 *
 * NodeId PoW (Argon2id) の採掘は既定パラメータで数秒かかるので、
 * 一度採掘したら封印して保存し、次回以降は復元する。
 *
 * 秘密鍵は保存側 (IndexedDBStore) が DEK で暗号化して書く。生で置くと、
 * 押収時に「このノードはリングのこの座標にいた」ことが確定してしまう。
 */
export class NodeIdentityStore {
  /**
   * 使い捨ての identity を採掘する (保存しない)。既定はこちら。
   *
   * ★ peerId を端末に永続化すると、トラッカーと全隣人がそれを見るので、
   *   IP や VPN を変えても全セッションが同一端末として紐付く (H4)。
   *   起動のたびに採掘し直す (既定パラメータで数秒) 代わりに、
   *   セッションを跨いだ追跡の手掛かりを消す。
   *
   *   以前の版が保存した**パスフレーズで保護されていない**ノード鍵が
   *   端末に残っていれば消す (押収時に読める状態で残さない)。
   */
  static async mineEphemeral(
    store: SealedStore,
    params: NodeIdPowParams = NODE_ID_POW,
  ): Promise<NodeIdentity> {
    await sodium.ready;
    // ★ 旧版が保存した保護なしのノード鍵は、アンロック時に DEK 配下へ移し替えられる
    //   (独自の封印は無くなった)。ここで消す必要は無い。
    void store;
    return NodeIdentity.mine(params);
  }

  /**
   * 保存済みの identity を復元する。無ければ採掘して保存する。
   *
   * ★ パスフレーズ必須。空のパスフレーズでの封印は秘匿性ゼロ (誰でも開ける) なので、
   *   「保護されているつもりで保護されていない」鍵を端末に置かせない。
   *
   * @param passphrase 封印のパスフレーズ (空文字は不可)
   */
  /**
   * ★ パスワードの照合は store.unlock が済ませている (打ち間違いでは、ここへ来る前に失敗して何も書き換わらない)
   */
  static async loadOrMine(
    store: SealedStore,
    passphrase: string,
    params: NodeIdPowParams = NODE_ID_POW,
  ): Promise<NodeIdentity> {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new RangeError('NodeIdentityStore.loadOrMine: a non-empty passphrase is required to persist the node identity');
    }
    await sodium.ready;

    const restored = await NodeIdentityStore.tryLoad(store, params);
    if (restored) {
      log.debug(`Restored node identity ${restored.peerId.substring(0, 8)}`);
      return restored;
    }

    log.debug(`Mining new node identity (difficulty ${params.difficulty})...`);
    const started = Date.now();
    const identity = await NodeIdentity.mine(params);
    log.debug(
      `[NodeIdentityStore] Mined ${identity.peerId.substring(0, 8)} in ${Date.now() - started}ms ` +
      `(bound position: ${identity.position.toFixed(6)})`,
    );

    await NodeIdentityStore.save(store, identity);
    return identity;
  }

  private static async tryLoad(
    store: SealedStore,
    params: NodeIdPowParams,
  ): Promise<NodeIdentity | null> {
    // 読み出しの失敗は伝える。「無かった」と扱うと、一時的な失敗で採掘し直した
    // identity が保存済みのものを上書きしてしまう。
    const record = await store.getSecret(NODE_SLOT);
    if (!record) return null;

    // ★ 旧実装はパスワード違いで null を返し、呼び出し側が新しい identity を採掘して上書きしていた
    //   (打ち間違い 1 回で元の鍵が永久に失われた)。今はパスワードの照合が store のアンロックに
    //   移ったので、ここに来た時点で正しいパスワードで開いている。
    const secret = record.secret;

    const skBytes = sodium.crypto_sign_SECRETKEYBYTES;
    const pkBytes = sodium.crypto_sign_PUBLICKEYBYTES;
    if (secret.length !== skBytes + pkBytes) return null;

    const powCounter = record.meta?.powCounter;
    if (!Number.isSafeInteger(powCounter) || powCounter < 0) return null;

    const identity = NodeIdentity.fromKeyPair(
      secret.slice(skBytes),
      secret.slice(0, skBytes),
      powCounter,
    );

    // 難易度を引き上げた後などは、保存済みの解が今の基準を満たさない。
    // その場合は捨てて採掘し直す (満たさない identity で参加しても弾かれる)。
    if (!NodeIdentity.verifyClaim(identity.claim(), params)) {
      log.warn(`Stored identity no longer meets NodeId PoW policy — re-mining.`);
      return null;
    }

    return identity;
  }

  private static async save(
    store: SealedStore,
    identity: NodeIdentity,
  ): Promise<void> {
    const secret = identity.exportSecret();
    const blob = new Uint8Array(secret.privkey.length + secret.pubkey.length);
    blob.set(secret.privkey, 0);
    blob.set(secret.pubkey, secret.privkey.length);

    // powCounter は秘密ではない (どうせ JOIN で全員に送る) ので meta に置く
    await store.saveSecret(NODE_SLOT, blob, {
      powCounter: secret.powCounter,
      peerId: identity.peerId,
    });
  }
}
