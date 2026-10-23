import sodium from '../crypto/sodium';
import { Encoding } from '../common/Encoding';

/**
 * PosterId — 画面に出す「ID:」(5ch の日替わり ID にあたるもの)。
 *
 * ★ トリップ有りの投稿はセッション鍵を載せない (PostCodec)。代わりに、トリップ鍵とスレッドから導く:
 *   hash(trip_pubkey ‖ thread_id) の先頭 4 バイト。スレごとに変わるので、別のスレの ID と結び付かない
 *   (トリップそのものの表示 ◆… とは別物)。セッション鍵の投稿は従来どおり hash(session_pubkey) の先頭 4 バイト
 *   (タブごとに変わる)。
 */
export function posterId(
  post: { session_pubkey?: Uint8Array | null; trip_pubkey?: Uint8Array | null },
  threadId: string,
): string {
  if (post.trip_pubkey) {
    const tid = new TextEncoder().encode(threadId);
    const msg = new Uint8Array(post.trip_pubkey.length + tid.length);
    msg.set(post.trip_pubkey, 0);
    msg.set(tid, post.trip_pubkey.length);
    return Encoding.toBase64(sodium.crypto_hash(msg).slice(0, 4));
  }
  if (post.session_pubkey) return Encoding.toBase64(sodium.crypto_hash(post.session_pubkey).slice(0, 4));
  return '???';
}
