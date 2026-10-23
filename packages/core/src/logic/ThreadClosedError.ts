export type ThreadClosedReason = 'closed' | 'expired' | 'full-posts' | 'full-bytes';

/**
 * スレッドがもう書き込めない (埋まった・落ちた・この書き込みで容量を超える) ときに
 * submitReply が投げる。PoW も送信も行わずに止めるので、入力は呼び出し側に残せる。
 */
export class ThreadClosedError extends Error {
  constructor(public readonly reason: ThreadClosedReason) {
    super(`thread closed: ${reason}`);
    this.name = 'ThreadClosedError';
  }
}
