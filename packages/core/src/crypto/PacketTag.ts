import sodium from './sodium';
import { DAY_MS, POW_POLICY, u32be } from './PowPolicy';
import { threadBirthFromId } from '../logic/ThreadLimits';

/**
 * PacketTag — ヘッダの tag (12 ビット) と age (スレ立てからの日数) の規則。
 *
 * ★ tag は「この板 / このスレの、その日の目印」。鍵を持つ者だけが計算できる (HMAC)。
 *   中継には何の意味も持たない 12 ビットの乱数に見える。読み手は tag が合わないパケットを、
 *   復号の前に (HMAC 1 回で) 落とせる。12 ビットなので他人のパケットが 1/4096 で偶然合うが、
 *   その場合も SIV が落とす。保管担当 (後続のタスク) は tag と age から置き場所を決める。
 *
 *   板のメタ (スレ立て・post_type 1・板の鍵 K_b):
 *     tag = HMAC-SHA256(K_b, "oz/v5/board-tag" ‖ u32be(day))[0..12 ビット], age = 0
 *     day = floor(time / 1 日) (UNIX 日)
 *   返信 (スレの鍵 K_t):
 *     tag = HMAC-SHA256(K_t, "oz/v5/thread-tag" ‖ u32be(birthDay))[0..12 ビット]
 *     age = 投稿日 - birthDay (0 以上)
 *     birthDay は thread_id に埋め込んだスレ立て日。旧形式 (10 文字) の ID は日付を持たないので、
 *     birthDay = 投稿日, age = 0 とする。
 *
 * ★ age は 90 日 (スレの寿命の上限) までで、中継も「90 超は捨てる」を検査できる。
 *   スレ立て日は tag にも入るので、同じスレのパケットは日付が違っても tag が変わらない
 *   (birthDay は固定) のに対し、板のメタは日替わりで変わる。
 */
const enc = new TextEncoder();
const BOARD_TAG_LABEL = enc.encode('oz/v5/board-tag');
const THREAD_TAG_LABEL = enc.encode('oz/v5/thread-tag');

/** 12 ビットに落とす */
function low12(mac: Uint8Array): number {
  return ((mac[0] << 8) | mac[1]) & 0x0fff;
}

/** ms → UNIX 日番号 */
export function dayOf(ms: number): number {
  return Math.floor(ms / DAY_MS);
}

function hmac(key: Uint8Array, label: Uint8Array, day: number): number {
  const msg = new Uint8Array(label.length + 4);
  msg.set(label, 0);
  msg.set(u32be(day), label.length);
  return low12(sodium.crypto_auth_hmacsha256(msg, key));
}

export function boardTag(boardKey: Uint8Array, day: number): number {
  return hmac(boardKey, BOARD_TAG_LABEL, day);
}

export function threadTag(threadKey: Uint8Array, birthDay: number): number {
  return hmac(threadKey, THREAD_TAG_LABEL, birthDay);
}

/** スレ ID から決まる birthDay。旧形式の ID なら null */
export function birthDayOfThread(threadId: string): number | null {
  const birthMs = threadBirthFromId(threadId);
  return birthMs === null ? null : dayOf(birthMs);
}

export interface TagAge {
  tag: number;
  age: number;
}

/**
 * その日を含む週の月曜 (UTC) の日番号。1970-01-01 は木曜なので (day + 3) % 7 が月曜からの日数。
 */
export function mondayOf(day: number): number {
  return day - (((day + 3) % 7) + 7) % 7;
}

/**
 * スレ立て (板のメタ) のヘッダの tag / age。timeMs は投稿の時刻。
 *
 * ★ スレ立ては週単位のバケットにまとめる (docs/design/history-v2.md §2)。age = 投稿日 − その週の月曜 (0..6)、
 *   tag は月曜の日番号で決める。保管担当から板の 90 日分のスレ一覧を取るとき、日ごとだと 90 回の
 *   問い合わせになるが、週ごとなら 13 回で済む。birthDay = 投稿日 − age = 月曜 になるので、
 *   保管担当はレスと同じ式でバケットを決められる。
 */
export function metaTagAge(boardKey: Uint8Array, timeMs: number): TagAge {
  const day = dayOf(timeMs);
  const monday = mondayOf(day);
  return { tag: boardTag(boardKey, monday), age: day - monday };
}

/**
 * 返信のヘッダの tag / age。
 * @throws RangeError スレ立てから 90 日を超えている (もう書けない)
 */
export function replyTagAge(threadKey: Uint8Array, threadId: string, timeMs: number): TagAge {
  const postDay = dayOf(timeMs);
  const birth = birthDayOfThread(threadId) ?? postDay;
  // 時計が 1 日ぶん戻っている (スレ立ての日より前に見える) 場合は 0 として扱う。読み手も同じ式で見る
  const age = Math.max(0, postDay - birth);
  if (age > POW_POLICY.MAX_AGE_DAYS) throw new RangeError(`thread is older than ${POW_POLICY.MAX_AGE_DAYS} days (age ${age})`);
  return { tag: threadTag(threadKey, birth), age };
}
