import { POW_POLICY } from '../crypto/PowPolicy';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * スレッドの上限と寿命 (2026-10-14 決定)。
 *
 * ★ 数えるのは読む側 (スレ鍵を持つ端末)。中継や保管担当は中身を読めないので数えられない。
 *
 * ★ 上限は「並べて先頭から 1000 件」ではなく、投稿ごとの祖先 (親を辿って届く過去の投稿)
 *   で判定する。祖先は packet_id に固定されていて後から変わらないので、後から来た投稿が
 *   既存の投稿を押し出すことはできない。並び順で数えると、時刻を 15 分前まで遡って名乗り、
 *   古い投稿を親に指定した投稿で、末尾の正規の投稿を上限の外へ押し出せた。
 *
 * ★ 容量は本文 (UTF-8) だけで数える。付帯データ (1 レス約 330B) を含めると、
 *   1000 レスで約 330KB を食い、本文に約 190KB しか残らない。
 */
export const THREAD_LIMITS = {
  /** 1 スレのレス数の上限。祖先の数 + 1 (= その投稿のレス番号相当) がこれ以下なら入る */
  MAX_POSTS: 1000,
  /** 1 スレの本文の合計 (UTF-8 バイト)。祖先と自分の本文の合計がこれ以下なら入る */
  MAX_CONTENT_BYTES: 512 * 1024,
  /**
   * 埋まった後の猶予。埋まった時刻からこれより後の日付の投稿は表示しない。
   * 網が受け付ける時刻のずれ (MAX_TIME_DRIFT) と揃える: 同時に書かれた正規の投稿は残し、
   * 埋まった後に古い投稿を親に指定して割り込む投稿は落とす。
   */
  CLOSE_GRACE_MS: POW_POLICY.MAX_TIME_DRIFT,
  /** 過疎: 最後の書き込みからこれだけ書き込みが無ければ落ちる */
  IDLE_EXPIRY_MS: 30 * DAY_MS,
  /** 寿命の上限: スレ立てからこれを過ぎたら、書き込みが続いていても落ちる */
  MAX_LIFETIME_MS: 90 * DAY_MS,
} as const;

/**
 * スレッドが落ちる時刻。
 *
 * ★ 寿命の上限 (スレ立て + 90 日) が要る。上限がないと、30 日に 1 回書き込むだけで
 *   完走スレ (付帯込み約 850KB) を保管担当に持たせ続けられ、保管の総量が
 *   「直近 90 日に書かれた量」に収まらなくなる。
 *
 * @param birthAt スレ立ての時刻 (ms)
 * @param lastPostAt 最後に表示される書き込みの時刻 (ms)。無ければ null (スレ立てから数える)
 */
export function threadExpiresAt(birthAt: number, lastPostAt: number | null): number {
  const last = lastPostAt === null ? birthAt : Math.max(birthAt, lastPostAt);
  return Math.min(birthAt + THREAD_LIMITS.MAX_LIFETIME_MS, last + THREAD_LIMITS.IDLE_EXPIRY_MS);
}

/** スレッド ID の先頭に置く「スレ立て日」(UTC の日番号を 36 進 4 桁) */
const BIRTH_DAY_CHARS = 4;
/** スレッド ID の乱数部の長さ (旧形式の ID はこれだけ) */
export const THREAD_ID_RANDOM_CHARS = 10;
const THREAD_ID_PATTERN = /^[0-9a-z]+$/;

/**
 * スレ立て日を埋め込んだスレッド ID を作る。
 *
 * ★ 寿命の起点 (スレ立て時刻) を、スレ立てのパケットの時刻から取ってはいけない。
 *   板の鍵を持つ者なら誰でも、同じスレッド ID で日付を遡ったスレ立てを作れ、
 *   過去ログの経路は古い日付を受け付ける (Guard の追いつきは PacketValidator の maxPastMs で 72 時間 + 15 分まで)。
 *   「最も古いスレ立て」を起点にすると他人のスレを早死にさせられ、
 *   「最も新しいスレ立て」を起点にすると、今日の日付で作り直して寿命の上限を延ばせる。
 *   ID に日付を入れれば、偽のスレ立ても同じ ID = 同じ日付になるので、起点は動かない。
 *
 * @param random 乱数部 (CryptoUtils.generateId(THREAD_ID_RANDOM_CHARS))
 */
export function makeThreadId(now: number, random: string): string {
  const day = Math.floor(now / DAY_MS);
  return day.toString(36).padStart(BIRTH_DAY_CHARS, '0') + random;
}

/**
 * スレッド ID から寿命の起点 (スレ立て日の 0 時、UTC) を取り出す。
 * 旧形式 (乱数だけの 10 文字) なら null。
 */
export function threadBirthFromId(threadId: string): number | null {
  if (typeof threadId !== 'string' || threadId.length !== BIRTH_DAY_CHARS + THREAD_ID_RANDOM_CHARS) return null;
  if (!THREAD_ID_PATTERN.test(threadId)) return null;
  const day = parseInt(threadId.slice(0, BIRTH_DAY_CHARS), 36);
  return Number.isSafeInteger(day) ? day * DAY_MS : null;
}

/**
 * スレ立てのパケットの時刻が、ID に埋め込んだ日付と合っているか。
 * 合わないスレ立ては受け付けない (未来の日付の ID で寿命を延ばす手も、ここで止まる)。
 * 旧形式の ID は検査できないので true。
 */
export function isThreadMetaTimeConsistent(threadId: string, createdAt: number): boolean {
  const birth = threadBirthFromId(threadId);
  if (birth === null) return true;
  return createdAt >= birth - POW_POLICY.MAX_TIME_DRIFT && createdAt < birth + DAY_MS + POW_POLICY.MAX_TIME_DRIFT;
}
