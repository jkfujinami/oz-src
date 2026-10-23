/**
 * 推奨 effort で PoW が重くなったときの案内 (A3)。
 * ★ 最低 effort は一瞬で終わるので何も出さない。網が混んで推奨が上がり、PoW が約 2 秒を超えそうなときだけ
 *   出す。利用者に見せるのは「混んでいる」ことだけで、数値や仕組みは見せない。
 */
export const CONGESTION_NOTICE = '混雑しているため、送信の準備に少し時間がかかります';
/** これを超える見込みのときに案内する (ms) */
export const SLOW_POW_NOTICE_MS = 2000;
