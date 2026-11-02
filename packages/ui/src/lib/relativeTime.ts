import { formatDate, getLocale, type Locale } from '../i18n';

const formats = new Map<Locale, Intl.RelativeTimeFormat>();

/** 「3 分前」「昨日」のような相対時刻 (今の言語の書き方)。7 日より前は日付 */
export function relativeTime(at: number, now: number = Date.now()): string {
  const locale = getLocale();
  let rtf = formats.get(locale);
  if (!rtf) {
    rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
    formats.set(locale, rtf);
  }
  const sec = Math.round((at - now) / 1000);
  const abs = Math.abs(sec);
  if (abs < 60) return rtf.format(0, 'second');
  if (abs < 3600) return rtf.format(Math.round(sec / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(sec / 3600), 'hour');
  if (abs < 7 * 86400) return rtf.format(Math.round(sec / 86400), 'day');
  return formatDate(at);
}
