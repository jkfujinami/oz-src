import { useT } from '../i18n';
import { type ByteBudget, MAX_POST_BYTES, remainingLabel } from '../lib/postLimit';

/**
 * 入力欄の下に出す残りバイト数。残りが少ないと黄色、超えると赤にする。
 * 超えているときは、送信できない理由をそのまま書く。
 */
export function PostLimitNote({ budget, subject }: { budget: ByteBudget; subject: string }) {
  const t = useT();
  const color = budget.over ? 'var(--danger)' : budget.nearLimit ? 'var(--warn)' : 'var(--text-dim)';
  return (
    <div style={{ fontSize: '12px', color }} aria-live="polite">
      <span>{remainingLabel(budget)}</span>
      {budget.over && (
        <span style={{ marginLeft: '8px' }}>
          {t('postLimit.note', { subject, max: MAX_POST_BYTES })}
        </span>
      )}
    </div>
  );
}
