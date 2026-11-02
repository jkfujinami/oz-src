import { useT } from '../i18n';

/**
 * 「守れること・守れないこと」の説明。
 *
 * ★ 過信による事故を防ぐための表示。誇張しないこと。
 *   ここに書いた内容は実装の到達点 (監査と修正の結果) と一致させておく。
 *   守れない範囲を広く・具体的に書くのが要点。
 */
export function SecurityInfo({ compact = false }: { compact?: boolean }) {
  const t = useT();
  return (
    <div style={{ fontSize: compact ? '11px' : '12px', lineHeight: 1.6, color: 'var(--text-dim)' }}>
      <div style={{ fontWeight: 700, color: 'var(--success)', marginBottom: '4px' }}>{t('security.canTitle')}</div>
      <ul style={{ margin: '0 0 10px 18px', padding: 0 }}>
        <li>{t('security.can1')}</li>
        <li>{t('security.can2')}</li>
        <li>{t('security.can3')}</li>
      </ul>

      <div style={{ fontWeight: 700, color: 'var(--danger)', marginBottom: '4px' }}>{t('security.cannotTitle')}</div>
      <ul style={{ margin: '0 0 0 18px', padding: 0 }}>
        <li>{t('security.cannot1')}</li>
        <li>{t('security.cannot2')}</li>
        <li>{t('security.cannot3')}</li>
        <li>{t('security.cannot4')}</li>
        <li>{t('security.cannot5')}</li>
        <li>{t('security.cannot6')}</li>
      </ul>
    </div>
  );
}
