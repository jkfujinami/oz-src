import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { useT, type MessageKey } from '../i18n';

const REASON_KEY = {
  'bad-url': 'ozzyWorker.reason.badUrl',
  unreachable: 'ozzyWorker.reason.unreachable',
  'not-ozzy': 'ozzyWorker.reason.notOzzy',
  outdated: 'ozzyWorker.reason.outdated',
  direct: 'ozzyWorker.reason.direct',
} as const satisfies Record<string, MessageKey>;

/** 自分の中継 Worker の URL を確かめて設定する欄 (ファイル共有の最初の画面と、設定画面で使う) */
export function OzzyWorkerForm({ onSaved }: { onSaved?: (url: string | null) => void }) {
  const t = useT();
  const { node } = useP2P();
  const [input, setInput] = useState<string>('');
  const [status, setStatus] = useState<string | null>(null);

  if (!node) return <div className="msg msg-warn">{t('ozzyWorker.locked')}</div>;

  const save = async () => {
    setStatus(t('ozzyWorker.checking'));
    const res = await node.setOzzyWorker(input);
    if (res.ok) {
      setStatus(t('ozzyWorker.done'));
      setInput('');
      onSaved?.(node.ozzyWorkerUrl);
      return;
    }
    setStatus(t(REASON_KEY[res.reason]));
  };

  return (
    <div className="stack stack-sm">
      <div className="row row-wrap" style={{ gap: 8 }}>
        <input
          id="ozzy-worker-url"
          type="text"
          className="mono"
          aria-label={t('ozzyWorker.urlLabel')}
          placeholder="https://ozzy-gatekeeper.<subdomain>.workers.dev"
          value={input}
          onChange={e => setInput(e.target.value)}
          style={{ flex: '1 1 240px', minWidth: 0 }}
        />
        <button className="btn btn-primary" onClick={() => void save()} disabled={!input.trim()}>
          {t('ozzyWorker.save')}
        </button>
      </div>
      {status && <div className="msg msg-info" role="status">{status}</div>}
    </div>
  );
}
