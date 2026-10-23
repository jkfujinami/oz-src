import { useState } from 'react';
import { useP2P } from '../providers/P2PProvider';

const REASON_TEXT = {
  'bad-url': 'https://<名前>.<サブドメイン>.workers.dev の形で入れてください (独自ドメインは使えません)',
  unreachable: 'Worker に届きません。デプロイが終わっているか、URL が合っているか確かめてください',
  'not-ozzy': 'OZ の中継 Worker ではありません。配布ページの OZ-worker を設置してください',
  outdated: 'Worker の版が古いです。最新の OZ-worker で設置し直してください',
} as const;

/** 自分の中継 Worker の URL を確かめて設定する欄 (ファイル共有の最初の画面と、設定画面で使う) */
export function OzzyWorkerForm({ onSaved }: { onSaved?: (url: string | null) => void }) {
  const { node } = useP2P();
  const [input, setInput] = useState<string>('');
  const [status, setStatus] = useState<string | null>(null);

  if (!node) return <div className="msg msg-warn">ロックを解除してから設定してください</div>;

  const save = async () => {
    setStatus('確かめています...');
    const res = await node.setOzzyWorker(input);
    if (res.ok) {
      setStatus('設定しました');
      setInput('');
      onSaved?.(node.ozzyWorkerUrl);
      return;
    }
    setStatus(REASON_TEXT[res.reason]);
  };

  return (
    <div className="stack stack-sm">
      <div className="row row-wrap" style={{ gap: 8 }}>
        <input
          id="ozzy-worker-url"
          type="text"
          className="mono"
          aria-label="中継 Worker の URL"
          placeholder="https://ozzy-gatekeeper.<subdomain>.workers.dev"
          value={input}
          onChange={e => setInput(e.target.value)}
          style={{ flex: '1 1 240px', minWidth: 0 }}
        />
        <button className="btn btn-primary" onClick={() => void save()} disabled={!input.trim()}>
          確かめて設定
        </button>
      </div>
      {status && <div className="msg msg-info" role="status">{status}</div>}
    </div>
  );
}
