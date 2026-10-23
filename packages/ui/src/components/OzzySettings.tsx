import { useEffect, useState } from 'react';
import { createProviderLeaseSet, isSafeExternalHttpsUrl, sodium, sodiumReady } from '@oz/core';
import { useP2P } from '../providers/P2PProvider';
import { setOzzyPrefs, useOzzyPrefs } from '../lib/ozzyPrefs';
import { OzzyWorkerForm } from './OzzyWorkerForm';

/** 設定画面の「ファイル共有」: 中継 Worker・保存先・Slab の束ね方・Gatekeeper の登録 */
export function OzzySettings() {
  const { node } = useP2P();
  const prefs = useOzzyPrefs();
  const [ownWorker, setOwnWorker] = useState<string | null>(node?.ozzyWorkerUrl ?? null);
  const [knownWorkers, setKnownWorkers] = useState<number>(0);
  const [changing, setChanging] = useState(false);
  const [gkUrl, setGkUrl] = useState('');
  const [gkBackend, setGkBackend] = useState('cloudflare-r2');
  const [gkStatus, setGkStatus] = useState<string | null>(null);

  useEffect(() => {
    setOwnWorker(node?.ozzyWorkerUrl ?? null);
    const t = setInterval(() => setKnownWorkers(node?.ozzyWorkers.size ?? 0), 2000);
    return () => clearInterval(t);
  }, [node]);

  const registerGatekeeper = async () => {
    const cleanUrl = gkUrl.trim().replace(/\/+$/, '');
    if (!isSafeExternalHttpsUrl(cleanUrl)) {
      setGkStatus('外部の HTTPS の URL を入れてください (HTTP やプライベートな IP は使えません)');
      return;
    }
    try {
      setGkStatus(`確かめています: ${cleanUrl}/ozzy/v2/status`);
      await sodiumReady;
      let freeDataSlots = 2074;
      let classACount = 0;
      let classBCount = 0;
      let statusText = '応答あり';
      try {
        const res = await fetch(`${cleanUrl}/ozzy/v2/status`, { method: 'GET', cache: 'no-store' });
        if (res.ok) {
          const data = (await res.json()) as { freeDataSlots?: number; classACount?: number; classBCount?: number };
          freeDataSlots = data.freeDataSlots ?? 2074;
          classACount = data.classACount ?? 0;
          classBCount = data.classBCount ?? 0;
        } else {
          statusText = `HTTP ${res.status}`;
        }
      } catch {
        statusText = '応答なし (登録だけ済ませました)';
      }
      const kp = sodium.crypto_sign_keypair();
      const lease = await createProviderLeaseSet({
        providerPubKey: kp.publicKey,
        providerPrivKey: kp.privateKey,
        endpoint: { workerUrl: cleanUrl, backendId: gkBackend, authToken: 'blind-token' },
        expiresAtSec: Math.floor(Date.now() / 1000) + 86400 * 30,
        freeDataSlots,
      });
      const providerIdHex = Array.from(lease.providerId.subarray(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
      setOzzyPrefs({
        registeredWorkers: [
          ...prefs.registeredWorkers.filter(w => w.workerUrl !== cleanUrl),
          { workerUrl: cleanUrl, backendId: gkBackend, providerIdHex, lease, freeDataSlots, classACount, classBCount, statusText },
        ],
      });
      setGkUrl('');
      setGkStatus(`登録しました: ${cleanUrl}`);
    } catch (err) {
      setGkStatus(`登録できませんでした: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  return (
    <div className="stack">
      <div className="subpanel">
        <div className="subpanel-title">中継 Worker</div>
        {ownWorker && !changing ? (
          <div className="stack stack-sm" style={{ marginTop: 8 }}>
            <div className="small">あなたの Worker: <code className="code-inline">{ownWorker}</code></div>
            <div className="xsmall muted">交換で知っている他の参加者の Worker: {knownWorkers} 台</div>
            <div>
              <button className="btn btn-sm" onClick={() => setChanging(true)}>変更する</button>
            </div>
          </div>
        ) : (
          <div style={{ marginTop: 8 }}>
            <OzzyWorkerForm onSaved={(url) => { setOwnWorker(url); setChanging(false); }} />
          </div>
        )}
      </div>

      <div className="subpanel">
        <div className="subpanel-title">保存先</div>
        <div className="stack stack-sm" style={{ marginTop: 8 }}>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-engine">ファイルを置く先</label>
            <select
              id="ozzy-engine"
              value={prefs.storageEngine}
              onChange={e => setOzzyPrefs({ storageEngine: e.target.value as 'overseas-multi' | 'r2-gatekeeper' })}
            >
              <option value="overseas-multi">海外ロッカー (オニオン回路の先のノードが置く)</option>
              <option value="r2-gatekeeper">Gatekeeper Worker (直接通信。IP が Gatekeeper に見える)</option>
            </select>
          </div>
          <label className="check">
            <input
              id="ozzy-live-lockers"
              type="checkbox"
              checked={prefs.useLiveLockers}
              onChange={e => setOzzyPrefs({ useLiveLockers: e.target.checked })}
            />
            <span>
              <strong>実機のロッカーへ置く</strong>
              <span className="muted"> (外すと、メモリ上のロッカーで試します。通信しません)</span>
            </span>
          </label>
          <label className="check">
            <input
              id="ozzy-fast-chunk"
              type="checkbox"
              checked={prefs.useFastDemoChunk}
              onChange={e => setOzzyPrefs({ useFastDemoChunk: e.target.checked })}
            />
            <span>
              <strong>小さいチャンクで試す</strong>
              <span className="muted"> (64 KiB。外すと本番の 4 MiB)</span>
            </span>
          </label>
        </div>
      </div>

      <div className="subpanel">
        <div className="subpanel-title">Slab の束ね方</div>
        <div className="field-grid" style={{ marginTop: 8 }}>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-batch">1 本の Slab のチャンク数</label>
            <input
              id="ozzy-batch"
              type="number"
              min={2}
              max={16}
              value={prefs.targetBatchChunks}
              onChange={e => setOzzyPrefs({ targetBatchChunks: Math.min(16, Math.max(2, parseInt(e.target.value || '8', 10))) })}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-idle">揃わないとき待つ時間 (ms)</label>
            <input
              id="ozzy-idle"
              type="number"
              min={20}
              max={60000}
              value={prefs.idleGapMs}
              onChange={e => setOzzyPrefs({ idleGapMs: Math.max(20, parseInt(e.target.value || '120', 10)) })}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-maxwait">待つ時間の上限 (ms)</label>
            <input
              id="ozzy-maxwait"
              type="number"
              min={50}
              max={180000}
              value={prefs.maxWaitMs}
              onChange={e => setOzzyPrefs({ maxWaitMs: Math.max(50, parseInt(e.target.value || '400', 10)) })}
            />
          </div>
        </div>
      </div>

      <div className="subpanel">
        <div className="subpanel-title">Gatekeeper Worker の登録 (セカンダリ互換)</div>
        <div className="stack stack-sm" style={{ marginTop: 8 }}>
          <div className="row row-wrap" style={{ gap: 8 }}>
            <input
              id="ozzy-gk-url"
              type="text"
              className="mono"
              aria-label="Gatekeeper Worker の URL"
              placeholder="https://ozzy-gatekeeper.<subdomain>.workers.dev"
              value={gkUrl}
              onChange={e => setGkUrl(e.target.value)}
              style={{ flex: '1 1 240px', minWidth: 0 }}
            />
            <select
              id="ozzy-gk-backend"
              aria-label="バックエンド"
              value={gkBackend}
              onChange={e => setGkBackend(e.target.value)}
              style={{ width: 'auto' }}
            >
              <option value="cloudflare-r2">cloudflare-r2</option>
              <option value="backblaze-b2">backblaze-b2</option>
              <option value="oracle-s3">oracle-s3</option>
            </select>
            <button className="btn btn-sm" onClick={() => void registerGatekeeper()} disabled={!gkUrl.trim()}>
              登録
            </button>
          </div>
          <label className="check">
            <input
              id="ozzy-gk-only"
              type="checkbox"
              checked={prefs.useOnlyRealWorkers}
              onChange={e => setOzzyPrefs({ useOnlyRealWorkers: e.target.checked })}
            />
            <span>登録した Gatekeeper だけを使う</span>
          </label>
          {gkStatus && <div className="msg msg-info" role="status">{gkStatus}</div>}
          {prefs.registeredWorkers.map(w => (
            <div key={w.workerUrl} className="worker-row">
              <span className="mono">{w.workerUrl} [{w.backendId}]</span>
              <span className="badge badge-neutral">{w.statusText}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
