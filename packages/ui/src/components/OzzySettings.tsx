import { useEffect, useState } from 'react';
import { createProviderLeaseSet, isSafeExternalHttpsUrl, sodium, sodiumReady } from '@oz/core';
import { useP2P } from '../providers/P2PProvider';
import { setOzzyPrefs, useOzzyPrefs } from '../lib/ozzyPrefs';
import { OzzyWorkerForm } from './OzzyWorkerForm';
import { tRich, useT } from '../i18n';

/** 設定画面の「ファイル共有」: 中継 Worker・保存先・Slab の束ね方・Gatekeeper の登録 */
export function OzzySettings() {
  const t = useT();
  const { node } = useP2P();
  const prefs = useOzzyPrefs();
  const [ownWorker, setOwnWorker] = useState<string | null>(node?.ozzyWorkerUrl ?? null);
  const [knownWorkers, setKnownWorkers] = useState<number>(0);
  const [changing, setChanging] = useState(false);
  const [fetcherOn, setFetcherOn] = useState<boolean>(node?.ozzyFetcherEnabled ?? false);
  const [fetcherError, setFetcherError] = useState<string | null>(null);
  const [gkUrl, setGkUrl] = useState('');
  const [gkBackend, setGkBackend] = useState('cloudflare-r2');
  const [gkStatus, setGkStatus] = useState<string | null>(null);

  useEffect(() => {
    setOwnWorker(node?.ozzyWorkerUrl ?? null);
    setFetcherOn(node?.ozzyFetcherEnabled ?? false);
    const timer = setInterval(() => setKnownWorkers(node?.ozzyWorkers.size ?? 0), 2000);
    return () => clearInterval(timer);
  }, [node]);

  const registerGatekeeper = async () => {
    const cleanUrl = gkUrl.trim().replace(/\/+$/, '');
    if (!isSafeExternalHttpsUrl(cleanUrl)) {
      setGkStatus(t('settings.ozzy.badUrl'));
      return;
    }
    try {
      setGkStatus(t('settings.ozzy.checking', { url: cleanUrl }));
      await sodiumReady;
      let freeDataSlots = 2074;
      let classACount = 0;
      let classBCount = 0;
      let statusText = t('settings.ozzy.responded');
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
        statusText = t('settings.ozzy.noResponse');
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
      setGkStatus(t('settings.ozzy.registered', { url: cleanUrl }));
    } catch (err) {
      setGkStatus(t('settings.ozzy.registerFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  const switchFetcher = async (on: boolean) => {
    if (!node) return;
    setFetcherError(null);
    try {
      await node.setOzzyFetcherEnabled(on);
      setFetcherOn(node.ozzyFetcherEnabled);
    } catch (err) {
      setFetcherError(t('settings.ozzy.switchFailed', { reason: err instanceof Error ? err.message : String(err) }));
    }
  };

  return (
    <div className="stack">
      {node?.ozzyDirect ? (
        <div className="subpanel">
          <div className="subpanel-title">{t('settings.ozzy.lockersTitle')}</div>
          <div className="stack stack-sm" style={{ marginTop: 8 }}>
            <div className="small">{t('settings.ozzy.directNote')}</div>
            <label className="check">
              <input
                id="ozzy-fetcher"
                type="checkbox"
                checked={fetcherOn}
                onChange={e => void switchFetcher(e.target.checked)}
              />
              <span>
                <strong>{t('settings.ozzy.fetcher')}</strong>
                <span className="muted">
                  {' '}{t('settings.ozzy.fetcherNote')}
                </span>
              </span>
            </label>
            {fetcherError && <div className="msg msg-warn" role="status">{fetcherError}</div>}
          </div>
        </div>
      ) : (
      <div className="subpanel">
        <div className="subpanel-title">{t('settings.ozzy.workerTitle')}</div>
        {ownWorker && !changing ? (
          <div className="stack stack-sm" style={{ marginTop: 8 }}>
            <div className="small">{tRich('settings.ozzy.ownWorker', { code: (c) => <code className="code-inline">{c}</code> }, { url: ownWorker })}</div>
            <div className="xsmall muted">{t('settings.ozzy.knownWorkers', { count: knownWorkers })}</div>
            <div>
              <button className="btn btn-sm" onClick={() => setChanging(true)}>{t('settings.ozzy.change')}</button>
            </div>
          </div>
        ) : (
          <div style={{ marginTop: 8 }}>
            <OzzyWorkerForm onSaved={(url) => { setOwnWorker(url); setChanging(false); }} />
          </div>
        )}
      </div>
      )}

      <div className="subpanel">
        <div className="subpanel-title">{t('settings.ozzy.storageTitle')}</div>
        <div className="stack stack-sm" style={{ marginTop: 8 }}>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-engine">{t('settings.ozzy.engineLabel')}</label>
            <select
              id="ozzy-engine"
              value={prefs.storageEngine}
              onChange={e => setOzzyPrefs({ storageEngine: e.target.value as 'overseas-multi' | 'r2-gatekeeper' })}
            >
              <option value="overseas-multi">{t('settings.ozzy.engineOverseas')}</option>
              <option value="r2-gatekeeper">{t('settings.ozzy.engineGatekeeper')}</option>
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
              <strong>{t('settings.ozzy.liveLockers')}</strong>
              <span className="muted">{t('settings.ozzy.liveLockersNote')}</span>
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
              <strong>{t('settings.ozzy.fastChunk')}</strong>
              <span className="muted">{t('settings.ozzy.fastChunkNote')}</span>
            </span>
          </label>
        </div>
      </div>

      <div className="subpanel">
        <div className="subpanel-title">{t('settings.ozzy.slabTitle')}</div>
        <div className="field-grid" style={{ marginTop: 8 }}>
          <div className="field">
            <label className="field-label" htmlFor="ozzy-batch">{t('settings.ozzy.batchLabel')}</label>
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
            <label className="field-label" htmlFor="ozzy-idle">{t('settings.ozzy.idleLabel')}</label>
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
            <label className="field-label" htmlFor="ozzy-maxwait">{t('settings.ozzy.maxWaitLabel')}</label>
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
        <div className="subpanel-title">{t('settings.ozzy.gkTitle')}</div>
        <div className="stack stack-sm" style={{ marginTop: 8 }}>
          <div className="row row-wrap" style={{ gap: 8 }}>
            <input
              id="ozzy-gk-url"
              type="text"
              className="mono"
              aria-label={t('settings.ozzy.gkUrlLabel')}
              placeholder="https://ozzy-gatekeeper.<subdomain>.workers.dev"
              value={gkUrl}
              onChange={e => setGkUrl(e.target.value)}
              style={{ flex: '1 1 240px', minWidth: 0 }}
            />
            <select
              id="ozzy-gk-backend"
              aria-label={t('settings.ozzy.backendLabel')}
              value={gkBackend}
              onChange={e => setGkBackend(e.target.value)}
              style={{ width: 'auto' }}
            >
              <option value="cloudflare-r2">cloudflare-r2</option>
              <option value="backblaze-b2">backblaze-b2</option>
              <option value="oracle-s3">oracle-s3</option>
            </select>
            <button className="btn btn-sm" onClick={() => void registerGatekeeper()} disabled={!gkUrl.trim()}>
              {t('settings.ozzy.register')}
            </button>
          </div>
          <label className="check">
            <input
              id="ozzy-gk-only"
              type="checkbox"
              checked={prefs.useOnlyRealWorkers}
              onChange={e => setOzzyPrefs({ useOnlyRealWorkers: e.target.checked })}
            />
            <span>{t('settings.ozzy.gkOnly')}</span>
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
