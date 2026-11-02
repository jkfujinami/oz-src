import { useEffect, useRef, useState } from 'react';
import { FileTransferError, sanitizeFileName, sanitizeMime, type FileLink } from '@oz/core';
import { useP2P } from '../providers/P2PProvider';
import { canPreview, formatBytes, maxFileBytes } from '../lib/fileLimits';
import { beginTransfer } from '../lib/transferGuard';
import { t, useT } from '../i18n';

type Dl =
  | { kind: 'idle' }
  | { kind: 'running'; phase: 'manifest' | 'chunks' | 'done'; done: number; name: string | null }
  | { kind: 'done'; name: string; mime: string }
  | { kind: 'error'; message: string };

function describeDownloadError(e: unknown): string {
  if (e instanceof FileTransferError) {
    switch (e.code) {
      case 'no-first-hop': return t('fileCard.noFirstHop');
      case 'bad-link':
      case 'bad-manifest': return t('fileCard.badLink');
      case 'unavailable':
      case 'no-holders': return t('fileCard.unavailable');
      default: return t('fileCard.failed');
    }
  }
  return t('fileCard.failed');
}

/**
 * 投稿の中の添付ファイルのカード。
 *
 * ★ 勝手には取らない: 取得すると最初の中継先に「この人はこのファイルに興味がある」と見えるため、
 *   「取得」を押したときだけ動く。画像のプレビューも取得後だけ。
 * ★ 取りかけ・取り終えた中身はこのコンポーネントのメモリ (Blob) だけ。画面を離れると捨てる。
 */
export function FileCard({ token, link }: { token: string; link: FileLink }) {
  const t = useT();
  const { node } = useP2P();
  const [state, setState] = useState<Dl>({ kind: 'idle' });
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const blobRef = useRef<Blob | null>(null);
  const cancelRef = useRef<(() => void) | null>(null);
  const aliveRef = useRef(true);
  const previewRef = useRef<string | null>(null);
  const tooBig = link.size > maxFileBytes();

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
      cancelRef.current?.();
      if (previewRef.current) URL.revokeObjectURL(previewRef.current);
      previewRef.current = null;
      blobRef.current = null;
    };
  }, []);

  const start = async () => {
    if (!node) { setState({ kind: 'error', message: t('fileCard.notReady') }); return; }
    const end = beginTransfer();
    let name: string | null = null;
    setState({ kind: 'running', phase: 'manifest', done: 0, name: null });
    let dl: ReturnType<typeof node.downloadFile>;
    try {
      dl = node.downloadFile(token, (p) => {
        if (!aliveRef.current) return;
        setState((s) => s.kind === 'running' ? { ...s, phase: p.phase, done: p.bytesDone } : s);
      });
    } catch {
      end();
      setState({ kind: 'error', message: t('fileCard.startFailed') });
      return;
    }
    cancelRef.current = () => dl.cancel();
    try {
      const manifest = await dl.manifest;
      name = sanitizeFileName(manifest.name);
      if (aliveRef.current) setState((s) => s.kind === 'running' ? { ...s, name } : s);
      const parts: Uint8Array[] = [];
      for await (const piece of dl) parts.push(piece);
      if (!aliveRef.current) return;
      const mime = sanitizeMime(manifest.mime);
      const previewable = canPreview(mime, manifest.size);
      // ★ 保存用の Blob の型は、画像として出すもの以外は汎用にする (送り手が決めた型を信用しない)
      const blob = new Blob(parts as BlobPart[], { type: previewable ? mime : 'application/octet-stream' });
      blobRef.current = blob;
      if (previewable) {
        const url = URL.createObjectURL(blob);
        previewRef.current = url;
        setPreviewUrl(url);
      }
      setState({ kind: 'done', name, mime });
    } catch (e) {
      if (!aliveRef.current) return;
      setState(e instanceof FileTransferError && e.code === 'cancelled' ? { kind: 'idle' } : { kind: 'error', message: describeDownloadError(e) });
    } finally {
      cancelRef.current = null;
      end();
    }
  };

  // ★ 保存のたびに Blob URL を作り、押し終わったら破棄する
  const save = () => {
    if (state.kind !== 'done' || !blobRef.current) return;
    const url = URL.createObjectURL(blobRef.current);
    const a = document.createElement('a');
    a.href = url;
    a.download = state.name;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const percent = state.kind === 'running' ? Math.min(100, Math.floor((state.done / link.size) * 100)) : 0;
  const title = state.kind === 'running' && state.name ? state.name
    : state.kind === 'done' ? state.name
    : t('fileCard.title', { size: formatBytes(link.size) });

  return (
    <div className="card file-card" data-testid="file-card">
      <div className="file-card-head">
        <span className="row" style={{ minWidth: 0 }}>
          <span className="file-icon" aria-hidden="true">📎</span>
          <span className="strong break">{title}</span>
          {(state.kind === 'running' || state.kind === 'done') && (
            <span className="muted" style={{ flex: 'none' }}>{t('fileCard.sizeNote', { size: formatBytes(link.size) })}</span>
          )}
        </span>
        <div style={{ flex: 'none' }}>
          {(state.kind === 'idle' || state.kind === 'error') && (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={tooBig}
              onClick={() => void start()}
              aria-label={t('fileCard.getLabel', { size: formatBytes(link.size) })}
            >
              {t('fileCard.get')}
            </button>
          )}
          {state.kind === 'running' && (
            <button type="button" className="btn btn-sm" onClick={() => cancelRef.current?.()}>{t('fileCard.cancel')}</button>
          )}
          {state.kind === 'done' && (
            <button type="button" className="btn btn-sm btn-primary" onClick={save} aria-label={t('fileCard.saveLabel', { name: state.name })}>
              {t('fileCard.save')}
            </button>
          )}
        </div>
      </div>
      {tooBig && state.kind === 'idle' && (
        <div className="alert alert-warn" style={{ marginTop: 8 }}>
          {t('fileCard.tooBig', { limit: formatBytes(maxFileBytes()) })}
        </div>
      )}
      {state.kind === 'idle' && !tooBig && (
        <div className="xsmall muted" style={{ marginTop: 6 }}>
          {t('fileCard.visibleNote')}
        </div>
      )}
      {state.kind === 'running' && (
        <div style={{ marginTop: 10 }}>
          <div
            role="progressbar"
            aria-label={t('fileCard.progressLabel')}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            className="progress"
          >
            <span style={{ width: `${percent}%` }} />
          </div>
          <div className="xsmall muted" style={{ marginTop: 4 }}>
            {state.phase === 'manifest' ? t('fileCard.fetchingInfo') : t('fileCard.fetching', { percent })}
          </div>
        </div>
      )}
      {state.kind === 'error' && (
        <div role="alert" className="msg msg-error" style={{ marginTop: 6 }}>{state.message}</div>
      )}
      {state.kind === 'done' && previewUrl && (
        <img
          src={previewUrl}
          alt={state.name}
          style={{ maxWidth: '100%', maxHeight: '360px', marginTop: 10, display: 'block', borderRadius: 'var(--r-sm)' }}
        />
      )}
    </div>
  );
}
