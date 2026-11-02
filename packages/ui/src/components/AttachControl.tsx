import { useEffect, useRef, useState } from 'react';
import { FileTransferError, type UploadProgress } from '@oz/core';
import { useP2P } from '../providers/P2PProvider';
import { formatBytes, maxFileBytes } from '../lib/fileLimits';
import { beginTransfer } from '../lib/transferGuard';
import { t, useT } from '../i18n';

type Upload =
  | { kind: 'idle' }
  | { kind: 'running'; name: string; size: number; placed: number; paused: boolean; phase: UploadProgress['phase'] }
  | { kind: 'error'; message: string };

function describeUploadError(e: unknown): string {
  if (e instanceof FileTransferError) {
    switch (e.code) {
      case 'no-first-hop': return t('attach.noFirstHop');
      case 'no-holders': return t('attach.noHolders');
      case 'insufficient-replicas': {
        // ★ ファイルの大きさではなく、別々の保持者 (自分以外・応答のあるもの) の数で決まる
        const r = e.replicas;
        const counts = r ? ` ${t('attach.counts', { needed: r.needed, placed: r.placed })}` : '';
        return t('attach.insufficientReplicas', { counts });
      }
      default: return t('attach.failed');
    }
  }
  return t('attach.failed');
}

/**
 * 添付ボタンと、アップロード中のカード。
 *
 * ★ 置き終えたリンクを入力欄に挿すだけで、投稿は利用者が「書き込む」で行う (時間をあけて書けるように)。
 * ★ 状態はこのコンポーネントのメモリだけ。保存しない。外れる (閉じる) と中止する。
 */
export function AttachControl({ onInsert, disabled }: { onInsert: (token: string) => void; disabled?: boolean }) {
  const t = useT();
  const { node } = useP2P();
  const [state, setState] = useState<Upload>({ kind: 'idle' });
  const inputRef = useRef<HTMLInputElement>(null);
  const handleRef = useRef<{ cancel(): void; pause(): void; resume(): void } | null>(null);
  const aliveRef = useRef(true);
  const onInsertRef = useRef(onInsert);
  onInsertRef.current = onInsert;
  const limit = maxFileBytes();

  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
      handleRef.current?.cancel();
      handleRef.current = null;
    };
  }, []);

  const start = (file: File) => {
    if (!node) { setState({ kind: 'error', message: t('attach.notReady') }); return; }
    if (file.size < 1) { setState({ kind: 'error', message: t('attach.empty') }); return; }
    if (file.size > limit) {
      setState({ kind: 'error', message: t('attach.tooBig', { size: formatBytes(file.size), limit: formatBytes(limit) }) });
      return;
    }
    const end = beginTransfer();
    let upload: ReturnType<typeof node.uploadFile>;
    try {
      upload = node.uploadFile(file, { name: file.name, mime: file.type || 'application/octet-stream' }, (p) => {
        if (!aliveRef.current || handleRef.current !== upload) return;
        setState((s) => s.kind === 'running' ? { ...s, placed: p.bytesPlaced, phase: p.phase } : s);
      });
    } catch {
      end();
      setState({ kind: 'error', message: t('attach.startFailed') });
      return;
    }
    handleRef.current = upload;
    setState({ kind: 'running', name: file.name, size: file.size, placed: 0, paused: false, phase: 'chunks' });
    upload.link.then(
      (token) => {
        end();
        if (!aliveRef.current || handleRef.current !== upload) return;
        handleRef.current = null;
        setState({ kind: 'idle' });
        onInsertRef.current(token);
      },
      (e) => {
        end();
        if (!aliveRef.current || handleRef.current !== upload) return;
        handleRef.current = null;
        // 中止は利用者の操作なので、メッセージは出さない
        setState(e instanceof FileTransferError && e.code === 'cancelled' ? { kind: 'idle' } : { kind: 'error', message: describeUploadError(e) });
      },
    );
  };

  const running = state.kind === 'running' ? state : null;
  const percent = running ? Math.min(100, Math.floor((running.placed / running.size) * 100)) : 0;
  const phaseText = !running ? '' : running.paused ? t('attach.paused')
    : running.placed === 0 && running.phase === 'chunks' ? t('attach.encrypting') : t('attach.sending');

  return (
    <div>
      <input
        ref={inputRef}
        type="file"
        aria-label={t('attach.inputLabel')}
        data-testid="attach-input"
        style={{ display: 'none' }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (f) start(f);
        }}
      />
      <button
        type="button"
        className="btn"
        style={{ fontSize: '12px' }}
        disabled={disabled || !!running}
        onClick={() => inputRef.current?.click()}
        aria-label={t('attach.buttonLabel', { limit: formatBytes(limit) })}
      >
        {t('attach.button')}
      </button>
      <span style={{ marginLeft: '8px', fontSize: '11px', color: 'var(--text-dim)' }}>{t('attach.limitNote', { limit: formatBytes(limit) })}</span>

      {state.kind === 'error' && (
        <div role="alert" style={{ marginTop: '6px', fontSize: '12px', color: 'var(--danger)' }}>{state.message}</div>
      )}

      {running && (
        <div className="card" style={{ marginTop: '8px', fontSize: '12px' }} data-testid="upload-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
            <span style={{ fontWeight: 700, wordBreak: 'break-all' }}>{running.name}</span>
            <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{formatBytes(running.size)}</span>
          </div>
          <div
            role="progressbar"
            aria-label={t('attach.progressLabel')}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            aria-valuetext={`${percent}% ${phaseText}`}
            style={{ background: 'var(--surface-3)', height: '4px', margin: '8px 0' }}
          >
            <div style={{ background: 'var(--accent-primary)', height: '100%', width: `${percent}%`, transition: 'width 0.2s' }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: 'var(--text-dim)' }}>{phaseText} ({percent}%)</span>
            <span style={{ display: 'flex', gap: '6px' }}>
              {running.paused ? (
                <button type="button" className="btn" style={{ fontSize: '11px' }} onClick={() => {
                  handleRef.current?.resume();
                  setState((s) => s.kind === 'running' ? { ...s, paused: false } : s);
                }}>{t('attach.resume')}</button>
              ) : (
                <button type="button" className="btn" style={{ fontSize: '11px' }} onClick={() => {
                  handleRef.current?.pause();
                  setState((s) => s.kind === 'running' ? { ...s, paused: true } : s);
                }}>{t('attach.pause')}</button>
              )}
              <button type="button" className="btn" style={{ fontSize: '11px' }} onClick={() => handleRef.current?.cancel()}>{t('attach.cancel')}</button>
            </span>
          </div>
          <div style={{ marginTop: '8px', color: 'var(--text-dim)', fontSize: '11px' }}>
            {t('attach.timingNote')}
          </div>
        </div>
      )}
    </div>
  );
}
