import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { LogLevel, currentLevels, setLevel, type LogRecord, type NodeDiagnostics } from '@oz/core';
import { useP2P } from '../providers/P2PProvider';
import { appLogHistory } from '../lib/logHistory';
import { describeGuardStatus } from '../lib/guardStatus';
import { useT, type MessageKey } from '../i18n';

/** 1 行の高さ (px)。行は見えている分だけ描く (5,000 行を全部 DOM にしない) */
const ROW_H = 22;
const OVERSCAN = 30;
/** 新しい行を画面へ反映する間隔 (ms)。行ごとに描き直さない */
const REFRESH_MS = 250;

const LEVEL_NAME: Record<number, string> = {
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.WARN]: 'WARN',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.TRACE]: 'TRACE',
};

/** 記録の細かさ (全体の既定 `*` を変える。ロックで既定に戻る) */
const RECORD_LEVELS: ReadonlyArray<{ name: string; label: MessageKey & `status.log.level.${string}` }> = [
  { name: 'WARN', label: 'status.log.level.warn' },
  { name: 'INFO', label: 'status.log.level.info' },
  { name: 'DEBUG', label: 'status.log.level.debug' },
  { name: 'TRACE', label: 'status.log.level.trace' },
];

function clock(at: number): string {
  const d = new Date(at);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function mib(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** 出どころの絞り込みの単位 (先頭 2 段まで。net.storage.leaseset → net.storage) */
function scopeGroup(scope: string): string {
  return scope.split('.').slice(0, 2).join('.');
}

function lineOf(r: LogRecord): string {
  return `${clock(r.at)} ${LEVEL_NAME[r.level] ?? r.level} [${r.scope}] ${r.text}`;
}

/**
 * 状態とログ: この端末の状態の数と、出たログをその場で見る画面。
 * ★ どれも端末の中の数とログだけ (網には問い合わせない)。ログはメモリだけで、ロックで消える (lib/logHistory.ts)。
 */
export function StatusLogView() {
  const t = useT();
  return (
    <div className="view-container column-content">
      <div className="page-head">
        <div>
          <div className="eyebrow">{t('status.eyebrow')}</div>
          <h1 className="page-title">{t('status.title')}</h1>
        </div>
      </div>
      <StatusGrid />
      <LogPanel />
    </div>
  );
}

function StatusGrid() {
  const t = useT();
  const { node, guardStatus } = useP2P();
  const [d, setD] = useState<NodeDiagnostics | null>(null);
  useEffect(() => {
    if (!node) return;
    const read = () => { try { setD(node.diagnostics()); } catch { /* 停止中 */ } };
    read();
    const t = setInterval(read, 2000);
    return () => clearInterval(t);
  }, [node]);
  if (!d) return null;
  const guardView = describeGuardStatus(guardStatus);
  const cells: Array<[string, string]> = [
    [t('status.cell.peers'), t('status.value.peers', { connected: d.peers.connected, verified: d.peers.verified, max: d.peers.maxDegree })],
    [t('status.cell.route'), t('status.value.route', { label: guardView.label, middles: d.route.middles })],
    [t('status.cell.service'), d.openGuardService ? t('status.value.serviceGuard') : t('status.value.serviceNormal')],
    [t('status.cell.tracker'), d.trackerConnected ? t('status.value.trackerConnected') : t('status.value.trackerIdle')],
    [t('status.cell.leaseSets'), String(d.storage.leaseSets)],
    [t('status.cell.slots'), String(d.storage.slots)],
    [t('status.cell.recent'), t('status.value.recent', { posts: d.recent.posts, size: mib(d.recent.bytes) })],
    [t('status.cell.history'), t('status.value.history', { fetches: d.history.fetches, attempts: d.history.attempts })],
    [t('status.cell.relayed'), t('status.value.relayed', { requests: d.relayed.requests, size: mib(d.relayed.bytes) })],
    [t('status.cell.dropped'), t('status.value.dropped', { relay: d.dropped.relay, rate: d.dropped.rate, preVerify: d.dropped.preVerify })],
  ];
  return (
    <div className="status-grid" aria-label={t('status.gridLabel')}>
      {cells.map(([k, v]) => (
        <div key={k} className="status-cell">
          <div className="status-key">{k}</div>
          <div className="status-val">{v}</div>
        </div>
      ))}
    </div>
  );
}

function LogPanel() {
  const t = useT();
  const [rows, setRows] = useState<LogRecord[]>(() => appLogHistory.snapshot());
  const [paused, setPaused] = useState(false);
  const [record, setRecord] = useState<string>(() => currentLevels()['*'] ?? 'WARN');
  const [onlyWarn, setOnlyWarn] = useState(false);
  const [scope, setScope] = useState('');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const [latestSeq, setLatestSeq] = useState(0);

  // 新しい行は REFRESH_MS ごとにまとめて反映する。一時停止中は表示を止め、件数だけ数える
  const dirty = useRef(true);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  useEffect(() => {
    const off = appLogHistory.subscribe(() => { dirty.current = true; });
    const t = setInterval(() => {
      if (!dirty.current) return;
      dirty.current = false;
      const snap = appLogHistory.snapshot();
      setLatestSeq(snap.length ? snap[snap.length - 1].seq : 0);
      if (!pausedRef.current) setRows(snap);
    }, REFRESH_MS);
    return () => { off(); clearInterval(t); };
  }, []);

  const scopes = useMemo(() => Array.from(new Set(rows.map(r => scopeGroup(r.scope)))).sort(), [rows]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter(r =>
      (!onlyWarn || r.level <= LogLevel.WARN) &&
      (!scope || scopeGroup(r.scope) === scope) &&
      (!q || r.text.toLowerCase().includes(q) || r.scope.includes(q)));
  }, [rows, onlyWarn, scope, query]);

  // 見えている範囲だけ描く。いちばん下に居るときは新しい行に付いていく
  const listRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(400);
  const follow = useRef(true);
  const [seenSeq, setSeenSeq] = useState(0);
  const onScroll = useCallback(() => {
    const el = listRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
    setViewH(el.clientHeight);
    follow.current = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_H;
  }, []);
  useLayoutEffect(() => {
    const el = listRef.current;
    if (!el) return;
    setViewH(el.clientHeight);
    if (follow.current && !paused) {
      el.scrollTop = el.scrollHeight;
      setScrollTop(el.scrollTop);
    }
  }, [filtered, paused]);
  const lastShown = filtered.length ? filtered[filtered.length - 1].seq : 0;
  useEffect(() => {
    if (follow.current && !paused) setSeenSeq(lastShown);
  }, [lastShown, paused]);

  // 一時停止中: 止めてから出た行の数。付いていっていないとき: 下に増えた行の数
  const pending = paused
    ? Math.max(0, latestSeq - (rows.length ? rows[rows.length - 1].seq : 0))
    : follow.current ? 0 : filtered.reduce((n, r) => n + (r.seq > seenSeq ? 1 : 0), 0);
  const jumpToLatest = () => {
    follow.current = true;
    setPaused(false);
    setRows(appLogHistory.snapshot());
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  };

  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const end = Math.min(filtered.length, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);
  const visible = filtered.slice(start, end);
  const sel = selected === null ? null : rows.find(r => r.seq === selected) ?? null;

  const changeRecord = (name: string) => {
    if (setLevel('*', name)) setRecord(name);
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(filtered.map(lineOf).join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };

  return (
    <div className="log-panel">
      <div className="log-toolbar">
        <label className="log-field">
          <span className="log-field-key">{t('status.log.record')}</span>
          <select aria-label={t('status.log.recordLabel')} value={record} onChange={(e) => changeRecord(e.target.value)}>
            {RECORD_LEVELS.map(l => <option key={l.name} value={l.name}>{t(l.label)}</option>)}
          </select>
        </label>
        <label className="log-field">
          <span className="log-field-key">{t('status.log.scope')}</span>
          <select aria-label={t('status.log.scope')} value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="">{t('status.log.scopeAll')}</option>
            {scopes.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <input
          className="log-search"
          aria-label={t('status.log.searchLabel')}
          placeholder={t('status.log.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="log-actions">
          <button className="btn btn-sm" aria-pressed={onlyWarn} onClick={() => setOnlyWarn(v => !v)}>
            {t('status.log.warnOnly')}
          </button>
          <button className="btn btn-sm" aria-pressed={paused} onClick={() => (paused ? jumpToLatest() : setPaused(true))}>
            {paused ? t('status.log.resume') : t('status.log.pause')}
          </button>
          <button className="btn btn-sm" onClick={() => { appLogHistory.clear(); setRows([]); setSelected(null); }}>
            {t('status.log.clear')}
          </button>
          <button className="btn btn-sm" onClick={copy} disabled={filtered.length === 0}>
            {copied ? t('status.log.copied') : t('status.log.copy')}
          </button>
        </div>
      </div>
      {record !== 'WARN' && (
        <div className="log-note">{t('status.log.heavyNote')}</div>
      )}

      <div className="log-list" ref={listRef} onScroll={onScroll} role="log" aria-live="off">
        {filtered.length === 0 ? (
          <div className="log-empty">{t('status.log.empty')}</div>
        ) : (
          <div style={{ height: filtered.length * ROW_H, position: 'relative' }}>
            {visible.map((r, i) => (
              <div
                key={r.seq}
                className={`log-row log-l${r.level}${selected === r.seq ? ' is-selected' : ''}`}
                style={{ top: (start + i) * ROW_H, height: ROW_H }}
                onClick={() => setSelected(r.seq === selected ? null : r.seq)}
              >
                <span className="log-time">{clock(r.at)}</span>
                <span className="log-level">{LEVEL_NAME[r.level] ?? r.level}</span>
                <span className="log-scope">{r.scope}</span>
                <span className="log-text">{r.text}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {pending > 0 && (
        <button className="log-more" onClick={jumpToLatest}>{t('status.log.newRows', { count: pending })}</button>
      )}

      <div className="log-foot">
        <span>{t('status.log.rows', { shown: filtered.length, total: rows.length })}</span>
        <span>{t('status.log.copyNote')}</span>
      </div>

      {sel && (
        <div className="log-detail" aria-label={t('status.log.selectedLabel')}>
          <div className="log-detail-head">
            <span>{clock(sel.at)}</span>
            <span className={`log-l${sel.level}`}>{LEVEL_NAME[sel.level]}</span>
            <span>{sel.scope}</span>
          </div>
          <pre className="log-detail-text">{sel.text}</pre>
        </div>
      )}
    </div>
  );
}
