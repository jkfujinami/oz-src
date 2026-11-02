"use client";

import { useEffect, useState } from "react";
import { useBoard } from "../hooks/useBoard";
import { lastActivity } from "../lib/threadOrder";
import { useP2P } from "../providers/P2PProvider";
import { needsWeakRouteConfirmation } from "../lib/guardStatus";
import { WeakRouteConfirm } from "./WeakRouteConfirm";
import { PostLimitNote } from "./PostLimitNote";
import { AttachControl } from "./AttachControl";
import { appendToken, replaceFileTokens } from "../lib/fileTokens";
import { confirmLeave } from "../lib/transferGuard";
import { copySecret } from "../lib/clipboard";
import { byteBudget, describeSubmitError } from "../lib/postLimit";
import { boardDisplayName } from "../lib/boardKeys";
import { ThreadRanker, type ThreadMeta, createLogger } from "@oz/core";
import { getBoardSort, setBoardSort, type BoardSort } from "../lib/boardSort";
import { loadReadThreads } from "../lib/readThreads";
import { relativeTime } from "../lib/relativeTime";
import { formatDateTime, useT } from "../i18n";

/** 「スレッドが見つかりませんでした」の表示 (取り終わってから) を出す段階 */
const EMPTY_VERDICT_PHASE = 'idle';

const log = createLogger('ui.board');

export default function BoardView({
  boardId,
}: {
  boardId: string;
}) {
  const t = useT();
  const { guardStatus, db } = useP2P();
  const [sort, setSort] = useState<BoardSort>(getBoardSort);
  const { threads, status, phase, submitThread, powProgress, isSubmitting, shareCode } = useBoard(boardId, sort);
  const [showForm, setShowForm] = useState(false);
  const [read, setRead] = useState<Set<string> | null>(null);
  // 相対時刻 (「3 分前」) を描き直すための時計
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    let cancelled = false;
    setRead(null);
    loadReadThreads(db, boardId).then((r) => { if (!cancelled) setRead(r); });
    return () => { cancelled = true; };
  }, [db, boardId]);
  const changeSort = (s: BoardSort) => { setBoardSort(s); setSort(s); };
  const [titleInput, setTitleInput] = useState('');
  const [copied, setCopied] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const budget = byteBudget(titleInput);

  // 送信は core が上限超過を RangeError で投げる。画面では黙って消えないよう、失敗を見せて本文は残す
  const trySubmit = async () => {
    // 確認ダイアログを開いたまま文字を足された場合も、上限を超えたものは送らない
    if (budget.over) return;
    setSubmitError(null);
    try {
      await submitThread(titleInput);
    } catch (e) {
      setSubmitError(describeSubmitError(e, t('board.subject')));
    }
  };

  // 警告状態 (最初の中継が普通の隣人) では、送る前に確認する。準備中 (待ち) は自動で待つので確認しない
  const requestSubmit = () => {
    if (budget.over) return;
    if (needsWeakRouteConfirmation(guardStatus)) setConfirming(true);
    else void trySubmit();
  };

  log.trace(() => `BoardView render: ${threads.length} threads`);

  // 共有コードは板の鍵そのもの。コピーしたら 30 秒後に消す (lib/clipboard.ts。画面を離れても消える)
  const copyShareCode = async () => {
    if (!shareCode) return;
    try {
      await copySecret(shareCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // クリップボードが使えない環境では何もしない
    }
  };

  return (
    <div className="view-container column-content">
      <div className="page-head">
        <div>
          <div className="eyebrow">OZ P2P BOARD</div>
          <h1 className="page-title">{t('board.heading', { name: boardDisplayName(boardId) })}</h1>
        </div>
        <div className="row row-wrap">
          {shareCode && (
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyShareCode}
              title={t('board.shareTitle')}
            >
              {copied ? t('board.copied') : t('board.copyShare')}
            </button>
          )}
          <button className="btn btn-sm btn-primary" onClick={() => setShowForm(true)}>
            {t('board.newThread')}
          </button>
        </div>
      </div>

      {showForm && (
        <div className="compose-inline">
          <textarea
            autoComplete="off"
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            placeholder={t('board.titlePlaceholder')}
            rows={2}
            value={titleInput}
            onChange={(e) => setTitleInput(e.target.value)}
            onKeyDown={(e) => {
              // Ctrl+Enter (macOS は ⌘+Enter) で作成、Esc で閉じる
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !isSubmitting && titleInput.trim()) {
                e.preventDefault();
                requestSubmit();
              } else if (e.key === 'Escape' && !isSubmitting && confirmLeave()) {
                setShowForm(false);
              }
            }}
            disabled={isSubmitting}
            autoFocus
          />
          <div className="compose-inline-foot">
            <PostLimitNote budget={budget} subject={t('board.subject')} />
            <div className="row row-wrap" style={{ gap: 8, justifyContent: 'flex-end' }}>
              <AttachControl
                disabled={isSubmitting}
                onInsert={(token) => { setTitleInput((prev) => appendToken(prev, token)); setSubmitError(null); }}
              />
              <button className="btn btn-sm btn-ghost" onClick={() => { if (confirmLeave()) setShowForm(false); }} disabled={isSubmitting}>
                {t('board.cancel')}
              </button>
              {isSubmitting ? (
                <button
                  className="btn btn-sm btn-progress"
                  disabled
                  style={{ backgroundImage: `linear-gradient(to right, var(--surface-3) ${powProgress}%, transparent ${powProgress}%)` }}
                >
                  {t('board.powRunning', { percent: powProgress })}
                </button>
              ) : (
                <button
                  className="btn btn-sm btn-primary"
                  disabled={budget.over || !titleInput.trim()}
                  onClick={requestSubmit}
                >
                  {t('board.create')}
                </button>
              )}
            </div>
          </div>
          <div className="compose-inline-hint">{t('board.composeHint')}</div>
          {submitError && (
            <div role="alert" className="alert alert-danger" style={{ marginTop: 10 }}>{submitError}</div>
          )}
          {confirming && (
            <WeakRouteConfirm
              onCancel={() => setConfirming(false)}
              onConfirm={() => { setConfirming(false); void trySubmit(); }}
            />
          )}
        </div>
      )}

      <div className="board-bar">
        <div className="segmented" role="tablist" aria-label={t('board.sortLabel')}>
          <button role="tab" aria-selected={sort === 'heat'} onClick={() => changeSort('heat')}>{t('board.sortHeat')}</button>
          <button role="tab" aria-selected={sort === 'new'} onClick={() => changeSort('new')}>{t('board.sortNew')}</button>
        </div>
        {/* 取得の進み具合などは一覧の上の 1 行に出す (届いたスレはすぐ一覧に並ぶ)。
            ★ 文が無いときも行は残す: 出たり消えたりで一覧の位置が動かないように (長い文は省略し、全文は title) */}
        {(() => {
          const shown = status && !(phase === EMPTY_VERDICT_PHASE && threads.length === 0) ? status : '';
          return <div className="load-status" role="status" title={shown || undefined}>{shown}</div>;
        })()}
      </div>

      {threads.length === 0 ? (
        // 取り終わってから 1 回だけ「無い」と言い、その場で立てられるようにする
        phase === EMPTY_VERDICT_PHASE ? (
          <div className="empty">
            <div>{status || t('board.empty')}</div>
            {!showForm && (
              <button className="btn btn-sm btn-primary" style={{ marginTop: 14 }} onClick={() => setShowForm(true)}>
                {t('board.newThread')}
              </button>
            )}
          </div>
        ) : null
      ) : (
        <div className="thread-table">
          <div className="thread-head" aria-hidden="true">
            <span className="thread-col-title">{t('board.colThread')}</span>
            <span className="thread-col-time">{t('board.colUpdated')}</span>
            <span className="thread-col-heat">{t('board.colHeat')}</span>
          </div>
          {threads.map((th: ThreadMeta) => {
            const url = `#board=${boardId}&thread=${th.thread_id}`;
            const score = ThreadRanker.calculateScore(th.max_pow || 0, th.created_at);
            const unread = read !== null && !read.has(th.thread_id);
            const last = lastActivity(th);
            return (
              <a key={th.thread_id} href={url} className={`thread-row${unread ? ' is-unread' : ''}`}>
                <div className="thread-col-title">
                  <div className="thread-title">{replaceFileTokens(th.content)}</div>
                  <div className="thread-meta">
                    <span>{formatDateTime(th.created_at)}</span>
                    <span>{t('board.idLabel')}<code className="mono">{th.thread_id.substring(0, 8)}</code></span>
                  </div>
                </div>
                <div className="thread-col-time" title={formatDateTime(last)}>{relativeTime(last, now)}</div>
                <div className="thread-col-heat" title={t('board.scoreTitle')}>
                  {score > 0.1 ? score.toFixed(1) : '0.1'}
                </div>
              </a>
            );
          })}
        </div>
      )}
    </div>
  );
}
