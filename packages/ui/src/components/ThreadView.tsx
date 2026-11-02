"use client";

import { useState, useEffect, useMemo, useRef, KeyboardEvent, MouseEvent } from "react";
import { useThread } from "../hooks/useThread";
import { useP2P } from "../providers/P2PProvider";
import { needsWeakRouteConfirmation } from "../lib/guardStatus";
import { WeakRouteConfirm } from "./WeakRouteConfirm";
import { PostLimitNote } from "./PostLimitNote";
import { AttachControl } from "./AttachControl";
import { PostBody } from "./PostBody";
import { appendToken } from "../lib/fileTokens";
import { appendAnchor } from "../lib/anchor";
import { confirmLeave } from "../lib/transferGuard";
import { navigate } from "../lib/route";
import { byteBudget, describeSubmitError } from "../lib/postLimit";
import { boardDisplayName } from "../lib/boardKeys";
import { KeyManager, THREAD_LIMITS, createLogger, posterId } from "@oz/core";
import { formatDateTime, useT } from "../i18n";

const log = createLogger('ui.thread');

/** 残りが少なくなったことを知らせ始めるレス数 */
const NEAR_POSTS = 900;

/**
 * 本文の整形 (HTML エスケープと >>N の印)。
 * ★ 部品の外に置いて毎回同じ関数にする: PostBody は本文と整形が同じなら描き直さない (書き込み欄に打つたびに
 *   全レスの本文の DOM を作り直さない。作り直すと、>>N に乗せた小窓の出し消しも乱れる)
 */
function formatContent(content: string): string {
  const sanitized = content
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return sanitized.replace(
    /&gt;&gt;(\d+)/g,
    '<span class="anchor" data-anchor="$1">&gt;&gt;$1</span>'
  );
}

/** 各レスの DOM id。>>N のジャンプ先に使う (packet_id は 16 進なので id にそのまま使える) */
const postElementId = (packetId: string) => `post-${packetId}`;

export default function ThreadView({
  boardId,
  threadId,
}: {
  boardId: string;
  threadId: string;
}) {
  const t = useT();
  const {
    posts, status, submitReply,
    powProgress, isSubmitting, postStatus, threadState: state, resolveAnchor,
  } = useThread(boardId, threadId);

  const [replyInput, setReplyInput] = useState('');
  const replyRef = useRef<HTMLTextAreaElement>(null);
  const { guardStatus } = useP2P();
  const [confirming, setConfirming] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const budget = byteBudget(replyInput);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (highlightTimer.current) clearTimeout(highlightTimer.current); }, []);

  // 新着: レスの一覧の最後が見えている間 (と、開いた直後の読み込み中) は全部読んだことにする。
  // 見えていない間に届いたレスは数だけ出す (画面は勝手に動かさない)
  const endRef = useRef<HTMLDivElement>(null);
  const [atEnd, setAtEnd] = useState(true);
  useEffect(() => {
    const el = endRef.current;
    if (!el || typeof IntersectionObserver === 'undefined') return;
    // 下に貼り付いた書き込み欄に隠れている分は「見えていない」
    const io = new IntersectionObserver(([e]) => setAtEnd(e.isIntersecting), { rootMargin: '0px 0px -220px 0px' });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  const [seen, setSeen] = useState<ReadonlySet<string>>(() => new Set());
  const markAll = atEnd || !!status;
  useEffect(() => {
    if (!markAll) return;
    // 同じ中身なら作り直さない (描き直しの連鎖を起こさない)
    setSeen((prev) => (prev.size === posts.length && posts.every((p) => prev.has(p.packet_id)) ? prev : new Set(posts.map((p) => p.packet_id))));
  }, [markAll, posts]);
  const unseen = markAll ? [] : posts.filter((p) => !seen.has(p.packet_id));
  const jumpToNew = () => {
    const first = unseen[0];
    if (first) document.getElementById(postElementId(first.packet_id))?.scrollIntoView?.({ block: 'start' });
    setSeen(new Set(posts.map((p) => p.packet_id)));
  };

  // >>n に乗せると、指しているレスを小窓で見せる
  const [preview, setPreview] = useState<{ id: string; left: number; top: number; above: boolean } | null>(null);
  const indexById = useMemo(() => new Map(posts.map((p, i) => [p.packet_id, i])), [posts]);
  useEffect(() => {
    if (!preview) return;
    const hide = () => setPreview(null);
    window.addEventListener('scroll', hide, true);
    return () => window.removeEventListener('scroll', hide, true);
  }, [preview]);
  const showPreview = (e: MouseEvent<HTMLElement>, packetId: string) => {
    const el = (e.target as HTMLElement).closest?.('[data-anchor]') as HTMLElement | null;
    if (!el) return;
    const n = Number(el.dataset.anchor);
    const target = Number.isSafeInteger(n) ? resolveAnchor?.(packetId, n) : null;
    if (!target || !indexById.has(target)) return;
    const r = el.getBoundingClientRect();
    const above = r.bottom > window.innerHeight * 0.6;
    setPreview({ id: target, left: Math.max(8, r.left), top: above ? r.top - 6 : r.bottom + 6, above });
  };
  const hidePreview = (e: MouseEvent<HTMLElement>) => {
    if ((e.target as HTMLElement).closest?.('[data-anchor]')) setPreview(null);
  };

  // 書き込める状態か。埋まった・落ちたスレには書き込み欄を出さない (core も送信時に断る)
  const closedNotice = state?.expired ? t('thread.expiredNotice')
    : state?.closed ? (state.closeReason === 'bytes' ? t('thread.bytesNotice') : t('thread.postsNotice'))
    : null;
  const remainingPosts = THREAD_LIMITS.MAX_POSTS - (state?.visibleCount ?? 0);
  const remainingBytes = THREAD_LIMITS.MAX_CONTENT_BYTES - (state?.contentBytes ?? 0);
  const nearPosts = !closedNotice && (state?.visibleCount ?? 0) >= NEAR_POSTS;
  const nearBytes = !closedNotice && (state?.contentBytes ?? 0) >= THREAD_LIMITS.MAX_CONTENT_BYTES * 0.9;
  // 概算。core が送信前に正確に判定する
  const overThread = budget.used > 0 && budget.used > remainingBytes;

  log.trace(() => `ThreadView render: ${posts.length} posts`);

  const handleBodyClick = (e: MouseEvent<HTMLElement>, packetId: string) => {
    const el = (e.target as HTMLElement).closest?.('[data-anchor]') as HTMLElement | null;
    if (!el) return;
    const n = Number(el.dataset.anchor);
    if (!Number.isSafeInteger(n)) return;
    const target = resolveAnchor?.(packetId, n);
    if (!target) return;
    const node = document.getElementById(postElementId(target));
    if (!node) return;
    node.scrollIntoView?.({ block: 'center' });
    setHighlightId(target);
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = setTimeout(() => setHighlightId(null), 1500);
  };

  // レス番を押すと、書き込み欄の末尾にアンカー (>>番号) を足し、書き込み欄へ移る (画面は動かさない)
  const quote = (n: number) => {
    setReplyInput((prev) => appendAnchor(prev, n));
    setSubmitError(null);
    requestAnimationFrame(() => {
      const el = replyRef.current;
      if (!el) return;
      el.focus({ preventScroll: true });
      el.setSelectionRange(el.value.length, el.value.length);
    });
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.ctrlKey && e.key === 'Enter') {
      handleSubmit();
    }
  };

  const handleSubmit = () => {
    if (!replyInput.trim() || isSubmitting || confirming || budget.over || overThread || closedNotice) return;
    if (needsWeakRouteConfirmation(guardStatus)) {
      setConfirming(true);
      return;
    }
    void doSubmit();
  };

  const doSubmit = async () => {
    if (budget.over || overThread || closedNotice) return;
    setSubmitError(null);
    try {
      await submitReply(replyInput);
    } catch (e) {
      setSubmitError(describeSubmitError(e, t('thread.subject')));
      return;
    }
    if (!status.startsWith('🔴')) {
      setReplyInput('');
    }
  };

  return (
    <div className="view-container thread-view column-content">
      <div style={{ marginBottom: 18 }}>
        <button
          className="btn-back"
          onClick={() => { if (confirmLeave()) navigate({ board: boardId }); }}
        >
          {t('thread.back')}
        </button>
        <h1 id="thread-title" className="page-title" style={{ marginTop: 8 }}>
          {t('thread.heading', { id: threadId.substring(0, 8) })}
        </h1>
        <div className="eyebrow" style={{ marginTop: 4 }}>{t('thread.boardLabel', { name: boardDisplayName(boardId) })}</div>
        {/* 取得の進み具合などは題名の下の 1 行に出す。★ 文が無いときも行は残す (消えてもレスの位置が動かないように) */}
        <div id="loading-status" className="load-status" role="status" title={status || undefined}>{status}</div>
      </div>

      <div id="posts-container" className="stack stack-sm">

        {posts.map((p, index) => {
          const trip = p.trip_pubkey ? '◆' + KeyManager.toBase64(KeyManager.cryptoHash(p.trip_pubkey).slice(0, 5)) : '';
          const id = posterId(p, threadId);

          return (
            <div
              className={`post${highlightId === p.packet_id ? ' is-highlight' : ''}`}
              key={p.packet_id || index}
              id={postElementId(p.packet_id)}
              style={highlightId === p.packet_id ? { outline: '2px solid var(--accent)', outlineOffset: '2px' } : undefined}
            >
              <div className="post-header">
                {closedNotice ? (
                  <span className="res-no">#{index + 1}</span>
                ) : (
                  <button
                    type="button"
                    className="res-no res-no-btn"
                    title={t('thread.quoteTitle')}
                    disabled={isSubmitting}
                    onClick={() => quote(index + 1)}
                  >
                    #{index + 1}
                  </button>
                )}
                <span className="author-name">{t('thread.anonymous', { trip })}</span>
                <span className="author-id">ID:{id}</span>
                <span className="post-time">{formatDateTime(p.created_at)}</span>
              </div>
              <div
                className="post-body"
                onClick={e => handleBodyClick(e, p.packet_id)}
                onMouseOver={e => showPreview(e, p.packet_id)}
                onMouseOut={hidePreview}
              >
                <PostBody content={p.content || ''} format={formatContent} />
              </div>
            </div>
          );
        })}
        <div ref={endRef} aria-hidden="true" />
      </div>

      {preview && (() => {
        const i = indexById.get(preview.id);
        const p = i === undefined ? null : posts[i];
        if (!p || i === undefined) return null;
        return (
          <div
            className="anchor-preview"
            role="tooltip"
            style={{ left: preview.left, top: preview.top, transform: preview.above ? 'translateY(-100%)' : undefined }}
          >
            <div className="post-header">
              <span className="res-no">#{i + 1}</span>
              <span className="author-id">ID:{posterId(p, threadId)}</span>
              <span className="post-time">{formatDateTime(p.created_at)}</span>
            </div>
            <div className="post-body">
              <PostBody content={p.content || ''} format={formatContent} />
            </div>
          </div>
        );
      })()}

      {(state?.hiddenCount ?? 0) > 0 && (
        <div id="hidden-note" className="alert alert-info" style={{ margin: '14px 0' }}>
          {t('thread.hidden', { count: state.hiddenCount })}
        </div>
      )}

      {closedNotice ? (
        <div className="compose-box" id="thread-closed-notice" role="status" style={{ color: 'var(--text-3)' }}>
          {closedNotice}
        </div>
      ) : (
      <div className="compose-box">
        {unseen.length > 0 && (
          <button className="new-posts" onClick={jumpToNew}>{t('thread.newPosts', { count: unseen.length })}</button>
        )}
        {(nearPosts || nearBytes) && (
          <div id="thread-near-limit" className="alert alert-warn" style={{ marginBottom: 10 }}>
            {nearPosts && <div>{t('thread.nearPosts', { count: remainingPosts })}</div>}
            {nearBytes && <div>{t('thread.nearBytes', { kb: Math.max(0, Math.floor(remainingBytes / 1024)) })}</div>}
          </div>
        )}
        <textarea
          id="reply-input"
          ref={replyRef}
          autoComplete="off"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          placeholder={t('thread.placeholder')}
          rows={3}
          value={replyInput}
          onChange={e => { setReplyInput(e.target.value); setSubmitError(null); }}
          onKeyDown={handleKeyDown}
          disabled={isSubmitting}
        />
        <div className="row row-between row-wrap" style={{ marginTop: 6 }}>
          <PostLimitNote budget={budget} subject={t('thread.subject')} />
          <AttachControl
            disabled={isSubmitting}
            onInsert={(token) => { setReplyInput((prev) => appendToken(prev, token)); setSubmitError(null); }}
          />
        </div>
        {overThread && !budget.over && (
          <div role="alert" className="msg msg-error" style={{ marginTop: 6 }}>{t('thread.overThread')}</div>
        )}
        <div className="compose-foot">
          <div id="post-status" className="small muted">
            {postStatus}
          </div>
          <button
            className="btn btn-sm btn-primary"
            id="btn-send-reply"
            onClick={handleSubmit}
            disabled={isSubmitting || budget.over || overThread || !replyInput.trim()}
          >
            {t('thread.send')}
          </button>
        </div>
        {submitError && (
          <div role="alert" className="alert alert-danger" style={{ marginTop: 10 }}>{submitError}</div>
        )}
        {confirming && (
          <WeakRouteConfirm
            onCancel={() => setConfirming(false)}
            onConfirm={() => { setConfirming(false); void doSubmit(); }}
          />
        )}
        {isSubmitting && (
          <div className="progress-container" id="pow-progress" style={{ marginTop: 12 }}>
            <div className="progress-bar" id="pow-bar" style={{ width: `${powProgress}%` }}></div>
          </div>
        )}
      </div>
      )}
    </div>
  );
}
