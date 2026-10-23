"use client";

import { useState, useEffect, useRef, KeyboardEvent, MouseEvent } from "react";
import { useThread } from "../hooks/useThread";
import { useP2P } from "../providers/P2PProvider";
import { needsWeakRouteConfirmation } from "../lib/guardStatus";
import { WeakRouteConfirm } from "./WeakRouteConfirm";
import { PostLimitNote } from "./PostLimitNote";
import { AttachControl } from "./AttachControl";
import { PostBody } from "./PostBody";
import { appendToken } from "../lib/fileTokens";
import { confirmLeave } from "../lib/transferGuard";
import { navigate } from "../lib/route";
import { byteBudget, describeSubmitError } from "../lib/postLimit";
import { KeyManager, THREAD_LIMITS, createLogger, posterId } from "@oz/core";

const log = createLogger('ui.thread');

const POSTS_NOTICE = 'このスレッドは 1000 レスに達したので、これ以上書き込めません。新しいスレッドを立ててください。';
const BYTES_NOTICE = 'このスレッドは容量の上限 (512KB) に達したので、これ以上書き込めません。新しいスレッドを立ててください。';
const EXPIRED_NOTICE = 'このスレッドは落ちました。最後の書き込みから 30 日、またはスレッドを立ててから 90 日が過ぎると落ちます。';
/** 残りが少なくなったことを知らせ始めるレス数 */
const NEAR_POSTS = 900;

/** 各レスの DOM id。>>N のジャンプ先に使う (packet_id は 16 進なので id にそのまま使える) */
const postElementId = (packetId: string) => `post-${packetId}`;

export default function ThreadView({
  boardId,
  threadId,
}: {
  boardId: string;
  threadId: string;
}) {
  const {
    posts, status, submitReply,
    powProgress, isSubmitting, postStatus, threadState: state, resolveAnchor,
  } = useThread(boardId, threadId);

  const [replyInput, setReplyInput] = useState('');
  const { guardStatus } = useP2P();
  const [confirming, setConfirming] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const budget = byteBudget(replyInput);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (highlightTimer.current) clearTimeout(highlightTimer.current); }, []);

  // 書き込める状態か。埋まった・落ちたスレには書き込み欄を出さない (core も送信時に断る)
  const closedNotice = state?.expired ? EXPIRED_NOTICE
    : state?.closed ? (state.closeReason === 'bytes' ? BYTES_NOTICE : POSTS_NOTICE)
    : null;
  const remainingPosts = THREAD_LIMITS.MAX_POSTS - (state?.visibleCount ?? 0);
  const remainingBytes = THREAD_LIMITS.MAX_CONTENT_BYTES - (state?.contentBytes ?? 0);
  const nearPosts = !closedNotice && (state?.visibleCount ?? 0) >= NEAR_POSTS;
  const nearBytes = !closedNotice && (state?.contentBytes ?? 0) >= THREAD_LIMITS.MAX_CONTENT_BYTES * 0.9;
  // 概算。core が送信前に正確に判定する
  const overThread = budget.used > 0 && budget.used > remainingBytes;

  log.trace(() => `ThreadView render: ${posts.length} posts`);

  const formatContent = (content: string) => {
    const sanitized = content
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const withLinks = sanitized.replace(
      /&gt;&gt;(\d+)/g,
      '<span class="anchor" data-anchor="$1">&gt;&gt;$1</span>'
    );
    return withLinks;
  };

  const handleBodyClick = (e: MouseEvent<HTMLElement>, packetId: string) => {
    const el = (e.target as HTMLElement).closest?.('[data-anchor]') as HTMLElement | null;
    if (!el) return;
    const n = Number(el.dataset.anchor);
    if (!Number.isSafeInteger(n)) return;
    const target = resolveAnchor?.(packetId, n);
    if (!target) return;
    const node = document.getElementById(postElementId(target));
    if (!node) return;
    node.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
    setHighlightId(target);
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = setTimeout(() => setHighlightId(null), 1500);
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
      setSubmitError(describeSubmitError(e, '1 レス'));
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
          ← 板に戻る
        </button>
        <h1 id="thread-title" className="page-title" style={{ marginTop: 8 }}>
          スレッド: {threadId.substring(0, 8)}
        </h1>
        <div className="eyebrow" style={{ marginTop: 4 }}>板: {boardId}</div>
      </div>

      <div id="posts-container" className="stack stack-sm">
        {status && <div id="loading-status" className="empty">{status}</div>}

        {posts.map((p, index) => {
          const trip = p.trip_pubkey ? '◆' + KeyManager.toBase64(KeyManager.cryptoHash(p.trip_pubkey).slice(0, 5)) : '';
          const id = posterId(p, threadId);

          return (
            <div
              className={`post${highlightId === p.packet_id ? ' is-highlight' : ''}`}
              key={p.packet_id || index}
              id={postElementId(p.packet_id)}
              style={highlightId === p.packet_id ? { outline: '2px solid var(--accent)', outlineOffset: '2px', transition: 'outline-color 0.3s' } : undefined}
            >
              <div className="post-header">
                <span className="res-no">#{index + 1}</span>
                <span className="author-name">名無しさん {trip}</span>
                <span className="author-id">ID:{id}</span>
                <span className="post-time">{new Date(p.created_at).toLocaleString()}</span>
              </div>
              <div
                className="post-body"
                onClick={e => handleBodyClick(e, p.packet_id)}
              >
                <PostBody content={p.content || ''} format={formatContent} />
              </div>
            </div>
          );
        })}
      </div>

      {(state?.hiddenCount ?? 0) > 0 && (
        <div id="hidden-note" className="alert alert-info" style={{ margin: '14px 0' }}>
          スレッドが埋まった後や落ちた後の書き込み {state.hiddenCount} 件は表示していません。
        </div>
      )}

      {closedNotice ? (
        <div className="compose-box" id="thread-closed-notice" role="status" style={{ color: 'var(--text-3)' }}>
          {closedNotice}
        </div>
      ) : (
      <div className="compose-box">
        {(nearPosts || nearBytes) && (
          <div id="thread-near-limit" className="alert alert-warn" style={{ marginBottom: 10 }}>
            {nearPosts && <div>あと {remainingPosts} レスで埋まります</div>}
            {nearBytes && <div>スレッドの残り容量: 約 {Math.max(0, Math.floor(remainingBytes / 1024))} KB</div>}
          </div>
        )}
        <textarea
          id="reply-input"
          autoComplete="off"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          placeholder=">>レスを入力... (Ctrl+Enterで送信)"
          rows={3}
          value={replyInput}
          onChange={e => { setReplyInput(e.target.value); setSubmitError(null); }}
          onKeyDown={handleKeyDown}
          disabled={isSubmitting}
        />
        <div className="row row-between row-wrap" style={{ marginTop: 6 }}>
          <PostLimitNote budget={budget} subject="1 レス" />
          <AttachControl
            disabled={isSubmitting}
            onInsert={(t) => { setReplyInput((prev) => appendToken(prev, t)); setSubmitError(null); }}
          />
        </div>
        {overThread && !budget.over && (
          <div role="alert" className="msg msg-error" style={{ marginTop: 6 }}>スレッドの残り容量を超えています</div>
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
            書き込む
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
