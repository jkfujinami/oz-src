"use client";

import { useState } from "react";
import { useBoard } from "../hooks/useBoard";
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

const log = createLogger('ui.board');

export default function BoardView({
  boardId,
}: {
  boardId: string;
}) {
  const { threads, status, submitThread, powProgress, isSubmitting, shareCode } = useBoard(boardId);
  const [showForm, setShowForm] = useState(false);
  const [titleInput, setTitleInput] = useState('');
  const [copied, setCopied] = useState(false);
  const { guardStatus } = useP2P();
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
      setSubmitError(describeSubmitError(e, 'スレッドタイトル'));
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
          <h1 className="page-title">板: {boardDisplayName(boardId)}</h1>
        </div>
        <div className="row row-wrap">
          {shareCode && (
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyShareCode}
              title="この板の鍵を含みます。信頼できる相手にだけ渡してください"
            >
              {copied ? 'コピーしました' : '共有コードをコピー'}
            </button>
          )}
          <button className="btn btn-sm btn-primary" onClick={() => setShowForm(true)}>
            新スレを立てる
          </button>
        </div>
      </div>

      {showForm && (
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-head">
            <div>
              <h3 className="panel-title">新規スレッド作成</h3>
              <p className="panel-desc">スレッドの先頭メッセージを入力してください。送信時に端末ローカルで Proof-of-Work (計算証明) を行います。</p>
            </div>
          </div>
          <div className="input-group">
            <textarea
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              placeholder="スレッドタイトル..."
              rows={3}
              value={titleInput}
              onChange={(e) => setTitleInput(e.target.value)}
              disabled={isSubmitting}
              autoFocus
            />
            <div className="row row-between row-wrap">
              <PostLimitNote budget={budget} subject="スレッドタイトル" />
              <AttachControl
                disabled={isSubmitting}
                onInsert={(t) => { setTitleInput((prev) => appendToken(prev, t)); setSubmitError(null); }}
              />
            </div>
            <div className="row row-end" style={{ gap: 10, marginTop: 10 }}>
              <button className="btn btn-sm btn-ghost" onClick={() => { if (confirmLeave()) setShowForm(false); }} disabled={isSubmitting}>
                中止
              </button>
              <button
                className="btn btn-sm btn-primary"
                disabled={isSubmitting || budget.over || !titleInput.trim()}
                onClick={requestSubmit}
              >
                作成
              </button>
            </div>
            {submitError && (
              <div role="alert" className="alert alert-danger" style={{ marginTop: 10 }}>{submitError}</div>
            )}
            {confirming && (
              <WeakRouteConfirm
                onCancel={() => setConfirming(false)}
                onConfirm={() => { setConfirming(false); void trySubmit(); }}
              />
            )}
            {isSubmitting && (
              <div style={{ marginTop: 12 }}>
                <div className="progress-status">
                  <span className="small text-ok">PoW計算中...</span>
                  <span className="small muted">{powProgress}%</span>
                </div>
                <div className="progress">
                  <span style={{ width: `${powProgress}%` }} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div>
        {status && <div className="muted" style={{ padding: '20px 0', textAlign: 'center' }}>{status}</div>}

        {threads.length === 0 && !status && (
          <div className="empty">
            スレッドはまだありません。「新スレを立てる」から投稿してください。
          </div>
        )}

        <div className="thread-list">
          {threads.map((t: ThreadMeta) => {
            const url = `#board=${boardId}&thread=${t.thread_id}`;
            const heat = Math.floor(t.max_pow || 0);
            const score = ThreadRanker.calculateScore(t.max_pow || 0, t.created_at);

            return (
              <a
                key={t.thread_id}
                href={url}
                className="thread-row"
              >
                <div className="grow">
                  <div className="thread-title">{replaceFileTokens(t.content)}</div>
                  <div className="thread-meta">
                    <span>{new Date(t.created_at).toLocaleString()}</span>
                    <span>ID: <code className="mono">{t.thread_id.substring(0, 8)}</code></span>
                    <span>Heat: {heat}</span>
                  </div>
                </div>
                <div className="thread-score" title="スコア (PoW計算量と新しさ)">
                  {score > 0.1 ? score.toFixed(1) : '0.1'}
                </div>
              </a>
            );
          })}
        </div>
      </div>
    </div>
  );
}
