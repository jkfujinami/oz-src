import { useState, useEffect, useCallback } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { KeyManager, type BoardRecord } from '@oz/core';
import { DEFAULT_BOARD_ID, newBoardId, parseShareCode } from '../lib/boardKeys';
import { navigate, useRoute } from '../lib/route';
import { useAppConfig } from '../providers/AppConfig';
import { describeGuardStatus, type GuardTone } from '../lib/guardStatus';
import { BrandMark } from './BrandMark';
import type { SettingsSection } from './SettingsView';

export type MainSection = 'vault' | 'board' | 'settings' | 'about';

/** Guard の状態表示のクラス (警告は目立つ色にする。待ちは警告に見せない) */
const GUARD_TONE_CLASS: Record<GuardTone, string> = {
  calm: 'chip-ok',
  warn: 'chip-warn',
  pending: 'chip-pending',
};

const NAV: ReadonlyArray<{ id: MainSection; label: string; icon: string }> = [
  { id: 'vault', label: 'ファイル共有', icon: '◈' },
  { id: 'board', label: '掲示板', icon: '≡' },
  { id: 'settings', label: '設定', icon: '\u2699\uFE0E' },
  { id: 'about', label: '仕組みと安全性', icon: '?' },
];

/** 板 ID は長い 16 進。並べるときは先頭だけ (全体は title で見られる) */
function shortBoardId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 10)}…` : id;
}

/**
 * 左のサイドバー: 画面の切り替え・板の一覧と追加・つながりの状態・ロックと緊急消去。
 * 設定や説明はサイドバーから開く画面 (設定 / 仕組みと安全性) にまとめ、ここには置かない。
 */
export function Sidebar({
  section,
  onSelect,
}: {
  section: MainSection;
  onSelect: (section: MainSection, focus?: SettingsSection) => void;
}) {
  const { node, identity, db, panicWipe, lock, trackerUrl, guardStatus } = useP2P();
  const { badge } = useAppConfig();
  const { route } = useRoute();
  const [peerCount, setPeerCount] = useState(0);
  const [boards, setBoards] = useState<BoardRecord[]>([]);
  const [showImport, setShowImport] = useState(false);
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const guardView = describeGuardStatus(guardStatus);

  useEffect(() => {
    if (!node) return;
    setPeerCount(node.degree);
    const timer = setInterval(() => setPeerCount(node.degree), 2000);
    return () => clearInterval(timer);
  }, [node]);

  const refreshBoards = useCallback(() => {
    if (!db) return;
    db.listBoards().then(setBoards).catch(() => setBoards([]));
  }, [db]);

  useEffect(() => {
    refreshBoards();
  }, [refreshBoards]);

  const openBoard = (boardId: string) => {
    navigate({ board: boardId });
    onSelect('board');
  };

  /**
   * 秘密の板を作る。
   * ★ 鍵は暗号化された端末 DB にだけ保存する。経路は URL に出さない (lib/route.ts)。
   */
  const handleCreatePrivateBoard = async () => {
    if (!db) return;
    const id = newBoardId();
    await db.saveBoard(id, KeyManager.generateBoardKey());
    refreshBoards();
    openBoard(id);
  };

  const handleImport = async () => {
    if (!db) return;
    const parsed = parseShareCode(importText);
    if (!parsed) {
      setImportError('共有コードの形式が正しくありません');
      return;
    }
    await db.saveBoard(parsed.boardId, parsed.key);
    setImportText('');
    setImportError(null);
    setShowImport(false);
    refreshBoards();
    openBoard(parsed.boardId);
  };

  /** 緊急消去。誤操作を防ぐため 2 回押させる */
  const handlePanicWipe = async () => {
    if (!confirmWipe) {
      setConfirmWipe(true);
      setTimeout(() => setConfirmWipe(false), 5000);
      return;
    }
    setConfirmWipe(false);
    await panicWipe();
  };

  const online = peerCount > 0;
  const trackerMissing = !!node && !trackerUrl;
  const savedBoards = boards.filter(b => b.boardId !== DEFAULT_BOARD_ID);

  return (
    <aside className="sidebar" aria-label="サイドバー" data-section={section}>
      <a
        href="#"
        onClick={(e) => { e.preventDefault(); openBoard(DEFAULT_BOARD_ID); }}
        className="brand"
      >
        <BrandMark />
        <span className="brand-name">OZ</span>
        <span className="badge">{badge}</span>
      </a>

      <nav className="side-group side-nav" aria-label="画面の切り替え">
        {NAV.map(item => (
          <button
            key={item.id}
            type="button"
            className="side-item"
            aria-current={section === item.id ? 'page' : undefined}
            onClick={() => onSelect(item.id)}
          >
            <span className="side-icon" aria-hidden="true">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="side-group side-boards">
        <div className="side-label">板</div>
        {[DEFAULT_BOARD_ID, ...savedBoards.map(b => b.boardId)].map(id => (
          <button
            key={id}
            type="button"
            className="side-item side-sub"
            title={id}
            aria-current={section === 'board' && route.board === id ? 'page' : undefined}
            onClick={() => openBoard(id)}
          >
            {shortBoardId(id)}
          </button>
        ))}
        <button className="side-item side-sub side-action" onClick={handleCreatePrivateBoard} disabled={!db}>
          + 秘密の板を作る
        </button>
        <button
          className="side-item side-sub side-action"
          onClick={() => setShowImport((v) => !v)}
          disabled={!db}
          aria-expanded={showImport}
        >
          共有コードで参加
        </button>
        {showImport && (
          <div className="side-form stack stack-sm">
            <div className="field-hint">相手から受け取った共有コードを貼り付けてください。鍵は暗号化された端末 DB にだけ保存します。</div>
            <input
              aria-label="共有コード"
              className="mono"
              placeholder="board=...&key=..."
              value={importText}
              autoFocus
              onChange={(e) => setImportText(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && importText.trim()) void handleImport(); }}
            />
            {importError && <div role="alert" className="msg msg-error">{importError}</div>}
            <div className="row row-end">
              <button className="btn btn-sm btn-ghost" onClick={() => { setShowImport(false); setImportError(null); }}>中止</button>
              <button className="btn btn-sm btn-primary" onClick={handleImport} disabled={!importText.trim()}>追加</button>
            </div>
          </div>
        )}
      </div>

      <div className="side-group side-status">
        <div className="side-label">状態</div>
        <span className={`chip ${online ? 'chip-ok' : 'chip-pending'}`} title="直接つながっている相手の数">
          <span className={`dot${online ? ' dot-live' : ''}`} style={online ? undefined : { color: 'var(--warn)' }} />
          <span>Peers: {peerCount}</span>
        </span>

        {node && (
          <button
            className={`chip ${GUARD_TONE_CLASS[guardView.tone]}`}
            onClick={() => onSelect('settings', 'guard')}
            title={`${guardView.headline} 設定で詳しく見られます。`}
            aria-label={`匿名経路の状態: ${guardView.label}`}
          >
            <span className="dot" />
            {guardView.label}
          </button>
        )}

        <button
          className={`chip${trackerMissing ? ' chip-warn' : ''}`}
          onClick={() => onSelect('settings', 'connection')}
          disabled={!node}
          title={trackerUrl ? 'トラッカーの設定' : 'トラッカーが未設定です'}
        >
          <span className="dot" style={{ color: trackerMissing ? 'var(--warn)' : trackerUrl ? 'var(--ok)' : 'var(--text-3)' }} />
          {trackerMissing ? 'トラッカー未設定' : 'トラッカー'}
        </button>

        {identity && (
          <span className="chip" style={{ fontFamily: 'var(--mono)' }}>
            <span className="muted">Trip</span>
            <span className="author-trip">{identity.tripDisplay || '名無し'}</span>
          </span>
        )}
        {identity?.hasTrip && (
          <span
            role="note"
            title="トリップを付けた投稿同士は、同じ人物のものとして紐付きます。継続して投稿すると、オンラインだった時間帯との突き合わせで候補を絞られる材料にもなります。"
            className="xsmall text-warn"
          >
            ⚠ 投稿同士が紐付きます
          </span>
        )}
      </div>

      <div className="side-actions">
        <button
          className="btn btn-sm"
          onClick={() => { void lock(); }}
          title="通信を止め、パスワード画面に戻ります (データは消えません)"
        >
          ロック
        </button>
        <button
          className={`btn btn-sm btn-danger${confirmWipe ? ' is-armed' : ''}`}
          onClick={handlePanicWipe}
          title="通信を止め、この端末のデータをすべて読めなくしてから消去します (元に戻せません)"
        >
          {confirmWipe ? 'もう一度押すと全消去' : '緊急消去'}
        </button>
      </div>
    </aside>
  );
}
