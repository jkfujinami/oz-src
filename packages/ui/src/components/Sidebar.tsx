import { useState, useEffect, useCallback } from 'react';
import { useP2P } from '../providers/P2PProvider';
import { KeyManager, type BoardRecord } from '@oz/core';
import { DEFAULT_BOARD_ID, PUBLIC_BOARDS, boardDisplayName, isPublicBoardId, newBoardId, parseShareCode } from '../lib/boardKeys';
import { navigate, useRoute } from '../lib/route';
import { useAppConfig } from '../providers/AppConfig';
import { describeGuardStatus, type GuardTone } from '../lib/guardStatus';
import { BrandMark } from './BrandMark';
import type { SettingsSection } from './SettingsView';
import { useT, type MessageKey } from '../i18n';

export type MainSection = 'vault' | 'board' | 'settings' | 'status' | 'about';

/** Guard の状態表示のクラス (警告は目立つ色にする。待ちは警告に見せない) */
const GUARD_TONE_CLASS: Record<GuardTone, string> = {
  calm: 'chip-ok',
  warn: 'chip-warn',
  pending: 'chip-pending',
};

const NAV: ReadonlyArray<{ id: MainSection; label: MessageKey & `sidebar.nav.${string}`; icon: string }> = [
  { id: 'vault', label: 'sidebar.nav.vault', icon: '◈' },
  { id: 'board', label: 'sidebar.nav.board', icon: '≡' },
  { id: 'settings', label: 'sidebar.nav.settings', icon: '\u2699\uFE0E' },
  { id: 'status', label: 'sidebar.nav.status', icon: '\u25A4' },
  { id: 'about', label: 'sidebar.nav.about', icon: '?' },
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
  const t = useT();
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
      setImportError(t('sidebar.badShare'));
      return;
    }
    // 公開板は共有コードなしで読める。公開板の ID を持つ共有コードは、公開板のすり替えを狙ったもの
    if (isPublicBoardId(parsed.boardId)) {
      setImportError(t('sidebar.publicShare'));
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
  const savedBoards = boards.filter(b => !isPublicBoardId(b.boardId));

  return (
    <aside className="sidebar" aria-label={t('sidebar.label')} data-section={section}>
      <a
        href="#"
        onClick={(e) => { e.preventDefault(); openBoard(DEFAULT_BOARD_ID); }}
        className="brand"
      >
        <BrandMark />
        <span className="brand-name">OZ</span>
        <span className="badge">{badge}</span>
      </a>

      <nav className="side-group side-nav" aria-label={t('sidebar.navLabel')}>
        {NAV.map(item => (
          <button
            key={item.id}
            type="button"
            className="side-item"
            aria-current={section === item.id ? 'page' : undefined}
            onClick={() => onSelect(item.id)}
          >
            <span className="side-icon" aria-hidden="true">{item.icon}</span>
            {t(item.label)}
          </button>
        ))}
      </nav>

      <div className="side-group side-boards">
        <div className="side-label">{t('sidebar.boards')}</div>
        {[...PUBLIC_BOARDS.map(b => b.id), ...savedBoards.map(b => b.boardId)].map(id => (
          <button
            key={id}
            type="button"
            className="side-item side-sub"
            title={id}
            aria-current={section === 'board' && route.board === id ? 'page' : undefined}
            onClick={() => openBoard(id)}
          >
            {isPublicBoardId(id) ? boardDisplayName(id) : shortBoardId(id)}
          </button>
        ))}
        <button className="side-item side-sub side-action" onClick={handleCreatePrivateBoard} disabled={!db}>
          {t('sidebar.createPrivate')}
        </button>
        <button
          className="side-item side-sub side-action"
          onClick={() => setShowImport((v) => !v)}
          disabled={!db}
          aria-expanded={showImport}
        >
          {t('sidebar.join')}
        </button>
        {showImport && (
          <div className="side-form stack stack-sm">
            <div className="field-hint">{t('sidebar.importHint')}</div>
            <input
              aria-label={t('sidebar.importLabel')}
              className="mono"
              placeholder="board=...&key=..."
              value={importText}
              autoFocus
              onChange={(e) => setImportText(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && importText.trim()) void handleImport(); }}
            />
            {importError && <div role="alert" className="msg msg-error">{importError}</div>}
            <div className="row row-end">
              <button className="btn btn-sm btn-ghost" onClick={() => { setShowImport(false); setImportError(null); }}>{t('sidebar.cancel')}</button>
              <button className="btn btn-sm btn-primary" onClick={handleImport} disabled={!importText.trim()}>{t('sidebar.add')}</button>
            </div>
          </div>
        )}
      </div>

      <div className="side-group side-status">
        <div className="side-label">{t('sidebar.status')}</div>
        <button
          className={`chip ${online ? 'chip-ok' : 'chip-pending'}`}
          title={t('sidebar.peersTitle')}
          onClick={() => onSelect('status')}
        >
          <span className={`dot${online ? ' dot-live' : ''}`} style={online ? undefined : { color: 'var(--warn)' }} />
          <span>Peers: {peerCount}</span>
        </button>

        {node && (
          <button
            className={`chip ${GUARD_TONE_CLASS[guardView.tone]}`}
            onClick={() => onSelect('settings', 'guard')}
            title={t('sidebar.guardTitle', { headline: guardView.headline })}
            aria-label={t('sidebar.guardLabel', { label: guardView.label })}
          >
            <span className="dot" />
            {guardView.label}
          </button>
        )}

        <button
          className={`chip${trackerMissing ? ' chip-warn' : ''}`}
          onClick={() => onSelect('settings', 'connection')}
          disabled={!node}
          title={trackerUrl ? t('sidebar.trackerSettings') : t('sidebar.trackerUnset')}
        >
          <span className="dot" style={{ color: trackerMissing ? 'var(--warn)' : trackerUrl ? 'var(--ok)' : 'var(--text-3)' }} />
          {trackerMissing ? t('sidebar.trackerMissing') : t('sidebar.tracker')}
        </button>

        {identity && (
          <span className="chip" style={{ fontFamily: 'var(--mono)' }}>
            <span className="muted">Trip</span>
            <span className="author-trip">{identity.tripDisplay || t('sidebar.anonymous')}</span>
          </span>
        )}
        {identity?.hasTrip && (
          <span
            role="note"
            title={t('sidebar.tripNote')}
            className="xsmall text-warn"
          >
            {t('sidebar.tripLinked')}
          </span>
        )}
      </div>

      <div className="side-actions">
        <button
          className="btn btn-sm"
          onClick={() => { void lock(); }}
          title={t('sidebar.lockTitle')}
        >
          {t('sidebar.lock')}
        </button>
        <button
          className={`btn btn-sm btn-danger${confirmWipe ? ' is-armed' : ''}`}
          onClick={handlePanicWipe}
          title={t('sidebar.wipeTitle')}
        >
          {confirmWipe ? t('sidebar.wipeAgain') : t('sidebar.wipe')}
        </button>
      </div>
    </aside>
  );
}
