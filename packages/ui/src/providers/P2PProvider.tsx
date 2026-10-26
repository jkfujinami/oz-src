import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import {
  OzNode,
  IndexedDBStore,
  WrongPassphraseError,
  parseTrackerUrl,
  describeTrackerUrlError,
  type BoardOrchestrator,
  type ThreadOrchestrator,
  type Identity,
  type PeerManager,
  type GuardStatus,
  type GuardListResult,
  createLogger,
} from '@oz/core';

import { loadTrackerUrl, saveTrackerUrl, loadIceServers, saveIceServers } from '../lib/trackerSetting';
import type { GuardTrustConfig } from '../lib/guardSetting';
import { resetRoute } from '../lib/route';
import { clearTermsAccepted } from '../lib/terms';
import { useAutoLock } from '../hooks/useAutoLock';

const log = createLogger('ui.p2p');

/** トラッカーの設定結果。ok でも、接続できなかった場合は notice に理由が入る */
export type TrackerSaveResult = { ok: true; notice?: string } | { ok: false; error: string };

/**
 * ロックの状態。
 *
 * - checking : 端末にパスワードが設定済みかを確かめている
 * - setup    : 初回起動。パスワードを決めてもらう
 * - locked   : パスワードの入力待ち
 * - starting : ロック解除してノードを起動中
 * - ready    : 起動済み
 */
export type LockState = 'checking' | 'setup' | 'locked' | 'starting' | 'ready';

/**
 * 端末の全データの暗号化に使うパスワードの最小長。
 *
 * ★ 押収された端末のデータはオフラインで総当たりできる。KDF を重くしても、短い
 *   パスワードでは守りきれないので 12 文字を下限にする (画面に強度の目安も出す)。
 */
export const MIN_PASSPHRASE_LENGTH = 12;

/**
 * 保管担当の既定の容量 (枠の数。1 枠 = 256MiB)。デスクトップ版 (Electron のプリロードがある) は 4、ブラウザ版は 1。
 * 端末に容量の設定があればそちらが優先される (core の StorageService)。
 */
export const DESKTOP_DEFAULT_SLOTS = 4;
export const WEB_DEFAULT_SLOTS = 1;

/** Electron のプリロードが公開する API (無ければブラウザ) */
function electronApi(): any {
  return typeof window !== 'undefined' ? (window as any).electronAPI : undefined;
}

interface P2PContextType {
  node: OzNode | null;
  boardOrchestrator: BoardOrchestrator | null;
  threadOrchestrator: ThreadOrchestrator | null;
  pm: PeerManager | null;
  identity: Identity | null;
  /** 暗号化された端末データ (ロック解除後のみ) */
  db: IndexedDBStore | null;
  isReady: boolean;
  lockState: LockState;
  /** 直近のロック解除の失敗理由 */
  unlockError: string | null;
  /** パスワードでロックを解除して起動する (初回はこのパスワードで暗号化を始める) */
  unlock: (passphrase: string) => Promise<void>;
  /** パスワードを忘れた: 全データを消して作り直す */
  resetAll: () => Promise<void>;
  /** 緊急消去: 通信を止め、全データを即座に読めなくしてから消す */
  panicWipe: () => Promise<void>;
  /** ロック: データは消さずに通信を止め、メモリ上の鍵を消してパスワード画面に戻る */
  lock: () => Promise<void>;
  /** 接続先のトラッカー (未設定なら null) */
  trackerUrl: string | null;
  /** トラッカーを設定する (null で消す)。暗号化 DB に保存し、すぐ接続し直す */
  setTrackerUrl: (url: string | null) => Promise<TrackerSaveResult>;
  /** 利用者が選んだ STUN (空なら既定を使っている) */
  iceServers: string[];
  /** 実際に使っている STUN */
  effectiveIceServers: string[];
  /** 既定の STUN の表示 (core が決める) */
  defaultStunServer: string | null;
  /** STUN を選ぶ (null で既定に戻す)。暗号化 DB に保存し、次に張る接続から使う */
  setIceServers: (input: string | null) => Promise<TrackerSaveResult>;
  /** Guard (1 ホップ目) の状態。ノードが無いときは none */
  guardStatus: GuardStatus;
  /** 信頼 Guard の設定 (メンテナの公開鍵) がアプリに組み込まれているか */
  guardTrustConfigured: boolean;
  /** 署名つきの Guard リストを取り込む (ノードが無いときは失敗する) */
  importGuardList: (text: string) => Promise<GuardListResult>;
}

/** ノードが無いときの Guard 状態 (送信できない) */
export const NO_GUARD_STATUS: GuardStatus = {
  mode: 'none',
  guardId: null,
  listVersion: null,
  listExpiresAt: null,
};

const noop = async () => {};

export const P2PContext = createContext<P2PContextType>({
  node: null,
  boardOrchestrator: null,
  threadOrchestrator: null,
  pm: null,
  identity: null,
  db: null,
  isReady: false,
  lockState: 'checking',
  unlockError: null,
  unlock: noop,
  resetAll: noop,
  panicWipe: noop,
  lock: noop,
  trackerUrl: null,
  setTrackerUrl: async () => ({ ok: false, error: 'ロックを解除してください' }),
  iceServers: [],
  effectiveIceServers: [],
  defaultStunServer: null,
  setIceServers: async () => ({ ok: false, error: 'ロックを解除してください' }),
  guardStatus: NO_GUARD_STATUS,
  guardTrustConfigured: false,
  importGuardList: async () => ({ ok: false, reason: 'malformed', detail: 'ロックを解除してください' }),
});

export const P2PContextForTest = P2PContext;
export const useP2P = () => useContext(P2PContext);

/**
 * P2PProvider
 *
 * ★ ノードはロック解除してから起動する。
 *
 *   端末の全データ (投稿・スレッド統計・板の鍵・保管中の Slot・鍵) はパスワードで
 *   暗号化してある。パスワードを受け取るまでは、何も読めず何も送らない。
 *   パスワードは起動に使った後は保持しない。
 */
export function P2PProvider({
  children,
  defaultTrackerUrl = null,
  trust = null,
  iceServers = null,
}: {
  children: React.ReactNode;
  /** 利用者がトラッカーを一度も設定していないときに使う既定値 (検証を通らなければ使わない) */
  defaultTrackerUrl?: string | null;
  /**
   * 信頼 Guard の設定 (メンテナの公開鍵)。null なら信頼設定なしで起動し、
   * Guard はオープン動作 (画面に警告を出す)。
   */
  trust?: GuardTrustConfig | null;
  /** STUN サーバ (`stun:` の URL の列)。null なら Google と Cloudflare の公開 STUN */
  iceServers?: string[] | null;
}) {
  const [node, setNode] = useState<OzNode | null>(null);
  const [lockState, setLockState] = useState<LockState>('checking');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [trackerUrl, setTrackerUrlState] = useState<string | null>(null);
  // STUN の表示用 (ノードの値の写し。変えたら作り直して再描画する)
  const [iceView, setIceView] = useState<{ chosen: string[]; effective: string[]; fallback: string | null }>({ chosen: [], effective: [], fallback: null });
  const [guardStatus, setGuardStatus] = useState<GuardStatus>(NO_GUARD_STATUS);
  const storeRef = useRef<IndexedDBStore | null>(null);
  const nodeRef = useRef<OzNode | null>(null);

  const store = () => {
    if (!storeRef.current) storeRef.current = new IndexedDBStore();
    return storeRef.current;
  };

  useEffect(() => {
    let cancelled = false;
    store()
      .hasVault()
      .then((has) => { if (!cancelled) setLockState(has ? 'locked' : 'setup'); })
      .catch((err) => {
        log.error('Failed to open local storage', err);
        if (!cancelled) setLockState('setup');
      });
    return () => {
      cancelled = true;
      nodeRef.current?.stop().catch((e) => log.warn('Error stopping node', e));
    };
  }, []);

  const unlock = useCallback(async (passphrase: string) => {
    setUnlockError(null);
    const previous = lockState;
    setLockState('starting');
    try {
      log.info(() => 'Unlocking local data and starting Desktop OzNode...');
      const oz = await OzNode.create({
        db: store(),
        passphrase,
        autoStart: false,
        storage: { defaultSlots: electronApi() ? DESKTOP_DEFAULT_SLOTS : WEB_DEFAULT_SLOTS },
        // 信頼 Guard の設定 (無ければ渡さない = オープン動作)
        ...(trust ? { trust } : {}),
        ...(iceServers && iceServers.length > 0 ? { iceServers } : {}),
      });
      try {
        // トラッカーの設定は暗号化 DB にあるので、ロック解除後に読んでから起動する
        const url = await loadTrackerUrl(oz.db, defaultTrackerUrl);
        if (url) await oz.setTrackerUrl(url);
        // 設定画面で選んだ STUN (無ければビルド時の指定、それも無ければ公開 STUN)
        const savedIce = await loadIceServers(oz.db);
        if (savedIce) oz.setIceServers(savedIce);

        await oz.start();
      } catch (err) {
        await oz.stop().catch(() => {});
        throw err;
      }
      setTrackerUrlState(oz.trackerUrl);
      void Promise.resolve(electronApi()?.guard?.setTrackerUrl?.(oz.trackerUrl)).catch(() => {});
      setIceView({ chosen: oz.iceServers, effective: oz.effectiveIceServers, fallback: oz.defaultStunServer });
      nodeRef.current = oz;
      setNode(oz);
      setLockState('ready');
      log.info(() => 'Desktop OzNode ready');
    } catch (err) {
      // 鍵をメモリに残さない (次の試行で必ずパスワードを照合させる)
      storeRef.current?.lock();
      if (err instanceof WrongPassphraseError) {
        setUnlockError('パスワードが違います');
      } else {
        log.error('Failed to initialize Desktop OzNode', err);
        setUnlockError('起動に失敗しました');
      }
      setLockState(previous === 'setup' ? 'setup' : 'locked');
    }
  }, [lockState, defaultTrackerUrl, trust, iceServers]);

  const resetAll = useCallback(async () => {
    await nodeRef.current?.stop().catch(() => {});
    nodeRef.current = null;
    setNode(null);
    await store().wipeAll();
    storeRef.current = null;
    clearTermsAccepted();
    resetRoute();
    setUnlockError(null);
    setLockState('setup');
  }, []);

  const panicWipe = useCallback(async () => {
    const current = nodeRef.current;
    nodeRef.current = null;
    setNode(null);
    if (current) {
      await current.panicWipe();
    } else {
      await store().wipeAll();
    }
    storeRef.current = null;
    clearTermsAccepted();
    resetRoute();
    setLockState('setup');
    // ★ デスクトップ版は、ブラウザ側の保存領域・キャッシュ・userData も消して終了する
    //   (メインプロセスが行う。ここまでで IndexedDB は消えている)。終了するので最後に呼ぶ。
    try {
      await electronApi()?.wipeDeviceData?.();
    } catch (e) {
      log.warn('Failed to wipe desktop storage', e);
    }
  }, []);

  const lock = useCallback(async () => {
    const current = nodeRef.current;
    nodeRef.current = null;
    setNode(null);
    await current?.stop().catch(() => {}); // stop() はメモリ上のデータ鍵も消す
    storeRef.current?.lock();
    // ★ 開いていた板・スレッドの記録を残さない (画面内の経路と URL の両方)
    resetRoute();
    // デスクトップ版: ブラウザ側のキャッシュ等も消す (IndexedDB は暗号化済みなので残す)
    void Promise.resolve(electronApi()?.clearCaches?.()).catch(() => {});
    setLockState('locked');
  }, []);

  // 操作が無いまま (隠れている間も含めて) 一定時間が過ぎたら自動でロックする
  useAutoLock({ enabled: lockState === 'ready', onLock: () => { void lock(); } });

  const setTrackerUrl = useCallback(async (input: string | null): Promise<TrackerSaveResult> => {
    const current = nodeRef.current;
    if (!current) return { ok: false, error: 'ロックを解除してください' };
    let url: string | null = null;
    if (input !== null) {
      const parsed = parseTrackerUrl(input);
      if (!parsed.ok) return { ok: false, error: describeTrackerUrlError(parsed.reason) };
      url = parsed.url;
    }
    await saveTrackerUrl(current.db, url);
    void Promise.resolve(electronApi()?.guard?.setTrackerUrl?.(url)).catch(() => {});
    try {
      await current.setTrackerUrl(url);
    } catch {
      // 設定は済んでいる。到達できなければ、ノードが定期的に再試行する
      setTrackerUrlState(current.trackerUrl);
      setIceView({ chosen: current.iceServers, effective: current.effectiveIceServers, fallback: current.defaultStunServer });
      return { ok: true, notice: '保存しました。いまは接続できませんでした (自動で再試行します)' };
    }
    setTrackerUrlState(current.trackerUrl);
    setIceView({ chosen: current.iceServers, effective: current.effectiveIceServers, fallback: current.defaultStunServer });
    return { ok: true };
  }, []);

  const setIceServers = useCallback(async (input: string | null): Promise<TrackerSaveResult> => {
    const current = nodeRef.current;
    if (!current) return { ok: false, error: 'ロックを解除してください' };
    // 既定に戻す: ビルド時の指定 (あれば) か、公開 STUN
    const wanted: string | readonly string[] | null =
      input === null || input.trim() === '' ? (iceServers && iceServers.length > 0 ? iceServers : null) : input;
    const r = current.setIceServers(wanted);
    if (!r.ok) return { ok: false, error: describeIceError(r.reason) };
    await saveIceServers(current.db, input === null || input.trim() === '' ? null : r.servers);
    setIceView({ chosen: current.iceServers, effective: current.effectiveIceServers, fallback: current.defaultStunServer });
    return { ok: true, notice: '保存しました。次に張る接続から使います' };
  }, [iceServers]);

  // Guard の状態を購読する。ノードが止まる (ロック・消去) と購読も解除される
  useEffect(() => {
    if (!node) {
      setGuardStatus(NO_GUARD_STATUS);
      return;
    }
    setGuardStatus(node.guardStatus);
    return node.onGuardStatus(setGuardStatus);
  }, [node]);

  const importGuardList = useCallback(async (text: string): Promise<GuardListResult> => {
    const current = nodeRef.current;
    if (!current) return { ok: false, reason: 'malformed', detail: 'ロックを解除してください' };
    return current.importGuardList(text);
  }, []);

  // トレイ (Electron のメインプロセス) からのロック / 緊急消去
  useEffect(() => {
    const api = electronApi();
    if (!api?.onCommand) return;
    return api.onCommand((command: 'lock' | 'panic-wipe') => {
      if (command === 'lock') void lock();
      else void panicWipe();
    });
  }, [lock, panicWipe]);

  return (
    <P2PContext.Provider
      value={{
        node,
        boardOrchestrator: node?.boardOrchestrator || null,
        threadOrchestrator: node?.threadOrchestrator || null,
        pm: node?.peerManager || null,
        identity: node?.identity || null,
        db: node ? node.db : null,
        isReady: lockState === 'ready' && node !== null,
        lockState,
        unlockError,
        unlock,
        resetAll,
        panicWipe,
        lock,
        trackerUrl: node ? trackerUrl : null,
        setTrackerUrl,
        iceServers: node ? iceView.chosen : [],
        effectiveIceServers: node ? iceView.effective : [],
        defaultStunServer: node ? iceView.fallback : null,
        setIceServers,
        guardStatus,
        guardTrustConfigured: trust !== null,
        importGuardList,
      }}
    >
      {children}
    </P2PContext.Provider>
  );
}

/** STUN の設定の誤りを、利用者向けの日本語にする */
function describeIceError(reason: string): string {
  if (/at most/.test(reason)) return 'STUN は 4 つまでです';
  if (/turn/i.test(reason)) return 'TURN には対応していません (stun: で始まる URL だけ)';
  return 'stun:ホスト名:ポート の形で入力してください (複数ならカンマ区切り)';
}
