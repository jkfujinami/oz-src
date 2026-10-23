import { useSyncExternalStore } from 'react';
import type { ProviderLeaseSet } from '@oz/core';

/** 登録した Gatekeeper Worker (セカンダリ互換の保存先) */
export interface RegisteredGatekeeper {
  readonly workerUrl: string;
  readonly backendId: string;
  readonly providerIdHex: string;
  readonly lease: ProviderLeaseSet;
  readonly freeDataSlots: number;
  readonly classACount: number;
  readonly classBCount: number;
  readonly statusText: string;
}

/**
 * ファイル共有 (Ozzy) の設定。設定画面で変え、ファイル共有の画面が読む。
 *
 * ★ メモリだけに持つ (端末に書かない)。ロックすると既定に戻る (resetOzzyPrefs)。
 */
export interface OzzyPrefs {
  /** 保存先: 海外ロッカー (回路の M1 が置く) か Gatekeeper Worker (直接通信) */
  readonly storageEngine: 'overseas-multi' | 'r2-gatekeeper';
  /** 実機のロッカーへ置く。false なら画面のメモリ上のロッカーで試す (通信しない) */
  readonly useLiveLockers: boolean;
  /** 64 KiB チャンクで試す (false なら本番の 4 MiB) */
  readonly useFastDemoChunk: boolean;
  /** 1 本の Slab に束ねるチャンクの数と、揃わないときに待つ時間 */
  readonly targetBatchChunks: number;
  readonly idleGapMs: number;
  readonly maxWaitMs: number;
  readonly registeredWorkers: readonly RegisteredGatekeeper[];
  readonly useOnlyRealWorkers: boolean;
}

const DEFAULTS: OzzyPrefs = {
  storageEngine: 'overseas-multi',
  useLiveLockers: true,
  useFastDemoChunk: true,
  targetBatchChunks: 8,
  idleGapMs: 120,
  maxWaitMs: 400,
  registeredWorkers: [],
  useOnlyRealWorkers: true,
};

let prefs: OzzyPrefs = DEFAULTS;
const listeners = new Set<() => void>();

export function setOzzyPrefs(patch: Partial<OzzyPrefs>): void {
  prefs = { ...prefs, ...patch };
  for (const fn of Array.from(listeners)) fn();
}

export function resetOzzyPrefs(): void {
  setOzzyPrefs(DEFAULTS);
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

export function useOzzyPrefs(): OzzyPrefs {
  return useSyncExternalStore(subscribe, () => prefs, () => prefs);
}
