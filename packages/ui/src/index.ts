/**
 * @oz/ui — Desktop と Web で共通の画面。
 *
 * プロトコルは @oz/core にだけ置き、ここは画面と端末データの扱い (ロック・板の鍵・
 * トラッカー設定) だけを持つ。各アプリはこのパッケージの OzApp を描画する。
 */
export { default as OzApp, RouterView, type OzAppProps } from './App';
export {
  P2PProvider,
  P2PContext,
  P2PContextForTest,
  useP2P,
  MIN_PASSPHRASE_LENGTH,
  type LockState,
  type TrackerSaveResult,
  NO_GUARD_STATUS,
} from './providers/P2PProvider';
export { iceServersFromEnv } from './lib/trackerSetting';
export { AppConfigContext, useAppConfig, type AppConfig } from './providers/AppConfig';
export { Sidebar, type MainSection } from './components/Sidebar';
export { SettingsView, type SettingsSection } from './components/SettingsView';
export { AboutView } from './components/AboutView';
export { default as BoardView } from './components/BoardView';
export { default as ThreadView } from './components/ThreadView';
export { SecurityInfo } from './components/SecurityInfo';
export { TrackerSettings } from './components/TrackerSettings';
export { GuardPanel } from './components/GuardPanel';
export { StorageSettings } from './components/StorageSettings';
export { AttachControl } from './components/AttachControl';
export { FileCard } from './components/FileCard';
export { UnlockScreen } from './components/UnlockScreen';
export { useBoard } from './hooks/useBoard';
export { useThread } from './hooks/useThread';
export * from './lib/boardKeys';
export * from './lib/trackerSetting';
export * from './lib/guardSetting';
export * from './lib/guardStatus';
export * from './lib/route';
export { useAutoLock, AUTO_LOCK_MS } from './hooks/useAutoLock';
export * from './lib/passphrase';
