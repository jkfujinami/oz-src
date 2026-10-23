/**
 * デスクトップ版で、この端末を信頼 Guard として動かす (Electron のメインプロセスが見えないウィンドウで動かす)。
 * Web 版には無い (desktopGuardApi() が null)。形は apps/desktop/src/guardProtocol.ts と同じ。
 */

export interface DesktopGuardReport {
  peerId: string;
  guardString: string;
  hasList: boolean;
  listed: boolean;
  listVersion: number | null;
  counts: { degree: number; clients: number; backbone: number; tunnels: number };
}

export interface DesktopGuardStatus {
  available: boolean;
  unavailableReason: string | null;
  enabled: boolean;
  starting: boolean;
  running: boolean;
  openAtLogin: boolean;
  slots: number;
  report: DesktopGuardReport | null;
  error: string | null;
}

export interface DesktopGuardApi {
  get(): Promise<DesktopGuardStatus | null>;
  enable(opts: { slots: number }): Promise<DesktopGuardStatus | null>;
  disable(): Promise<DesktopGuardStatus | null>;
  setOpenAtLogin(on: boolean): Promise<DesktopGuardStatus | null>;
  onStatus(cb: (status: DesktopGuardStatus) => void): () => void;
}

export function desktopGuardApi(): DesktopGuardApi | null {
  if (typeof window === 'undefined') return null;
  const api = (window as unknown as { electronAPI?: { guard?: DesktopGuardApi } }).electronAPI?.guard;
  return api ?? null;
}
