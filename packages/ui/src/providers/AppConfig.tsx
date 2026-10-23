import { createContext, useContext } from 'react';

/** アプリ (Desktop / Web) ごとに違う、表示上の設定。プロトコルの挙動はここに置かない */
export interface AppConfig {
  /** ヘッダーのロゴ横に出すラベル */
  badge: string;
}

export const AppConfigContext = createContext<AppConfig>({ badge: 'Desktop Full Node' });
export const useAppConfig = () => useContext(AppConfigContext);
