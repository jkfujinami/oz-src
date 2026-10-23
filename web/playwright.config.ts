import { defineConfig } from '@playwright/test';

const PORT = 3123;

/**
 * Web の端から端までの確認: 本番ビルドを配信し、ブラウザで開いて、
 * パスワードで解錠 → 同じサーバのトラッカーへ所有証明つきで登録 → 2 つのブラウザが
 * WebRTC で繋がる、までを見る。事前に `npm run build` が必要。
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 180_000,
  expect: { timeout: 120_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${PORT}`,
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH }
      : undefined,
  },
  webServer: {
    command: 'npm run start',
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: { PORT: String(PORT), NEXT_TELEMETRY_DISABLED: '1' },
  },
});
