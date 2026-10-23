import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      // テストは常に共有パッケージのソースに対して走らせる (古い dist で通ってしまうのを防ぐ)
      '@oz/core': path.resolve(__dirname, '../packages/core/src/index.ts'),
      '@oz/ui/styles.css': path.resolve(__dirname, '../packages/ui/src/styles.css'),
      '@oz/ui': path.resolve(__dirname, '../packages/ui/src/index.ts'),
      '@oz/tracker': path.resolve(__dirname, '../packages/tracker/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.{ts,tsx}'],
    setupFiles: ['./tests/setup.ts'],
    // libsodium の WASM 初期化と Argon2id の PoW 探索に時間がかかるため長めに取る
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts', 'src/**/*.tsx', 'server.ts'],
    },
  },
});
