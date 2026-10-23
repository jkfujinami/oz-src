import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      // テストは常に core / tracker のソースに対して走らせる (古い dist で通ってしまうのを防ぐ)
      '@oz/core': path.resolve(__dirname, '../../packages/core/src/index.ts'),
      '@oz/tracker': path.resolve(__dirname, '../../packages/tracker/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
