import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // ★ Equi-X の Wasm は非同期で読み込む。検証 (PacketValidator) は同期関数なので、
    //   どのテストも始まる前に読み込みを終わらせておく。
    setupFiles: ['./tests/setup.ts'],
    exclude: process.env.RUN_SIM ? ['**/node_modules/**', '**/dist/**'] : ['**/node_modules/**', '**/dist/**', 'tests/simulation/**'],
  },
});
