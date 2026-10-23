import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import electron from 'vite-plugin-electron';
import renderer from 'vite-plugin-electron-renderer';
import path from 'node:path';
import fs from 'node:fs';

/**
 * 信頼 Guard の設定 (リポジトリの trust/) を組み込む。環境変数で渡されていればそちらを使う。
 * ★ ここに入るのはメンテナの公開鍵と署名済みのリストだけ (秘密ではない)。リストは画面で検証してから使う。
 */
function embedTrust(): void {
  const dir = path.resolve(__dirname, '../../trust');
  try {
    const trust = JSON.parse(fs.readFileSync(path.join(dir, 'trust.json'), 'utf8')) as { maintainerKeys?: string[]; threshold?: number };
    const keys = (trust.maintainerKeys ?? []).filter(Boolean);
    if (keys.length > 0) {
      process.env.VITE_OZ_MAINTAINER_KEYS ??= keys.join(',');
      process.env.VITE_OZ_MAINTAINER_THRESHOLD ??= String(trust.threshold ?? 1);
    }
    const list = fs.readFileSync(path.join(dir, 'guard-list.txt'), 'utf8').trim();
    if (list) process.env.VITE_OZ_GUARD_LIST ??= list;
  } catch {
    // trust/ が無いときは組み込まない (信頼設定なしで動き、画面に警告を出す)
  }
}
embedTrust();

/**
 * 配布版の画面に CSP を入れる (開発サーバは HMR のために緩いままにする)。
 * ★ 画面が読めるのは同梱したファイルだけ。外へつなぐのはトラッカー・中継 Worker など (https / wss) だけ。
 *   PoW と libsodium の Wasm のために 'wasm-unsafe-eval' を許す。スタイルは画面部品が style 属性を使うので inline を許す。
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  "font-src 'self' data:",
  "worker-src 'self' blob:",
  "connect-src 'self' https: wss:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

function cspForBuild(): Plugin {
  return {
    name: 'oz-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<head>', `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`);
    },
  };
}

// OZ_RENDERER_ONLY=1 のときは画面だけを配信し、Electron を起動しない (ブラウザで画面を確かめる用)
const rendererOnly = process.env.OZ_RENDERER_ONLY === '1';

export default defineConfig({
  plugins: [
    react(),
    cspForBuild(),
    ...(rendererOnly
      ? []
      : [
          electron([
            {
              entry: 'electron/main.ts',
              vite: {
                build: {
                  outDir: 'dist-electron',
                },
              },
            },
            {
              entry: 'electron/preload.ts',
              onstart(args) {
                args.reload();
              },
              vite: {
                build: {
                  outDir: 'dist-electron',
                },
              },
            },
            {
              // この端末で動かす Guard の見えないウィンドウの preload
              entry: 'electron/guardPreload.ts',
              onstart(args) {
                args.reload();
              },
              vite: {
                build: {
                  outDir: 'dist-electron',
                },
              },
            },
          ]),
          renderer(),
        ]),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    rollupOptions: {
      // 画面 (index.html) と、この端末で動かす Guard の見えないウィンドウ (guard.html)
      input: {
        main: path.resolve(__dirname, 'index.html'),
        guard: path.resolve(__dirname, 'guard.html'),
      },
    },
  },
});
