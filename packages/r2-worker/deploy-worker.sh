#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================="
echo "  Ozzy Gatekeeper Worker 一括デプロイ スクリプト"
echo "==================================================="
echo ""

if ! command -v node >/dev/null 2>&1; then
    echo "[エラー] Node.js が見つかりません。LTS 版をインストールしてください。"
    exit 1
fi

echo "★ Worker の URL (workers.dev のサブドメイン) は Ozzy の参加者に配られます。"
echo "  本名や普段のメールに結び付かない Cloudflare アカウントで、身元が分からないサブドメインを使ってください。"
echo ""
echo "[1/3] Cloudflare 認証状態の確認..."
if ! npx -y wrangler whoami >/dev/null 2>&1; then
    echo "Cloudflare アカウントのブラウザ認証を開始します..."
    npx -y wrangler login
fi

echo "[2/3] デプロイ構成ファイルを準備中 (完全無料・カード不要モード)..."
cat << 'EOF' > wrangler.free.toml
name = "ozzy-gatekeeper"
main = "worker.js"
compatibility_date = "2026-01-01"
EOF

echo "[3/3] Cloudflare Workers へのデプロイを実行中..."
npx -y wrangler deploy --config wrangler.free.toml

echo ""
echo "==================================================="
echo "  デプロイが完了しました。"
echo "  表示された https://….workers.dev を Ozzy の画面の「確かめて設定」に貼ってください。"
echo "  (設定するまで Ozzy は使えません。あなたの Worker は他の参加者の中継に使われます)"
echo "==================================================="
