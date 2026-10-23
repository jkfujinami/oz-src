#!/usr/bin/env bash
# OZ の中継 Worker を Cloudflare Workers に設置する (Node.js の LTS 版が必要)。
#   bash deploy-worker.sh
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==================================================="
echo "  OZ 中継 Worker の設置"
echo "==================================================="
echo ""
echo "この Worker の URL は、OZ の他の参加者に共有されます。"
echo "本名や普段お使いのメールアドレスと結び付かない Cloudflare アカウントを使い、"
echo "workers.dev のサブドメインにも、身元が推測できない名前を付けてください。"
echo ""

if ! command -v node >/dev/null 2>&1; then
  echo "[エラー] Node.js が見つかりません。"
  echo "https://nodejs.org/ から LTS 版をインストールしてから、もう一度実行してください。"
  echo "Node.js を入れずに設置する方法は、README.txt をご覧ください。"
  exit 1
fi

echo "[1/3] Cloudflare へのログイン状態を確認しています..."
if ! npx -y wrangler whoami 2>/dev/null | grep -q "logged in"; then
  echo "ブラウザで Cloudflare のログイン画面が開きます。ログインして「Allow」を押してください。"
  npx -y wrangler login
fi

echo ""
echo "[2/3] 設定ファイルを作成しています..."
cat > wrangler.free.toml <<'EOF'
name = "ozzy-gatekeeper"
main = "worker.js"
compatibility_date = "2026-01-01"
EOF

echo ""
echo "[3/3] Cloudflare Workers に設置しています..."
echo "初めて Worker を設置する場合は、workers.dev のサブドメインの名前を尋ねられます。"
npx -y wrangler deploy --config wrangler.free.toml

echo ""
echo "==================================================="
echo "  設置が完了しました。"
echo "  上に表示された https://ozzy-gatekeeper.〜.workers.dev の URL を、"
echo "  OZ の「設定」→「ファイル共有」に貼り付け、「確かめて設定」を押してください。"
echo "==================================================="
