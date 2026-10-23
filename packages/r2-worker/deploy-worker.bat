@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ===================================================
echo   Ozzy Gatekeeper Worker 一括デプロイ スクリプト
echo ===================================================
echo.

:: 1. Node.js の存在確認
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [エラー] Node.js が見つかりません。
    echo 公式サイト (https://nodejs.org/) から LTS 版をインストールしてください。
    echo.
    pause
    exit /b 1
)

:: 2. 実行ディレクトリを作業ディレクトリ (packages\r2-worker) に固定
cd /d "%~dp0"

echo ★ Worker の URL (workers.dev のサブドメイン) は Ozzy の参加者に配られます。
echo   本名や普段のメールに結び付かない Cloudflare アカウントで、身元が分からないサブドメインを使ってください。
echo.
echo [1/3] Cloudflare 認証状態の確認...
call npx -y wrangler whoami >nul 2>nul
if %errorlevel% neq 0 (
    echo.
    echo Cloudflare アカウントのブラウザ認証を開始します。
    echo ブラウザが起動したら [承認] (Allow / Authorize) をクリックしてください...
    call npx -y wrangler login
    if %errorlevel% neq 0 (
        echo [エラー] ログインに失敗しました。
        pause
        exit /b 1
    )
)

echo.
echo [2/3] デプロイ構成ファイルを準備中 (完全無料・カード不要モード)...
(
echo name = "ozzy-gatekeeper"
echo main = "worker.js"
echo compatibility_date = "2026-01-01"
) > wrangler.free.toml

echo.
echo [3/3] Cloudflare Workers へのデプロイを実行中...
call npx -y wrangler deploy --config wrangler.free.toml
if %errorlevel% neq 0 (
    echo.
    echo [エラー] デプロイに失敗しました。
    pause
    exit /b 1
)

echo.
echo ===================================================
echo   デプロイが完了しました。
echo   コンソールに表示された Worker URL (https://xxxx.workers.dev) を
echo   Ozzy の画面の「確かめて設定」に貼ってください (設定するまで Ozzy は使えません)。
echo   あなたの Worker は P2P で他の参加者と交換され、他の参加者の中継に使われます。
echo ===================================================
echo.
pause
