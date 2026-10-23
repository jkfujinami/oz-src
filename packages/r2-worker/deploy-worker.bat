@echo off
chcp 65001 >nul
setlocal

rem OZ の中継 Worker を Cloudflare Workers に設置する (Node.js の LTS 版が必要)。
rem ★ 括弧で囲んだブロックの中の echo には、丸括弧を書かないこと (ブロックがそこで閉じてしまう)。
rem ★ ブロックの中の終了コードは %errorlevel% ではなく if errorlevel 1 で確かめる
rem   (%errorlevel% はブロックを読み込んだ時点の値になる)。
rem ★ 配布キットでは改行を CRLF にする (scripts/release.sh が変換する)。

cd /d "%~dp0"

echo ===================================================
echo   OZ 中継 Worker の設置
echo ===================================================
echo.
echo この Worker の URL は、OZ の他の参加者に共有されます。
echo 本名や普段お使いのメールアドレスと結び付かない Cloudflare アカウントを使い、
echo workers.dev のサブドメインにも、身元が推測できない名前を付けてください。
echo.

where node >nul 2>nul
if errorlevel 1 goto no_node

echo [1/3] Cloudflare へのログイン状態を確認しています...
call npx -y wrangler whoami 2>nul | findstr /c:"logged in" >nul
if errorlevel 1 (
  echo ブラウザで Cloudflare のログイン画面が開きます。ログインして「Allow」を押してください。
  call npx -y wrangler login
  if errorlevel 1 goto login_failed
)

echo.
echo [2/3] 設定ファイルを作成しています...
(
echo name = "ozzy-gatekeeper"
echo main = "worker.js"
echo compatibility_date = "2026-01-01"
) > wrangler.free.toml

echo.
echo [3/3] Cloudflare Workers に設置しています...
echo 初めて Worker を設置する場合は、workers.dev のサブドメインの名前を尋ねられます。
call npx -y wrangler deploy --config wrangler.free.toml
if errorlevel 1 goto deploy_failed

echo.
echo ===================================================
echo   設置が完了しました。
echo   上に表示された https://ozzy-gatekeeper.〜.workers.dev の URL を、
echo   OZ の「設定」→「ファイル共有」に貼り付け、「確かめて設定」を押してください。
echo ===================================================
echo.
pause
exit /b 0

:no_node
echo [エラー] Node.js が見つかりません。
echo https://nodejs.org/ から LTS 版をインストールしてから、もう一度実行してください。
echo Node.js を入れずに設置する方法は、README.txt をご覧ください。
echo.
pause
exit /b 1

:login_failed
echo.
echo [エラー] Cloudflare にログインできませんでした。もう一度実行してください。
echo.
pause
exit /b 1

:deploy_failed
echo.
echo [エラー] 設置に失敗しました。上に表示されたメッセージをご確認ください。
echo.
pause
exit /b 1
