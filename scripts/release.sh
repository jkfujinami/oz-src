#!/usr/bin/env bash
# この Mac で 3 OS 分のインストーラを作り、公開の配布リポ (jkfujinami/Oz) の Releases に上げる。
#
#   (apps/desktop/package.json の version を上げてコミットしてから)
#   scripts/release.sh
#
# ★ 上げるのはインストーラと SHA256SUMS.txt だけ。コードは上げない。
# ★ コード署名はしない (Apple / Microsoft の開発者アカウントに身元が結び付くため)。
# ★ メンテナの公開鍵と信頼リストは trust/ からビルド時に組み込まれる。
# ★ 上げたコミットにはこのリポで同じ名前のタグを付ける (どのコードから作ったか後で追えるように)。
set -euo pipefail

RELEASE_REPO="${OZ_RELEASE_REPO:-jkfujinami/Oz}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v gh >/dev/null || { echo "gh が見つかりません (brew install gh)"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh にログインしていません (gh auth login)"; exit 1; }

# ドキュメント (*.md) の書きかけはビルドに入らないので見ない
if [ -n "$(git status --porcelain -- . ':(exclude)*.md')" ]; then
  echo "コミットしていない変更があります。コミットしてから実行してください。"
  exit 1
fi

VERSION="v$(node -p "require('./apps/desktop/package.json').version")"
if gh release view "$VERSION" --repo "$RELEASE_REPO" >/dev/null 2>&1; then
  echo "$RELEASE_REPO に $VERSION はもうあります。apps/desktop/package.json の version を上げてください。"
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  echo "このリポにタグ $VERSION がもうあります。"
  exit 1
fi

echo "== $VERSION を作ります (公開先: $RELEASE_REPO)"
npm run build:core
npm run test:desktop
npm run test:ui
npm run build:desktop

cd apps/desktop
rm -rf release
CSC_IDENTITY_AUTO_DISCOVERY=false npx electron-builder --mac --win --linux --publish never

# 中継 Worker の設置キット (worker.js・設置用スクリプト・説明書)。コードを公開していないので、ここで配る。
# Windows で開くファイルは改行を CRLF にする (LF のままだと bat の goto が誤動作することがある)
KIT_TMP="$(mktemp -d)"
mkdir "$KIT_TMP/OZ-worker"
cp "$ROOT/packages/r2-worker/worker.js" "$ROOT/packages/r2-worker/deploy-worker.sh" "$KIT_TMP/OZ-worker/"
chmod 755 "$KIT_TMP/OZ-worker/deploy-worker.sh"
for f in deploy-worker.bat README.txt; do
  perl -pe 's/\r?\n/\r\n/' "$ROOT/packages/r2-worker/$f" > "$KIT_TMP/OZ-worker/$f"
done
(cd "$KIT_TMP" && zip -qrX "$ROOT/apps/desktop/release/OZ-worker-${VERSION#v}.zip" OZ-worker)
rm -rf "$KIT_TMP"

cd release
shopt -s nullglob
FILES=(*.dmg *.zip *.exe *.AppImage)
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "インストーラができていません。"
  exit 1
fi
shasum -a 256 "${FILES[@]}" > SHA256SUMS.txt
cat SHA256SUMS.txt

NOTES="$(mktemp)"
trap 'rm -f "$NOTES"' EXIT
cat > "$NOTES" <<'EOF'
Installers for macOS, Windows and Linux. Check them against `SHA256SUMS.txt`.

The builds are not code-signed.
- **macOS:** the first time, try to open OZ in Applications and close the warning, then go to **System Settings → Privacy & Security** and click **Open Anyway**. On macOS 14 and earlier, right-click OZ and choose **Open** instead.
- **Windows:** when SmartScreen warns about an unknown publisher, choose **More info → Run anyway**.
- **Linux:** `chmod +x OZ-*.AppImage` and run it.

`OZ-worker-<version>.zip` is the kit for setting up your own relay Worker, which file sharing needs. Follow `README.txt` inside (Japanese).

By using OZ you agree to the [Terms of Use](https://github.com/jkfujinami/Oz/blob/main/TERMS.md).

---

macOS・Windows・Linux 向けのインストーラーです。ダウンロードしたファイルは `SHA256SUMS.txt` と照合して、改ざんされていないことを確認できます。

コード署名は行っていないため、初回は次の方法で起動してください。
- **macOS：** 「アプリケーション」フォルダの OZ を一度開こうとして警告を閉じ、「システム設定」→「プライバシーとセキュリティ」で「このまま開く」を押してください。macOS 14 以前は、OZ を右クリックして「開く」を選択してください。
- **Windows：** SmartScreen の警告が表示されたら、「詳細情報」→「実行」を選択してください。
- **Linux：** `chmod +x OZ-*.AppImage` を実行してから起動してください。

`OZ-worker-<版>.zip` は、ファイル共有に必要な中継 Worker の設置キットです。手順は同梱の `README.txt` をご覧ください。

ご利用の前に、必ず[利用規約](https://github.com/jkfujinami/Oz/blob/main/TERMS.md)をお読みください。
EOF

gh release create "$VERSION" --repo "$RELEASE_REPO" --title "OZ $VERSION" --notes-file "$NOTES" \
  "${FILES[@]}" SHA256SUMS.txt

git -C "$ROOT" tag -a "$VERSION" -m "OZ $VERSION"
if git -C "$ROOT" remote get-url origin >/dev/null 2>&1; then
  git -C "$ROOT" push origin "$VERSION"
fi

echo "== 公開しました: https://github.com/$RELEASE_REPO/releases/tag/$VERSION"
