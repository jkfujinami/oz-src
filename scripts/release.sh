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

if [ -n "$(git status --porcelain)" ]; then
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
- **macOS:** right-click OZ in Applications and choose **Open** the first time.
- **Windows:** when SmartScreen warns about an unknown publisher, choose **More info → Run anyway**.
- **Linux:** `chmod +x OZ-*.AppImage` and run it.

By using OZ you agree to the [Terms of Use](https://github.com/jkfujinami/Oz/blob/main/TERMS.md).

---

macOS・Windows・Linux 向けのインストーラーです。ダウンロードしたファイルは `SHA256SUMS.txt` と照合して、改ざんされていないことを確認できます。

コード署名は行っていないため、初回は次の方法で起動してください。
- **macOS：** 「アプリケーション」フォルダの OZ を右クリックし、「開く」を選択してください。
- **Windows：** SmartScreen の警告が表示されたら、「詳細情報」→「実行」を選択してください。
- **Linux：** `chmod +x OZ-*.AppImage` を実行してから起動してください。

ご利用の前に、必ず[利用規約](https://github.com/jkfujinami/Oz/blob/main/TERMS.md)をお読みください。
EOF

gh release create "$VERSION" --repo "$RELEASE_REPO" --title "OZ $VERSION" --notes-file "$NOTES" \
  "${FILES[@]}" SHA256SUMS.txt

git -C "$ROOT" tag -a "$VERSION" -m "OZ $VERSION"
if git -C "$ROOT" remote get-url origin >/dev/null 2>&1; then
  git -C "$ROOT" push origin "$VERSION"
fi

echo "== 公開しました: https://github.com/$RELEASE_REPO/releases/tag/$VERSION"
