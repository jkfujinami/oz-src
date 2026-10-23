# 信頼 Guard の設定 (アプリに組み込む値)

ここに置いた値を、デスクトップ版・Web 版・Guard ノードがビルド時 / 起動時に読みます。
どれも秘密ではありません (公開鍵と署名済みのリスト)。メンテナの **秘密鍵はここに置かない** こと。

| ファイル | 中身 | 読むもの |
|:--|:--|:--|
| `trust.json` | メンテナの公開鍵 (base64url) と必要な署名の数 | デスクトップ・Web (ビルド時)、Guard (`--trust-dir`) |
| `guards.txt` | 信頼リストに載せる Guard 文字列 (`oz-guard:...`) | メンテナの署名 (`sign --guards`) |
| `guard-list.txt` | 署名済みの最新の信頼リスト (`oz-guards:...`) | デスクトップ・Web (ビルド時)、Guard (`--trust-dir`) |
| `lists/v<版>.txt` | 過去の全版 (追加・削除の経緯を誰でも追えるように) | 人 |

環境変数 (`VITE_OZ_MAINTAINER_KEYS` / `NEXT_PUBLIC_OZ_MAINTAINER_KEYS` など) を設定してビルドすると、そちらが優先されます。

## 手順

1. **メンテナ鍵を作る** (秘密鍵はリポジトリの外。普段のターミナルで実行し、パスワードを入れる)

   ```
   mkdir -m 700 -p ~/.oz-maintainer
   cd packages/core && npm run guard-maintainer -- keygen --out ~/.oz-maintainer/maintainer.key
   ```

2. **公開鍵を `trust.json` に入れる**

   ```
   cd packages/core && npm run guard-maintainer -- pubkey --key ~/.oz-maintainer/maintainer.key
   ```

3. **Guard を起動し、表示された Guard 文字列を `guards.txt` に足す**。どちらかで動かす:
   - デスクトップ版: 設定の「この端末の Guard」で「Guard として動かす」。画面のノードとは別の身元で、
     見えないウィンドウで動く (画面をロックしても止まらない。ログイン時の起動も選べる)。Guard 文字列はその画面に出る。
   - サーバー: `npm run guard -- --tracker <wss://...> --data <dir> --passphrase-file <file> --trust-dir trust` (`--help` で一覧)

4. **署名して信頼リストを作る** (版は毎回前より大きくする。利用者は古い版を受け付けない)

   ```
   cd packages/core && npm run guard-maintainer -- sign --key ~/.oz-maintainer/maintainer.key \
     --guards ../../trust/guards.txt --version <版> --days 90 --out ../../trust/lists/v<版>.txt
   cp ../../trust/lists/v<版>.txt ../../trust/guard-list.txt
   ```

5. **ビルドし直して配る** (`npm run build:web`、`npm --workspace=@oz/desktop run dist`)。
   すでに配ったアプリの利用者は、設定の「匿名経路」に新しいリストを貼れば取り込めます。
