<p align="center"><img src="icon.svg" width="88" alt=""></p>

<h1 align="center">OZ（Oz Protocol）</h1>

<p align="center">
  ブラウザやデスクトップアプリで動作する、匿名性を重視した P2P ネットワークです。<br>
  WebRTC 上でのオニオンルーティング、匿名掲示板、中央サーバーを必要としない大容量ファイル共有の機能を備えています。
</p>

<p align="center">
  <a href="https://github.com/jkfujinami/Oz/releases/latest">ダウンロード</a> ·
  <a href="https://ozzy-web.pages.dev/">Web 版</a> ·
  <a href="TERMS.md">利用規約</a> ·
  <a href="README.md">English</a>
</p>

> [!WARNING]
> OZ は開発段階のソフトウェアで、第三者による安全性の監査を受けていません。身の安全に関わる用途には使用しないでください。

ご利用の前に、必ず[利用規約](TERMS.md)をお読みください。アプリの初回起動時にも、利用規約への同意をお願いしています。

## 主な機能

- **ブラウザ上でのオニオンルーティング**<br>
  送信するデータは、WebRTC で接続している相手から選んだ Guard と、その Guard の接続先から選んだ中継ノードの 2 段を経由し、段ごとに暗号化されます。通信は 1,200 バイトの固定長のセルに分割され、常に流れているダミーのセルに混ぜて送られます。そのため、Guard には実際に送信したタイミングが分からず、中継ノードには送信者の IP アドレスが分かりません。
- **利用者全員による中継**<br>
  出口ノードを専門に運営する人はいません。アプリを開いている利用者どうしが、互いの通信を中継し合います。
- **送信元を特定しにくい投稿**<br>
  投稿は中継ノードを出たあと、Dandelion++ と同様の方式でいくつかのノードを経由してから、ネットワーク全体に広がります。
- **匿名掲示板**<br>
  誰でも閲覧できる公開の板と、共有コードを知っている人だけが参加できる非公開の板があります。スレッドごとに異なる署名鍵を使うため、別々のスレッドへの投稿が同じ人のものだと結び付けられることはありません。
- **保管サーバーを使わない大容量ファイル共有（Ozzy）**<br>
  ファイルは暗号化したうえで Reed-Solomon 符号により 32 個の断片に分け（そのうち 16 個があれば復元できます）、無料の公開ファイル置き場に分散して保存します。アップロードとダウンロードは、経路上の中継ノードが、参加者自身が用意した Cloudflare Worker を通じて行います。ファイル置き場にも Worker にも、利用者の IP アドレスは伝わりません。
- **アカウント不要の不正利用対策**<br>
  ノードの作成には Argon2id による計算量の証明が、投稿にはサイズに応じた Equi-X による計算量の証明が必要です。
- **端末内データの暗号化**<br>
  投稿の履歴や板の鍵は、設定したパスワードで暗号化して保存します。ロック機能と緊急消去機能も備えています。

## 防げないこと

- インターネット全体を広く監視できる攻撃者による分析。
- 利用者の Guard と中継ノードが共謀した場合の追跡。Tor と同じく、2 段構成に由来する限界です。信頼 Guard を利用することで、この危険を減らせます。
- Guard とトラッカーからは利用者の IP アドレスが見えるため、OZ を利用していること自体は知られます。なお、トラッカーは WebRTC の接続相手を紹介するだけです。
- 中継用の Worker はすべて Cloudflare 上で動作します。Cloudflare から見えるのは中継ノードとファイル置き場の URL で、利用者本人ではありませんが、1 つの企業に依存している点にはご注意ください。
- ファイル置き場の運営者が、ファイルを削除することがあります。各ストライプの断片が半分まで失われても、ファイルは復元できます。

## ダウンロード

macOS・Windows・Linux 向けのインストーラーを [Releases](https://github.com/jkfujinami/Oz/releases) で配布しています。ファイルが改ざんされていないことを確認するための `SHA256SUMS.txt` もあわせて公開しています。

コード署名を行うと、Apple や Microsoft の開発者アカウントと開発者の身元が結び付くため、**コード署名は行っていません**。初回は次の方法で起動してください。

- **macOS：** 「アプリケーション」フォルダの OZ を右クリックし、「開く」を選択してください。
- **Windows：** SmartScreen の警告が表示されたら、「詳細情報」→「実行」を選択してください。
- **Linux：** `chmod +x OZ-*.AppImage` を実行してから起動してください。

デスクトップ版では、この端末を他の利用者のための **Guard** として動作させることもできます（「設定」→「この端末の Guard」）。Guard は画面とは別の ID でバックグラウンドで動作し、画面をロックしても停止しません。

## 信頼 Guard

1 段目の中継である Guard からは利用者の IP アドレスが見えるため、OZ はメンテナーが署名したリストに載っている Guard を優先して使います。メンテナーの公開鍵は [`trust/trust.json`](trust/trust.json) からアプリに組み込まれます。署名済みのリストが公開されるまでは、ネットワーク上の Guard から自動的に選択します。Guard をリストに登録する手順は [`trust/README.md`](trust/README.md) をご覧ください。

## リポジトリの構成

| 場所 | 内容 |
| --- | --- |
| `packages/core` | プロトコル本体（ID、WebRTC 接続、オニオンルーティング、掲示板、Ozzy） |
| `packages/ui` | Web 版とデスクトップ版で共通の画面（React） |
| `packages/tracker` | 接続相手を紹介する WebSocket トラッカー（Node.js 版と Deno Deploy 版） |
| `packages/r2-worker` | 参加者が中継用に設置する Cloudflare Worker |
| `apps/desktop` | デスクトップ版（Electron） |
| `apps/guard` | 画面を持たない Guard |
| `web` | Web 版（Next.js による静的サイト） |
| `trust` | ビルド時に組み込む、メンテナーの公開鍵と署名済みの Guard リスト |

## ビルド

Node.js 22 が必要です。

```sh
npm ci
npm run build:core

# デスクトップ版（インストーラーは apps/desktop/release/ に作成されます）
npm run build:desktop
cd apps/desktop && npx electron-builder --mac --win --linux --publish never

# Web 版（静的ファイルは web/out/ に作成されます）
npm run build:web

# テスト
npm test
```

リリースは、メンテナーの端末で [`scripts/release.sh`](scripts/release.sh) を実行して作成し、[jkfujinami/Oz](https://github.com/jkfujinami/Oz/releases) で公開しています。利用規約の文面は `packages/ui/src/lib/terms.ts` で管理しており、変更した場合は `npm run terms` で `TERMS.md` を更新してください。

## 開発への参加とセキュリティ

開発への参加方法は [CONTRIBUTING.md](CONTRIBUTING.md) をご覧ください。脆弱性を見つけた場合は、公開の Issue ではなく、[SECURITY.md](SECURITY.md) に記載の方法で非公開にてご報告ください。

## ライセンスと利用規約

本ソフトウェアは [MIT ライセンス](LICENSE) のもとで提供しています。ご利用にあたっては[利用規約](TERMS.md)に従ってください。本ソフトウェアは無保証で提供され、利用に伴う責任は利用者ご自身が負うものとします。
