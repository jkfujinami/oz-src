<p align="center"><img src="icon.svg" width="88" alt=""></p>

<h1 align="center">OZ — Oz Protocol</h1>

<p align="center">
  ブラウザのタブか小さなデスクトップアプリで動く、匿名の P2P ネットワーク。<br>
  WebRTC 上のオニオンルーティング、匿名掲示板、中央サーバーの無い大容量ファイル共有。
</p>

<p align="center">
  <a href="https://github.com/jkfujinami/Oz/releases/latest">ダウンロード</a> ·
  <a href="https://ozzy-web.pages.dev/">Web 版</a> ·
  <a href="README.md">English</a>
</p>

> [!WARNING]
> OZ は実験段階で、第三者の監査を受けていません。身の安全がかかる場面では頼らないでください。

## できること

- **ブラウザの中でオニオンルーティング。** 送るものはすべて 2 ホップ (WebRTC の隣接ノードから選んだ Guard と、その Guard の隣から選んだ中継) を、層ごとに暗号化して通ります。通信は 1,200 バイト固定のセルに切られ、常に流れているダミーのセルに混ぜて送られます。Guard にはあなたがいつ本当に送ったのか分からず、中継にはあなたの IP が分かりません。
- **全員が中継する。** 出口を運営するボランティアはいません。タブを開いている人が、互いのセルを運びます。
- **投稿はあなたから始まらない。** 中継のあと、投稿は Dandelion++ 風のランダムな経路を歩いてから広がります。
- **匿名掲示板。** 公開の板と、合言葉で共有する非公開の板があります。スレッドごとに別の署名鍵を使うので、別々のスレッドへの投稿は結び付けられません。
- **保管サーバーの無い大容量ファイル共有 (Ozzy)。** ファイルは暗号化して Reed-Solomon 符号化し (32 個の断片のうち 16 個あれば元に戻る)、無料の公開ファイル置き場に分散します。アップロードもダウンロードも、あなたの経路上の中継が、参加者が各自で立てた Cloudflare Worker を通して行うので、ファイル置き場にも Worker にもあなたの IP は見えません。
- **アカウント無しの乱用対策。** ノードの身元には Argon2id の計算量証明が要り、投稿には大きさに応じた Equi-X の計算量証明が付きます。
- **手元のデータは封印。** 履歴や板の鍵はパスワードで暗号化します。ロックと緊急消去のボタンがあります。

## 守れないもの

- インターネットの大部分を見張れる、全域を盗聴する相手。
- あなたの Guard と中継の 1 つが結託している場合。Tor と同じ 2 ホップの限界です。下の「信頼 Guard」で危険を減らします。
- Guard とトラッカーにはあなたの IP が見えるので、OZ を使っていることは分かります。トラッカーは WebRTC の相手を紹介するだけです。
- すべての中継 Worker は Cloudflare の上で動きます。Cloudflare に見えるのは中継とファイル置き場の URL で、あなたではありませんが、1 つの会社です。
- ファイル置き場はファイルを消すことがあります。各ストライプの断片が半分まで消えても、ファイルは元に戻せます。

## ダウンロード

macOS・Windows・Linux 用のインストーラは [Releases](https://github.com/jkfujinami/Oz/releases) にあります。照合用の `SHA256SUMS.txt` も置いています。

Apple や Microsoft の開発者アカウントに身元が結び付くため、**コード署名はしていません**。

- **macOS:** 初回は「アプリケーション」の OZ を右クリックして **開く** を選んでください。
- **Windows:** SmartScreen が「発行元不明」と警告します。**詳細情報 → 実行** を選んでください。
- **Linux:** `chmod +x OZ-*.AppImage` してから起動してください。

デスクトップ版は、他の人のための **Guard** にもなれます (設定 → この端末の Guard)。画面とは別の身元で裏で動き、画面をロックしても止まりません。

## 信頼 Guard

1 ホップ目にはあなたの IP が見えるので、OZ はメンテナが署名したリストに載っている Guard を優先します。メンテナの公開鍵は [`trust/trust.json`](trust/trust.json) からアプリに組み込まれます。署名済みのリストができるまでは、開かれたネットワークから Guard を選びます。Guard をリストに載せる手順は [`trust/README.md`](trust/README.md) にあります。

## リポジトリの構成

| 場所 | 中身 |
| --- | --- |
| `packages/core` | プロトコル本体 (身元、WebRTC のメッシュ、オニオンルーティング、掲示板、Ozzy) |
| `packages/ui` | Web 版とデスクトップ版で共通の React の画面 |
| `packages/tracker` | 相手を紹介する WebSocket のトラッカー (Node と Deno Deploy) |
| `packages/r2-worker` | 参加者が中継として立てる Cloudflare Worker |
| `apps/desktop` | Electron のアプリ |
| `apps/guard` | 画面の無い Guard |
| `web` | 静的な Web 版 (Next.js) |
| `trust` | ビルド時に組み込むメンテナの公開鍵と署名済みの Guard リスト |

## ビルド

Node.js 22 が必要です。

```sh
npm ci
npm run build:core

# デスクトップ版 (インストーラは apps/desktop/release/ にできる)
npm run build:desktop
cd apps/desktop && npx electron-builder --mac --win --linux --publish never

# Web 版 (静的ファイルは web/out/ にできる)
npm run build:web

# テスト
npm test
```

リリースはメンテナの端末で [`scripts/release.sh`](scripts/release.sh) を使って作り、[jkfujinami/Oz](https://github.com/jkfujinami/Oz/releases) に公開します。

## 参加とセキュリティ

[CONTRIBUTING.md](CONTRIBUTING.md) を見てください。脆弱性は公開の Issue ではなく、[SECURITY.md](SECURITY.md) の方法で非公開で知らせてください。

## ライセンス

[MIT](LICENSE)。OZ は無保証で提供されます。使い方と、あなたに適用される法律を守ることは、利用者自身の責任です。
