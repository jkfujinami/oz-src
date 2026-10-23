OZ 中継 Worker 設置キット
==========================

OZ のファイル共有を利用するには、ご自身の Cloudflare アカウントに、中継用の Worker を 1 つ設置していただく必要があります。
設置した Worker は、他の参加者がファイルをやり取りする際の中継にも使われます。ファイルの中身は暗号化されているため、Worker から読み取ることはできません。

設置は無料で、クレジットカードの登録も必要ありません。

このフォルダの内容
  worker.js          Worker のプログラム
  deploy-worker.bat  設置用スクリプト (Windows)
  deploy-worker.sh   設置用スクリプト (macOS / Linux)
  README.txt         この説明書


■ はじめに：Cloudflare アカウントについて

Worker の URL (https://ozzy-gatekeeper.<サブドメイン>.workers.dev) は、OZ の他の参加者に共有されます。

  - 本名や普段お使いのメールアドレスと結び付かないアカウントを作成してください。
  - workers.dev のサブドメインには、身元が推測できない名前を付けてください。

アカウントは https://dash.cloudflare.com/sign-up で作成できます。


■ 方法 1：管理画面にコードを貼り付ける (インストール不要)

1. https://dash.cloudflare.com/ にログインし、「Workers & Pages」を開きます。
2. 「作成」(Create) から新しい Worker を作成します。名前は「ozzy-gatekeeper」などにして、そのままデプロイします。
   初めて Worker を作成する場合は、workers.dev のサブドメインを決める画面が表示されます。
3. 作成した Worker の「コードを編集」(Edit code) を開きます。最初から入っているコードをすべて削除し、
   このフォルダの worker.js の内容をすべて貼り付けます。
4. 「デプロイ」(Deploy) を押します。
5. Worker の URL を、OZ の「設定」→「ファイル共有」に貼り付け、「確かめて設定」を押します。


■ 方法 2：スクリプトで設置する (Node.js が必要)

1. Node.js の LTS 版を https://nodejs.org/ からインストールします。
2. ダウンロードした ZIP ファイルを展開します (ZIP を開いたままでは実行できません)。
3. 展開したフォルダのスクリプトを実行します。
     Windows        : deploy-worker.bat をダブルクリックします。
                      セキュリティの警告が表示された場合は、「実行」を選択してください。
     macOS / Linux  : ターミナルでこのフォルダに移動し、次のコマンドを実行します。
                        bash deploy-worker.sh
4. ブラウザで Cloudflare のログイン画面が開いたら、ログインして「Allow」を押します。
5. 最後に表示された Worker の URL を、OZ の「設定」→「ファイル共有」に貼り付け、「確かめて設定」を押します。


■ OZ を更新したとき

Worker の更新が必要な場合、OZ に「Worker の版が古いです」と表示されます。
新しい版の設置キットを使って、同じ手順をもう一度行ってください。同じ名前の Worker が上書きされます。


■ ご注意

  - Worker の運用は、OZ の利用規約 (https://github.com/jkfujinami/Oz/blob/main/TERMS.md) と
    Cloudflare の利用規約に従い、ご自身の責任で行ってください。
  - Worker を削除すると、OZ のファイル共有は利用できなくなります。
