import { SecurityInfo } from './SecurityInfo';
import { TermsText } from './TermsText';
import { TERMS_TITLE } from '../lib/terms';

/**
 * 仕組みと安全性の説明をまとめた画面。各画面には短い案内だけを置き、詳しい説明はここに集める。
 *
 * ★ 書く内容は実装と一致させること (誇張しない。守れない範囲を具体的に書く)。
 */
export function AboutView() {
  return (
    <div className="column-content about">
      <div className="page-head">
        <div>
          <div className="eyebrow">About</div>
          <h1 className="page-title">仕組みと安全性</h1>
        </div>
      </div>

      <div className="stack">
        <section className="panel" aria-labelledby="a-safety">
          <h2 id="a-safety" className="panel-title">守れること・守れないこと</h2>
          <SecurityInfo />
        </section>

        <section className="panel" aria-labelledby="a-route">
          <h2 id="a-route" className="panel-title">匿名経路</h2>
          <div className="prose">
            <p>
              送るものは、あなた → Guard (直接つながっている隣人) → M1 (Guard の隣人) の 2 段の暗号経路を通ります。
              中身は 1,200 バイトの固定長のセルに分け、すべてのノードが常に出し続けているダミーのセルに混ぜて送ります。
            </p>
            <ul>
              <li>Guard に見えるのは、あなたの IP と、セルを送っていることと、その量だけです。いつ本物を送ったかは分かりません。</li>
              <li>M1 に見えるのは行き先 (取りに行く URL など) と手前の Guard だけで、あなたの IP は届きません。</li>
              <li>Guard と M1 の両方が同じ相手の手にあると、あなたと行き先が結び付きます (Tor と同じ限界)。信頼 Guard を設定すると、この確率を下げられます。</li>
              <li>投稿は M1 の先でさらに何人かを経てから網に広がるので、最初に広めたノードはあなたでも Guard でもありません。</li>
              <li>
                Guard と M1 には、あなたと同じネットワーク (同じ LAN・同じ公開 IP) のノードを使いません。
                1 台の端末で複数のノードを動かしても、自分のノードだけで経路が組まれることはありません。
                そのため、ほかの人のノードが見つかるまでは「匿名経路を準備しています」のままになります。
              </li>
            </ul>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-ozzy">
          <h2 id="a-ozzy" className="panel-title">ファイル共有 (Ozzy)</h2>
          <div className="prose">
            <p>
              ファイルは端末で暗号化して 64 MiB ずつに分け、それぞれを 32 個のかけら (どの 16 個からでも元に戻せる) にして、
              複数の公開ロッカーにまとめて置きます。数社が消えたり止まったりしても取り出せます。
            </p>
            <ul>
              <li>ロッカーへ置くのも取るのも、あなたではなくオニオン回路の先のノード (M1) です。M1 は別の参加者の中継 Worker を通してロッカーへ行くので、ロッカーにも Worker にもあなたの IP は届きません。回路が組めないときは失敗し、直接は行きません。</li>
              <li>置いた直後に、別の経路で取り出して本当に置かれたかを確かめます。取ったかけらはハッシュで確かめ、偽物を返したノードは避けます。</li>
              <li>置き場所の一覧は暗号化して P2P のファイル保管に置き、リンク <code>[[ozzy:v3:…]]</code> だけがその鍵です。共通のサーバーやディレクトリは使いません。</li>
              <li>Guard には、あなたが送った量が見えます (誤り訂正の分、ファイルの約 2 倍)。</li>
              <li>ロッカーは置いたものを消すことがあり、期限で消える所もあります。半分まで消えても元に戻せます。</li>
              <li>Internet Archive は使いません。自分のアカウントで置くので、アカウントがあなたを名指しします。</li>
              <li>保存先を Gatekeeper Worker にすると、Gatekeeper に直接つなぐので IP が見えます。</li>
            </ul>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-worker">
          <h2 id="a-worker" className="panel-title">中継 Worker</h2>
          <div className="prose">
            <p>
              ファイル共有を利用する方には、Cloudflare Workers に中継用の Worker を 1 つずつ設置していただきます。
              設置した Worker は、他の参加者の中継ノード (M1) がファイル置き場にアクセスする際の中継に使われます。Worker の URL は他の参加者に共有されます。
            </p>
            <ol>
              <li>Cloudflare のアカウントを作成します。本名や普段お使いのメールアドレスと結び付かないアカウントにし、workers.dev のサブドメインにも身元が推測できない名前を付けてください。</li>
              <li>
                配布ページ (<code>https://github.com/jkfujinami/Oz/releases/latest</code>) から <code>OZ-worker-&lt;版&gt;.zip</code> をダウンロードし、同梱の README.txt の手順で Worker を設置します。
                Cloudflare の管理画面にコードを貼り付ける方法なら、ソフトウェアのインストールは不要です。クレジットカードの登録も必要ありません。
              </li>
              <li>表示された <code>https://….workers.dev</code> の URL を、「設定」→「ファイル共有」に貼り付けます。</li>
            </ol>
          </div>
        </section>

        <section className="panel" aria-labelledby="a-terms">
          <h2 id="a-terms" className="panel-title">{TERMS_TITLE}</h2>
          <TermsText />
        </section>
      </div>
    </div>
  );
}
