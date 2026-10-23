/**
 * 「守れること・守れないこと」の説明。
 *
 * ★ 過信による事故を防ぐための表示。誇張しないこと。
 *   ここに書いた内容は実装の到達点 (監査と修正の結果) と一致させておく。
 *   守れない範囲を広く・具体的に書くのが要点。
 */
export function SecurityInfo({ compact = false }: { compact?: boolean }) {
  return (
    <div style={{ fontSize: compact ? '11px' : '12px', lineHeight: 1.6, color: 'var(--text-dim)' }}>
      <div style={{ fontWeight: 700, color: 'var(--success)', marginBottom: '4px' }}>守れること</div>
      <ul style={{ margin: '0 0 10px 18px', padding: 0 }}>
        <li>網の中の監視者 (隣人・中継・保管ノード) から「どの投稿を誰が書いたか」を隠します。投稿はダミーの通信に混ぜた多段の暗号経路で送られます。</li>
        <li>この端末に保存するデータ (投稿履歴・板の鍵など) はパスワードで暗号化されます。推測されにくい長いパスワードであれば、ロック中や電源を切った状態で押収されても読めません。</li>
        <li>板の鍵を持たない人には、投稿の内容は読めません。</li>
      </ul>

      <div style={{ fontWeight: 700, color: 'var(--danger)', marginBottom: '4px' }}>守れないこと</div>
      <ul style={{ margin: '0 0 0 18px', padding: 0 }}>
        <li>OZ を使っていること自体。あなたの IP アドレスは接続先の端末、トラッカーの運営者、通信事業者 (ISP)、STUN の運営者 (既定では Google と Cloudflare) から見えます。端末に OZ が入っていることも隠せません。</li>
        <li>国全体の通信を監視できる相手。そのような環境での告発には使わないでください。</li>
        <li>職場など所属組織のネットワークや端末からの利用。組織内の調査では、利用者であること自体から特定され得ます。</li>
        <li>ロックを解除している間の端末の押収。席を離れるときはロックしてください。</li>
        <li>トリップを使った投稿同士は、同じ人物のものとして紐付きます。</li>
        <li>本文に含まれる情報 (自分しか知らない事実、文体など) からの特定。</li>
      </ul>
    </div>
  );
}
