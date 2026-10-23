export enum WireType {
  // Control (0x1x)
  JOIN          = 0x10,
  PING          = 0x12,
  PONG          = 0x13,
  /** 接続直後のチャレンジ。相手はこれに署名して JOIN を返す (Bound Identity の所有証明) */
  HELLO         = 0x17,

  // PEX (0x2x)
  PEX_REQUEST   = 0x20,
  PEX_RESPONSE  = 0x21,

  // Signaling Relay (0x3x)
  SDP_RELAY     = 0x30,
  ICE_RELAY     = 0x31,

  // Gossip (0x4x)
  GOSSIP        = 0x40,
  STEM          = 0x41,
  /**
   * 多段オニオン暗号化された Stem パケット (Onion Stem Routing)。
   * 中継ノードは平文パケットIDも内容も読めず、全ホップ共謀時以外特定不能。
   */
  ONION_STEM    = 0x44,

  // Catch-up (0x6x): 再接続した端末が、Guard (または 1 ホップ目の隣人) に取り逃した投稿を頼む
  /**
   * 「since (OZ_EPOCH からの分) 以降の投稿を古い順に送って」。本体は 3 バイト。
   * ★ 全員が同じ要求を出し、同じものが流れる (誰が何を読むかは漏れない)。network/history/CatchupServer。
   */
  CATCHUP_REQ   = 0x60,
  /** 投稿の束 (u16 件数 ‖ { u16 長さ ‖ パケット } × 件数)。1 フレーム 16KiB 以内に分けて送る */
  CATCHUP_DATA  = 0x61,
  /** 追いつきの終わり (status u8 ‖ nextSince u24) */
  CATCHUP_END   = 0x62,

  // LeaseSet (0x7x): 保管担当の位置と受け口 (IP なし)。全員が手元に持つ。network/storage/LeaseSetRouter
  /** leaseSet 1 件 (LeaseSet のバイト列そのまま)。flood で全員に配る */
  LEASESET          = 0x70,
  /** 手持ちの leaseSet を全部ください (本体は空)。1 ホップ目の検証後に 1 回 */
  LEASESET_SYNC_REQ = 0x71,
  /** leaseSet の束 (u16 件数 ‖ { u16 長さ ‖ leaseSet } × 件数)。1 フレーム 16KiB 以内に分けて送る */
  LEASESET_SYNC     = 0x72,

  // Tunnel (0x8x): 保管担当 (保持者) への受け口。取りに行く側 R → R の 1 ホップ目 G_R → 保持者の Guard G_h → 保持者 H。
  //   network/tunnel/TunnelRelay。本体 (body) は H の公開鍵への sealed box で、中継 (Guard) には読めない。
  /** 保持者 → 受け口の Guard: 「この tunnelId 宛の要求を、この接続に回して」 (tunnelId 8) */
  TUNNEL_REGISTER   = 0x80,
  /** Guard → 保持者: 登録の結果 (tunnelId 8 ‖ ok u8) */
  TUNNEL_REGISTERED = 0x81,
  /** R → G_R: 要求 (reqId u32 ‖ gateway 16 ‖ tunnelId 8 ‖ body) */
  TUNNEL_SEND       = 0x82,
  /** G_R → G_h: 転送 (returnTag u32 ‖ tunnelId 8 ‖ body) */
  TUNNEL_FWD        = 0x83,
  /** G_h → H: 配送 (returnTag u32 ‖ fromHop 16 ‖ body) */
  TUNNEL_DELIVER    = 0x84,
  /** H → G_h: 応答の 1 片 (returnTag u32 ‖ toHop 16 ‖ seq u16 ‖ flags u8 ‖ body) */
  TUNNEL_REPLY      = 0x85,
  /** G_h → G_R: 応答の 1 片 (returnTag u32 ‖ seq u16 ‖ flags u8 ‖ body) */
  TUNNEL_RET        = 0x86,
  /** G_R → R: 応答の 1 片 (reqId u32 ‖ seq u16 ‖ flags u8 ‖ body) */
  TUNNEL_RESULT     = 0x87,
  /** 経路上のどこかで失敗した (id u32 ‖ code u8)。id は受け手から見て reqId か returnTag */
  TUNNEL_ERROR      = 0x88,

  // Ozzy (0x9x): 外部ロッカーの範囲 (1 チャンク) を、オニオン回路の M1 に代わりに取ってもらう。ozzy/MeshRange
  //   要求は ONION_STEM のセル (読み手 → Guard → M1。cover と同じ送出枠)。応答はこの 2 つで戻る。
  /** M1 → Guard: 応答の 1 片 (replyHeader 68 ‖ seq u16 ‖ flags u8 (bit0 = final) ‖ body)。replyHeader は Guard 宛ての封印 */
  OZZY_REPLY        = 0x90,
  /** Guard → 読み手: 応答の 1 片 (replyId u32 ‖ seq u16 ‖ flags u8 ‖ body)。body は読み手の鍵で暗号化されたまま */
  OZZY_RESULT       = 0x91,
  /** 隣人へ: 知っている Ozzy の中継 Worker の広告をください (本体なし)。ozzy/WorkerPool */
  OZZY_WORKER_REQ   = 0x92,
  /** 隣人から: 中継 Worker の広告 (count u8 ‖ { pubkey 32 ‖ powCounter u32 ‖ expiresMin u32 ‖ lp8(url) ‖ sig 64 } × count) */
  OZZY_WORKER_ADS   = 0x93,
  /** 告発者 → Guard: Slab の本体の 1 片 (upHeader 80 ‖ seq u16 ‖ flags u8 ‖ body)。upHeader は Guard 宛ての封印 (M1 ‖ uploadId) */
  OZZY_UP           = 0x94,
  /** Guard → M1: Slab の本体の 1 片 (uploadId 16 ‖ seq u16 ‖ flags u8 ‖ body)。body は告発者の鍵で暗号化されたまま */
  OZZY_UP_FWD       = 0x95,

  UNKNOWN       = 0xFF
}
