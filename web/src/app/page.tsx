"use client";

import { useEffect, useState } from "react";
import { DEFAULT_TRACKER_URL as STANDARD_DEFAULT_TRACKER, OzApp, guardTrustFromEnv, iceServersFromEnv } from "@oz/ui";
import { sodiumReady } from "@oz/core";

/**
 * Web 版。画面もプロトコルも Desktop と同じもの (@oz/ui + @oz/core) を使う。
 *
 * トラッカーの既定値は、このページを配信したサーバ自身の /ws とする。
 * ページを取得した時点でそのサーバには IP アドレスが見えているので、新たに晒すものは無い。
 * 利用者が設定画面で変えた値があれば、そちらが優先される。
 * 平文の ws:// は localhost 以外では検証で弾かれる (https で配信すること)。
 */
function defaultTracker(): string {
  if (process.env.NEXT_PUBLIC_DEFAULT_TRACKER_URL) {
    return process.env.NEXT_PUBLIC_DEFAULT_TRACKER_URL;
  }
  if (typeof window !== "undefined") {
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      return `${scheme}://${window.location.host}/ws`;
    }
  }
  return STANDARD_DEFAULT_TRACKER;
}

/**
 * 信頼 Guard の設定 (ビルド時の環境変数)。Desktop と同じ意味。
 * 未設定・不正なら信頼設定なしで起動し、画面に警告を出す。
 * Next.js は process.env.NEXT_PUBLIC_* を名前で直接参照したものだけをビルド時に埋め込むので、
 * 下の参照は必ずこの形で書く (env オブジェクトに丸ごと渡すと埋め込まれない)。
 */
const GUARD_TRUST = guardTrustFromEnv({
  maintainerKeys: process.env.NEXT_PUBLIC_OZ_MAINTAINER_KEYS,
  maintainerThreshold: process.env.NEXT_PUBLIC_OZ_MAINTAINER_THRESHOLD,
  guardList: process.env.NEXT_PUBLIC_OZ_GUARD_LIST,
});

/**
 * STUN サーバ (ビルド時の環境変数。カンマ区切りの stun: URL)。未設定ならトラッカー (= このサーバ) の UDP 3478。
 * 未設定なら Google と Cloudflare の公開 STUN。NEXT_PUBLIC_* は名前で直接参照すること (上と同じ理由)。
 */
const ICE_SERVERS = iceServersFromEnv(process.env.NEXT_PUBLIC_OZ_ICE_SERVERS);

export default function Page() {
  const [tracker, setTracker] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    // IndexedDB と libsodium はブラウザでしか使えないので、描画はクライアントで始める
    let cancelled = false;
    sodiumReady.then(() => {
      if (!cancelled) setTracker(defaultTracker());
    });
    return () => { cancelled = true; };
  }, []);

  if (tracker === undefined) return null;
  return <OzApp badge="Web" defaultTrackerUrl={tracker} trust={GUARD_TRUST} iceServers={ICE_SERVERS} />;
}
