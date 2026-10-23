import type { Metadata } from "next";
import "@oz/ui/styles.css";

export const metadata: Metadata = {
  title: "Oz Protocol",
  description: "Oz Protocol (OZ) Web",
  // 検索エンジンに載せない (利用者の参照元として記録されるのを避ける)
  robots: { index: false, follow: false },
  // 外部へ参照元を送らない
  referrer: "no-referrer",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ja">
      <body>
        <div id="root">{children}</div>
      </body>
    </html>
  );
}
