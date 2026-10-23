import type { NextConfig } from "next";
import fs from "node:fs";
import path from "node:path";

/**
 * 信頼 Guard の設定 (リポジトリの trust/) を組み込む。環境変数で渡されていればそちらを使う。
 * ★ ここに入るのはメンテナの公開鍵と署名済みのリストだけ (秘密ではない)。リストは画面で検証してから使う。
 */
function trustEnv(): Record<string, string> {
  const dir = path.resolve(__dirname, "../trust");
  const out: Record<string, string> = {};
  try {
    const trust = JSON.parse(fs.readFileSync(path.join(dir, "trust.json"), "utf8")) as { maintainerKeys?: string[]; threshold?: number };
    const keys = (trust.maintainerKeys ?? []).filter(Boolean);
    if (keys.length > 0 && !process.env.NEXT_PUBLIC_OZ_MAINTAINER_KEYS) {
      out.NEXT_PUBLIC_OZ_MAINTAINER_KEYS = keys.join(",");
      out.NEXT_PUBLIC_OZ_MAINTAINER_THRESHOLD = String(trust.threshold ?? 1);
    }
    const list = fs.readFileSync(path.join(dir, "guard-list.txt"), "utf8").trim();
    if (list && !process.env.NEXT_PUBLIC_OZ_GUARD_LIST) out.NEXT_PUBLIC_OZ_GUARD_LIST = list;
  } catch {
    // trust/ が無いときは組み込まない (信頼設定なしで動き、画面に警告を出す)
  }
  return out;
}

const nextConfig: NextConfig = {
  // 画面は Desktop と共通の @oz/ui (TypeScript ソースのまま配布) を使う
  transpilePackages: ["@oz/ui"],
  output: "export",
  env: trustEnv(),
};

export default nextConfig;
