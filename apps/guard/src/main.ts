/**
 * ヘッドレスの信頼 Guard。
 *
 *   OZ_GUARD_PASSPHRASE=... npm run guard -- \
 *     --tracker wss://tracker.example.org/ws --data /var/lib/oz-guard
 *
 * ★ `npm run guard` は esbuild で dist/main.mjs にまとめてから node で動かす。tsx で直接動かさないのは、
 *   core の src を tsx が CJS として読み、`export *` で再公開した名前 (定数など) が undefined になるため。
 *   core の dist も拡張子なしの ESM で、Node が直接は読めない (packages/tracker の `npm run tracker` も同じ理由で動かない)。
 *
 * ★ 公開 IP (または endpoint-independent な NAT) のあるサーバで動かす。Guard は利用者から
 *   WebRTC で接続を受けるので、UDP の到達性が要る (README の「Guard を立てる」)。
 * ★ ログには件数だけを出す。利用者の peerId や IP は出さない。
 */
import { LogLevel, currentLevels, setLevel } from '@oz/core';
import { ConfigError, USAGE, loadConfig } from './config';
import { startGuard } from './GuardApp';

async function main(): Promise<number> {
  let loaded;
  try {
    loaded = loadConfig(process.argv.slice(2), process.env);
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`設定エラー: ${err.message}\n`);
      console.error(USAGE);
      return 2;
    }
    throw err;
  }
  if (loaded.help) {
    console.log(USAGE);
    return 0;
  }
  // ★ パスフレーズの環境変数は読んだら消す (子プロセスへ引き継がない)
  delete process.env.OZ_GUARD_PASSPHRASE;

  // 状態行は INFO で出す (OZ_LOG で guard を指定していればそちらに従う)。core 全体は既定の WARN のまま
  if (!('guard' in currentLevels())) setLevel('guard', LogLevel.INFO);

  let handle;
  try {
    handle = await startGuard(loaded.config);
  } catch (err) {
    console.error(`起動できませんでした: ${(err as Error).message}`);
    return 1;
  }

  let signals = 0;
  const shutdown = (name: string) => {
    signals++;
    // 2 回目のシグナルは待たずに終える (止まらないときの逃げ道)
    if (signals > 1) process.exit(130);
    console.log(`${name} を受け取りました。停止します...`);
    handle.stop().then(
      () => {
        console.log('停止しました');
        process.exit(0);
      },
      (err) => {
        console.error(`停止中にエラー: ${(err as Error).message}`);
        process.exit(1);
      },
    );
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  // 常駐させる: トラッカーが落ちていて接続が 0 本でも、プロセスは終わらない
  setInterval(() => undefined, 2 ** 30);
  return -1; // 起動完了: プロセスは接続が生かし続ける
}

main().then((code) => {
  if (code >= 0) process.exit(code);
});
