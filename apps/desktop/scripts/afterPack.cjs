// macOS のアプリに ad-hoc 署名をかけ直す (electron-builder の afterPack。DMG・zip を作る前に走る)。
//
// ★ 開発者アカウントでの署名はしない (身元が結び付くため。electron-builder.yml の identity: null)。
//   ただ、署名を飛ばすと Electron の実行ファイルに元から付いている署名が、electron-builder が
//   Info.plist やリソースを差し替えた後の中身と合わなくなる。そのアプリをダウンロードして開くと、
//   Apple シリコンの macOS は「壊れているため開けません」と表示し、右クリックの「開く」でも開けない。
//   中身に合った ad-hoc 署名 (`-`) をかけ直せば、「開発元を確認できない」扱いになり、利用者が許可すれば開ける。
const { execFileSync } = require('node:child_process');
const path = require('node:path');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'darwin') return;
  const app = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
  execFileSync('codesign', ['--force', '--deep', '--sign', '-', app], { stdio: 'inherit' });
  execFileSync('codesign', ['--verify', '--deep', '--strict', app], { stdio: 'inherit' });
};
