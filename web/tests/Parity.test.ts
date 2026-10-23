import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * Web と Desktop が同じプロトコル・同じ画面を使っていることの検査。
 *
 * ★ 以前の Web は @oz/core の古い複製 (src/lib) を持っており、Desktop と
 *   プロトコルが食い違っていた。プロトコルは @oz/core、画面は @oz/ui、
 *   トラッカーは @oz/tracker にだけ置き、アプリ側に複製させない。
 */
const ROOT = path.resolve(__dirname, '..');
const DESKTOP = path.resolve(ROOT, '../apps/desktop');

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sourceFiles(p));
    else if (/\.(ts|tsx)$/.test(name) && !name.endsWith('.d.ts')) out.push(p);
  }
  return out;
}

/** プロトコルの実装があることを示す識別子 (これらがアプリ側に現れたら複製を疑う) */
const PROTOCOL_MARKERS = [
  /crypto_sign_detached|crypto_box_seal|crypto_aead|crypto_pwhash/,
  /new RTCPeerConnection/,
  /class \w*(PeerManager|WireCodec|PacketBuilder|NodeIdentity|SignalingClient|TrackerServer|SessionManager)\b/,
  /from ['"]libsodium-wrappers/,
  /from ['"]idb['"]/,
  /from ['"]@msgpack\/msgpack['"]/,
];

describe('Web: プロトコルを複製しない', () => {
  const files = [...sourceFiles(path.join(ROOT, 'src')), path.join(ROOT, 'server.ts')];

  it('Web のソースにプロトコルの実装が無い', () => {
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      for (const marker of PROTOCOL_MARKERS) {
        expect(marker.test(text), `${path.relative(ROOT, file)} matches ${marker}`).toBe(false);
      }
    }
  });

  it('旧い複製のディレクトリが残っていない', () => {
    for (const dir of ['src/lib', 'src/server', 'src/providers', 'src/components', 'src/hooks']) {
      expect(() => statSync(path.join(ROOT, dir)), dir).toThrow();
    }
  });

  it('画面は @oz/ui の OzApp、トラッカーは @oz/tracker を使う', () => {
    expect(readFileSync(path.join(ROOT, 'src/app/page.tsx'), 'utf8')).toMatch(/from ["']@oz\/ui["']/);
    expect(readFileSync(path.join(ROOT, 'server.ts'), 'utf8')).toMatch(/from ['"]@oz\/tracker['"]/);
  });

  it('依存に @oz/core・@oz/ui・@oz/tracker があり、暗号ライブラリを直接持たない', () => {
    const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    expect(Object.keys(pkg.dependencies)).toEqual(expect.arrayContaining(['@oz/core', '@oz/ui', '@oz/tracker']));
    for (const dep of ['libsodium-wrappers-sumo', 'idb', '@msgpack/msgpack']) {
      expect(pkg.dependencies[dep], dep).toBeUndefined();
    }
  });
});

describe('Desktop: プロトコルを複製しない', () => {
  it('Desktop のレンダラーは OzApp を描画するだけで、プロトコルの実装を持たない', () => {
    const files = sourceFiles(path.join(DESKTOP, 'src'));
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      for (const marker of PROTOCOL_MARKERS) {
        expect(marker.test(text), `${path.relative(DESKTOP, file)} matches ${marker}`).toBe(false);
      }
    }
    expect(readFileSync(path.join(DESKTOP, 'src/main.tsx'), 'utf8')).toMatch(/from ['"]@oz\/ui['"]/);
  });
});
