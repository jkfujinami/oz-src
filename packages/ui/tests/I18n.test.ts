import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { compile, readSources, OUTPUT_FILE } from '../i18n/generate';
import { t } from '../src/i18n';
import { scanJapaneseLiterals } from './i18nScan';

describe('画面の文言 (i18n): 生成と見張り', () => {
  it('★messages.gen.ts は locales/*.yaml から作ったものと同じ (YAML を直したら npm run i18n -w @oz/ui)', () => {
    expect(fs.readFileSync(OUTPUT_FILE, 'utf8')).toBe(compile(readSources()).code);
  });

  it('★検査: ja に無いキー・差し込みや部品の印の食い違い・other の無い複数形・使えない名前・閉じていない印は生成しない', () => {
    const ja = 'a:\n  b: "x {n}"\n  c: "<link>y</link>"\n  d: z\n';
    expect(() => compile({ ja, en: 'a:\n  z: q\n' })).toThrow(/ja.yaml に無い/);
    expect(() => compile({ ja, en: 'a:\n  b: "x {m}"\n' })).toThrow(/差し込み/);
    expect(() => compile({ ja, en: 'a:\n  c: "<b>y</b>"\n' })).toThrow(/部品の印/);
    expect(() => compile({ ja: 'a:\n  p:\n    one: "{count} x"\n' })).toThrow(/other/);
    expect(() => compile({ ja: 'a-b: x\n' })).toThrow(/使えない名前/);
    expect(() => compile({ ja: 'a: "<link>x"\n' })).toThrow(/閉じていない/);
    // 英語の複数形: other 以外は {count} を省いてよい。訳していないキーは警告だけ
    const ok = compile({ ja: 'r: "{count} 行"\nq: x\n', en: 'r:\n  one: one row\n  other: "{count} rows"\n' });
    expect(ok.warnings).toEqual(['en.yaml: 訳していないキー 1 件 (ja を出す)']);
    expect(ok.code).toContain('"r": { one: "one row", other: "{count} rows" }');
  });

  it('★型: 無いキー・差し込みの渡し忘れや名前違いは型で落ちる (この行が tsc を通ることが確かめ)', () => {
    // @ts-expect-error 無いキー
    expect(t('status.nope')).toBe('status.nope');
    // @ts-expect-error 差し込みが要るキーに値を渡していない
    t('status.value.history');
    // @ts-expect-error 差し込みの名前が違う
    t('status.value.history', { fetches: 1, tries: 2 });
    expect(t('status.value.history', { fetches: 1, attempts: 2 })).toBe('取得 1 回・要求 2 回');
    expect(t('status.title')).toBe('状態とログ');
  });

  it('★画面のコードに日本語を直書きしない。locales/ja.yaml に書いて t() で出す', () => {
    const found = scanJapaneseLiterals(path.resolve(__dirname, '../src'));
    const unexpected = [...found].map(([f, lines]) => `${f}:${lines.join(',')}`);
    expect(unexpected, '日本語の直書き (locales/ja.yaml へ移す。画面に出さない文字列だけは行末に i18n-ignore)').toEqual([]);
  });
});
