// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, cleanup, act } from '@testing-library/react';

// 実際の文言ではなく、言語ごとの違いが分かる見本で確かめる
const FIXTURE = {
  LOCALES: ['ja', 'en'],
  BASE_LOCALE: 'ja',
  MESSAGES: {
    ja: { 'x.hello': 'こんにちは {name}', 'x.rows': '{count} 行', 'x.only': '日本語だけ', 'x.rich': '手順は <link>仕組み</link> に<br/>以上', 'x.html': '<b>{v}</b>' },
    en: { 'x.hello': 'Hello {name}', 'x.rows': { one: 'one row', other: '{count} rows' }, 'x.rich': 'See <link>how it works</link><br/>Done', 'x.html': '<b>{v}</b>' },
  },
};

let i18n: typeof import('../src/i18n');
beforeEach(async () => {
  vi.resetModules();
  vi.doMock('../src/i18n/messages.gen', () => FIXTURE);
  localStorage.setItem('oz.locale', 'ja');
  i18n = await import('../src/i18n');
});
afterEach(() => { cleanup(); vi.doUnmock('../src/i18n/messages.gen'); });

const t = (k: string, p?: Record<string, unknown>) => (i18n.t as any)(k, p);

describe('画面の文言 (i18n): 出し方', () => {
  it('★差し込み・言語の切り替え・訳していないキーは日本語・複数形', () => {
    expect(t('x.hello', { name: 'A' })).toBe('こんにちは A');
    expect(t('x.rows', { count: 1 })).toBe('1 行');
    i18n.setLocale('en');
    expect(localStorage.getItem('oz.locale')).toBe('en');
    expect(t('x.hello', { name: 'A' })).toBe('Hello A');
    expect(t('x.only')).toBe('日本語だけ');
    expect(t('x.rows', { count: 1 })).toBe('one row');
    expect(t('x.rows', { count: 3 })).toBe('3 rows');
    i18n.setLocale('fr' as any); // 無い言語は無視
    expect(i18n.getLocale()).toBe('en');
  });

  it('★部品の印は部品に置き換え、文そのものは HTML として解釈しない', () => {
    const node = (i18n.tRich as any)('x.rich', { link: (c: string) => <a href="#x">{c}</a>, br: () => <br /> });
    render(<p data-testid="p">{node}</p>);
    const p = screen.getByTestId('p');
    expect(p.querySelector('a')?.textContent).toBe('仕組み');
    expect(p.querySelector('br')).not.toBeNull();
    expect(p.textContent).toBe('手順は 仕組み に以上');
    // 差し込んだ値の < > はただの文字
    cleanup();
    render(<p data-testid="q">{(i18n.tRich as any)('x.html', { b: (c: string) => <strong>{c}</strong> }, { v: '<img src=x>' })}</p>);
    expect(screen.getByTestId('q').querySelector('img')).toBeNull();
    expect(screen.getByTestId('q').textContent).toBe('<img src=x>');
  });

  it('★useT の部品は、言語を変えると描き直す', () => {
    function Hello() {
      const tt = i18n.useT() as any;
      return <span data-testid="h">{tt('x.hello', { name: 'B' })}</span>;
    }
    render(<Hello />);
    expect(screen.getByTestId('h').textContent).toBe('こんにちは B');
    act(() => i18n.setLocale('en'));
    expect(screen.getByTestId('h').textContent).toBe('Hello B');
  });

  it('保存された選択が無ければ OS の言語、それも無ければ日本語', async () => {
    localStorage.removeItem('oz.locale');
    vi.resetModules();
    vi.doMock('../src/i18n/messages.gen', () => FIXTURE);
    vi.stubGlobal('navigator', { languages: ['en-GB', 'ja'], language: 'en-GB' });
    expect((await import('../src/i18n')).getLocale()).toBe('en');
    vi.resetModules();
    vi.doMock('../src/i18n/messages.gen', () => FIXTURE);
    vi.stubGlobal('navigator', { languages: ['fr-FR'], language: 'fr-FR' });
    expect((await import('../src/i18n')).getLocale()).toBe('ja');
    vi.unstubAllGlobals();
  });
});
