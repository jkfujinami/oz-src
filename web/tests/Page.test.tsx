// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/react';

const received: any[] = [];
vi.mock('@oz/ui', async (importOriginal) => ({
  // 環境変数から信頼設定を作る関数だけは本物を使う (ページが読むのはこの関数の結果)
  ...(await importOriginal<typeof import('@oz/ui')>()),
  OzApp: (props: any) => {
    received.push(props);
    return <div>oz-app</div>;
  },
}));

import Page from '../src/app/page';

afterEach(() => {
  cleanup();
  received.length = 0;
});

describe('Web: ページ', () => {
  it('共通の OzApp を Web のラベルで描画し、配信元の /ws を既定のトラッカーにする', async () => {
    render(<Page />);
    await waitFor(() => expect(screen.getByText('oz-app')).toBeTruthy());
    const props = received[received.length - 1];
    expect(props.badge).toBe('Web');
    const expected = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`;
    expect(props.defaultTrackerUrl).toBe(expected);
  });

  it('信頼 Guard の公開鍵が環境変数に無ければ、信頼設定なし (オープン動作) で起動する', async () => {
    render(<Page />);
    await waitFor(() => expect(screen.getByText('oz-app')).toBeTruthy());
    expect(received[received.length - 1].trust).toBeNull();
  });
});
