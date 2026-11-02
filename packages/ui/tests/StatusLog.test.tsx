// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, act } from '@testing-library/react';
import { createLogger, setLevel, resetLevels } from '@oz/core';

const diag = {
  peers: { connected: 5, verified: 4, maxDegree: 64 }, route: { ready: true, middles: 3 }, guardMode: 'open',
  openGuardService: true, trackerConnected: false, storage: { leaseSets: 30, slots: 2 }, recent: { posts: 12, bytes: 2 * 1024 * 1024 },
  history: { fetches: 14, attempts: 100, rejectedPackets: 0, badChunks: 0 }, relayed: { requests: 7, bytes: 0 },
  dropped: { relay: 1, rate: 2, preVerify: 3 },
};
vi.mock('../src/providers/P2PProvider', () => ({
  useP2P: () => ({ node: { diagnostics: () => diag }, guardStatus: { mode: 'open' } }),
}));
vi.mock('../src/lib/guardStatus', () => ({
  describeGuardStatus: () => ({ label: 'ラベル', tone: 'calm', headline: '' }),
}));

const { StatusLogView } = await import('../src/components/StatusLogView');
const { appLogHistory, startLogHistory, forgetLogs } = await import('../src/lib/logHistory');

afterEach(() => { cleanup(); forgetLogs(); vi.useRealTimers(); });

/** 画面の反映 (250ms ごと) を進める */
async function tick() {
  await act(async () => { vi.advanceTimersByTime(300); });
}

describe('状態とログ', () => {
  it('★状態の数を出し、出たログを流す。出どころ・検索・警告以上で絞れる', async () => {
    vi.useFakeTimers();
    startLogHistory();
    setLevel('*', 'debug');
    render(<StatusLogView />);
    expect(screen.getByText('5 (検証済み 4・上限 64)')).toBeTruthy();
    expect(screen.getByText('中継 1・受信の制限 2・握手前 3')).toBeTruthy();

    createLogger('net.gossip.relay').debug('relayed packet');
    createLogger('net.storage.leaseset').warn('sync retry');
    createLogger('ui.board').error('render failed');
    await tick();
    expect(document.querySelectorAll('.log-row')).toHaveLength(3);

    fireEvent.change(screen.getByLabelText('出どころ'), { target: { value: 'net.storage' } });
    expect([...document.querySelectorAll('.log-text')].map(e => e.textContent)).toEqual(['sync retry']);
    fireEvent.change(screen.getByLabelText('出どころ'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('ログを検索'), { target: { value: 'RENDER' } });
    expect([...document.querySelectorAll('.log-text')].map(e => e.textContent)).toEqual(['render failed']);
    fireEvent.change(screen.getByLabelText('ログを検索'), { target: { value: '' } });
    fireEvent.click(screen.getByText('警告以上'));
    expect([...document.querySelectorAll('.log-text')].map(e => e.textContent)).toEqual(['sync retry', 'render failed']);
    resetLevels();
  });

  it('★一時停止すると表示を止め、止めてから出た行の数を出す。押すと最新へ戻る。ロックで行も細かさも消える', async () => {
    vi.useFakeTimers();
    startLogHistory();
    render(<StatusLogView />);
    const log = createLogger('net.peer');
    log.error('first');
    await tick();
    fireEvent.click(screen.getByText('一時停止'));
    log.error('second');
    log.error('third');
    await tick();
    expect(document.querySelectorAll('.log-row')).toHaveLength(1);
    fireEvent.click(screen.getByText('新しい行 2 件'));
    expect(document.querySelectorAll('.log-row')).toHaveLength(3);

    fireEvent.change(screen.getByLabelText('記録の細かさ'), { target: { value: 'TRACE' } });
    expect(screen.getByText(/細かくするほど処理が重くなります/)).toBeTruthy();
    forgetLogs();
    expect(appLogHistory.size).toBe(0);
    const { currentLevels } = await import('@oz/core');
    expect(currentLevels()['*']).toBe('WARN');
  });
});
