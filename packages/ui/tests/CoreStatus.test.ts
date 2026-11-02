import { describe, it, expect } from 'vitest';
import { describeCoreStatus } from '../src/lib/coreStatus';
import { t } from '../src/i18n';

describe('core の状態 → 画面の文 (core は文を作らず、code と params を返す)', () => {
  it('★code から、ja.yaml の core.* の文を作る (文言は YAML で変えられる。ここは code と差し込みの対応を確かめる)', () => {
    expect(describeCoreStatus({ code: 'none', message: '' })).toBe('');
    expect(describeCoreStatus({ code: 'connecting-neighbors', message: '' })).toBe(t('core.board.connectingNeighbors'));
    expect(describeCoreStatus({ code: 'syncing-neighbors', params: { degree: 4 }, message: '' })).toBe(t('core.board.syncingNeighbors', { degree: 4 }));
    expect(describeCoreStatus({ code: 'syncing-neighbors', params: { degree: 4 }, message: '' })).toContain('4');
    expect(describeCoreStatus({ code: 'board-empty', message: '' })).toBe(t('core.board.empty'));
    expect(describeCoreStatus({ code: 'thread-empty', message: '' })).toBe(t('core.thread.empty'));
    expect(describeCoreStatus({ code: 'waiting-network', message: '' })).toBe(t('core.thread.waitingNetwork'));
    expect(describeCoreStatus({ code: 'send-failed', params: { error: 'x' }, message: '' })).toBe(t('core.thread.sendFailed', { error: 'x' }));
    expect(describeCoreStatus({ code: 'send-failed', params: { error: 'x' }, message: '' })).toContain('x');
  });

  it('★過去ログの取得中: 進み具合 (done/total) と件数 (count) があれば添える', () => {
    expect(describeCoreStatus({ code: 'history-fetching', message: '' })).toBe('過去ログを取得中...');
    expect(describeCoreStatus({ code: 'history-fetching', params: { count: 3 }, message: '' })).toBe('過去ログを取得中... (3件)');
    expect(describeCoreStatus({ code: 'history-fetching', params: { done: 6, total: 13 }, message: '' })).toBe('過去ログを取得中... (6/13)');
    expect(describeCoreStatus({ code: 'history-fetching', params: { done: 6, total: 13, count: 1 }, message: '' })).toBe('過去ログを取得中... (6/13・1件)');
  });

  it('★知らない code は core の message をそのまま出す', () => {
    expect(describeCoreStatus({ code: 'something-new', message: '新しい状態' })).toBe('新しい状態');
    expect(describeCoreStatus({ message: '古い core' } as never)).toBe('古い core');
  });
});
