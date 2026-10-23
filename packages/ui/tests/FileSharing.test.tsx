// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { render, screen, cleanup, fireEvent, waitFor, act } from '@testing-library/react';
import { FileTransferError, formatFileLink } from '@oz/core';

const mock = {
  posts: [] as any[],
  submitReply: vi.fn().mockResolvedValue(undefined),
};
vi.mock('../src/hooks/useThread', () => ({
  useThread: () => ({
    posts: mock.posts, status: '', submitReply: mock.submitReply, powProgress: 0, isSubmitting: false, postStatus: '',
    threadState: { visibleCount: 1, hiddenCount: 0, contentBytes: 0, closed: false, expired: false }, resolveAnchor: vi.fn(),
  }),
}));
vi.mock('../src/hooks/useBoard', () => ({
  useBoard: () => ({ threads: [], status: '', submitThread: vi.fn(), powProgress: 0, isSubmitting: false, shareCode: null }),
}));

import ThreadView from '../src/components/ThreadView';
import BoardView from '../src/components/BoardView';
import { StorageSettings } from '../src/components/StorageSettings';
import { P2PContextForTest } from '../src/providers/P2PProvider';
import { byteBudget } from '../src/lib/postLimit';
import { splitFileTokens } from '../src/lib/fileTokens';

const MIB = 1024 ** 2;
const makeLink = (size: number, seed = 1) =>
  formatFileLink({ manifestId: new Uint8Array(16).fill(seed), key: new Uint8Array(32).fill(seed + 1), size });
const TOKEN = makeLink(3 * MIB);

const post = (id: string, content: string) => ({
  packet_id: id, content, post_number: 0, created_at: 1_700_000_000_000, board_id: 'b', thread_id: 't', parents: [], cumulative_pow: 0, thread_root: 't',
});

/** 外から解決・拒否できるアップロード */
function fakeUpload() {
  let resolve!: (t: string) => void; let reject!: (e: unknown) => void;
  const link = new Promise<string>((res, rej) => { resolve = res; reject = rej; });
  link.catch(() => undefined);
  const h = { link, cancel: vi.fn(), pause: vi.fn(), resume: vi.fn(), resolve, reject, onProgress: undefined as any };
  return h;
}

/** 外から進められるダウンロード */
function fakeDownload(manifest: { name: string; mime: string; size: number }, bytes: Uint8Array) {
  const d = { onProgress: undefined as any, cancel: vi.fn(), release: undefined as unknown as () => void };
  const gate = new Promise<void>((r) => { d.release = r; });
  const dl = {
    manifest: Promise.resolve({ ...manifest, version: 1, chunkSizeLog2: 18, chunkIds: [] }),
    cancel: d.cancel,
    async *[Symbol.asyncIterator]() { await gate; yield bytes; },
  };
  return { d, dl };
}

let node: any;
const view = (ui: React.ReactNode) =>
  render(<P2PContextForTest.Provider value={{ node, guardStatus: { mode: 'trusted', listVersion: 1, listExpiresAt: null, guardId: null } } as any}>{ui}</P2PContextForTest.Provider>);
const thread = () => view(<ThreadView boardId="b" threadId="t0000001" />);
const replyBox = () => screen.getByPlaceholderText(/レスを入力/) as HTMLTextAreaElement;
const pick = (file: File) => fireEvent.change(screen.getByTestId('attach-input'), { target: { files: [file] } });
const fileOf = (name: string, size: number, type = 'application/pdf') => {
  const f = new File([new Uint8Array(Math.min(size, 16))], name, { type });
  Object.defineProperty(f, 'size', { value: size });
  return f;
};

let created: string[]; let revoked: string[];
beforeEach(() => {
  mock.posts = [];
  node = { uploadFile: vi.fn(), downloadFile: vi.fn(), storageCapacity: 1, setStorageCapacity: vi.fn().mockResolvedValue(undefined) };
  created = []; revoked = [];
  let n = 0;
  (URL as any).createObjectURL = vi.fn(() => { const u = `blob:test/${++n}`; created.push(u); return u; });
  (URL as any).revokeObjectURL = vi.fn((u: string) => { revoked.push(u); });
  delete (window as any).electronAPI;
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); delete (window as any).electronAPI; });

describe('添付 (アップロード)', () => {
  it('進み具合・フェーズ・一時停止/再開を出し、終わったらトークンを入力欄に入れてバイト数に数える', async () => {
    const up = fakeUpload();
    node.uploadFile.mockImplementation((_f: any, _m: any, cb: any) => { up.onProgress = cb; return up; });
    thread();
    replyBox().value = '';
    fireEvent.change(replyBox(), { target: { value: '資料です' } });
    pick(fileOf('memo.pdf', 4 * MIB));
    expect(node.uploadFile.mock.calls[0][1]).toEqual({ name: 'memo.pdf', mime: 'application/pdf' });
    expect(screen.getByText('memo.pdf')).toBeTruthy();
    expect(screen.getByText(/暗号化中/)).toBeTruthy();
    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBe('0');
    expect(screen.getByText(/最初の中継先とプロバイダ/)).toBeTruthy();

    act(() => up.onProgress({ phase: 'chunks', bytesPlaced: 2 * MIB, totalBytes: 4 * MIB, chunksPlaced: 8, replicasAcked: 24, degradedChunks: 0 }));
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('50');
    expect(screen.getByText(/保管先へ送信中/)).toBeTruthy();

    fireEvent.click(screen.getByText('一時停止'));
    expect(up.pause).toHaveBeenCalled();
    expect(screen.getAllByText(/一時停止中/).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText('再開'));
    expect(up.resume).toHaveBeenCalled();

    await act(async () => { up.resolve(TOKEN); await up.link; });
    await waitFor(() => expect(replyBox().value).toBe(`資料です\n${TOKEN}`));
    expect(screen.queryByTestId('upload-card')).toBeNull();
    // バイト数は本文 + トークンを数える
    const used = byteBudget(replyBox().value).used;
    expect(used).toBeGreaterThan(TOKEN.length);
    expect(screen.getByText(`残り ${(2048 - used).toLocaleString('ja-JP')} バイト`)).toBeTruthy();
  });

  it('中止すると取りやめ、トークンは入らない', async () => {
    const up = fakeUpload();
    node.uploadFile.mockImplementation(() => up);
    thread();
    pick(fileOf('a.bin', MIB));
    fireEvent.click(screen.getByText('中止'));
    expect(up.cancel).toHaveBeenCalled();
    await act(async () => { up.reject(new FileTransferError('cancelled')); await up.link.catch(() => 0); });
    await waitFor(() => expect(screen.queryByTestId('upload-card')).toBeNull());
    expect(replyBox().value).toBe('');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('失敗は理由を出し、入力は残る', async () => {
    const up = fakeUpload();
    node.uploadFile.mockImplementation(() => up);
    thread();
    pick(fileOf('a.bin', MIB));
    await act(async () => { up.reject(new FileTransferError('insufficient-replicas')); await up.link.catch(() => 0); });
    expect((await screen.findByRole('alert')).textContent).toMatch(/置ききれませんでした/);
  });

  it('ブラウザ版は 512MiB まで、デスクトップ版は 2GiB まで', () => {
    node.uploadFile.mockImplementation(() => fakeUpload());
    thread();
    expect(screen.getByText(/512\.0 MiB まで/)).toBeTruthy();
    pick(fileOf('big.bin', 600 * MIB));
    expect(screen.getByRole('alert').textContent).toMatch(/大きすぎます/);
    expect(node.uploadFile).not.toHaveBeenCalled();
    cleanup();

    (window as any).electronAPI = {};
    thread();
    expect(screen.getByText(/2\.00 GiB まで/)).toBeTruthy();
    pick(fileOf('big.bin', 600 * MIB));
    expect(node.uploadFile).toHaveBeenCalledTimes(1);
  });

  it('画面を外すとアップロードを中止する', () => {
    const up = fakeUpload();
    node.uploadFile.mockImplementation(() => up);
    thread();
    pick(fileOf('a.bin', MIB));
    cleanup();
    expect(up.cancel).toHaveBeenCalled();
  });

  it('転送中に「板に戻る」を押すと確認し、断れば留まる', () => {
    node.uploadFile.mockImplementation(() => fakeUpload());
    thread();
    pick(fileOf('a.bin', MIB));
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    fireEvent.click(screen.getByText('← 板に戻る'));
    expect(confirm).toHaveBeenCalled();
  });

  it('新規スレの欄にも添付できる', async () => {
    const up = fakeUpload();
    node.uploadFile.mockImplementation(() => up);
    view(<BoardView boardId="b" />);
    fireEvent.click(screen.getByText('新スレを立てる'));
    pick(fileOf('a.bin', MIB));
    await act(async () => { up.resolve(TOKEN); await up.link; });
    const box = screen.getByPlaceholderText('スレッドタイトル...') as HTMLTextAreaElement;
    await waitFor(() => expect(box.value).toBe(TOKEN));
  });
});

describe('投稿の中の添付カード', () => {
  it('取得前は「添付ファイル (サイズ)」と取得ボタン。勝手には取らない', () => {
    mock.posts = [post('aa', `見てください\n${TOKEN}\n以上`)];
    thread();
    expect(screen.getByText('添付ファイル (3.0 MiB)')).toBeTruthy();
    expect(screen.getByRole('button', { name: /添付ファイルを取得/ })).toBeTruthy();
    expect(screen.getByText(/見てください/)).toBeTruthy();
    expect(node.downloadFile).not.toHaveBeenCalled();
    expect(document.querySelector('img')).toBeNull();
  });

  it('取得 → 進捗 → 名前が出て 保存 → Blob URL を作り、使い終わったら破棄する', async () => {
    mock.posts = [post('aa', TOKEN)];
    const { d, dl } = fakeDownload({ name: 'report.pdf', mime: 'application/pdf', size: 3 * MIB }, new Uint8Array([1, 2, 3]));
    node.downloadFile.mockImplementation((_t: string, cb: any) => { d.onProgress = cb; return dl; });
    thread();
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    expect(node.downloadFile.mock.calls[0][0]).toBe(TOKEN);
    await screen.findByText('report.pdf');
    act(() => d.onProgress({ phase: 'chunks', bytesDone: 3 * MIB / 2, totalBytes: 3 * MIB, chunksDone: 6, chunkCount: 12 }));
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('50');
    expect(created).toHaveLength(0);

    await act(async () => { d.release(); });
    const saveBtn = await screen.findByRole('button', { name: 'report.pdf を保存' });
    // 画像でないので、プレビュー用の URL は作られていない
    expect(created).toHaveLength(0);
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('report.pdf');
      expect(this.href).toBe(created[0]);
    });
    vi.useFakeTimers();
    fireEvent.click(saveBtn);
    expect(created).toHaveLength(1);
    expect(click).toHaveBeenCalled();
    expect(revoked).toHaveLength(0);
    act(() => { vi.advanceTimersByTime(1500); });
    vi.useRealTimers();
    expect(revoked).toEqual(created);
  });

  it('保存名は無害化される (パスの区切りを含む名前)', async () => {
    mock.posts = [post('aa', TOKEN)];
    const { d, dl } = fakeDownload({ name: '../../etc/passwd', mime: 'text/plain', size: 3 }, new Uint8Array([1]));
    node.downloadFile.mockImplementation(() => dl);
    thread();
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    await act(async () => { d.release(); });
    await waitFor(() => expect(screen.getByRole('button', { name: /を保存/ })).toBeTruthy());
    const label = screen.getByRole('button', { name: /を保存/ }).getAttribute('aria-label')!;
    expect(label).not.toMatch(/[\\/]/);
  });

  it('画像は取得後にだけ表示し、画面を外すと Blob URL を破棄する', async () => {
    mock.posts = [post('aa', TOKEN)];
    const { d, dl } = fakeDownload({ name: 'pic.png', mime: 'image/png', size: 3 * MIB }, new Uint8Array([1, 2]));
    node.downloadFile.mockImplementation(() => dl);
    thread();
    expect(document.querySelector('img')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    await screen.findByText('pic.png');
    expect(document.querySelector('img')).toBeNull(); // 取得の途中では出さない
    await act(async () => { d.release(); });
    const img = await waitFor(() => { const i = document.querySelector('img'); expect(i).toBeTruthy(); return i!; });
    expect(img.getAttribute('src')).toBe(created[0]);
    expect(img.getAttribute('alt')).toBe('pic.png');
    cleanup();
    expect(revoked).toContain(created[0]);
  });

  it('画像でも 8MiB を超えるものはプレビューしない', async () => {
    const big = makeLink(9 * MIB, 5);
    mock.posts = [post('aa', big)];
    const { d, dl } = fakeDownload({ name: 'huge.png', mime: 'image/png', size: 9 * MIB }, new Uint8Array([1]));
    node.downloadFile.mockImplementation(() => dl);
    thread();
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    await act(async () => { d.release(); });
    await screen.findByRole('button', { name: 'huge.png を保存' });
    expect(document.querySelector('img')).toBeNull();
  });

  it('取得中の中止、画面を外すと取得を中止する', async () => {
    mock.posts = [post('aa', TOKEN)];
    const { d, dl } = fakeDownload({ name: 'a.bin', mime: 'application/octet-stream', size: 3 * MIB }, new Uint8Array([1]));
    node.downloadFile.mockImplementation(() => dl);
    thread();
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    await screen.findByText('a.bin');
    cleanup();
    expect(d.cancel).toHaveBeenCalled();
  });

  it('形式の合わないトークンはただの文字として表示する (カードにしない・HTML にもならない)', () => {
    const broken = TOKEN.slice(0, -3) + ']]'; // 短い
    const evil = '[[file:<img src=x onerror=alert(1)>]]';
    const wrongChars = `[[file:${'!'.repeat(74)}]]`;
    mock.posts = [post('aa', `${broken}\n${evil}\n${wrongChars}`)];
    thread();
    expect(screen.queryByTestId('file-card')).toBeNull();
    const body = document.querySelector('.post-body')!;
    expect(body.textContent).toContain(broken);
    expect(body.textContent).toContain(evil);
    expect(body.querySelector('img')).toBeNull();
    expect(splitFileTokens(`${broken}`)).toEqual([{ type: 'text', text: broken }]);
  });

  it('1 つの投稿に複数あればそれぞれカードにし、>>N の着色は残る', () => {
    const t2 = makeLink(2048, 9);
    mock.posts = [post('aa', `>>1 前\n${TOKEN}\n間\n${t2}\n後`)];
    thread();
    expect(screen.getAllByTestId('file-card')).toHaveLength(2);
    expect(document.querySelector('.anchor')).toBeTruthy();
    expect(screen.getByText('添付ファイル (2.0 KiB)')).toBeTruthy();
  });

  it('ブラウザでは 512MiB を超える添付を取得させない', () => {
    mock.posts = [post('aa', makeLink(600 * MIB, 7))];
    thread();
    expect((screen.getByRole('button', { name: /添付ファイルを取得/ }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('何も保存しない', () => {
  it('アップロード・ダウンロードを通して localStorage / sessionStorage / IndexedDB に書かない', async () => {
    const ls = vi.spyOn(Storage.prototype, 'setItem');
    const idbOpen = vi.spyOn(indexedDB, 'open');
    const up = fakeUpload();
    node.uploadFile.mockImplementation((_f: any, _m: any, cb: any) => { up.onProgress = cb; return up; });
    const { d, dl } = fakeDownload({ name: 'pic.png', mime: 'image/png', size: 3 * MIB }, new Uint8Array([1]));
    node.downloadFile.mockImplementation(() => dl);
    mock.posts = [post('aa', TOKEN)];
    thread();
    pick(fileOf('a.bin', MIB));
    act(() => up.onProgress({ phase: 'chunks', bytesPlaced: 10, totalBytes: MIB, chunksPlaced: 1, replicasAcked: 3, degradedChunks: 0 }));
    await act(async () => { up.resolve(TOKEN); await up.link; });
    fireEvent.click(screen.getByRole('button', { name: /添付ファイルを取得/ }));
    await act(async () => { d.release(); });
    await screen.findByRole('button', { name: 'pic.png を保存' });
    expect(ls).not.toHaveBeenCalled();
    expect(idbOpen).not.toHaveBeenCalled();
  });
});

describe('保管の容量の設定', () => {
  it('ブラウザは 1〜4 枠、デスクトップは 1〜16 枠から選べて、選ぶと反映される', async () => {
    view(<StorageSettings />);
    const sel = screen.getByLabelText('預かる枠の数') as HTMLSelectElement;
    expect(Array.from(sel.options).map(o => o.value)).toEqual(['1', '2', '3', '4']);
    expect(screen.getByText(/中身は、あなたにも読めません/)).toBeTruthy();
    fireEvent.change(sel, { target: { value: '3' } });
    await waitFor(() => expect(node.setStorageCapacity).toHaveBeenCalledWith(3));
    expect(await screen.findByText('保存しました')).toBeTruthy();
    cleanup();

    (window as any).electronAPI = {};
    node.storageCapacity = 4;
    view(<StorageSettings />);
    const sel2 = screen.getByLabelText('預かる枠の数') as HTMLSelectElement;
    expect(sel2.options.length).toBe(16);
    expect(sel2.value).toBe('4');
  });
});
