import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  LogLevel,
  createLogger,
  setLevel,
  levelFor,
  resetLevels,
  currentLevels,
  parseLevel,
  levelName,
  setSink,
  installConsoleHandle,
  type Sink,
} from '../../src/common/Logger';

function capture() {
  const lines: Array<{ method: keyof Sink; args: unknown[] }> = [];
  const push = (method: keyof Sink) => (...args: unknown[]) => { lines.push({ method, args }); };
  setSink({ error: push('error'), warn: push('warn'), info: push('info'), log: push('log'), debug: push('debug') });
  return lines;
}

const savedEnv = { OZ_LOG: process.env.OZ_LOG, NODE_ENV: process.env.NODE_ENV };

beforeEach(() => {
  delete process.env.OZ_LOG;
  resetLevels();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setSink(console);
  if (savedEnv.OZ_LOG === undefined) delete process.env.OZ_LOG;
  else process.env.OZ_LOG = savedEnv.OZ_LOG;
  process.env.NODE_ENV = savedEnv.NODE_ENV;
  delete (globalThis as any).ozLog;
  resetLevels();
});

describe('Logger: 既定レベル (押収時の痕跡を増やさない)', () => {
  it('何も指定しなければ全スコープ WARN で、info / debug / trace は出ない', () => {
    const lines = capture();
    const log = createLogger('net.gossip');
    log.error('e');
    log.warn('w');
    log.info('peer abcdef');
    log.debug('route to xyz');
    log.trace('t');
    expect(lines.map((l) => l.method)).toEqual(['error', 'warn']);
    expect(levelFor('anything')).toBe(LogLevel.WARN);
  });

  it('NODE_ENV=development でも既定は WARN のまま (DEBUG にならない)', () => {
    process.env.NODE_ENV = 'development';
    resetLevels();
    expect(levelFor('x')).toBe(LogLevel.WARN);
    expect(currentLevels()).toEqual({ '*': 'WARN' });
  });

  it('出力にはスコープ名が前置される', () => {
    const lines = capture();
    createLogger('crypto.identity').warn('hello', 42);
    expect(lines[0].args).toEqual(['[crypto.identity]', 'hello', 42]);
  });
});

describe('Logger: レベル判定とスコープ', () => {
  it('SILENT は error も含めて何も出さない', () => {
    const lines = capture();
    setLevel('*', 'SILENT');
    const log = createLogger('x');
    log.error('e'); log.warn('w'); log.info('i'); log.debug('d'); log.trace('t');
    expect(lines).toHaveLength(0);
  });

  it('TRACE は全部出し、各レベルの出力先は error/warn/info/log/debug', () => {
    const lines = capture();
    setLevel('*', 'TRACE');
    const log = createLogger('x');
    log.error('e'); log.warn('w'); log.info('i'); log.debug('d'); log.trace('t');
    expect(lines.map((l) => l.method)).toEqual(['error', 'warn', 'info', 'log', 'debug']);
  });

  it('ドット区切りのスコープは長い方から前方一致で親を継承する', () => {
    setLevel('network', 'DEBUG');
    setLevel('network.mailbox', 'TRACE');
    expect(levelFor('network.mailbox.dht')).toBe(LogLevel.TRACE);
    expect(levelFor('network.gossip')).toBe(LogLevel.DEBUG);
    expect(levelFor('networkx')).toBe(LogLevel.WARN); // 単なる文字列前方一致ではない
    expect(levelFor('logic')).toBe(LogLevel.WARN);
  });

  it('child() は親スコープ名にドットで連結する', () => {
    const lines = capture();
    setLevel('*', 'SILENT');
    setLevel('net.mail', 'INFO');
    const child = createLogger('net').child('mail');
    expect(child.scope).toBe('net.mail');
    child.info('x');
    createLogger('net').info('hidden');
    expect(lines).toHaveLength(1);
    expect(lines[0].args[0]).toBe('[net.mail]');
  });

  it('不正なレベル指定は false を返し、設定を変えない', () => {
    setLevel('*', 'INFO');
    expect(setLevel('*', 'bogus')).toBe(false);
    expect(setLevel('*', 99 as any)).toBe(false);
    expect(levelFor('*')).toBe(LogLevel.INFO);
  });

  it('enabled() は解決済みレベルと比較する', () => {
    setLevel('*', 'INFO');
    const log = createLogger('x');
    expect(log.enabled(LogLevel.ERROR)).toBe(true);
    expect(log.enabled(LogLevel.INFO)).toBe(true);
    expect(log.enabled(LogLevel.DEBUG)).toBe(false);
  });

  it('setLevel はレベル値 (数値) でも受け付ける', () => {
    expect(setLevel('a', LogLevel.TRACE)).toBe(true);
    expect(levelFor('a')).toBe(LogLevel.TRACE);
  });
});

describe('Logger: 遅延評価', () => {
  it('出力しないレベルでは関数引数を呼ばない', () => {
    capture();
    const build = vi.fn(() => 'secret-route');
    createLogger('x').debug(build);
    createLogger('x').trace(build);
    expect(build).not.toHaveBeenCalled();
  });

  it('出力するレベルでは関数引数を 1 回だけ評価して展開する', () => {
    const lines = capture();
    setLevel('*', 'TRACE');
    const build = vi.fn(() => 'expensive');
    createLogger('x').trace('pre', build, 3);
    expect(build).toHaveBeenCalledTimes(1);
    expect(lines[0].args).toEqual(['[x]', 'pre', 'expensive', 3]);
  });
});

describe('Logger: レベル文字列の解釈', () => {
  it('大文字小文字・前後空白を問わない', () => {
    expect(parseLevel('trace')).toBe(LogLevel.TRACE);
    expect(parseLevel(' Warn ')).toBe(LogLevel.WARN);
    expect(parseLevel('SILENT')).toBe(LogLevel.SILENT);
  });

  it('不正値・プロトタイプ由来の名前は null', () => {
    for (const v of ['nope', '', 'constructor', '__proto__', 'toString', 'valueOf', undefined, null, {}, [], 1.5, -1, 6, NaN]) {
      expect(parseLevel(v)).toBeNull();
    }
  });

  it('数値は定義済みの値だけ受ける', () => {
    for (let i = 0; i <= 5; i++) expect(parseLevel(i)).toBe(i);
  });

  it('levelName は往復し、未知の値は SILENT', () => {
    for (const [name, value] of Object.entries(LogLevel)) expect(levelName(value)).toBe(name);
    expect(levelName(42 as any)).toBe('SILENT');
  });
});

describe('Logger: 起動時の指定', () => {
  it('OZ_LOG のスペック ("*=..,scope=..") を解釈する', () => {
    process.env.OZ_LOG = '*=error,gossip=trace,network.mailbox=debug';
    resetLevels();
    expect(levelFor('gossip')).toBe(LogLevel.TRACE);
    expect(levelFor('network.mailbox.x')).toBe(LogLevel.DEBUG);
    expect(levelFor('other')).toBe(LogLevel.ERROR);
  });

  it('スコープ省略の単独レベルは * への指定、空白区切りも受ける', () => {
    process.env.OZ_LOG = 'info  gossip=trace';
    resetLevels();
    expect(levelFor('anything')).toBe(LogLevel.INFO);
    expect(levelFor('gossip')).toBe(LogLevel.TRACE);
  });

  it('壊れた指定を混ぜても他の指定は生き、既定は WARN のまま', () => {
    process.env.OZ_LOG = 'gossip=nope,mailbox=trace,=warn,x=,===,bogus';
    resetLevels();
    expect(levelFor('mailbox')).toBe(LogLevel.TRACE);
    expect(levelFor('gossip')).toBe(LogLevel.WARN);
    expect(levelFor('x')).toBe(LogLevel.WARN);
    expect(Object.keys(currentLevels()).sort()).toEqual(['*', 'mailbox']);
  });

  it('sessionStorage.oz_log は OZ_LOG より優先される', () => {
    process.env.OZ_LOG = '*=error';
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => (k === 'oz_log' ? '*=debug' : null),
      setItem: () => {},
      removeItem: () => {},
    });
    resetLevels();
    expect(levelFor('x')).toBe(LogLevel.DEBUG);
  });

  it('sessionStorage が例外を投げても OZ_LOG にフォールバックする', () => {
    process.env.OZ_LOG = '*=error';
    vi.stubGlobal('sessionStorage', {
      getItem: () => { throw new Error('SecurityError'); },
    });
    resetLevels();
    expect(levelFor('x')).toBe(LogLevel.ERROR);
  });

  it('resetLevels 後の設定は環境指定から作り直される (実行時の上書きは消える)', () => {
    setLevel('gossip', 'TRACE');
    resetLevels();
    expect(currentLevels()).toEqual({ '*': 'WARN' });
  });
});

describe('Logger: コンソールハンドル', () => {
  it('ozLog.set / show / reset が動き、設定は sessionStorage に引き継がれる', () => {
    const store = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => { store.set(k, v); },
      removeItem: (k: string) => { store.delete(k); },
    });
    vi.spyOn(console, 'info').mockImplementation(() => {});
    installConsoleHandle();
    const handle = (globalThis as any).ozLog;

    const shown = handle.set('gossip', 'trace');
    expect(shown.gossip).toBe('TRACE');
    expect(levelFor('gossip')).toBe(LogLevel.TRACE);
    expect(store.get('oz_log')).toBe('*=warn,gossip=trace');
    expect(handle.show()).toEqual({ '*': 'WARN', gossip: 'TRACE' });
    expect(handle.levels).toEqual(['SILENT', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE']);

    const after = handle.reset();
    expect(after).toEqual({ '*': 'WARN' });
    expect(store.has('oz_log')).toBe(false);
  });

  it('不正なレベルでは警告して設定を変えず、例外も投げない', () => {
    vi.spyOn(console, 'info').mockImplementation(() => {});
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    installConsoleHandle();
    const handle = (globalThis as any).ozLog;
    expect(() => handle.set('x', 'bogus')).not.toThrow();
    expect(warn).toHaveBeenCalled();
    expect(currentLevels().x).toBeUndefined();
  });

  it('sessionStorage への保存が失敗しても set は成功する', () => {
    vi.stubGlobal('sessionStorage', {
      getItem: () => null,
      setItem: () => { throw new Error('QuotaExceeded'); },
      removeItem: () => { throw new Error('nope'); },
    });
    vi.spyOn(console, 'info').mockImplementation(() => {});
    installConsoleHandle();
    const handle = (globalThis as any).ozLog;
    expect(handle.set('y', 'debug').y).toBe('DEBUG');
    expect(() => handle.reset()).not.toThrow();
  });
});

describe('Logger: 端末に残さない・ID を出し切らない', () => {
  it('詳細ログの設定は localStorage に書かず、前の版が残した値は使わずに消す', () => {
    const local = new Map<string, string>([['oz_log', '*=trace']]);
    const session = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => local.get(k) ?? null,
      setItem: (k: string, v: string) => { local.set(k, v); },
      removeItem: (k: string) => { local.delete(k); },
    });
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => session.get(k) ?? null,
      setItem: (k: string, v: string) => { session.set(k, v); },
      removeItem: (k: string) => { session.delete(k); },
    });
    resetLevels();
    expect(levelFor('x')).toBe(LogLevel.WARN); // 残っていた trace は効かない
    expect(local.has('oz_log')).toBe(false);

    vi.spyOn(console, 'info').mockImplementation(() => {});
    installConsoleHandle();
    (globalThis as any).ozLog.set('*', 'debug');
    expect(session.get('oz_log')).toContain('*=debug');
    expect(local.has('oz_log')).toBe(false);
  });

  it('WARN / ERROR の長い 16 進列 (peerId など) は先頭 8 文字に縮める。INFO 以下は触らない', () => {
    const lines = capture();
    const id = 'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56abcd';
    const log = createLogger('net.peer');
    log.warn(`peer ${id} dropped`);
    log.error('failed', new Error(`bad ${id}`));
    const printed = JSON.stringify(lines.map((l) => l.args.map((a) => (a instanceof Error ? a.message : a))));
    expect(printed).not.toContain(id);
    expect(printed).toContain('ab12cd34…');
    expect(printed).toContain('peer ab12cd34… dropped');

    setLevel('*', 'INFO');
    lines.length = 0;
    log.info(`peer ${id}`);
    expect(lines[0].args[1]).toContain(id);
  });
});
