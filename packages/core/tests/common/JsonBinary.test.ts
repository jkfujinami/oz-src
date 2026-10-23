import { describe, it, expect } from 'vitest';
import { JsonBinary } from '../../src/common/JsonBinary';

describe('JsonBinary', () => {
  it('入れ子の Uint8Array と BigInt を往復させる', () => {
    const obj = {
      a: new Uint8Array([0, 1, 255]),
      n: 12345678901234567890n,
      neg: -5n,
      list: [new Uint8Array([7]), 1n, 'x', null],
      nested: { deep: { bytes: new Uint8Array(0) } },
      plain: 3,
    };
    const back = JsonBinary.parse(JsonBinary.stringify(obj));
    expect(back.a).toBeInstanceOf(Uint8Array);
    expect(Array.from(back.a)).toEqual([0, 1, 255]);
    expect(back.n).toBe(12345678901234567890n);
    expect(back.neg).toBe(-5n);
    expect(back.list[0]).toBeInstanceOf(Uint8Array);
    expect(back.list[1]).toBe(1n);
    expect(back.list.slice(2)).toEqual(['x', null]);
    expect(back.nested.deep.bytes).toBeInstanceOf(Uint8Array);
    expect(back.nested.deep.bytes).toHaveLength(0);
    expect(back.plain).toBe(3);
  });

  it('subarray はビューの範囲だけを書き出す', () => {
    const base = new Uint8Array([1, 2, 3, 4, 5]);
    const back = JsonBinary.parse(JsonBinary.stringify({ v: base.subarray(1, 3) }));
    expect(Array.from(back.v)).toEqual([2, 3]);
  });

  it('ラップ形式は _type タグ付きの JSON になる', () => {
    expect(JSON.parse(JsonBinary.stringify({ b: new Uint8Array([9]), n: 2n }))).toEqual({
      b: { _type: 'Uint8Array', data: [9] },
      n: { _type: 'BigInt', value: '2' },
    });
  });

  it('トップレベルの値でも動く', () => {
    expect(JsonBinary.parse(JsonBinary.stringify(7n))).toBe(7n);
    expect(Array.from(JsonBinary.parse(JsonBinary.stringify(new Uint8Array([4]))))).toEqual([4]);
    expect(JsonBinary.parse(JsonBinary.stringify('s'))).toBe('s');
  });

  it('replacer / reviver は JSON.stringify / JSON.parse に直接渡せる', () => {
    const s = JSON.stringify({ x: new Uint8Array([1]) }, JsonBinary.replacer);
    const back = JSON.parse(s, JsonBinary.reviver);
    expect(back.x).toBeInstanceOf(Uint8Array);
  });

  it('壊れた JSON や不正な BigInt 表記は例外になる (呼び出し側で catch する前提)', () => {
    expect(() => JsonBinary.parse('{')).toThrow();
    expect(() => JsonBinary.parse('{"_type":"BigInt","value":"1.5"}')).toThrow();
  });

  it('_type を持たない、または未知の _type のオブジェクトはそのまま', () => {
    const back = JsonBinary.parse('{"a":{"_type":"Map","data":[1]},"b":{"data":[1]}}');
    expect(back).toEqual({ a: { _type: 'Map', data: [1] }, b: { data: [1] } });
  });
});

describe('JsonBinary.reviver: 未認証入力の検証 (DoS 対策の回帰テスト)', () => {
  it('data が数値 (長さ指定) の Uint8Array ラップは TypeError で拒否する (37 バイトで 200MB 確保させない)', () => {
    expect(() => JsonBinary.parse('{"_type":"Uint8Array","data":200000000}')).toThrow(TypeError);
  });

  it('length だけ大きい偽の配列風オブジェクトは要素を走査せずに拒否する', () => {
    expect(() => JsonBinary.parse('{"_type":"Uint8Array","data":{"length":50000000}}')).toThrow(TypeError);
  });

  it('配列以外の data (文字列・null・欠落・オブジェクト) は拒否する', () => {
    for (const data of ['"abc"', 'null', '{}', 'true']) {
      expect(() => JsonBinary.parse(`{"_type":"Uint8Array","data":${data}}`)).toThrow(TypeError);
    }
    expect(() => JsonBinary.parse('{"_type":"Uint8Array"}')).toThrow(TypeError);
  });

  it('0..255 の整数でない要素は (剰余で丸めず) 拒否する', () => {
    for (const bad of ['256', '-1', '1.5', '"1"', 'null', '[]', '1e3']) {
      expect(() => JsonBinary.parse(`{"_type":"Uint8Array","data":[0,${bad}]}`), bad).toThrow(TypeError);
    }
    expect(Array.from(JsonBinary.parse('{"_type":"Uint8Array","data":[0,255]}'))).toEqual([0, 255]);
  });

  it('MAX_BYTES (1 MiB) ちょうどは受け付け、超えたら拒否する', () => {
    expect(JsonBinary.MAX_BYTES).toBe(1 << 20);
    // JSON 文字列を経由すると 1M 要素の構文解析が重いので、reviver を直接呼ぶ
    const atLimit = JsonBinary.reviver('', { _type: 'Uint8Array', data: new Array(JsonBinary.MAX_BYTES).fill(7) });
    expect(atLimit).toBeInstanceOf(Uint8Array);
    expect(atLimit).toHaveLength(JsonBinary.MAX_BYTES);
    expect(() => JsonBinary.reviver('', { _type: 'Uint8Array', data: new Array(JsonBinary.MAX_BYTES + 1).fill(0) })).toThrow(TypeError);
  });

  it('BigInt は 80 桁以内の 10 進文字列だけを受け付ける', () => {
    expect(JsonBinary.parse(`{"_type":"BigInt","value":"${'9'.repeat(80)}"}`)).toBe(BigInt('9'.repeat(80)));
    expect(JsonBinary.parse('{"_type":"BigInt","value":"-42"}')).toBe(-42n);
    const bads = [`"${'9'.repeat(81)}"`, '"0x10"', '" 1"', '"1 "', '""', '"-"', '"1e3"', '12', 'null', '[1]'];
    for (const v of bads) {
      expect(() => JsonBinary.parse(`{"_type":"BigInt","value":${v}}`), v).toThrow(TypeError);
    }
    expect(() => JsonBinary.parse('{"_type":"BigInt"}')).toThrow(TypeError);
  });

  it('入れ子の奥にある不正なラップも全体を拒否する', () => {
    expect(() => JsonBinary.parse('{"a":[{"b":{"_type":"Uint8Array","data":999999999}}]}')).toThrow(TypeError);
  });
});
