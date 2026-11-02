// 組み立て時の生成 (generate.ts) で使う分だけの型 (@types/js-yaml は入れていない)
declare module 'js-yaml' {
  export function load(text: string): unknown;
}
