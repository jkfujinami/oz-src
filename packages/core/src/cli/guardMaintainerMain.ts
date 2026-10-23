#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { runGuardMaintainer } from './guardMaintainer';

/** 端末に表示せずに 1 行読む (パスワード入力) */
function promptSecret(question: string): Promise<string> {
  const env = process.env.OZ_MAINTAINER_PASSPHRASE;
  if (env) return Promise.resolve(env);
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const output = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WritableStream };
    let muted = false;
    output._writeToOutput = (s: string) => {
      if (!muted) output.output.write(s);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    muted = true;
  });
}

runGuardMaintainer(process.argv.slice(2), {
  readFile: (p) => readFile(p, 'utf8'),
  writeFile: (p, c) => writeFile(p, c, { encoding: 'utf8', mode: 0o600 }),
  promptSecret,
  print: (l) => console.log(l),
  error: (l) => console.error(l),
  now: () => Date.now(),
}).then((code) => process.exit(code));
