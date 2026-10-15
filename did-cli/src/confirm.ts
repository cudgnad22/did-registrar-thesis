/**
 * Xác nhận của người dùng TRÊN MÁY CỦA CLIENT (terminal), không qua trang web của Registrar.
 * Nếu Registrar bị chiếm quyền, trang web có thể hiển thị sai, nhưng không giả được màn hình này.
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stderr } from 'node:process';
import type { Analysis } from './signing.ts';

const C = { bold: '\x1b[1m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', reset: '\x1b[0m' };

export function printAnalysis(a: Analysis, out = stderr) {
  out.write(`\n${C.bold}=== Yêu cầu ký (jobId ${a.jobId}) ===${C.reset}\n`);
  for (const line of a.summary) out.write(`  ${a.operation === 'deactivate' ? C.red : C.yellow}${line}${C.reset}\n`);
  out.write('  Đối chiếu trước khi ký:\n');
  for (const c of a.checks) {
    out.write(`   ${c.errors.length ? C.red + '✘' : C.green + '✔'}${C.reset} ${c.title}\n`);
    for (const e of c.errors) out.write(`       - ${e}\n`);
  }
}

let queue: Promise<unknown> = Promise.resolve();

/** Hỏi y/N; các yêu cầu đến cùng lúc được hỏi lần lượt. Hết thời gian thì coi như từ chối. */
export function confirm(question: string, timeoutMs = 120_000): Promise<boolean> {
  const run = async () => {
    const rl = createInterface({ input: stdin, output: stderr });
    const timer = new Promise<string>((resolve) => setTimeout(() => resolve('__timeout__'), timeoutMs));
    const answer = await Promise.race([rl.question(`\n? ${question} (y/N) `), timer]);
    rl.close();
    if (answer === '__timeout__') { stderr.write('\n  Hết thời gian chờ, coi như từ chối.\n'); return false; }
    return String(answer).trim().toLowerCase() === 'y';
  };
  const p = queue.then(run, run);
  queue = p.catch(() => undefined);
  return p;
}
