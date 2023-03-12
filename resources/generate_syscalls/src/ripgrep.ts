import { $, TemplateExpression } from 'execa';
import { RgMatch, RgMessage, RgSummary } from './ripgrep.types.js';
import { FindSyscallResult } from './types.js';

// When running, don't open stdin, and also ignore non-zero return codes
// For stdin, see https://github.com/sindresorhus/execa/issues/549
const $$ = (strings: TemplateStringsArray, ...values: TemplateExpression[]) =>
  $({ stdin: 'ignore' })(strings, ...values).catch((err) => err);

const parseRipgrepStdout = (stdout: string): RgMessage[] =>
  stdout
    .split(/\n/)
    .filter(Boolean)
    .map((line: string): RgMessage => JSON.parse(line) as RgMessage);

async function runRipgrep(cwd: string, pattern: string): Promise<RgMessage[]> {
  const { stdout } = await $$`rg --json ${pattern} ${cwd}`;
  return parseRipgrepStdout(stdout);
}

function isRipgrepEmpty(rgOutput: RgMessage[]): boolean {
  return rgOutput.find<RgSummary>((x): x is RgSummary => x.type === 'summary')!.data.stats.matches === 0;
}

export async function findSyscall(cwd: string, name: string): Promise<FindSyscallResult> {
  // pattern for definitions with parameters
  let rgOutput = await runRipgrep(cwd, `^SYSCALL_DEFINE\\d+\\(${name},.*?`);
  let parameterless = false;

  // if nothing found, search for a definition without parameters
  if (isRipgrepEmpty(rgOutput)) {
    rgOutput = await runRipgrep(cwd, `__SYSCALL\\(__NR_${name},`);
    parameterless = true;
  }

  // if we haven't found anything yet, then error
  if (isRipgrepEmpty(rgOutput)) {
    throw new Error(`Failed to find definition for ${name}`);
  }

  const results = rgOutput.filter((x): x is RgMatch => x.type === 'match');
  results.sort((a, b) => a.data.absolute_offset - b.data.absolute_offset);
  return { parameterless, results };
}
