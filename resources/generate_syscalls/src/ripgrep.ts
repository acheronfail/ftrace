import { spawnSync } from 'node:child_process';
import { RgMatch, RgMessage, RgSummary } from './ripgrep.types.js';
import { FindSyscallResult } from './types.js';

const filterRipgrepMatches = (x: RgMessage): x is RgMatch => x.type == 'match';
const parseRipgrepStdout = (buf: Buffer): RgMessage[] =>
  buf
    .toString()
    .split(/\n/)
    .filter(Boolean)
    .map((line: string): RgMessage => JSON.parse(line) as RgMessage);

// TODO: test if making this async speeds things up, I don't think it'll make up difference since
// rg will already be using all the CPUs, and it'll probably just cause CPU contention
export function findSyscall(cwd: string, name: string): FindSyscallResult {
  // search for definitions of syscalls that have parameters
  let results = parseRipgrepStdout(spawnSync('rg', ['--json', `^SYSCALL_DEFINE\\d+\\(${name},.*?`, cwd]).stdout);
  let summary = results.find<RgSummary>((x): x is RgSummary => x.type === 'summary')!;
  if (summary.data.stats.matches > 0) {
    return { parameterless: false, results: results.filter(filterRipgrepMatches) };
  }

  // search for definitions of syscalls that don't require any parameters
  results = parseRipgrepStdout(spawnSync('rg', ['--json', `__SYSCALL\\(__NR_${name},`, cwd]).stdout);
  summary = results.find<RgSummary>((x): x is RgSummary => x.type === 'summary')!;
  if (summary.data.stats.matches > 0) {
    return { parameterless: true, results: results.filter(filterRipgrepMatches) };
  }

  throw new Error(`Failed to find definition for ${name}`);
}
