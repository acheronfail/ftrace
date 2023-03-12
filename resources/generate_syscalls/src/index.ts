import * as fs from 'fs/promises';
import minimist from 'minimist';

import { DEPRECATED_SYSCALLS, SYSCALL_TABLE, UNIMPLEMENTED_SYSCALLS } from './constants.js';
import { findSyscall } from './ripgrep.js';
import { RgText } from './ripgrep.types.js';
import { SyscallDefinition } from './types.js';

// could probably do better argument parsing...
const args = minimist(process.argv.slice(2));
if (!args['linux-source'] || !args.output) {
  console.error('Please pass the --linux-source and --output paths!');
  process.exit(1);
}

const strip = (s: string) => s.replace(/\s+/g, ' ').trim();

const definitions: SyscallDefinition[] = [];
for (const line of (await fs.readFile(`${args['linux-source']}/${SYSCALL_TABLE}`, 'utf-8')).split(/\n/)) {
  // skip empty lines and comments
  if (line.startsWith('#') || line.trim().length == 0) continue;

  // split out and parse table
  const [idString, abi, name, implName] = line.split(/\s+/);
  const id = parseInt(idString);

  // these seem to be reserved, but aren't in the linux source code (as far as I have seen)
  if (abi == '64') {
    definitions.push({ id, abi, name, implName, skipped: 'unimplemented' });
    continue;
  }

  // syscalls that are reserved but unimplemented
  if (UNIMPLEMENTED_SYSCALLS.includes(name)) {
    definitions.push({ id, abi, name, implName, skipped: 'unimplemented' });
    continue;
  }

  // syscalls that have been deprecated and removed
  if (DEPRECATED_SYSCALLS.includes(name)) {
    definitions.push({ id, abi, name, implName, skipped: 'deprecated' });
    continue;
  }

  // if there's no implementation name, then we've encountered a syscall we can't find
  if (!implName) {
    throw new Error(`No implementation and no exception for ${name}`);
  }

  // search source code for syscall definitions
  const { parameterless, results } = findSyscall(args['linux-source'], name);
  if (parameterless) {
    definitions.push({ id, abi, name, skipped: 'parameterless' });
    continue;
  }

  // process results
  const matches = (
    await Promise.all(
      results
        // get what we need from ripgrep
        .map((rgMatch) => {
          // NOTE: all these casts should be safe since the linux source is utf-8
          return {
            path: (rgMatch.data.path as RgText).text,
            text: (rgMatch.data.lines as RgText).text,
            offset: rgMatch.data.absolute_offset,
          };
        })
        // filter out syscalls for other architectures
        .filter(({ path }) => {
          const result = /arch\/(.+?)\//.exec(path);
          return result ? result[1] == 'x86' : true;
        })
        // extract full match (if it spanned multiple lines)
        .map(async (match) => {
          const { offset, path, text } = match;
          if (text.endsWith(')')) return match;

          // Read the file for the full match
          const file = await fs.readFile(path, 'utf-8');
          const fullText = strip(file.substring(offset, file.indexOf(')', offset) + 1));
          return { ...match, text: fullText };
        })
    )
  )
    // parse signature for types
    .map((match) => {
      const { text } = match;

      // format of the syscall macros are: `MACRO_NAME + digit + (SYSCALL_NAME, [PARAM_TYPE, PARAM_NAME]...)`
      const paramText = text.substring(text.indexOf('(') + 1, text.indexOf(')'));
      const paramList = paramText.split(',').slice(1);
      const params = [];
      for (let i = 0; i < paramList.length; i += 2) {
        const type = strip(paramList[i]);
        const name = strip(paramList[i + 1]);
        params.push({ name, type });
      }

      // also include a string of just the types, so we can use it to diff against potential duplicates later
      const types = params.map((p) => p.type).join(', ');

      return { ...match, params, types };
    });

  // group matches together if they have the same parameter types
  const partitions = matches.reduce((map, match) => {
    const items = map.get(match.types);
    if (items) {
      map.set(match.types, [...items, match]);
    } else {
      map.set(match.types, [match]);
    }

    return map;
  }, new Map<string, typeof matches>());

  // collect into destination type
  const signatures = [...partitions.entries()].map(([key, matches]) => ({
    key,
    matches: matches.map(({ types, ...rest }) => rest),
  }));

  definitions.push({
    id,
    abi,
    name,
    signatures,
  });
}

await fs.writeFile(args.output, JSON.stringify(definitions, null, 2), 'utf-8');
