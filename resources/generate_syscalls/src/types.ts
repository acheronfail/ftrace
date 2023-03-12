import { RgMatch } from './ripgrep.types.js';

export interface FindSyscallResult {
  parameterless: boolean;
  results: RgMatch[];
}

export interface SyscallDefinitionBase {
  /**
   * Number of the syscall
   */
  id: number;
  abi: string;
  /**
   * Name of the syscall
   */
  name: string;
  /**
   * The name of the implementation in the kernel (undefined when the syscall isn't defined)
   */
  implName?: string;
}

export interface SyscallDefinitionFound extends SyscallDefinitionBase {
  /**
   * A list of signatures for this syscall
   */
  signatures: SyscallSignature[];
}

export interface SyscallDefinitionSkipped extends SyscallDefinitionBase {
  /**
   * When set, indicates that signatures for this syscall couldn't be found due to the given reason
   */
  skipped: 'unimplemented' | 'deprecated' | 'parameterless';
}

export type SyscallDefinition = SyscallDefinitionFound | SyscallDefinitionSkipped;

export interface SyscallSignature {
  /**
   * Key that represents this signature uniquely from other signatures for the same syscall.
   * Syscalls can be "overloaded", because their low-level calling conventions sometimes take different parameters.
   */
  key: string;
  matches: SyscallSignatureMatch[];
}

export interface SyscallSignatureMatch {
  params: {
    /**
     * Name of the variable as found in the source
     */
    name: string;
    /**
     * Type of the variable as found in the source (C code)
     */
    type: string;
  }[];
  /**
   * File path of the file in which the match was found
   */
  path: string;
  /**
   * Raw match string from the search
   */
  text: string;
  /**
   * The absolute offset into the file where the start of `text` appeared
   */
  offset: number;
}
