export const SYSCALL_TABLE = 'arch/x86/entry/syscalls/syscall_64.tbl';

// https://man7.org/linux/man-pages/man2/tuxcall.2.html
export const UNIMPLEMENTED_SYSCALLS = [
  'afs_syscall',
  'break',
  'fattach',
  'fdetach',
  'ftime',
  'getmsg',
  'getpmsg',
  'gtty',
  'isastream',
  'lock',
  'madvise1',
  'mpx',
  'prof',
  'profil',
  'putmsg',
  'putpmsg',
  'security',
  'stty',
  'tuxcall',
  'ulimit',
  'vserver',
];

export const DEPRECATED_SYSCALLS = [
  // https://man7.org/linux/man-pages/man2/sysctl.2.html
  '_sysctl',
];
