# Unanswered questions

## the first syscall is `execve` without any arguments - why does this happen?

* `lurk` shows `execve("", "", "") = 0`
* `strace` shows `execve("/usr/bin/cat", ["cat", "/etc/hosts"], 0x7ffd5ddcf7e8 /* 69 vars */)`
* https://github.com/strace/strace/blob/5b4f05f42a12596fa895b7665bbd740b5e5cc2a8/src/execve.c

## `mmap`'s 6th arg is an fd, but sometimes it's `0xfffffff`. What does that mean?

## Misc. things to investigate

* would it be easier to parse `man 2 <syscall>` entries rather than grep the kernel source?
  * https://www.kernel.org/doc/man-pages/download.html
  * crazy idea: ask something like ChatGPT to read the man-pages and return structured JSON for me
