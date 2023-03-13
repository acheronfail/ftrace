# Unanswered questions

## the first syscall is `execve` without any arguments - why does this happen?

* `lurk` shows `execve("", "", "") = 0`
* `strace` shows `execve("/usr/bin/cat", ["cat", "/etc/hosts"], 0x7ffd5ddcf7e8 /* 69 vars */)`

## `mmap`'s 6th arg is an fd, but sometimes it's `0xfffffff`. What does that mean?
