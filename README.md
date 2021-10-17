# seccomp-demo
## Compile the code
**gcc sec-t1.c -o sec-t1**
## Source the nr_syscall.source 
**source nr_syscall.source**
## Use strace to see system calls used
**strace /usr/bin/whoami**

## Lookup a syscall used
**nr_syscall openat**
__257__
## Use sec-t1 to restrict syscall 
**./sec-t1 257 0xC000003E 99 /usr/bin/whoami**
__/usr/bin/whoami: error while loading shared libraries: libc.so.6: cannot open shared object file: Error 99__
