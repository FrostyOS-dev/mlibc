#ifndef _FROSTYOS_SYSCALL_H
#define _FROSTYOS_SYSCALL_H

#include <stddef.h>
#include <stdint.h>

#define ENUMERATE_SYSTEM_CALLS(SC) \
    SC(EXIT, exit) \
    SC(OPEN, open) \
    SC(CLOSE, close) \
    SC(READ, read) \
    SC(WRITE, write) \
    SC(SEEK, seek) \
    SC(MMAP, mmap) \
    SC(MUNMAP, munmap) \
    SC(MPROTECT, mprotect) \
    SC(SETTCB, settcb) \
    SC(GETPID, getpid) \
    SC(GETPPID, getppid) \
    SC(GETTID, gettid) \
    SC(GETUID, getuid) \
    SC(GETEUID, geteuid) \
    SC(GETGID, getgid) \
    SC(GETEGID, getegid) \
    SC(CLOCKGET, clockget) \
    SC(ISATTY, isatty) \
    SC(GETDENTS, getdents) \
    SC(FORK, fork) \
    SC(EXEC, exec)

enum SystemCalls : uint64_t {
#define ENUMERATE_CALL(u, l) SYSCALL_##u,
    ENUMERATE_SYSTEM_CALLS(ENUMERATE_CALL)
#undef ENUMERATE_CALL
};

#define FROSTYOS_DEBUGFD 3

#ifndef __MLIBC_ABI_ONLY

static long syscall(long func, uint64_t p1 = 0, uint64_t p2 = 0, uint64_t p3 = 0, uint64_t p4 = 0, uint64_t p5 = 0) {
	volatile long ret;

	register uint64_t r4 asm("r8") = p4;
	register uint64_t r5 asm("r9") = p5;

	asm volatile("syscall"
		: "=a"(ret)
		: "a"(func), "D"(p1), "S"(p2), "d"(p3), "r"(r4), "r"(r5)
		: "memory", "rcx", "r11");
    return ret;
}

#endif /* !__MLIBC_ABI_ONLY */

#endif /* _FROSTYOS_SYSCALL_H */
