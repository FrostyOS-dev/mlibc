#include "mlibc/sysdep-tags.hpp"
#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <frostyos/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define STUB()                                                                                     \
    ({                                                                                             \
        __ensure(!"STUB function was called");                                                     \
        __builtin_unreachable();                                                                   \
    })

namespace mlibc {

    struct UIDs {
        uid_t ruid;
        uid_t euid;
        uid_t suid;
    };

    struct GIDs {
        gid_t rgid;
        gid_t egid;
        gid_t sgid;
    };

    [[noreturn]] void Sysdeps<Exit>::operator()(int status) {
        syscall(SYSCALL_EXIT, status);
        __builtin_unreachable();
    }

    #define FUTEX_WAIT 0
    #define FUTEX_WAKE 1

    int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
        int rc = syscall(SYSCALL_FUTEX, FUTEX_WAIT, (uint64_t)pointer, expected, (uint64_t)time);
        if (rc < 0)
            return -rc;
        return 0;
    }

	int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
        int rc = syscall(SYSCALL_FUTEX, FUTEX_WAKE, (uint64_t)pointer, all ? INT32_MAX : 1);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Open>::operator()(const char *pathname, int flags, mode_t mode, int *fd) {
		int rc = syscall(SYSCALL_OPEN, (uint64_t)pathname, strlen(pathname), flags, mode);
        if (rc < 0)
            return -rc;
        *fd = rc;
        return 0;
	};

    int Sysdeps<Read>::operator()(int fd, void *buff, size_t count, ssize_t *bytes_read) {
        long rc = syscall(SYSCALL_READ, fd, (uint64_t)buff, count);
        if (rc < 0)
            return rc;
		*bytes_read = rc;
		return 0;
	}

	int Sysdeps<Write>::operator()(int fd, const void *buff, size_t count, ssize_t *bytes_written) {
		long rc = syscall(SYSCALL_WRITE, fd, (uint64_t)buff, count);
        if (rc < 0)
            return rc;
		*bytes_written = rc;
		return 0;
	}

	int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
		off_t ret = syscall(SYSCALL_SEEK, fd, offset, whence);
        if (ret < 0)
            return ret;
        *new_offset = ret;
        return 0;
	}

	int Sysdeps<Close>::operator()(int fd) {
		return syscall(SYSCALL_CLOSE, fd);
	}

    int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
        timespec t;
        int rc = syscall(SYSCALL_CLOCKGET, clock, (uint64_t)&t);
        if (rc < 0)
            return rc;
        *secs = t.tv_sec;
        *nanos = t.tv_nsec;
        return 0;
    }

    void Sysdeps<LibcLog>::operator()(const char *message) {
        ssize_t bytes;
		sysdep<Write>(STDERR_FILENO, message, strlen(message), &bytes);
        sysdep<Write>(STDERR_FILENO, "\n", 1, &bytes);
	}

	[[noreturn]] void Sysdeps<LibcPanic>::operator()() {
		sysdep<LibcLog>("mlibc: panic");
		sysdep<Exit>(1);
	}

    int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
		size += 4096 - (size % 4096);
		return sysdep<VmMap>(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0, pointer);
	}

	int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
		size += 4096 - (size % 4096);
		return sysdep<VmUnmap>(pointer, size);
	}

    struct [[gnu::packed]] sys_mmapExtraArgs {
        int fd;
        off_t offset;
    };

    int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        sys_mmapExtraArgs args = {fd, offset};
		long rc = syscall(SYSCALL_MMAP, (uint64_t)hint, size, prot, flags, (uint64_t)&args);
        if (rc < 0)
            return rc;
		*window = (void *)rc;
		return 0;
	}

	int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
		long rc = syscall(SYSCALL_MUNMAP, (uintptr_t)pointer, size);
        if (rc < 0)
            return -rc;
        return 0;
	}

    int Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot) {
		long rc = syscall(SYSCALL_MPROTECT, (uint64_t)pointer, size, prot);
        if (rc < 0)
            return -rc;
        return 0;
	}

    int Sysdeps<TcbSet>::operator()(void *pointer) {
        long rc = syscall(SYSCALL_SETTCB, (uintptr_t)pointer);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Isatty>::operator()(int fd) {
        long rc = syscall(SYSCALL_ISATTY, fd);
        if (rc < 0)
            return -rc;
        return 0;
    }

    pid_t Sysdeps<GetPid>::operator()() {
        return syscall(SYSCALL_GETPID);
    }

    pid_t Sysdeps<GetPpid>::operator()() {
        return syscall(SYSCALL_GETPPID);
    }

    int Sysdeps<FutexTid>::operator()() {
        return syscall(SYSCALL_GETTID);
    }

    pid_t Sysdeps<GetTid>::operator()() {
        return syscall(SYSCALL_GETTID);
    }

    uid_t Sysdeps<GetUid>::operator()() {
        UIDs uids = {};
        long rc = syscall(SYSCALL_GETRESUID, (uint64_t)&uids);
        if (rc < 0)
            return rc;
        return uids.ruid;
    }

    uid_t Sysdeps<GetEuid>::operator()() {
        UIDs uids = {};
        long rc = syscall(SYSCALL_GETRESUID, (uint64_t)&uids);
        if (rc < 0)
            return rc;
        return uids.euid;
    }

    uid_t Sysdeps<GetGid>::operator()() {
        GIDs gids = {};
        long rc = syscall(SYSCALL_GETRESGID, (uint64_t)&gids);
        if (rc < 0)
            return rc;
        return gids.rgid;
    }

    uid_t Sysdeps<GetEgid>::operator()() {
        GIDs gids = {};
        long rc = syscall(SYSCALL_GETRESGID, (uint64_t)&gids);
        if (rc < 0)
            return rc;
        return gids.egid;
    }

    int Sysdeps<OpenDir>::operator()(const char *path, int* handle) {
        return sysdep<Open>(path, O_DIRECTORY, 0, handle);
    }

    int Sysdeps<ReadEntries>::operator()(int handle, void* buffer, size_t max_size, size_t* bytes_read) {
        long rc = syscall(SYSCALL_GETDENTS, handle, (uint64_t)buffer, max_size, (uint64_t)bytes_read);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Fork>::operator()(pid_t *pid) {
		long rc = syscall(SYSCALL_FORK);
		if (rc < 0)
            return -rc;
        *pid = rc;
        return 0;
	}

    int Sysdeps<Execve>::operator()(const char *path, char *const *argv, char *const *envp) {
        long rc = syscall(SYSCALL_EXEC, (uint64_t)path, (uint64_t)argv, (uint64_t)envp);
		if (rc < 0)
            return -rc;
        sysdep<LibcLog>("SYSCALL_EXEC returned!");
        sysdep<LibcPanic>();
    }

    int Sysdeps<GetCwd>::operator()(char* buffer, size_t size) {
        long rc = syscall(SYSCALL_GETCWD, (uint64_t)buffer, size);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<GetResuid>::operator()(uid_t* ruid, uid_t* euid, uid_t* suid) {
        UIDs uids = {};
        long rc = syscall(SYSCALL_GETRESUID, (uint64_t)&uids);
        if (rc < 0)
            return -rc;
        *ruid = uids.ruid;
        *euid = uids.euid;
        *suid = uids.suid;
        return 0;
    }

    int Sysdeps<GetResgid>::operator()(gid_t* rgid, gid_t* egid, gid_t* sgid) {
        GIDs gids = {};
        long rc = syscall(SYSCALL_GETRESGID, (uint64_t)&gids);
        if (rc < 0)
            return -rc;
        *rgid = gids.rgid;
        *egid = gids.egid;
        *sgid = gids.sgid;
        return 0;
    }

    int Sysdeps<Ttyname>::operator()(int fd, char *buf, size_t size) {
        (void)fd;
        (void)buf;
        (void)size;
        return 0;
    }

    int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t* __restrict set, sigset_t* __restrict retrieve) {
        long rc = syscall(SYSCALL_SIGPROCMASK, how, (uint64_t)set, (uint64_t)retrieve);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Symlink>::operator()(const char* target_path, const char* link_path) {
        long rc = syscall(SYSCALL_SYMLINK, (uint64_t)target_path, strlen(target_path), (uint64_t)link_path, strlen(link_path));
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Kill>::operator()(pid_t pid, int signal) {
        long rc = syscall(SYSCALL_KILL, pid, signal);
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Sigpending>::operator()(sigset_t* set) {
        long rc = syscall(SYSCALL_SIGPENDING, (uint64_t)set);
        if (rc < 0)
            return -rc;
        return 0;
    }

#ifndef MLIBC_BUILDING_RTLD
    extern "C" void __mlibc_restorer();

    int Sysdeps<Sigaction>::operator()(int sig, const struct sigaction* __restrict act, struct sigaction* __restrict oldact) {
        struct sigaction newAction;
        if (act != nullptr)
            memcpy(&newAction, act, sizeof(struct sigaction));

        if (act != nullptr && (newAction.sa_flags & SA_RESTORER) == 0) {
            newAction.sa_restorer = __mlibc_restorer;
            newAction.sa_flags |= SA_RESTORER;
        }

        long rc = syscall(SYSCALL_SIGACTION, sig, act != nullptr ? (uint64_t)&newAction : 0, (uint64_t)oldact);
        if (rc < 0)
            return -rc;
        return 0;
    }

#endif

    int Sysdeps<GetHostname>::operator()(char* buffer, size_t bufsize) {
        if (buffer != nullptr && bufsize > 0) {
            const char* host = "frostyos";
            memcpy(buffer, host, 8 > bufsize ? bufsize : 8);
        }
        return 0;
    }

    int Sysdeps<Chdir>::operator()(const char* path) {
        long rc = syscall(SYSCALL_CHDIR, (uint64_t)path, strlen(path));
        if (rc < 0)
            return -rc;
        return 0;
    }

    int Sysdeps<Fchdir>::operator()(int fd) {
        long rc = syscall(SYSCALL_FCHDIR, fd);
        if (rc < 0)
            return -rc;
        return 0;
    }

}