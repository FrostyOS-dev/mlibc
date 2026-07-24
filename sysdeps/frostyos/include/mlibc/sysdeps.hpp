#pragma once

#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct FrostyOSSysdepTags :
    Exit,
    FutexWait,
    FutexWake,
    Open,
    Read,
    Write,
    Seek,
    Close,
    ClockGet,
    LibcLog,
    LibcPanic,
    AnonAllocate,
    AnonFree,
    VmMap,
    VmUnmap,
    VmProtect,
    TcbSet,
    Isatty,
    GetPid,
    GetPpid,
    FutexTid,
    GetTid,
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,
    OpenDir,
    ReadEntries,
    Fork,
    Execve
{};

template<typename Tag>
using Sysdeps = SysdepOf<FrostyOSSysdepTags, Tag>;

} // namespace mlibc