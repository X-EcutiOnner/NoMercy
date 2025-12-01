#pragma once
#include <cstdint>

namespace cleancall
{
    enum ECleancallCallgateTypes : uint8_t
    {
        SYSCALL_CALL_TYPE_UNKNOWN = 0,  // not defined
        SYSCALL_CALL_TYPE_INT2E = 1,    // for x86 or x64
        SYSCALL_CALL_TYPE_SYSENTER = 2, // for x86
        SYSCALL_CALL_TYPE_WOW64 = 3,    // for x86_64
        SYSCALL_CALL_TYPE_SYSCALL = 4,   // for x64
        SYSCALL_CALL_TYPE_WOW64_SYSCALL = 5,  //for x86_64
    };

    ECleancallCallgateTypes get_gate_type();
    void set_gate_type(ECleancallCallgateTypes type);

    int32_t __stdcall call(uint32_t syscall_idx, uint32_t arg_count, ...);
#ifdef _M_IX86
    int64_t __stdcall callwow64(uint32_t syscall_idx, uint32_t x64_thunk, uint32_t arg_count, ...);
    int64_t __stdcall call64(uint32_t syscall_idx, uint32_t x64_thunk, uint32_t arg_count, ...);
#endif
};
