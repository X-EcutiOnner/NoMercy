#include "../../include/Cleancall.hpp"
#include <ProtectionMacros.h>
#include <intrin.h>
#include <stdarg.h>

#ifdef _M_AMD64

using sys_gate_proc = int32_t(__fastcall*)(uint32_t syscall_idx, uint32_t args_count, uint64_t* arg_table);

extern "C" int32_t __fastcall internal_cleancall_native_int2e(uint32_t syscall_idx, uint32_t args_count, uint64_t * arg_table);
extern "C" int32_t __fastcall internal_cleancall_native_syscall(uint32_t syscall_idx, uint32_t args_count, uint64_t * arg_table);

#else

extern "C" void* internal_cleancall_wow64_gate = 0;

using sys_gate_proc = int32_t(__cdecl*)(uint32_t syscall_idx, uint32_t args_count, uint32_t* arg_table);

extern "C" int32_t __cdecl internal_cleancall_native_int2e(uint32_t syscall_idx, uint32_t args_count, uint32_t * arg_table);
extern "C" int32_t __cdecl internal_cleancall_native_sysenter(uint32_t syscall_idx, uint32_t args_count, uint32_t * arg_table);
extern "C" int32_t __cdecl internal_cleancall_WOW64(uint32_t syscall_idx, uint32_t args_count, uint32_t* arg_table);
extern "C" int32_t __cdecl internal_cleancall_WOW64_syscall(uint32_t syscall_idx, uint32_t args_count, uint32_t * arg_table);

#endif

#ifdef _M_IX86
extern "C" void* __cdecl intrnl__ntcallmalloc32(void* ctx, uint32_t size)
{
	uint32_t* allocated32_ctx = (uint32_t*)ctx;

	PVOID baseaddress = 0;
	SIZE_T region_size = 0x1000;
	NtAllocateVirtualMemory(GetCurrentProcess(), &baseaddress, 0, &region_size, MEM_COMMIT, PAGE_READWRITE);

	allocated32_ctx[allocated32_ctx[0] + 1] = (uint32_t)baseaddress;
	allocated32_ctx[0]++;

	if (allocated32_ctx[0] == 12) {
		__debugbreak();
	}

	return baseaddress;
}
#endif

namespace cleancall
{
	static sys_gate_proc used_sys_gate = 0;
	static ECleancallCallgateTypes used_gate_type = SYSCALL_CALL_TYPE_UNKNOWN;

	void detect_gate_type()
	{
#ifndef _M_AMD64
		internal_cleancall_wow64_gate = (void*)__readfsdword(0xC0);
		if (internal_cleancall_wow64_gate)
		{
			set_gate_type(SYSCALL_CALL_TYPE_WOW64);
			// set_gate_type(SYSCALL_CALL_TYPE_WOW64_SYSCALL);
		}
		else
#endif
		{
			if (*(uint32_t*)0x7FFE0308 == 0) // TODO: better isx64 for win11
			{
#ifdef _M_AMD64
				set_gate_type(SYSCALL_CALL_TYPE_SYSCALL);
#else
				set_gate_type(SYSCALL_CALL_TYPE_SYSENTER);
#endif
			}
			else
			{
				set_gate_type(SYSCALL_CALL_TYPE_INT2E);
			}
		}
	}

	ECleancallCallgateTypes get_gate_type()
	{
		if (used_gate_type == SYSCALL_CALL_TYPE_UNKNOWN)
			detect_gate_type();

		return used_gate_type;
	}

	void set_gate_type(ECleancallCallgateTypes type)
	{
		used_gate_type = type;

		switch (used_gate_type)
		{
#ifdef _M_AMD64
			case SYSCALL_CALL_TYPE_SYSCALL:
			{
				used_sys_gate = internal_cleancall_native_syscall;
				break;
			}
#else
			case SYSCALL_CALL_TYPE_WOW64:
			{
				used_sys_gate = internal_cleancall_WOW64;
				break;
			}

			case SYSCALL_CALL_TYPE_WOW64_SYSCALL:
			{
				used_sys_gate = internal_cleancall_WOW64_syscall;
				break;
			}
				
			case SYSCALL_CALL_TYPE_SYSENTER:
			{
				used_sys_gate = internal_cleancall_native_sysenter;
				break;
			}
#endif

			case SYSCALL_CALL_TYPE_INT2E:
			{
				used_sys_gate = internal_cleancall_native_int2e;
				break;
			}

			default:
			{
				used_sys_gate = 0;
				break;
			}
		}
	}

	int32_t __stdcall call(uint32_t syscall_idx, uint32_t arg_count, ...)
	{
		if (used_gate_type == SYSCALL_CALL_TYPE_UNKNOWN)
			detect_gate_type();

#ifdef _M_AMD64
		using arg_t = uint64_t;
#else
		using arg_t = uint32_t;
#endif

		arg_t arg_table[20];

		va_list variadic_arg;
		va_start(variadic_arg, arg_count);

		for (uint32_t idx = 0; idx < arg_count; idx++)
			arg_table[idx] = va_arg(variadic_arg, arg_t);

		va_end(variadic_arg);

		if (used_sys_gate)
		{
//			__PROTECTOR_START__("syscall")
			const auto nRet = used_sys_gate(syscall_idx, arg_count, arg_table);
//			__PROTECTOR_END__("syscall")

			return nRet;
		}

		return STATUS_NOT_IMPLEMENTED;
	}

#ifdef _M_IX86
	int64_t __stdcall callwow64(uint32_t syscall_idx, uint32_t x64_thunk, uint32_t arg_count, ...)
	{
		if (used_gate_type == SYSCALL_CALL_TYPE_UNKNOWN)
			detect_gate_type();

#ifdef _M_AMD64
		using arg_t = uint64_t;
#else
		using arg_t = uint32_t;
#endif

		arg_t arg_table[20];
		size_t arg_idx = 0;

		va_list variadic_arg;
		uint32_t allocate32_ctx[10];

		va_start(variadic_arg, arg_count);

		if (used_gate_type == SYSCALL_CALL_TYPE_WOW64_SYSCALL)
		{
			allocate32_ctx[0] = 0;

			arg_table[0] = (uint32_t)&allocate32_ctx;

			arg_table[1] = (uint32_t)syscall_idx;
			arg_idx = 2;

			//now it point to x64 callback function
			syscall_idx = x64_thunk;
		}

		for (uint32_t idx = 0; idx < arg_count; idx++, arg_idx++)
			arg_table[arg_idx] = va_arg(variadic_arg, arg_t);

		va_end(variadic_arg);


		int64_t result = STATUS_NOT_IMPLEMENTED;

		if (used_sys_gate) {
			result = used_sys_gate(syscall_idx, arg_count, arg_table);
		}

#ifdef _M_IX86
		if (used_gate_type == SYSCALL_CALL_TYPE_WOW64_SYSCALL)
		{
			for (size_t idx = 0; idx < allocate32_ctx[0]; idx++)
			{
				PVOID baseaddress = (PVOID)allocate32_ctx[2 + idx];
				SIZE_T region_size = 0x1000;
				NtFreeVirtualMemory(GetCurrentProcess(), &baseaddress, &region_size, MEM_FREE);
			}
		}
#endif

		return result;
	}

	int64_t __stdcall call64(uint32_t syscall_idx, uint32_t x64_thunk, uint32_t arg_count, ...)
	{
		if (used_gate_type == SYSCALL_CALL_TYPE_UNKNOWN)
			detect_gate_type();

		uint64_t arg_table[20];
		size_t arg_idx = 0;

		va_list variadic_arg;
		uint64_t allocate32_ctx[10];

		va_start(variadic_arg, arg_count);

		if (used_gate_type == SYSCALL_CALL_TYPE_WOW64_SYSCALL) {

			allocate32_ctx[0] = 0;

			arg_table[0] = (uint32_t)&allocate32_ctx;

			arg_table[1] = (uint32_t)syscall_idx;
			arg_idx = 2;

			//now it point to x64 callback function
			syscall_idx = x64_thunk;
		}

		for (uint32_t idx = 0; idx < arg_count; idx++, arg_idx++) {

			arg_table[arg_idx] = va_arg(variadic_arg, uint64_t);
		}

		va_end(variadic_arg);

		int64_t result = STATUS_NOT_IMPLEMENTED;

		if (used_sys_gate) {
			result = used_sys_gate(syscall_idx, arg_count, (uint32_t*)arg_table);
		}

		if (used_gate_type == SYSCALL_CALL_TYPE_WOW64_SYSCALL)
		{
			for (size_t idx = 0; idx < allocate32_ctx[0]; idx++) {
				PVOID baseaddress = (PVOID)allocate32_ctx[2 + idx];
				SIZE_T region_size = 0x1000;
				NtFreeVirtualMemory(GetCurrentProcess(), &baseaddress, &region_size, MEM_FREE);
			}
		}

		return result;
	}

#endif
};
