#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiBreakpoint.hpp"

namespace NoMercy
{
	bool CAntiBreakpoint::HasHardwareBreakpoint(HANDLE hThread)
	{
		CONTEXT ctx{ 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (g_winAPIs->GetThreadContext(hThread, &ctx))
		{
			APP_TRACE_LOG(LL_SYS, L"HasHardwareBreakpoint: Dr0: %x, Dr1: %x, Dr2: %x, Dr3: %x, Dr6: %x, Dr7: %x", ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
			
			if (ctx.Dr6 && ctx.Dr7)
			{
				return true;
			}
		}

		return false;
	}

	bool CAntiBreakpoint::HasEntrypointBreakpoint()
	{
		const auto pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(g_winModules->hBaseModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(pIDH) + pIDH->e_lfanew));
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pEntryPoint = reinterpret_cast<PBYTE>((pINH->OptionalHeader.AddressOfEntryPoint + reinterpret_cast<DWORD_PTR>(pIDH)));
		return (pEntryPoint[0] == 0xCC);
	}

	bool CAntiBreakpoint::HasMemoryBreakpoint()
	{
		SYSTEM_INFO SystemInfo = { 0 };
		g_winAPIs->GetSystemInfo(&SystemInfo);

		auto pAllocation = g_winAPIs->VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pAllocation)
			return false;

		RtlFillMemory(pAllocation, 1, 0xC3);

		DWORD OldProtect = 0;
		if (!g_winAPIs->VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect))
			return false;

		__try
		{
			((void(*)())pAllocation)();
		}
		__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
		{
			g_winAPIs->VirtualFree(pAllocation, NULL, MEM_RELEASE);
			return false;
		}

		g_winAPIs->VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return true;
	}
};
