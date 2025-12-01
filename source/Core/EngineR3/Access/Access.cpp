#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Access.hpp"

namespace NoMercy
{
	bool CAccess::EnablePermanentDep()
	{
		// Set up proper flags, call NtSetInformationProcess to disable RW memory execution and make it permanent
		ULONG ulExecuteFlags = MEM_EXECUTE_OPTION_ENABLE | MEM_EXECUTE_OPTION_PERMANENT;
		const auto ntStatus = g_winAPIs->NtSetInformationProcess(NtCurrentProcess(), ProcessExecuteFlags, &ulExecuteFlags, sizeof(ulExecuteFlags));

		if (NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_SYS, L"Permanent DEP enabled!");
			return true;
		}

		APP_TRACE_LOG(LL_ERR, L"Permanent DEP can NOT enabled! Ntstat: %p", ntStatus);
		return false;
	}

	bool CAccess::EnableNullPageProtection()
	{
		// Allocate null page and first 0x1000 bytes proceeding it
		SIZE_T cbRegionSize = 0x1000;
		LPVOID lpBaseAddress = (PVOID)0x1;

		const auto ntStatus = g_winAPIs->NtAllocateVirtualMemory(NtCurrentProcess(), &lpBaseAddress, 0L, &cbRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
		if (NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_SYS, L"NULL Page Allocation Prevention enabled!");
			return true;
		}

		APP_TRACE_LOG(LL_ERR, L"NULL Page Allocation Prevention can NOT enabled! Ntstat: %p", ntStatus);
		return false;
	}

	bool CAccess::EnableDebugPrivileges()
	{
		static auto s_nCount = 0;

		BOOLEAN bPrevStat = TRUE;
		const auto ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bPrevStat);
		const auto bSuccessed = NT_SUCCESS(ntStatus);
		if (!bSuccessed)
		{
			APP_TRACE_LOG(LL_WARN, L"RtlAdjustPrivilege completed with status: %p prev status: %d", ntStatus, bPrevStat);
		}

		if (!bPrevStat)
			s_nCount++;

		if (s_nCount > 3)
			CApplication::Instance().OnCloseRequest(EXIT_ERR_DEBUG_PRIV_LIMIT_EXCEED, ntStatus);

		return bSuccessed || ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_PRIVILEGE_NOT_HELD;
	}
};
