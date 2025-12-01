#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../SelfProtection/SelfProtection.hpp"
#include "../../EngineR3_Core/include/Elevation.hpp"
#include <sysinfoapi.h>
#include <memoryapi.h>

namespace NoMercy
{
	bool CSelfProtection::InitializeHiddenMemoryExecutor(LPVOID pvFunc)
	{
		auto __EnableSeLockMemoryPrivilege = []() {
			static auto s_bOnce = false;
			if (s_bOnce)
				return true;
			s_bOnce = true;

			HANDLE hToken = nullptr;
			if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			const auto bRet = CElevationHelper::SetProcessPrivilege(hToken, xorstr_(L"SeLockMemoryPrivilege"), true);

			g_winAPIs->CloseHandle(hToken);
			return bRet;
		};

		__EnableSeLockMemoryPrivilege();

		SYSTEM_INFO sysInfo;
		g_winAPIs->GetSystemInfo(&sysInfo);

		APP_TRACE_LOG(LL_SYS, L"SystemInfo: PageSize: %u, AllocationGranularity: %u", sysInfo.dwPageSize, sysInfo.dwAllocationGranularity);

		const auto lpAddress = g_winAPIs->VirtualAlloc(NULL, sysInfo.dwPageSize, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
		if (!lpAddress)
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualAlloc failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		ULONG_PTR PageArray = 0;
		ULONG_PTR PageArraySize = 1;
		if (!g_winAPIs->AllocateUserPhysicalPages(NtCurrentProcess(), &PageArraySize, &PageArray))
		{
			APP_TRACE_LOG(LL_ERR, L"AllocateUserPhysicalPages failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->MapUserPhysicalPages(lpAddress, 1, &PageArray))
		{
			APP_TRACE_LOG(LL_ERR, L"MapUserPhysicalPages (1) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		*(LPVOID*)lpAddress = pvFunc;

		if (!g_winAPIs->MapUserPhysicalPages(lpAddress, 1, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"MapUserPhysicalPages (2) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->MapUserPhysicalPages(lpAddress, 1, &PageArray))
		{
			APP_TRACE_LOG(LL_ERR, L"MapUserPhysicalPages (3) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		g_winAPIs->FreeUserPhysicalPages(NtCurrentProcess(), &PageArraySize, &PageArray);
		g_winAPIs->VirtualFree(lpAddress, 0, MEM_RELEASE);
		return true;
	}
};
