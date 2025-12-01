#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumeratorNt.hpp"
#include <comdef.h>


namespace NoMercy
{
	bool IScanner::CheckDnsServiceIntegrity()
	{
		bool bRet = false;
		LPBYTE lpBuffer = nullptr;

		auto hSCManager = g_winAPIs->OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
		if (!hSCManager)
			return true; // pass

		auto hService = g_winAPIs->OpenServiceW(hSCManager, xorstr_(L"Dnscache"), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
		if (!hService)
		{
			APP_TRACE_LOG(LL_ERR, L"OpenServiceA failed with error: %u", g_winAPIs->GetLastError());
			goto _exit;
		}

		DWORD dwReqSize = 0;
		if (!g_winAPIs->QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, nullptr, 0, &dwReqSize) && !dwReqSize)
		{
			APP_TRACE_LOG(LL_ERR, L"QueryServiceStatusEx(1) failed with error: %u", g_winAPIs->GetLastError());
			goto _exit;
		}

		lpBuffer = (BYTE*)CMemHelper::Allocate(dwReqSize);
		if (!lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"Buffer allocation failed with error: %u", g_winAPIs->GetLastError());
			goto _exit;
		}

		if (!g_winAPIs->QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, lpBuffer, dwReqSize, &dwReqSize) || !lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"QueryServiceStatusEx(2) failed with error: %u", g_winAPIs->GetLastError());
			goto _exit;
		}

		const auto lpProcessStatus = (SERVICE_STATUS_PROCESS*)lpBuffer;
		if (!lpProcessStatus->dwProcessId)
		{
			APP_TRACE_LOG(LL_ERR, L"Service query buffer does not contain process id");
			bRet = true;
			goto _exit;
		}
		APP_TRACE_LOG(LL_SYS, L"DNS Cache service status: %u Host process: %u", lpProcessStatus->dwCurrentState, lpProcessStatus->dwProcessId);

		if (lpProcessStatus->dwCurrentState != SERVICE_RUNNING)
		{
			APP_TRACE_LOG(LL_ERR, L"DNS Cache service is not running!");
			goto _exit;
		}

		if (!CProcessFunctions::ProcessIsItAlive(lpProcessStatus->dwProcessId))
		{
			APP_TRACE_LOG(LL_ERR, L"DNS Cache service host process not alive!");
			bRet = true;
			goto _exit;
		}

		if (CProcessFunctions::HasSuspendedThread(lpProcessStatus->dwProcessId))
		{
			APP_TRACE_LOG(LL_ERR, L"DNS Cache service host process contains suspended threads!");
			goto _exit;
		}

		bRet = true;
_exit:
		if (hSCManager)
		{
			g_winAPIs->CloseServiceHandle(hSCManager);
			hSCManager = nullptr;
		}
		if (hService)
		{
			g_winAPIs->CloseServiceHandle(hService);
			hService = nullptr;
		}
		if (lpBuffer)
		{
			CMemHelper::Free(lpBuffer);
			lpBuffer = nullptr;
		}
		return bRet;
	}

	void IScanner::CheckDnsHistory()
	{
		if (IsWindows7OrGreater() == false)
			return;
		
		CheckDnsServiceIntegrity();

		auto bConnected = false;
		auto hInternet = g_winAPIs->InternetOpenW(xorstr_(L"WebAgent"), NULL, NULL, NULL, NULL);
		if (hInternet)
		{
			auto hFile = g_winAPIs->InternetOpenUrlW(hInternet, xorstr_(L"http://www.yahoo.de"), NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
			if (hFile)
			{
				bConnected = true;
				g_winAPIs->InternetCloseHandle(hFile);
			}
			g_winAPIs->InternetCloseHandle(hInternet);
		}

		WinAPI::PDNS_CACHE_ENTRY pEntry = nullptr;
		auto iTableStat = g_winAPIs->DnsGetCacheDataTable(&pEntry);
		if (!iTableStat)
		{
			APP_TRACE_LOG(LL_CRI, L"DnsGetCacheDataTable failed with error: %u", g_winAPIs->GetLastError()); // throw
			return;
		}
		auto ptr = pEntry;

		auto bTrapEntryFound = false;
		auto dwCount = 0UL;
		while (pEntry)
		{
			dwCount++;

			const auto stEntry = stdext::to_ansi(pEntry->Name);
			// APP_TRACE_LOG(LL_SYS, L"[%u] DNS Entry: %s", dwCount, stEntry.c_str());

			// TODO: Scan DNS

			if (stEntry.find(xorstr_("yahoo.de")) != std::wstring::npos)
				bTrapEntryFound = true;

			pEntry = pEntry->Next;
		}
		// free(ptr);

		if (dwCount == 0)
		{
			APP_TRACE_LOG(LL_CRI, L"Not found any dns history"); // throw
			return;
		}

		if (bConnected && !bTrapEntryFound)
		{
			APP_TRACE_LOG(LL_CRI, L"DNS cache table integrity corrupted"); // throw
			return;
		}

		return;
	}
};
