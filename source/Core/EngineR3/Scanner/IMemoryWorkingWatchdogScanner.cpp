#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	inline LPVOID __CreateMemoryPage(HANDLE hProcess, DWORD dwRegionSize, DWORD dwProtection)
	{
		LPVOID pMemBase = nullptr;

		__try
		{
			pMemBase = g_winAPIs->VirtualAlloc(0, dwRegionSize, MEM_COMMIT | MEM_RESERVE, dwProtection);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		return pMemBase;
	}

	bool IScanner::IsProtectedMemoryRegions(HANDLE hProcess, LPVOID lpMemBase)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxMemWatchdogMutex);

		for (const auto& [hMemOwnerProcess, lpMemWatchdog] : m_mapMemoryWatchdogs)
		{
			if (hMemOwnerProcess == hProcess && lpMemBase == lpMemWatchdog)
				return true;
		}
		return false;
	}
	auto IScanner::GetProtectedMemoryRegions(HANDLE hProcess)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxMemWatchdogMutex);

		std::vector <LPVOID> vMemoryWatchdogs;
		for (const auto& [hMemOwnerProcess, lpMemWatchdog] : m_mapMemoryWatchdogs)
		{
			if (hMemOwnerProcess == hProcess)
				vMemoryWatchdogs.push_back(lpMemWatchdog);
		}
		return vMemoryWatchdogs;
	};

	bool IScanner::InitializeMemoryWatchdogs(HANDLE hProcess)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxMemWatchdogMutex);

		if (!IsWindowsVistaOrGreater())
			return true;

		APP_TRACE_LOG(LL_SYS, L"Memory watchdog create routine has been started!");
		m_mapMemoryWatchdogs.clear();

		auto iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages pre
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_READWRITE);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}

		const auto pFirstWatchdog = __CreateMemoryPage(hProcess, 0x10000, PAGE_READWRITE); // Create watchdog page
		if (!pFirstWatchdog)
		{
			APP_TRACE_LOG(LL_ERR, L"First watchdog create fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		m_mapMemoryWatchdogs.emplace(hProcess, pFirstWatchdog);
		APP_TRACE_LOG(LL_SYS, L"First watchdog created at: %p", pFirstWatchdog);

		iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages post
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_READWRITE);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}


		iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages pre
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_READONLY);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}

		auto pSecondWatchdog = __CreateMemoryPage(hProcess, 0x10000, PAGE_READONLY); // Create watchdog page
		if (!pSecondWatchdog)
		{
			APP_TRACE_LOG(LL_ERR, L"Second watchdog create fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		m_mapMemoryWatchdogs.emplace(hProcess, pSecondWatchdog);
		APP_TRACE_LOG(LL_SYS, L"Second watchdog created at: %p", pSecondWatchdog);

		iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages post
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_READONLY);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}


		iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages pre
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_NOACCESS);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}

		const auto pThirdWatchdog = __CreateMemoryPage(hProcess, 0x10000, PAGE_NOACCESS); // Create watchdog page
		if (!pThirdWatchdog)
		{
			APP_TRACE_LOG(LL_ERR, L"Third watchdog create fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		m_mapMemoryWatchdogs.emplace(hProcess, pThirdWatchdog);
		APP_TRACE_LOG(LL_SYS, L"Third watchdog created at: %p", pThirdWatchdog);

		iRandomNumber = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 15);
		for (auto i = 0UL; i <= iRandomNumber; i++) // Create fake pages post
		{
			const auto pCurrMem = __CreateMemoryPage(hProcess, 0x10000, PAGE_NOACCESS);
			if (pCurrMem)
				m_mapMemoryDummyPages.emplace(hProcess, pCurrMem);
		}

		// TODO: Add unused random winapi for avoid than hook scanners

		APP_TRACE_LOG(LL_SYS, L"Memory watchdog pages succesfully created! Watchdog count: %u Dummy page count: %u", m_mapMemoryWatchdogs.size(), m_mapMemoryDummyPages.size());
		return true;
	}

	bool IScanner::CheckMemoryWatchdogs(HANDLE hProcess)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxMemWatchdogMutex);

		APP_TRACE_LOG(LL_TRACE, L"Memory watchdog check routine started!");

		if (m_mapMemoryWatchdogs.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Any watchdog page is NOT exist yet");
			return true;
		}

		if (!IsWindowsVistaOrGreater())
			return true;

		for (const auto& [hCurrProcess, lpCurrWatchdog] : m_mapMemoryWatchdogs)
		{
			APP_TRACE_LOG(LL_TRACE, L"Current watchdog page: %p in process: %p", lpCurrWatchdog, hCurrProcess);

			/*
			if (IsBadCodePtr((FARPROC)pCurrWatchdog))
			{
				APP_TRACE_LOG(LL_ERR, L"Memory page is corrupted!");
				return false;
			}
			*/
			/*
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			if (!g_winAPIs->VirtualQuery(pCurrWatchdog, &mbi, sizeof(mbi)))
			{
				APP_TRACE_LOG(LL_ERR, L"VirtualQuery fail! Error: %u", g_winAPIs->GetLastError());
				return false;
			}

			if (mbi.State == MEM_FREE)
			{
				APP_TRACE_LOG(LL_ERR, L"Memory page is free'd!");
				return false;
			}
			*/
			PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { lpCurrWatchdog, 0 };
			const auto ntStatus = g_winAPIs->NtQueryVirtualMemory(hCurrProcess, nullptr, MemoryWorkingSetExInformation, &pworkingSetExInformation, sizeof(pworkingSetExInformation), nullptr);
			if (!NT_SUCCESS(ntStatus))
			{
				if (ntStatus == STATUS_OBJECT_TYPE_MISMATCH)
					return true;

				APP_TRACE_LOG(LL_WARN, L"NtQueryVirtualMemory (%p) failed with status: %p", lpCurrWatchdog, ntStatus);
				if (IsWindowsVistaOrGreater() && !g_winAPIs->QueryWorkingSetEx(hCurrProcess, &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
				{
					APP_TRACE_LOG(LL_WARN, L"QueryWorkingSetEx (%p) failed with error: %u", lpCurrWatchdog, g_winAPIs->GetLastError());
					return true;
				}
			}

			if (pworkingSetExInformation.VirtualAttributes.Valid)
			{
				APP_TRACE_LOG(LL_ERR, L"Memory scan detected at watchdog: %p", lpCurrWatchdog);
				return false;
			}
		}
		return true;
	}
};
