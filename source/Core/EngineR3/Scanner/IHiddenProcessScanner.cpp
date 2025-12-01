#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"


namespace NoMercy
{
	DWORD GetServicePID(const std::wstring& stServiceName)
	{
		SafeService hServiceMgr = g_winAPIs->OpenSCManagerW(nullptr, nullptr, NULL);
		SafeService hService = g_winAPIs->OpenServiceW(hServiceMgr, stServiceName.c_str(), SERVICE_QUERY_STATUS);

		SERVICE_STATUS_PROCESS ssp{};
		
		DWORD bytesNeeded = 0;
		if (g_winAPIs->QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
			return ssp.dwProcessId;
		return 0;
	}
	
	inline bool IsHiddenProcess(DWORD dwProcessId)
	{
		// TODO: Get process list & pids, check is it exist

		const auto lstWhitelist = std::vector <std::wstring>{
			xorstr_(L"dwm.exe"),
			xorstr_(L"adappmgrsvc.exe"),
			xorstr_(L"ipoverusbsvc.exe"),
			xorstr_(L"vmnat.exe")
		};

		const auto dwHidServPID = GetServicePID(xorstr_(L"hidserv"));
		const auto dwWpnSvcPID = GetServicePID(xorstr_(L"WpnService"));
		if (dwHidServPID == dwProcessId || dwWpnSvcPID == dwProcessId)
		{
			APP_TRACE_LOG(LL_SYS, L"Whitelisted service process: %u", dwProcessId);
			return false;
		}

		auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		for (const auto& hWnd : windowEnumerator->EnumerateWindows())
		{
			if (!hWnd)
				continue;

			// ---
			auto dwCurrProcessId = 0UL;
			const auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwCurrProcessId);
			if (!dwThreadId || !dwCurrProcessId)
				continue;

			auto hProc = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwCurrProcessId);
			if (!IS_VALID_HANDLE(hProc))
			{
				const auto dwWaitRet = g_winAPIs->WaitForSingleObject(hProc, 0);

				if (dwWaitRet != WAIT_TIMEOUT)
					return true;
			}

			// -----
			
			/*
			if (g_winAPIs->GetParent(hWnd) != 0)
				continue;

			auto dwCurrProcessId = 0UL;
			const auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwCurrProcessId);
			if (!dwThreadId || !dwCurrProcessId)
				continue;

			// TODO: extra checks
			const auto stName = CProcessFunctions::GetProcessNameFromProcessId(dwCurrProcessId);
			if (!stName.empty() && stdext::in_vector(lstWhitelist, stName))
				continue;

			if (dwProcessId == dwCurrProcessId)
				return true;
			*/

			g_winAPIs->CloseHandle(hProc);
		}

		return false;
	}

	static bool CheckHiddenProcessByWindows()
	{
		APP_TRACE_LOG(LL_SYS, L"CheckHiddenProcessByWindows has been started!");
		
		auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto vWindows = windowEnumerator->EnumerateWindows();
		if (vWindows.empty()) {
			APP_TRACE_LOG(LL_ERR, L"Can not enumerated windows");
			return false;
		}

		for (const auto& hWnd : vWindows)
		{
			if (!hWnd)
				continue;
			
			auto dwProcessId = 0UL;
			g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessId);

			if (dwProcessId < 5)
				continue;

			if (g_winAPIs->IsWindow(hWnd))
			{
				auto hProc = g_winAPIs->OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
				if (!IS_VALID_HANDLE(hProc))
				{
					const auto param = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HIDDEN_PROCESS, HIDDEN_PROCESS_SCAN_1, param);

					APP_TRACE_LOG(LL_ERR, L"Hidden process detected. PID: %u", dwProcessId);
					return true;
				}
				else
				{
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProc);
				}
			}
		}
		return false;
	}

	inline bool IsProcessLinked(DWORD dwProcessId, PSYSTEM_PROCESS_INFORMATION pInfos)
	{
		auto pCurrent = pInfos;

		while (true)
		{
			if ((DWORD)pCurrent->UniqueProcessId == dwProcessId)
				return true;

			if (pCurrent->NextEntryOffset == 0)
				break;
			pCurrent = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pCurrent + pCurrent->NextEntryOffset);
		}

		return false;
	}

	static bool CheckHiddenProcessByHandles()
	{
		APP_TRACE_LOG(LL_SYS, L"CheckHiddenProcessByHandles has been started!");
		
		auto dwLength = 1UL;
		auto pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)malloc(dwLength);
		if (!pProcessInfos)
			return false;

		auto ntStatus = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, pProcessInfos, dwLength, &dwLength);
		if (!NT_SUCCESS(ntStatus) || ntStatus != STATUS_INFO_LENGTH_MISMATCH)
		{
			free(pProcessInfos);
			return false;
		}

		if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)realloc(pProcessInfos, dwLength);
		}

		if (!pProcessInfos)
			return false;

		ntStatus = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, pProcessInfos, dwLength, &dwLength);
		if (!NT_SUCCESS(ntStatus))
		{
			free(pProcessInfos);
			return false;
		}

		// ---

		dwLength = 1;
		auto pHandleInfos = (PSYSTEM_HANDLE_INFORMATION)malloc(dwLength);
		if (!pHandleInfos)
			return false;

		ntStatus = g_winAPIs->NtQuerySystemInformation(SystemHandleInformation, pHandleInfos, dwLength, &dwLength);
		if (!NT_SUCCESS(ntStatus) || ntStatus != STATUS_INFO_LENGTH_MISMATCH)
		{
			free(pProcessInfos);
			return false;
		}

		if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			pHandleInfos = (PSYSTEM_HANDLE_INFORMATION)malloc(dwLength);
		}

		if (!pHandleInfos)
			return false;

		ntStatus = g_winAPIs->NtQuerySystemInformation(SystemHandleInformation, pHandleInfos, dwLength, &dwLength);
		if (!NT_SUCCESS(ntStatus))
		{
			free(pHandleInfos);
			return false;
		}

		for (ULONG i = 0; i < pHandleInfos->NumberOfHandles; i++)
		{
			auto hCurrHandle = pHandleInfos->Handles[i];
			auto hDupHandle = HANDLE(INVALID_HANDLE_VALUE);
			auto hOwnerHandle = HANDLE(INVALID_HANDLE_VALUE);

			if (hCurrHandle.UniqueProcessId == g_winAPIs->GetCurrentProcessId()) /* Itself */
				continue;

			if (hCurrHandle.UniqueProcessId < 5) /* System */
				continue;

			if (hCurrHandle.ObjectTypeIndex != 0x5 && hCurrHandle.ObjectTypeIndex != 0x7) // Just process handles 
				continue;

			hOwnerHandle = g_winAPIs->OpenProcess(PROCESS_DUP_HANDLE, FALSE, hCurrHandle.UniqueProcessId);
			if (!IS_VALID_HANDLE(hOwnerHandle))
				continue;

			ntStatus = g_winAPIs->NtDuplicateObject(hOwnerHandle, (HANDLE)hCurrHandle.HandleValue, GetCurrentProcess(), &hDupHandle, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
			if (!NT_SUCCESS(ntStatus))
			{
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hOwnerHandle);
				continue;
			}

			auto dwProcessId = CProcessFunctions::GetProcessIdNative(hDupHandle);
			if (false == IsProcessLinked(dwProcessId, pProcessInfos))
			{
				APP_TRACE_LOG(LL_ERR, L"Hidden process detected. PID: %u", dwProcessId);

				const auto param = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HIDDEN_PROCESS, HIDDEN_PROCESS_SCAN_2, param);

				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hOwnerHandle);

				return true;
			}

			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hOwnerHandle);
		}

		free(pHandleInfos);
		free(pProcessInfos);

		return false;
	}

	static bool CheckHiddenProcessByBruteforce()
	{
		APP_TRACE_LOG(LL_SYS, L"CheckHiddenProcessByBruteforce has been started!");

		for (auto i = 4UL; i < 65535; i += 4UL)
		{
			auto hProcess = g_winAPIs->OpenProcess(SYNCHRONIZE, FALSE, i);
			if (IS_VALID_HANDLE(hProcess))
			{
				if (IsHiddenProcess(i))
				{
					APP_TRACE_LOG(LL_ERR, L"Hidden process detected. PID: %u", i);

					const auto param = CProcessFunctions::GetProcessNameFromProcessId(i);
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HIDDEN_PROCESS, HIDDEN_PROCESS_SCAN_3, param);
				}
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);
			}
		}
		return false;
	}

	static void CheckHiddenProcessByWMI()
	{
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT __RELPATH FROM Win32_Process"),
			[](std::map <std::wstring, std::wstring> ctx) {
				for (const auto& [_, stPID] : ctx)
				{
					const auto dwPID = stdext::str_to_u32(stPID);
					if (dwPID)
					{
						const auto hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
						if (IS_VALID_HANDLE(hProcess))
						{
							if (!CProcessFunctions::ProcessIsItAlive(dwPID))
							{
								DWORD dwExitCode = 0;
								if (g_winAPIs->GetExitCodeProcess(hProcess, &dwExitCode) && dwExitCode == STILL_ACTIVE)
								{
									const auto stName = CProcessFunctions::GetProcessNameFromProcessId(dwPID);
									APP_TRACE_LOG(LL_SYS, L"Hidden process detected. PID: %u, Name: %S", dwPID, stName.c_str());
									CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HIDDEN_PROCESS, HIDDEN_PROCESS_SCAN_4, stName);
								}
							}

							NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);
						}
					}
				}
			}
		);
	}

	void IScanner::CheckHiddenProcess()
	{		
		APP_TRACE_LOG(LL_SYS, L"CheckHiddenProcess has been started!");

		CheckHiddenProcessByWindows();
		CheckHiddenProcessByHandles();
		// CheckHiddenProcessByBruteforce(); // FIXME: false positives
		CheckHiddenProcessByWMI();

		APP_TRACE_LOG(LL_SYS, L"CheckHiddenProcess completed!");
	}
};
