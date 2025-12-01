#include "../../include/PCH.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/ProcessFunctions.hpp"
#include "../../include/ProcessEnumerator.hpp"
#include "../../include/ThreadEnumerator.hpp"
#include "../../include/ThreadEnumeratorNT.hpp"
#include "../../../../Common/StdExtended.hpp"

namespace NoMercyCore
{
	DWORD CProcessFunctions::GetProcessParentProcessId(DWORD dwMainProcessId)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				if (pe.th32ProcessID == dwMainProcessId)
				{
					g_winAPIs->CloseHandle(hSnap);
					return pe.th32ParentProcessID;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hSnap);
		return 0;
	}

	DWORD CProcessFunctions::FindProcess(const std::wstring& wstProcessName)
	{
		DWORD dwRet = 0;

		std::wstring wstLowerProcessName = stdext::to_lower_wide(wstProcessName);

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return dwRet;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);
				if (wstCurrProcessName.find(wstLowerProcessName) != std::wstring::npos)
				{
					dwRet = pe.th32ProcessID;
					break;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return dwRet;
	}

	DWORD CProcessFunctions::FindAnyProcess(const std::vector <std::wstring>& vecProcessNames)
	{
		DWORD dwRet = 0;

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return dwRet;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);

				auto nFindIdx = 0;
				auto nCurrIdx = 0;
				for (const auto& wstProcessName : vecProcessNames)
				{
					const auto wstLowerProcessName = stdext::to_lower_wide(wstProcessName);
					if (wstCurrProcessName.find(wstLowerProcessName) != std::wstring::npos)
					{
						nFindIdx = nCurrIdx;
					}

					nCurrIdx++;
				}

				if (nFindIdx)
				{
					dwRet = nFindIdx;
					break;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return dwRet;
	}

	DWORD CProcessFunctions::GetProcessIdFromProcessName(const std::wstring& wstProcessName, bool bDumpProcesses)
	{
		std::wstring wstLowerProcessName = stdext::to_lower_wide(wstProcessName);

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);

				if (bDumpProcesses)
				{
					APP_TRACE_LOG(LL_SYS, L"Current process: %s (%u), Looking for: %s", wstCurrProcessName.c_str(), pe.th32ProcessID, wstProcessName.c_str());
				}

				if (wstLowerProcessName == wstCurrProcessName)
				{
					g_winAPIs->CloseHandle(hSnap);
					return pe.th32ProcessID;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return 0;
	}

	DWORD CProcessFunctions::GetProcessCountFromProcessName(const std::wstring& wstProcessName)
	{
		std::wstring wstLowerProcessName = stdext::to_lower_wide(wstProcessName);

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		DWORD dwCount = 0;

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);
				if (wstLowerProcessName == wstCurrProcessName)
					dwCount++;

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return dwCount;
	}

	std::wstring CProcessFunctions::GetProcessNameFromProcessId(DWORD dwProcessId)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return {};
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				if (dwProcessId == pe.th32ProcessID)
				{
					const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);

					g_winAPIs->CloseHandle(hSnap);
					return wstCurrProcessName;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return {};
	}

	bool CProcessFunctions::ProcessIsItAlive(DWORD dwProcessId)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				if (pe.th32ProcessID == dwProcessId)
				{
					g_winAPIs->CloseHandle(hSnap);
					return true;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return false;
	}

	std::vector <DWORD> CProcessFunctions::GetProcessIdsFromProcessName(const std::wstring& wstProcessName)
	{
		auto vPIDs = std::vector<DWORD>();

		std::wstring wstLowerProcessName = stdext::to_lower_wide(wstProcessName);

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return vPIDs;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);
				if (wstCurrProcessName.find(wstLowerProcessName) != std::wstring::npos)
					vPIDs.emplace_back(pe.th32ProcessID);

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return vPIDs;
	}

	std::wstring CProcessFunctions::GetProcessFullName(HANDLE hProcess)
	{
		if (!hProcess)
			return {};

		wchar_t processPath[MAX_PATH]{ L'\0' };
		if (g_winAPIs->GetProcessImageFileNameW(hProcess, processPath, _countof(processPath)))
			return processPath;
		
		APP_TRACE_LOG(LL_ERR, L"GetProcessImageFileNameW fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
		memset(processPath, 0, MAX_PATH);

		if (g_winAPIs->GetModuleFileNameExW(hProcess, nullptr, processPath, _countof(processPath)))
			return processPath;

		APP_TRACE_LOG(LL_ERR, L"GetModuleFileNameExW fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
		return {};
	}

	std::wstring CProcessFunctions::GetProcessName(HANDLE hProcess)
	{
		const auto wstDosName = GetProcessFullName(hProcess);
		if (wstDosName.empty())
			return {};

		auto wstProcessName = DosDevicePath2LogicalPath(wstDosName.c_str());
		if (wstProcessName.empty())
			return {};

		return stdext::to_lower_wide(wstProcessName);
	}

	DWORD CProcessFunctions::GetProcessIdNative(HANDLE hProcess)
	{
		PROCESS_BASIC_INFORMATION pPBI{ 0 };
		const auto ntStat = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), 0);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess fail! Target process: %p Status: %p", hProcess, ntStat);
			return 0UL;
		}

		return reinterpret_cast<DWORD>(pPBI.UniqueProcessId);
	}

	DWORD CProcessFunctions::GetParentProcessIdNative(HANDLE hProcess)
	{
		PROCESS_BASIC_INFORMATION pPBI{ 0 };
		const auto ntStat = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), 0);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess fail! Target process: %p Status: %p", hProcess, ntStat);
			return 0UL;
		}

		return reinterpret_cast<DWORD>(pPBI.InheritedFromUniqueProcessId);
	}

	std::wstring CProcessFunctions::GetParentProcessName(DWORD dwCurrPID, bool bSilent)
	{
		std::wstring wstOutput;

		const auto dwParentPID = CProcessFunctions::GetProcessParentProcessId(dwCurrPID);
		if (!dwParentPID)
		{
			if (!bSilent)
			{
				APP_TRACE_LOG(LL_ERR, L"Parent PID not found! Last error: %u", g_winAPIs->GetLastError());
			}
			return wstOutput;
		}

		auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (!IS_VALID_SMART_PTR(processEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"processEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return wstOutput;
		}

		auto hProcess = processEnumerator->FindProcessFromPID(dwParentPID);

		processEnumerator.reset();

		if (!IS_VALID_HANDLE(hProcess))
		{
			if (!bSilent)
			{
				APP_TRACE_LOG(LL_ERR, L"Parent process not found on process list! PID: %u", dwParentPID);
			}

			hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwParentPID);
			if (!IS_VALID_HANDLE(hProcess))
			{
				const auto bIsAlive = CProcessFunctions::ProcessIsItAlive(dwParentPID);
				if (!bSilent)
				{
					APP_TRACE_LOG(LL_ERR, L"Parent process can not open! Last error: %u IsAlive: %d", g_winAPIs->GetLastError(), bIsAlive);
				}
				return wstOutput;
			}
		}

		const auto wstParentName = CProcessFunctions::GetProcessName(hProcess);
		if (wstParentName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Parent process name not found!");
			CWinAPIManager::Instance().SafeCloseHandle(hProcess);
			return wstOutput;
		}
		const auto wstLowerParentName = stdext::to_lower_wide(wstParentName);

		CWinAPIManager::Instance().SafeCloseHandle(hProcess);
		wstOutput = wstLowerParentName;
		return wstOutput;
	}

	std::wstring CProcessFunctions::DosDevicePath2LogicalPath(LPCWSTR lpwszDosPath)
	{
		std::wstring wstrResult;
		wchar_t wszTemp[MAX_PATH];
		wszTemp[0] = L'\0';

		if (!lpwszDosPath || !wcslen(lpwszDosPath) || !g_winAPIs->GetLogicalDriveStringsW(_countof(wszTemp) - 1, wszTemp))
			return wstrResult;

		wchar_t wszName[MAX_PATH];
		wchar_t wszDrive[3] = L" :";
		BOOL bFound = FALSE;
		wchar_t* p = wszTemp;

		do {
			// Copy the drive letter to the template string
			*wszDrive = *p;

			// Look up each device name
			if (g_winAPIs->QueryDosDeviceW(wszDrive, wszName, _countof(wszName)))
			{
				UINT uNameLen = (UINT)wcslen(wszName);

				if (uNameLen < MAX_PATH)
				{
					bFound = wcsncmp(lpwszDosPath, wszName, uNameLen) == 0;

					if (bFound) {
						// Reconstruct pszFilename using szTemp
						// Replace device path with DOS path
						wchar_t wszTempFile[MAX_PATH];
						swprintf_s(wszTempFile, xorstr_(L"%s%s"), wszDrive, lpwszDosPath + uNameLen);
						wstrResult = wszTempFile;
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		} while (!bFound && *p); // end of string

		return wstrResult;
	}

	bool CProcessFunctions::IsValidProcessHandle(HANDLE hProcess)
	{
		DWORD dwExitCode = 0;
		g_winAPIs->GetExitCodeProcess(hProcess, &dwExitCode);

		return dwExitCode == STILL_ACTIVE;
	}

	SModuleData CProcessFunctions::GetProcessBaseData(DWORD dwProcessId)
	{
		SModuleData pModuleData{ 0 };

		auto hSnapshot = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (!IS_VALID_HANDLE(hSnapshot))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot failed with error: %u", g_winAPIs->GetLastError());
			return pModuleData;
		}

		MODULEENTRY32W me32{ 0 };
		me32.dwSize = sizeof(me32);

		if (!g_winAPIs->Module32FirstW(hSnapshot, &me32))
		{
			APP_TRACE_LOG(LL_ERR, L"Module32First failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hSnapshot);
			return pModuleData;
		}

		pModuleData = { (ptr_t)me32.modBaseAddr, me32.modBaseSize };
		g_winAPIs->CloseHandle(hSnapshot);
		return pModuleData;
	}

	HMODULE CProcessFunctions::GetModuleHandle(DWORD dwProcessId, const std::wstring& wstModuleName)
	{
		HMODULE hModule = nullptr;

		auto hSnapshot = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (!IS_VALID_HANDLE(hSnapshot))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot failed for: %u (%s) with error: %u", dwProcessId, wstModuleName.c_str(), g_winAPIs->GetLastError());
			return hModule;
		}

		MODULEENTRY32W me{ 0 };
		me.dwSize = sizeof(me);

		if (!g_winAPIs->Module32FirstW(hSnapshot, &me))
		{
			APP_TRACE_LOG(LL_ERR, L"Module32First failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hSnapshot);
			return hModule;
		}

		if (wstModuleName.empty())
		{
			g_winAPIs->CloseHandle(hSnapshot);
			return me.hModule;
		}

		const auto wstTargetModuleName = stdext::to_lower_wide(wstModuleName);
		do
		{
			const auto wstCurrentModuleName = stdext::to_lower_wide(me.szModule);
			if (wstCurrentModuleName.find(wstTargetModuleName) != std::wstring::npos)
				return me.hModule;

			me.dwSize = sizeof(me);
			g_winAPIs->Sleep(10);
		} while (g_winAPIs->Module32NextW(hSnapshot, &me));

		g_winAPIs->CloseHandle(hSnapshot);
		return hModule;
	}

	bool CProcessFunctions::HasSuspendedThread(DWORD dwProcessId, bool bDumpThreads, bool bKillSuspendedThreads)
	{
		const auto threadEnumerator = stdext::make_unique_nothrow<CThreadEnumeratorNT>(dwProcessId);
		if (!IS_VALID_SMART_PTR(threadEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"threadEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto systemThreadOwnerProcInfo = (SYSTEM_PROCESS_INFORMATION*)threadEnumerator->GetProcInfo();
		if (!systemThreadOwnerProcInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"systemThreadOwnerProcInfo is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto dwThreadCount = threadEnumerator->GetThreadCount(systemThreadOwnerProcInfo);
		if (!dwThreadCount)
		{
			APP_TRACE_LOG(LL_ERR, L"dwThreadCount is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto pkThread = (SYSTEM_THREAD_INFORMATION*)threadEnumerator->GetThreadList(systemThreadOwnerProcInfo);
		if (!pkThread)
		{
			APP_TRACE_LOG(LL_ERR, L"pkThread is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_WARN, L"%u thread found!", dwThreadCount);

		for (std::size_t i = 0; i < dwThreadCount; i++)
		{
			const auto dwStartAddress = reinterpret_cast<DWORD_PTR>(pkThread->StartAddress);
			const auto dwThreadId = reinterpret_cast<DWORD_PTR>(pkThread->ClientId.UniqueThread);
			
			if (bDumpThreads)
			{
				const auto bIsMainThread = NoMercyCore::CApplication::Instance().DataInstance()->GetMainThreadId() == dwThreadId;

				wchar_t wszModuleName[MAX_PATH * 2]{ L'\0' };
				g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), pkThread->StartAddress, wszModuleName, _countof(wszModuleName));

				APP_TRACE_LOG(LL_SYS, L"[%u] IsMain:%d ID: %u State: %u Wait Reason: %u Start address: %p Module: %s",
					i, bIsMainThread ? 1 : 0, dwThreadId, pkThread->ThreadState, pkThread->WaitReason, dwStartAddress, wszModuleName
				);
			}

			if (pkThread->ThreadState == Waiting && pkThread->WaitReason == Suspended)
			{
				APP_TRACE_LOG(LL_ERR, L"Suspended thread found in process: %u Thread ID: %u", dwProcessId, dwThreadId);

				auto bContinue = false;
				if (bKillSuspendedThreads)
				{
					auto hThread = g_winAPIs->OpenThread(THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, dwThreadId);
					if (IS_VALID_HANDLE(hThread))
					{
						const auto bIsMainThread = NoMercyCore::CApplication::Instance().DataInstance()->GetMainThreadId() == dwThreadId;

						if (bIsMainThread)
						{
							NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ResumeThread(hThread, false);
							bContinue = true;
						}
						else
						{
							if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->TerminateThread(hThread, 0))
								bContinue = true;
						}

						g_winAPIs->CloseHandle(hThread);
					}
				}

				if (!bContinue)
					return true;
			}

			pkThread++;
			g_winAPIs->Sleep(10);
		}

		return false;
	};
	bool CProcessFunctions::IsThreadInProgress(DWORD dwProcessId, DWORD dwThreadId)
	{
		const auto threadEnumerator = stdext::make_unique_nothrow<CThreadEnumeratorNT>(dwProcessId);
		if (!IS_VALID_SMART_PTR(threadEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"threadEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto systemThreadOwnerProcInfo = (SYSTEM_PROCESS_INFORMATION*)threadEnumerator->GetProcInfo();
		if (!systemThreadOwnerProcInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"systemThreadOwnerProcInfo is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto dwThreadCount = threadEnumerator->GetThreadCount(systemThreadOwnerProcInfo);
		if (!dwThreadCount)
		{
			APP_TRACE_LOG(LL_ERR, L"dwThreadCount is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto pkThread = (SYSTEM_THREAD_INFORMATION*)threadEnumerator->GetThreadList(systemThreadOwnerProcInfo);
		if (!pkThread)
		{
			APP_TRACE_LOG(LL_ERR, L"pkThread is null! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_WARN, L"%u thread found!", dwThreadCount);

		for (std::size_t i = 0; i < dwThreadCount; i++)
		{
			const auto dwCurrThreadId = reinterpret_cast<DWORD_PTR>(pkThread->ClientId.UniqueThread);

			if (dwCurrThreadId == dwThreadId)
			{
				APP_TRACE_LOG(LL_WARN, L"#%u state: %u wait reason: %u", dwThreadId, pkThread->ThreadState, pkThread->WaitReason);

				if (pkThread->ThreadState == Running)
					return true;
			}

			pkThread++;
			g_winAPIs->Sleep(10);
		}

		return false;
	};

	std::wstring CProcessFunctions::ParentProcessName()
	{
		auto out = std::wstring(xorstr_(L"<unknown_parent>"));

		auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (!IS_VALID_SMART_PTR(processEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"processEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return out;
		}

		const auto dwParentPIDFromPEB = CProcessFunctions::GetParentProcessIdNative(NtCurrentProcess());
		auto hProcess = processEnumerator->FindProcessFromPID(dwParentPIDFromPEB);
		
		processEnumerator.reset();

		if (!IS_VALID_HANDLE(hProcess)) 
		{
			hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentPIDFromPEB);
			if (!IS_VALID_HANDLE(hProcess))
			{
				const auto bIsAlive = CProcessFunctions::ProcessIsItAlive(dwParentPIDFromPEB);
				APP_TRACE_LOG(LL_ERR, L"Parent process can not open! Last error: %u IsAlive: %d", g_winAPIs->GetLastError(), bIsAlive);
				return out;
			}
		}

		const auto stName = CProcessFunctions::GetProcessName(hProcess);
		if (stName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Parent process name not found!");
		}
		else
		{
			out = stName;
		}

		CWinAPIManager::Instance().SafeCloseHandle(hProcess);
		return out;
	}

	bool CProcessFunctions::EnumerateProcessesNative(std::function<void(std::wstring, DWORD, PVOID)> fnCallback)
	{
		auto ntStat = NTSTATUS(0x0);

		auto dwProcessInfoSize = 2000UL;
		auto pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)CMemHelper::Allocate(dwProcessInfoSize);

		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwProcessInfoSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwProcessInfoSize *= 2;
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)CMemHelper::ReAlloc(pProcessInfo, dwProcessInfoSize);
		}

		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQuerySystemInformation failed with status: %p", ntStat);

			CMemHelper::Free(pProcessInfo);
			return false;
		}

		auto pIterator = pProcessInfo;
		while (pIterator->NextEntryOffset)
		{
			if (fnCallback)
			{
				fnCallback(
					std::wstring(pIterator->ImageName.Buffer, pIterator->ImageName.Length),
					(DWORD)pIterator->UniqueProcessId,
					pIterator
				);
			}
			
			if (pIterator->NextEntryOffset == 0)
				break;

			pIterator = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pIterator + pIterator->NextEntryOffset);
		}

		CMemHelper::Free(pProcessInfo);
		return true;
	}

	uint64_t CProcessFunctions::GetProcessCreationTime(HANDLE hProcess)
	{
		static constexpr auto UNIX_TIME_START = 0x019DB1DED53E8000; // January 1, 1970 (start of Unix epoch) in "ticks"
		static constexpr auto TICKS_PER_SECOND = 10000000; // a tick is 100ns
		
		FILETIME nCreationTime{};
		FILETIME nExitTime{};
		FILETIME nKernelTime{};
		FILETIME nUserTime{};

		if (!g_winAPIs->GetProcessTimes(hProcess, &nCreationTime, &nExitTime, &nKernelTime, &nUserTime))
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcessTimes failed with error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		LARGE_INTEGER nTime{};
		nTime.LowPart = nCreationTime.dwLowDateTime;
		nTime.HighPart = nCreationTime.dwHighDateTime;

		return (nTime.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND;
	}
};
