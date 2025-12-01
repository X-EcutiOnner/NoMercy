#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../../Common/IconHelper.hpp"
#include <shellapi.h>




namespace NoMercy
{
	struct SProcEnumInfo
	{
		DWORD dwProcessId;
		wchar_t wszProcessName[MAX_PATH];
	};

	std::vector < std::shared_ptr <SProcEnumInfo> > ListProcessesM1()
	{
		auto vOutput = std::vector<std::shared_ptr<SProcEnumInfo>>();
		auto dwProcessInfoSize = 2000UL;
		auto ntStat = NTSTATUS(0x0);

		auto pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwProcessInfoSize);
		ZeroMemory(pProcessInfo, dwProcessInfoSize);

		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemExtendedProcessInformation, pProcessInfo, dwProcessInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwProcessInfoSize *= 2;
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)realloc(pProcessInfo, dwProcessInfoSize);
		}

		if (!NT_SUCCESS(ntStat))
		{
			SCANNER_LOG(LL_ERR, L"NtQuerySystemInformation failed! Error code: %u Ntstatus: %u", g_winAPIs->GetLastError(), ntStat);

			free(pProcessInfo);
			return vOutput;
		}

		auto pIterator = pProcessInfo;
		while (pIterator->NextEntryOffset)
		{
			auto pCurrProc = stdext::make_shared_nothrow<SProcEnumInfo>();
			if (IS_VALID_SMART_PTR(pCurrProc))
			{
				pCurrProc->dwProcessId = (DWORD)pIterator->UniqueProcessId;
				if (pIterator->ImageName.Buffer && pIterator->ImageName.Length)
					wcsncpy(pCurrProc->wszProcessName, pIterator->ImageName.Buffer, pIterator->ImageName.Length);

				vOutput.emplace_back(pCurrProc);
			}

			if (pIterator->NextEntryOffset == 0)
				break;

			pIterator = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pIterator + pIterator->NextEntryOffset);
		}

		free(pProcessInfo);
		return vOutput;
	}

	std::vector < std::shared_ptr <SProcEnumInfo> > ListProcessesM2()
	{
#if 0
		auto vOutput = std::vector<std::shared_ptr<SProcEnumInfo>>();

		PVOID pvBuffer = nullptr;
		const auto ret = g_winAPIs->WinStationEnumerateProcesses(NULL, &pvBuffer);
		if (!ret || !pvBuffer)
		{
			SCANNER_LOG(LL_ERR, L"WinStationEnumerateProcesses failed! Error code: %u", g_winAPIs->GetLastError());
			return vOutput;
		}
		auto pIterator = (PTS_SYS_PROCESS_INFORMATION)pvBuffer;

		while (true)
		{
			auto pCurrProc = stdext::make_shared_nothrow<SProcEnumInfo>();
			if (IS_VALID_SMART_PTR(pCurrProc))
			{
				pCurrProc->dwProcessId = (DWORD)pIterator->UniqueProcessId;
				if (pIterator->ImageName.Buffer && pIterator->ImageName.Length)
					wcsncpy(pCurrProc->wszProcessName, pIterator->ImageName.Buffer, pIterator->ImageName.Length);

				vOutput.emplace_back(pCurrProc);
			}

			if (pIterator->NextEntryOffset == 0)
				break;

			pvBuffer = (PTS_SYS_PROCESS_INFORMATION)(((LPBYTE)pvBuffer) + pIterator->NextEntryOffset);
		}
		g_winAPIs->LocalFree(pIterator);

		return vOutput;
#endif
		auto vOutput = std::vector<std::shared_ptr<SProcEnumInfo>>();
		auto dwProcessInfoSize = 2000UL;
		auto ntStat = NTSTATUS(0x0);

		auto pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(dwProcessInfoSize);
		ZeroMemory(pProcessInfo, dwProcessInfoSize);

		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwProcessInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwProcessInfoSize *= 2;
			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)realloc(pProcessInfo, dwProcessInfoSize);
		}

		if (!NT_SUCCESS(ntStat))
		{
			SCANNER_LOG(LL_ERR, L"NtQuerySystemInformation failed! Error code: %u Ntstatus: %u", g_winAPIs->GetLastError(), ntStat);

			free(pProcessInfo);
			return vOutput;
		}

		auto pIterator = pProcessInfo;
		while (pIterator->NextEntryOffset)
		{
			auto pCurrProc = stdext::make_shared_nothrow<SProcEnumInfo>();
			if (IS_VALID_SMART_PTR(pCurrProc))
			{
				pCurrProc->dwProcessId = (DWORD)pIterator->UniqueProcessId;
				if (pIterator->ImageName.Buffer && pIterator->ImageName.Length)
					wcsncpy(pCurrProc->wszProcessName, pIterator->ImageName.Buffer, pIterator->ImageName.Length);

				vOutput.emplace_back(pCurrProc);
			}

			if (pIterator->NextEntryOffset == 0)
				break;

			pIterator = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pIterator + pIterator->NextEntryOffset);
		}

		free(pProcessInfo);
		return vOutput;
	}

	std::vector < std::shared_ptr <SProcEnumInfo> > GetDifferentProcessList()
	{
		auto vOutput = std::vector<std::shared_ptr<SProcEnumInfo>>();

		auto pProcessList1 = ListProcessesM1();
		if (pProcessList1.empty())
			return vOutput;

		auto pProcessList2 = ListProcessesM2();
		if (pProcessList2.empty())
			return vOutput;

		std::sort(pProcessList1.begin(), pProcessList1.end());
		std::sort(pProcessList2.begin(), pProcessList2.end());

		auto vDifferentProcessIds = std::vector <std::shared_ptr <SProcEnumInfo> >();
		std::set_intersection
		(
			pProcessList1.begin(), pProcessList1.end(),
			pProcessList2.begin(), pProcessList2.end(),
			std::back_inserter(vDifferentProcessIds)
		);

		return vDifferentProcessIds;
	}

	// ----------------------------------------------------------------------


	std::vector <std::wstring> GetIconHashList(const std::wstring& szTargetProcess)
	{
		auto vIconList = std::vector<std::wstring>();

		HICON hIconLarge;
		HICON hIconSmall;

		int nIconCount = (int)g_winAPIs->ExtractIconExW(szTargetProcess.c_str(), -1, NULL, NULL, 0);
		for (auto t = 0; t < nIconCount; t++)
		{
			if (g_winAPIs->ExtractIconExW(szTargetProcess.c_str(), t, &hIconLarge, &hIconSmall, 1) == 0)
			{
				SCANNER_LOG(LL_ERR, L"ExtractIconExA fail! Error: %u", g_winAPIs->GetLastError());
				continue;
			}

			auto szTempFileName = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->CreateTempFileName(xorstr_(L"gdic"));
			SCANNER_LOG(LL_SYS, L"Temp file created! File: %s", szTempFileName.c_str());

			if (SaveIcon(szTempFileName.c_str(), &hIconSmall, 1) == 0)
			{
				SCANNER_LOG(LL_ERR, L"SaveIcon fail! Last Error: %u", g_winAPIs->GetLastError());

				g_winAPIs->DestroyIcon(hIconLarge);
				g_winAPIs->DestroyIcon(hIconSmall);
				continue;
			}

			auto szHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA256(szTempFileName);
			if (szHash.empty())
			{
				if (g_winAPIs->GetLastError() != ERROR_RESOURCE_TYPE_NOT_FOUND)
				{
					SCANNER_LOG(LL_ERR, L"Hash can NOT created! Last Error: %u", g_winAPIs->GetLastError());
				}

				g_winAPIs->DestroyIcon(hIconLarge);
				g_winAPIs->DestroyIcon(hIconSmall);
				continue;
			}
			vIconList.emplace_back(szHash);

			g_winAPIs->DestroyIcon(hIconLarge);
			g_winAPIs->DestroyIcon(hIconSmall);
			g_winAPIs->DeleteFileW(szTempFileName.c_str());
		}

		return vIconList;
	}

	static bool CheckProcessIconHash(HANDLE hProcess)
	{
		auto stProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (stProcessName.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}
		// SCANNER_LOG(LL_SYS, L"Process image name: %s", stProcessName.c_str());

		auto vIconHashList = GetIconHashList(stProcessName);
		if (vIconHashList.empty())
		{
#if 0
			if (g_winAPIs->GetLastError() != ERROR_RESOURCE_TYPE_NOT_FOUND)
			{
				SCANNER_LOG(LL_ERR, L"GetIconHashList failed with error: %u", g_winAPIs->GetLastError());
			}
#endif
			return false;
		}
		SCANNER_LOG(LL_TRACE, L"Process icon hash list created! Size: %u", vIconHashList.size());

		for (const auto& szCurrHash : vIconHashList)
		{
			//SCANNER_LOG(LL_TRACE, "Icon hash: %s", szCurrHash.c_str());
			// TODO: CApplication::Instance().QuarentineInstance()->CheckProcessIconHash(szProcessName, szCurrHash);
		}
		return true;
	}

	static bool CheckProcessBase(HANDLE hProcess)
	{
		// TODO: Forward to process helper class funcs
		return true;
#if 0
		SCANNER_LOG(LL_SYS, L"Process base check routine has been started!");

		BYTE pBaseMem[12] = { 0 };
		DWORD_PTR dwImageBase = 0;

		auto process_base_scan_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_(L"ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				SCANNER_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return false;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_(L"NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return false;
			}

			NTSTATUS ntStat = 0;
			ULONG64 ul64ReadBytes = 0;

			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pPBI = { 0 };
			ntStat = g_winAPIs->NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtWow64QueryInformationProcess64(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (!pPBI.PebBaseAddress)
			{
				SCANNER_LOG(LL_ERR, L"pPBI.PebBaseAddress is null");
				return false;
			}

			wow64pp::defs::PEB_64 pPEB = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat) || ul64ReadBytes != sizeof(pBaseMem))
			{
				SCANNER_LOG(LL_WARN, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			auto nullBuff = { 0x0 };
			if (!memcmp(&pPEB, &nullBuff, sizeof(pPEB)))
			{
				SCANNER_LOG(LL_ERR, L"pPEB is null");
				return false;
			}

			dwImageBase = (DWORD_PTR)pPEB.ImageBaseAddress;
			if (!dwImageBase)
			{
				SCANNER_LOG(LL_ERR, L"Process base not found! Target process: %p", hProcess);
				return false;
			}
			SCANNER_LOG(LL_SYS, L"Process image base: %p", dwImageBase);

			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, dwImageBase, &pBaseMem, sizeof(pBaseMem), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat) || ul64ReadBytes != sizeof(pBaseMem))
			{
				SCANNER_LOG(LL_ERR, L"Process base read fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}
			return true;
		};
		auto process_base_scan_native = [&] {
			NTSTATUS ntStat = 0;
			SIZE_T ulReadBytes = 0;

			PROCESS_BASIC_INFORMATION pPBI = { 0 };
			ntStat = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtQueryInformationProcess(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (!pPBI.PebBaseAddress)
			{
				SCANNER_LOG(LL_ERR, L"pPBI.PebBaseAddress is null");
				return false;
			}

			PEB pPEB = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ulReadBytes);
			if (!NT_SUCCESS(ntStat) || ulReadBytes != sizeof(pBaseMem))
			{
				SCANNER_LOG(LL_WARN, L"NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			auto nullBuff = { 0x0 };
			if (!memcmp(&pPEB, &nullBuff, sizeof(pPEB)))
			{
				SCANNER_LOG(LL_ERR, L"pPEB is null");
				return false;
			}

			dwImageBase = (DWORD_PTR)pPEB.ImageBaseAddress;
			if (!dwImageBase)
			{
				SCANNER_LOG(LL_ERR, L"Process base not found! Target process: %p", hProcess);
				return false;
			}
			SCANNER_LOG(LL_SYS, L"Process image base: %p", dwImageBase);

			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)dwImageBase, &pBaseMem, sizeof(pBaseMem), &ulReadBytes);
			if (!NT_SUCCESS(ntStat) || ulReadBytes != sizeof(pBaseMem))
			{
				SCANNER_LOG(LL_ERR, L"Process base read fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			return true;
		};

		auto bRet = false;
		const auto is_wow64 = CApplication::Instance().FunctionsInstance()->IsWow64Process(NtCurrentProcess());
		if (is_wow64)
			bRet = process_base_scan_wow64();
		else
			bRet = process_base_scan_native();

		if (!bRet)
			return false;

		const auto stMemDump = stdext::dump_hex(pBaseMem, 12);
		SCANNER_LOG(LL_SYS, L"Process image base: %p data: %s", dwImageBase, stMemDump.c_str());

		char szImageName[MAX_PATH]{ 0 };
		if (g_winAPIs->GetProcessImageFileNameA(hProcess, szImageName, MAX_PATH) <= 0)
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, GetLastError());
			return false;
		}
		SCANNER_LOG(LL_SYS, L"Process image name: %s", szImageName);

		// TODO CApplication::Instance().QuarentineInstance()->CheckProcessBaseMem(szImageName, (PVOID64)pImageBase, pBaseMem);
		return true;
#endif
	}


	IProcessScanner::IProcessScanner()
	{
//#ifdef __EXPERIMENTAL__
		// create parallel executor
		m_upTaskExecutor = stdext::make_unique_nothrow<tf::Executor>();

		// create a default observer
		m_upTaskExecutor->make_observer<STFScannerObserver>(xorstr_(L"ProcScannerObserver"));
//#endif
	}
	IProcessScanner::~IProcessScanner()
	{
	}

	bool IProcessScanner::IsScanned(DWORD dwProcessId)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_PROCESS, std::to_wstring(dwProcessId));
	}

	void IProcessScanner::AddScanned(DWORD dwProcessId)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_PROCESS, std::to_wstring(dwProcessId));
	}
	
	void IProcessScanner::OnScanTerminatedProcess(HANDLE hProcess)
	{
		if (!IS_VALID_HANDLE(hProcess) || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
			return;

		const auto dwProcessId = g_winAPIs->GetProcessId(hProcess);
		if (!dwProcessId)
			return;

		if (IsScanned(dwProcessId))
			return;

		SCANNER_LOG(LL_SYS, L"Target process id: %u", dwProcessId);

		// Add to checked list
		AddScanned(dwProcessId);

		// Quick filter for system process
		if (dwProcessId <= 4)
		{
			SCANNER_LOG(LL_SYS, L"System process scan passed!");
			return;
		}

		// Check target pid is it our pid
		if (g_winAPIs->GetCurrentProcessId() == dwProcessId)
		{
			SCANNER_LOG(LL_SYS, L"Itself scan passed!");
			return;
		}

		// Check icon hash
		CheckProcessIconHash(hProcess);

		// Forard to file scan for process file
		CApplication::Instance().ScannerInstance()->FileScanner()->ScanProcessFile(hProcess, FILE_SCAN_TYPE_TERMINATED_PROCESS);

		return;
	}

	void IProcessScanner::ScanSync(DWORD dwProcessId)
	{
		SCANNER_LOG(LL_SYS, L"Process scanner has been started! Target process id: %u", dwProcessId);

		if (IsScanned(dwProcessId))
		{
			SCANNER_LOG(LL_WARN, L"Process: %u already scanned!", dwProcessId);
			return;
		}

		// Add to checked list
		AddScanned(dwProcessId);

		// Quick filter for system process
		if (dwProcessId <= 4) // IDLE & System
		{
			SCANNER_LOG(LL_WARN, L"System process scan passed!");
			return;
		}

		// Check target pid is it our pid
		if (g_winAPIs->GetCurrentProcessId() == dwProcessId)
		{
			SCANNER_LOG(LL_WARN, L"Itself scan passed!");
			return;
		}

		/*
		// Query process SID
		DWORD dwSessionID = 0;
		if (!g_winAPIs->ProcessIdToSessionId(dwProcessId, &dwSessionID) || !dwSessionID)
		{
			SCANNER_LOG(LL_ERR, L"ProcessIdToSessionId (%u) failed with error: %u", dwProcessId, g_winAPIs->GetLastError());
			return;
		}

		// Check target process SID
		if (dwSessionID != CApplication::Instance().GetCurrentProcessSID())
		{
			SCANNER_LOG(LL_SYS, L"Current process working on different session: %u", dwSessionID);
			return;
		}
		*/

		const auto stProcessBaseName = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);
		const auto stParentName = CProcessFunctions::GetParentProcessName(dwProcessId, true);
		SCANNER_LOG(LL_SYS, L"Process: %u Name: %s Parent: %s", dwProcessId, stProcessBaseName.c_str(), stParentName.c_str());

		if (stProcessBaseName.empty())
		{
			// SCANNER_LOG(LL_ERR, L"Process: %u base name is empty!", dwProcessId); // Probably dead process
			return;
		}

		// Quick check target protection
		auto hProcessLitePtr = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, dwProcessId);
		if (!IS_VALID_HANDLE(hProcessLitePtr))
		{
			hProcessLitePtr = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, dwProcessId);
			if (!IS_VALID_HANDLE(hProcessLitePtr))
			{
				const auto wstCurrProcName = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeName());
				const auto wstTargetProcName = stdext::to_lower_wide(stProcessBaseName);
				if (wstCurrProcName == wstTargetProcName)
				{
					SCANNER_LOG(LL_WARN, L"Target process: %u is itself! Last error: %u", dwProcessId, g_winAPIs->GetLastError());
					return;
				}

				const auto dwErr = g_winAPIs->GetLastError();
				const auto bForceCheck = CProcessFunctions::ProcessIsItAlive(dwProcessId);
				SCANNER_LOG(LL_ERR, L"Target process: %u is not alive! Last error: %u Force ret: %d", dwProcessId, dwErr, bForceCheck ? 1 : 0);

				auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(SYNCHRONIZE | PROCESS_QUERY_INFORMATION);
				if (IS_VALID_SMART_PTR(processEnumerator))
				{
					hProcessLitePtr = processEnumerator->FindProcessFromPID(dwProcessId);

					processEnumerator.reset();
				}

				if (!IS_VALID_HANDLE(hProcessLitePtr) && bForceCheck)
				{
					// Debug priv non-assigned system cannot access to system processes, block allowing to STATUS_PRIVILEGE_NOT_HELD in SeDebugPrivilege funcs or creae whitelist
					/*
					wmiprvse.exe
					mousocoreworker.exe
					tiworker.exe
					trustedinstaller.exe
					svchost.exe
					trustedinstaller.exe
					gamingservicesnet.exe
					gamingservices.exe
					sppsvc.exe
					*/

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_PROCESS_SCAN, PROCESS_SCAN_HEAVY_PROTECTED_PROCESS, stProcessBaseName);
				}

				return;
			}
		}
		
		const auto stProcessFullName = CProcessFunctions::GetProcessName(hProcessLitePtr);
		if (stProcessFullName.empty())
		{
			if (stProcessFullName.empty() || (!stProcessFullName.empty() && !NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(stProcessFullName)))
			{
				// TODO: Extra check for SID
				const auto lstWhitelistedProcesses = std::vector <std::wstring> {
					xorstr_(L"system"),
					xorstr_(L"secure system"),
					xorstr_(L"registry"),
					xorstr_(L"memory compression"),
					xorstr_(L"hotpatch")
				};
				if (!stdext::in_vector(lstWhitelistedProcesses, stProcessBaseName))
				{
					auto bSkip = false;

					// Check for docker processess
					if (stdext::starts_with(stProcessBaseName, std::wstring(xorstr_(L"vmmem"))) &&
						stProcessBaseName.find(xorstr_(L".")) == std::wstring::npos)
					{
						bSkip = true;
					}

					if (!bSkip)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_PROCESS_SCAN, PROCESS_SCAN_GET_LITE_DATA_FAIL, stProcessBaseName);
						return;
					}
				}
			}
		}

		static const auto bIsWow64 = stdext::is_wow64();
		if (bIsWow64 && !CApplication::Instance().FunctionsInstance()->IsWow64Process(hProcessLitePtr))
		{
			APP_TRACE_LOG(LL_WARN, L"Skipped WoW64 process: %u", dwProcessId);
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcessLitePtr);
			return;
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcessLitePtr);

		/*
			HANDLE process_handle = OpenProcess(MAXIMUM_ALLOWED, FALSE, m_ProcessId);

	if (!process_handle)
		process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, m_ProcessId);

	if (!process_handle)
		process_handle = OpenProcess(PROCESS_ACCESS_WIN10_XXX, FALSE, m_ProcessId);

	if (!process_handle)
		process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_ProcessId);

	if (!process_handle)
		return;
		*/

		// Open target process, At the first from user, if fails try than kernel
		auto hProcess = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, dwProcessId
		);
		if (!IS_VALID_HANDLE(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Handle could NOT created from user land for target process: %u! Error: %u", dwProcessId, g_winAPIs->GetLastError());
			return;
		}

		// Check executable name
		const auto wstProcessName = CProcessFunctions::GetProcessName(hProcess);
		const auto stProcessPath = !wstProcessName.empty() ? NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetPathFromProcessName(wstProcessName) : L"";
		SCANNER_LOG(LL_SYS, L"Handle: %p created for target process: %u (%s)", hProcess, dwProcessId, wstProcessName.c_str());


		auto bRet = false;

		const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstProcessName.c_str());
		if (obHasCert.has_value() && !obHasCert.value()
#ifdef _DEBUG
			&& wstProcessName.find(xorstr_(L"nomercy")) == std::wstring::npos
#endif
		){
			// Decrease debug priv of target process
			bRet = CApplication::Instance().AccessHelperInstance()->RemoveProcessDebugPriv(dwProcessId, hProcess);
			SCANNER_LOG(bRet ? LL_SYS : LL_ERR, L"Decrease debug access completed! Result: %d", bRet);
		}
		else if (!obHasCert.has_value())
		{
			SCANNER_LOG(LL_ERR, L"Could NOT check certificate for target process: %u! Error: %u", dwProcessId, g_winAPIs->GetLastError());
		}

		// Scan routine
		tf::Taskflow tf(fmt::format(xorstr_("tf_proc_scanner_{0}"), dwProcessId));

		// Add scanners
		tf.emplace([&]() {
			const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->GetBlacklist();
			if (!vecBlacklist.empty())
			{
				for (const auto& [obj, opts] : vecBlacklist)
				{
					if (obj.pattern.empty() || obj.mask.empty())
						continue;

					const auto nPatternType = obj.pattern_type;
					const auto stPattern = obj.pattern;
					const auto stMask = obj.mask;

					CApplication::Instance().ScannerInstance()->CDB_IsPatternExistInAllProcesses(
						SCDBBaseContext{
							obj.idx - sc_nCheatDBBlacklistIDBase,
							obj.id,
							true,
							true
						},
						stPattern, stMask, std::to_wstring(nPatternType), dwProcessId
					);
				}
			}

		}).name(xorstr_("proc_pattern"));
#ifdef __EXPERIMENTAL__
		tf.emplace([&]() { CheckProcessBase(hProcess); }).name(xorstr_("proc_base"));
		tf.emplace([&]() { CheckProcessIconHash(hProcess); }).name(xorstr_("proc_icon"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->CheckProcessHollow(hProcess); }).name(xorstr_("proc_hollow"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->FileScanner()->ScanProcessFile(hProcess, FILE_SCAN_TYPE_PROCESS); }).name(xorstr_("proc_file"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->ModuleScanner()->ScanProcessModules(hProcess);  }).name(xorstr_("proc_module"));
		// tf.emplace([&]() { CApplication::Instance().ScannerInstance()->SectionScanner()->ScanProcessSections(hProcess); }).name(xorstr_("proc_section")); // heavy asf
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->ThreadScanner()->ScanProcessThreads(hProcess);  }).name(xorstr_("proc_thread"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->HeapScanner()->ScanProcessHeaps(hProcess); }).name(xorstr_("proc_heap"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->WindowScanner()->ScanProcessWindows(hProcess);  }).name(xorstr_("proc_window"));
		tf.emplace([&]() { CApplication::Instance().ScannerInstance()->CheckProcessShim(hProcess); }).name(xorstr_("proc_shim"));
		if (!stProcessPath.empty())
			tf.emplace([&]() { CApplication::Instance().ScannerInstance()->FolderScanner()->ScanAsync(stProcessPath); }).name(xorstr_("proc_folder"));
#endif

		// run the taskflow
		if (IS_VALID_SMART_PTR(m_upTaskExecutor))
		{
			m_upTaskExecutor->run(tf).get();
		}

		// Drop created handle
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);
		return;
	}

	bool IProcessScanner::ScanAll()
	{
		SCANNER_LOG(LL_SYS, L"Process scanner routine started!");

		// Check SystemExtendedProcessInformation and SystemProcessInformation and compare both of them
		auto vDifferentProcesses = GetDifferentProcessList();
		if (vDifferentProcesses.empty() == false)
		{
			SCANNER_LOG(LL_ERR, L"Unknown process(es) found! Size: %u", vDifferentProcesses.size());

			for (auto& pCurrProc : vDifferentProcesses)
			{
				const auto stProcessName = CProcessFunctions::GetProcessNameFromProcessId(pCurrProc->dwProcessId);
				SCANNER_LOG(LL_CRI, L"Unlinked process found: %u (%s)", pCurrProc->dwProcessId, stProcessName.c_str());

				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_PROCESS_SCAN, PROCESS_SCAN_DIFFERENT_PROCESS_ID, stProcessName);
			}
		}

		// List processes
		auto vProcesses = ListProcessesM1();
		if (vProcesses.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process enumeration failed!");
			return false;
		}

		// Scan processes
		for (auto& pCurrProc : vProcesses)
		{
			if (IS_VALID_SMART_PTR(pCurrProc))
			{
				this->ScanAsync(pCurrProc->dwProcessId);
			}
		}

		// Over scan for scan terminated processes with NtGetNextProcess
		auto upProcessEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (!IS_VALID_SMART_PTR(upProcessEnumerator))
		{
			SCANNER_LOG(LL_ERR, L"Process enumerator allocation failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto vTerminatedProcesses = upProcessEnumerator->EnumerateProcesses(false);
		if (vTerminatedProcesses.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process enumeration part2 failed!");
			upProcessEnumerator.reset();
			return false;
		}

		for (auto hCurrProc : vTerminatedProcesses)
		{
			if (IS_VALID_HANDLE(hCurrProc))
			{
				auto dwExitCode = 0UL;
				if (!g_winAPIs->GetExitCodeProcess(hCurrProc, &dwExitCode) || dwExitCode != STILL_ACTIVE)
				{
					this->OnScanTerminatedProcess(hCurrProc);
				}
			}
		}
		
		upProcessEnumerator.reset();
		return true;
	}
};
