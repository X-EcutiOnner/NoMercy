#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Anti/AntiDebug.hpp"
#include "../Anti/AntiBreakpoint.hpp"
#include "../SelfProtection/SelfProtection.hpp"
#include "../Thread/ThreadStackWalker.hpp"
#include "../../EngineR3_Core/include/Elevation.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
#pragma region ExternValidateFuncs
	extern bool ValidateAddressInImage(LPVOID lpAddress, LPVOID& lpBaseAddress);
	extern bool ValidateTextExecution(LPVOID lpAddress, LPVOID lpBaseAddress);
	extern bool ValidateImageSection(LPVOID lpBaseAddress, PHANDLE phFile);
	extern bool ValidateMatchesFile(HANDLE hFile, LPVOID lpBaseAddress);
	extern bool ValidateFile(HANDLE hFile);
	extern bool ValidateLoader(LPVOID lpBaseAddress, HANDLE hFile);
	extern bool ValidateThreadAddress(LPVOID lpAddress);
	extern bool ValidateInstructionPointer(LPVOID lpInstrPtr);
	extern bool ValidateThradeFrames();
	extern bool ValidateWow32ReservedIntegrity(HANDLE hThread);
#pragma endregion ExternValidateFuncs

	bool ThawProcess(DWORD dwProcessID)
	{
		if (!IsWindows11OrGreater())
			return true;
		
		auto bRet = false;
		HANDLE hProcess = nullptr;
		HANDLE hState = nullptr;
		
		do
		{
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, NULL, OBJ_EXCLUSIVE, NULL, NULL);
			
			hProcess = g_winAPIs->OpenProcess(PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, dwProcessID);
			if (!hProcess)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to open process with ID: %u error: %u", dwProcessID, g_winAPIs->GetLastError());
				break;
			}
			
			auto ntStatus = g_winAPIs->NtCreateProcessStateChange(&hState, STATECHANGE_SET_ATTRIBUTES, &oa, hProcess, 0);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to create process state change object for process with ID: %u error: %p", dwProcessID, ntStatus);
				break;
			}
			
			ntStatus = g_winAPIs->NtChangeProcessState(hState, hProcess, ProcessStateChangeResume, NULL, 0, 0);
			if (!NT_SUCCESS(ntStatus))
			{
#ifdef _DEBUG
				const auto nLevel = LL_ERR;
#else
				const auto nLevel = STATUS_INVALID_PARAMETER == ntStatus ? LL_TRACE : LL_ERR;
#endif
				APP_TRACE_LOG(nLevel, L"Failed to resume process with ID: %u error: %p", dwProcessID, ntStatus);
				break;
			}

			bRet = true;
		} while (FALSE);

		if (IS_VALID_HANDLE(hProcess))
		{
			g_winAPIs->CloseHandle(hProcess);
			hProcess = nullptr;
		}
		if (IS_VALID_HANDLE(hState))
		{
			g_winAPIs->CloseHandle(hState);
			hState = nullptr;
		}
		
		return bRet;
	}

	DWORD GetCurrentTimestampRemoteSec()
	{
		const auto res = cpr::Get(
			cpr::Url{ xorstr_("http://worldtimeapi.org/api/timezone/UTC") },
			cpr::ConnectTimeout{ 2000 },
			cpr::Timeout{ 2000 }
		);
		if (res.error.code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_WARN, L"Failed to get time: %hs(%d)", res.error.message.c_str(), res.error.code);
		}
		else if (res.status_code != 200)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get time: %d", res.status_code);
		}
		else if (!stdext::starts_with(stdext::to_wide(res.text), std::wstring(xorstr_(L"{"))) ||
				 !stdext::ends_with(stdext::to_wide(res.text),   std::wstring(xorstr_(L"}"))))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get time: invalid response (%hs)", res.text.c_str());
		}
		else
		{
			// APP_TRACE_LOG(LL_SYS, L"Current time: %hs", res.text.c_str());

			auto document = rapidjson::Document{};
			document.Parse<kParseCommentsFlag>(res.text);
			if (document.HasParseError())
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to parse time: %hs", rapidjson::GetParseError_En(document.GetParseError()));
			}
			else
			{
				if (!document.IsObject())
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to parse time: root is not an object: %hs", res.text.c_str());
				}
				else
				{
					if (!document.HasMember(xorstr_("unixtime")))
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to parse time: unixtime does not exist: %hs", res.text.c_str());
					}
					else
					{
						const auto& unixtime = document[xorstr_("unixtime")];
						if (!unixtime.IsNumber())
						{
							APP_TRACE_LOG(LL_ERR, L"Failed to parse time: unixtime is not a number: %hs", res.text.c_str());
						}
						else
						{
							const auto dwTimestamp = unixtime.GetUint();
							// APP_TRACE_LOG(LL_SYS, L"Current time: %u", dwTimestamp);

							return dwTimestamp;
						}
					}
				}
			}
		}
		return 0;
	}

	DWORD WINAPI NoMercyClientMainRoutine(LPVOID)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		static auto s_iIdx = 0ULL;
		APP_TRACE_LOG(LL_SYS, L"[CMR] #%lld Main routine works!", s_iIdx++);
#endif

		const auto dwIntegrityLevel = CElevationHelper::GetIntegrityLevel(NtCurrentProcess());
		if (dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
		{
			APP_TRACE_LOG(LL_CRI, L"Integrity level has lowest privilege: %u than system level: %u", dwIntegrityLevel, SECURITY_MANDATORY_SYSTEM_RID);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CLIENT_INTEGRITY_LEVEL_CHECK_FAIL, g_winAPIs->GetLastError());
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Integrity level: %u", dwIntegrityLevel);
#endif

		if (CApplication::Instance().AccessHelperInstance()->EnableDebugPrivileges() == false)
		{
			APP_TRACE_LOG(LL_CRI, L"Debug priv can NOT assigned!");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_DEBUG_PRIV_ASSIGN_FAIL, g_winAPIs->GetLastError());
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Debug priv assigned!");
#endif
		
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		auto dwDebugDetectType = 0UL;
		if (CAntiDebug::CheckRuntimeAntiDebug(&dwDebugDetectType))
		{
			APP_TRACE_LOG(LL_CRI, L"Runtime debugging detected! Error step: %u", dwDebugDetectType);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_RUNTIME_DEBUGGER_DETECT, dwDebugDetectType);
		}
#endif

		if (CSelfProtection::IsDumpTriggered())
		{
			APP_TRACE_LOG(LL_CRI, L"Memory dump detected");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_MEMORY_DUMP_DETECT, 0);
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Memory dump check completed!");
#endif

		CApplication::Instance().ScannerInstance()->CheckMemoryWatchdogs(NtCurrentProcess());
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Memory watchdog check completed!");
#endif

		if (CApplication::Instance().SelfHooksInstance()->IsHookIntegrityCorrupted())
		{
			APP_TRACE_LOG(LL_ERR, L"Hook integrity corrupted");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_INTEGRITY_CORRUPT, 0);
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Hook integrity check completed!");
#endif

//#ifdef __EXPERIMENTAL__
		if (!CApplication::Instance().HwbpWatcherInstance()->ValidateHwbpTrap())
		{
			APP_TRACE_LOG(LL_CRI, L"HWBP trap integrity corrupted");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_INTEGRITY_CORRUPT, 0);
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] HWBP trap integrity check completed!");
#endif
//#endif

#if 0 // DISABLED due to high time consumption
		// Check game clones
		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			for (auto hProc : upProcEnumerator->EnumerateProcesses(true))
			{
				if (IS_VALID_HANDLE(hProc) && NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProc))
				{
					auto dwNowTimestamp = stdext::get_current_epoch_time();
					if (dwNowTimestamp)
					{
						const auto dwCreateTime = static_cast<uint32_t>(CProcessFunctions::GetProcessCreationTime(hProc));
						const auto dwCurrProcID = CProcessFunctions::GetProcessIdNative(hProc);
						const auto dwParentProcID = CProcessFunctions::GetParentProcessIdNative(hProc);

						const auto wstCurrProcFullName = CProcessFunctions::GetProcessName(hProc);
						const auto wstCurrProcName = CProcessFunctions::GetProcessNameFromProcessId(dwCurrProcID);
						const auto wstParentProcName = CProcessFunctions::GetProcessNameFromProcessId(dwParentProcID);
						if (dwParentProcID == g_winAPIs->GetCurrentProcessId())
						{
							const auto dwDiffTime = dwNowTimestamp - dwCreateTime;
							if (dwDiffTime < 60)
							{
								APP_TRACE_LOG(LL_TRACE, L"Process: %u skipped from clone check!", dwCurrProcID);
								continue;
							}

							if (wstCurrProcFullName.find(xorstr_(L"cefprocess.bin")) != std::wstring::npos ||
								wstCurrProcFullName.find(xorstr_(L"nomercy_crash_handler_x")) != std::wstring::npos)
							{
								APP_TRACE_LOG(LL_TRACE, L"Process: %u skipped from clone check!", dwCurrProcID);
								continue;
							}

							APP_TRACE_LOG(LL_WARN, L"Child game process detected! [P] %u (%s) >> [C] %u (%s), CreateTime: %u, Now: %u, Diff: %u",
								dwParentProcID, wstParentProcName.c_str(), dwCurrProcID, wstCurrProcName.c_str(),
								dwCreateTime, dwNowTimestamp, dwDiffTime
							);

							auto upThreadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>();
							if (IS_VALID_SMART_PTR(upThreadEnumerator))
							{
								auto vecThreads = upThreadEnumerator->EnumerateThreads(hProc);
								APP_TRACE_LOG(LL_WARN, L"Thread count: %u", vecThreads.size());
								
								if (vecThreads.empty())
								{
									auto hMainWnd = CApplication::Instance().FunctionsInstance()->GetMainWindow(dwCurrProcID);
									if (!hMainWnd || (hMainWnd && !g_winAPIs->IsHungAppWindow(hMainWnd)))
									{
										APP_TRACE_LOG(LL_CRI, L"Process have not threads, it's looks like a clone process! [P] %u (%s) >> [C] %u (%s)[%s] >> W: %p >> TD: %u",
											dwParentProcID, wstParentProcName.c_str(), dwCurrProcID, wstCurrProcName.c_str(), wstCurrProcFullName.c_str(), hMainWnd, dwDiffTime
										);
										g_winAPIs->NtTerminateProcess(hProc, STATUS_SUCCESS);
										// CApplication::Instance().OnCloseRequest(EXIT_ERR_CLONE_PROCESS_DETECT, 0);
									}
								}
							}
						}
					}
				}
				g_winAPIs->Sleep(10);
			}

			upProcEnumerator.reset();
		}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Game clone check completed!");
#endif
#endif

#ifdef __EXPERIMENTAL__ // DISABLED due to possible crash  105/4, access lost to this thread
		// Check EPT hook
		CApplication::Instance().SelfHooksInstance()->CheckEPTHook();
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] EPT hook check completed!");
#endif
#endif

		// FIXME memory leak - abnormal program termination
#ifdef __EXPERIMENTAL__
		auto upThreadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>();
		if (IS_VALID_SMART_PTR(upThreadEnumerator))
		{
			for (auto& hThread : upThreadEnumerator->EnumerateThreads(NtCurrentProcess()))
			{
				std::vector <std::shared_ptr <SStackFrame>> vecStackData;
				const auto bStackRet = GetThreadCallStack(NtCurrentProcess(), hThread, vecStackData);

				const auto dwThreadID = g_winAPIs->GetThreadId(hThread);
				const auto bIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadID);
				ADMIN_DEBUG_LOG(LL_SYS, L"Thread: %u (%p), Alive: %d, Stack ret: %d, Stack size: %u", dwThreadID, hThread, bIsAlive, bStackRet, vecStackData.size());

				if (!bIsAlive)
				{
					ADMIN_DEBUG_LOG(LL_WARN, L"Thread: %u (%p) is not alive!", dwThreadID, hThread);
					continue;
				}

				if (bStackRet == false)
				{
					APP_TRACE_LOG(LL_CRI, L"GetThreadCallStack failed! Thread: %u (%p)", dwThreadID, hThread);
					continue;
					// CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 1);
				}
				
				static constexpr auto STACK_CHECK_LIMIT = 6;

				auto nIdx = 0;
				for (auto& spStackCtx : vecStackData)
				{
					if (nIdx++ >= STACK_CHECK_LIMIT)
						break;

					const auto lpAddress = Ptr64ToPtr((ptr_t)spStackCtx->qwFrameAddress);
//					APP_TRACE_LOG(LL_SYS, L"#%d Stack frame address: %p", nIdx, lpAddress);

					if (!lpAddress)
						continue;

					if (CMemHelper::IsBadReadPtr(lpAddress))
					{
						APP_TRACE_LOG(LL_SYS, L"Bad read pointer: %p", lpAddress);
						continue;
					}

					LPVOID lpBaseAddress = nullptr;
					if (!ValidateAddressInImage(lpAddress, lpBaseAddress))
					{
						const std::vector <std::wstring> vecWhitelistedModules = {
							xorstr_(L"wow64cpu.dll"),
							xorstr_(L"wow64.dll"),
							xorstr_(L"wow64win.dll")
						};
						if (lpBaseAddress)
						{
							wchar_t wszMappedName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpBaseAddress, wszMappedName, MAX_PATH)) {
								APP_TRACE_LOG(LL_ERR, L"Failed to get mapped file name for %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Base owner module: %s", wszMappedName);
							}
							MEMORY_BASIC_INFORMATION mbi{};
							if (!g_winAPIs->VirtualQuery(lpBaseAddress, &mbi, sizeof(mbi))) {
								APP_TRACE_LOG(LL_ERR, L"Failed to query memory %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address: %p/%p Allocation: %p (w/ P: %p) P: %p L: %p S: %p T: %p",
									lpBaseAddress, mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.RegionSize, mbi.State, mbi.Type
								);
							}
						}
						if (lpAddress)
						{
							wchar_t wszMappedName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpAddress, wszMappedName, MAX_PATH)) {
								APP_TRACE_LOG(LL_ERR, L"Failed to get mapped file name for %p Error: %u", lpAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address owner module: %s", wszMappedName);

								auto bWhitelisted = false;
								const auto wstLowerMappedModuleName = stdext::to_lower_wide(wszMappedName);
								for (const auto& wstWhitelistedModule : vecWhitelistedModules)
								{
									if (wstLowerMappedModuleName.find(wstWhitelistedModule) != std::wstring::npos)
									{
										bWhitelisted = true;
										break;
									}
								}

								if (bWhitelisted)
									continue;
							}
							MEMORY_BASIC_INFORMATION mbi{};
							if (!g_winAPIs->VirtualQuery(lpAddress, &mbi, sizeof(mbi))) {
								APP_TRACE_LOG(LL_ERR, L"Failed to query memory %p Error: %u", lpAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address: %p/%p Allocation: %p (w/ P: %p) P: %p L: %p S: %p T: %p",
									lpAddress, mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.RegionSize, mbi.State, mbi.Type
								);
							}
						}
						APP_TRACE_LOG(LL_CRI, L"ValidateAddressInImage failed! Thread: %u (%p), Stack frame address: %p Base: %p", dwThreadID, hThread, lpAddress, lpBaseAddress);
						
						// CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 2); // TODO
						continue;
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame: %p is executed from image: %p", lpAddress, lpBaseAddress);

					if (!ValidateTextExecution(lpAddress, lpBaseAddress))
					{
						/*
						if (lpBaseAddress)
						{
							wchar_t wszMappedName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpBaseAddress, wszMappedName, MAX_PATH)) {
								APP_TRACE_LOG(LL_ERR, L"Failed to get mapped file name for %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Base owner module: %s", wszMappedName);
							}
							MEMORY_BASIC_INFORMATION mbi{};
							if (!g_winAPIs->VirtualQuery(lpBaseAddress, &mbi, sizeof(mbi))) {
								APP_TRACE_LOG(LL_ERR, L"Failed to query memory %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address: %p/%p Allocation: %p (w/ P: %p) P: %p L: %p S: %p T: %p",
									lpBaseAddress, mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.RegionSize, mbi.State, mbi.Type
								);
							}
						}
						if (lpAddress)
						{
							wchar_t wszMappedName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpAddress, wszMappedName, MAX_PATH)) {
								APP_TRACE_LOG(LL_ERR, L"Failed to get mapped file name for %p Error: %u", lpAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address owner module: %s", wszMappedName);
							}
							MEMORY_BASIC_INFORMATION mbi{};
							if (!g_winAPIs->VirtualQuery(lpAddress, &mbi, sizeof(mbi))) {
								APP_TRACE_LOG(LL_ERR, L"Failed to query memory %p Error: %u", lpAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address: %p/%p Allocation: %p (w/ P: %p) P: %p L: %p S: %p T: %p",
									lpAddress, mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.RegionSize, mbi.State, mbi.Type
								);
							}
						}
						APP_TRACE_LOG(LL_ERR, L"ValidateTextExecution failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						*/

						// CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 3);
						continue;
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame is in text section!");

					HANDLE hFile{};
					if (!ValidateImageSection(lpBaseAddress, &hFile))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateImageSection failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);

						if (lpBaseAddress)
						{
							wchar_t wszMappedName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpBaseAddress, wszMappedName, MAX_PATH)) {
								APP_TRACE_LOG(LL_ERR, L"Failed to get mapped file name for %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Base owner module: %s", wszMappedName);
							}
							MEMORY_BASIC_INFORMATION mbi{};
							if (!g_winAPIs->VirtualQuery(lpBaseAddress, &mbi, sizeof(mbi))) {
								APP_TRACE_LOG(LL_ERR, L"Failed to query memory %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
							} else {
								APP_TRACE_LOG(LL_WARN, L"Address: %p/%p Allocation: %p (w/ P: %p) P: %p L: %p S: %p T: %p",
									lpBaseAddress, mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.RegionSize, mbi.State, mbi.Type
								);
							}
						}

						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 4);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame is in image section: %p", hFile);

					if (!ValidateMatchesFile(hFile, lpBaseAddress))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateMatchesFile failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 5);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame memory is matched with their file!");

					if (!ValidateFile(hFile))
					{
						APP_TRACE_LOG(LL_ERR, L"ValidateFile failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						// CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 6);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame file is valid!");

					if (!ValidateLoader(lpBaseAddress, hFile))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateLoader failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 7);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame is in loader!");

					if (IS_VALID_HANDLE(hFile))
					{
						g_winAPIs->CloseHandle(hFile);
						hFile = nullptr;
					}

					if (!ValidateThreadAddress(lpBaseAddress))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateThreadAddress failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 8);
					}
//					APP_TRACE_LOG(LL_SYS, L"Thread address validated!");

					LPVOID lpInstrPtrBaseAddress = nullptr;
					if (!ValidateAddressInImage((LPVOID)spStackCtx->qwInstrPtr, lpInstrPtrBaseAddress))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateAddressInImage failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 9);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame instruction ptr: %p is executed from image: %p", (LPVOID)spStackCtx->qwInstrPtr, lpInstrPtrBaseAddress);

					if (!ValidateInstructionPointer((LPVOID)spStackCtx->qwInstrPtr))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateInstructionPointer failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 10);
					}
//					APP_TRACE_LOG(LL_SYS, L"Instruction pointer validated!");

					if (spStackCtx->bHasDebugRegister)
					{
						APP_TRACE_LOG(LL_CRI, L"Thread has debug registers! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 11);
					}
//					APP_TRACE_LOG(LL_SYS, L"Stack frame has no debug register!");

					if (!ValidateThradeFrames())
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateThradeFrames failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 12);
					}
//					APP_TRACE_LOG(LL_SYS, L"Thread frames validated!, #%d Stack check completed!", nIdx);

					if (!ValidateWow32ReservedIntegrity(hThread))
					{
						APP_TRACE_LOG(LL_CRI, L"ValidateWow32ReservedIntegrity failed! Thread: %u (%p), Stack frame address: %p", dwThreadID, hThread, lpAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_CALL_STACK_FAIL, 13);
					}
//					APP_TRACE_LOG(LL_SYS, L"Wow32 reserved integrity validated!");
				}

				ADMIN_DEBUG_LOG(LL_SYS, L"Stack check completed for Thread: %u (%p)", dwThreadID, hThread);
			}
		}
#endif
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Thread stack check completed!");
#endif

		// Check speedhack by queryin worldtimeapi.org
		static auto s_dwPrevRemoteTime = 0;
		const auto dwRemoteTime = GetCurrentTimestampRemoteSec();
		if (dwRemoteTime == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"GetCurrentTimestampRemoteSec failed!");
			// Query failed, clear previous result
			s_dwPrevRemoteTime = 0;
		}
		else
		{
			if (s_dwPrevRemoteTime != 0)
			{
				// We have a previous time, so we can check the speedhack. Thread execution interval is 15sec so delay should not be less than 13sec
				const auto dwDelay = dwRemoteTime - s_dwPrevRemoteTime;
				APP_TRACE_LOG(LL_SYS, L"Current time: %u, Previous time: %u, Delay: %u", dwRemoteTime, s_dwPrevRemoteTime, dwDelay);
				if (dwDelay < 13)
				{
					APP_TRACE_LOG(LL_CRI, L"Speedhack detected! Delay: %u sec", dwDelay);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_SPEEDHACK_DETECTED, dwDelay);
				}
				else if (dwDelay > 100)
				{
					APP_TRACE_LOG(LL_CRI, L"Abnormal delay detected: %u sec", dwDelay);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_MAIN_CHECK_THREAD_ABNORMAL_DELAY, dwDelay);
				}

				// Update previous time
				s_dwPrevRemoteTime = dwRemoteTime;
			}
			else
			{
				APP_TRACE_LOG(LL_SYS, L"First remote time: %u", dwRemoteTime);
				s_dwPrevRemoteTime = dwRemoteTime;
			}
		}
		
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_SYS, L"[CMR] Speedhack check completed!");	
#endif

//#ifdef _DEBUG
		APP_TRACE_LOG(LL_TRACE, L"Main routine completed!");
//#endif
		return 0;
	}

	bool CApplication::InitializeClientMainCheckThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_CLIENT_MAIN_ROUTINE, NoMercyClientMainRoutine, nullptr, 15000, false);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
};
