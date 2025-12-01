#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/ExceptionHandlers.hpp"
#include "../Common/MessageProcManager.hpp"
#include "../Anti/AntiDebug.hpp"
#include "../Anti/AntiEmulation.hpp"
#include "../Anti/AntiBreakpoint.hpp"
#include "../Anti/AntiMacro.hpp"
#include "../Thread/ThreadExitCallback.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/Keys.hpp"
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <MinHook.h>
#include <crashpad/client/simulate_crash_win.h>
#include "../Monitor/MemoryAccessDetect.hpp"

namespace NoMercy
{
	// Shared variables
#pragma region ClientSharedVariables
	static auto gs_hTimerCheckerThread	= HANDLE(INVALID_HANDLE_VALUE);
	static auto gs_pkTimerChecker		= CStopWatch <std::chrono::milliseconds>();
	static std::atomic_bool gs_abThreadsInitialized	= false;
	static std::atomic_bool gs_abWatchdogTimerFirstWorkCompleted = false;
#pragma endregion ClientSharedVariables
	
	// --------------------------------------------------------------------------------------------------------------------------------------------

	// Self hosting sample client main routine
#pragma region ClientMainRoutine
	static bool __ClientMainRoutine()
	{
		MSG message{};
		while (g_winAPIs->GetMessageW(&message, nullptr, 0, 0))
		{
			APP_TRACE_LOG(LL_TRACE, L"Message: %u handled! IsTimer: %d", message.message, message.message == WM_TIMER);

			if (message.message == WM_QUIT)
			{
				APP_TRACE_LOG(LL_CRI, L"Quit message handled!");
				break;
			}

			g_winAPIs->TranslateMessage(&message);
			g_winAPIs->DispatchMessageW(&message);
		}

		APP_TRACE_LOG(LL_CRI, L"Message handle stopped!");
		return true;
	}

	static void __EnterToClientMainRoutine()
	{
		auto bEnterLoop = false;
		if (NoMercyCore::CApplication::Instance().DataInstance()->GetAppType() == NM_STANDALONE)
			bEnterLoop = true;
		else if (NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() == GAME_CODE_DUMMYAPP)
			bEnterLoop = true;

		if (bEnterLoop)
		{
			APP_TRACE_LOG(LL_CRI, L"Client main loop started!");
			__ClientMainRoutine();
		}

		APP_TRACE_LOG(LL_SYS, L"Client main routine completed!");
	}
#pragma endregion ClientMainRoutine

	// --------------------------------------------------------------------------------------------------------------------------------------------

	// Watchdog timer validator thread routine
#pragma region ClientTimerCheckThread
	DWORD WINAPI TimerCheckThreadRoutine(LPVOID)
	{
		APP_TRACE_LOG(LL_TRACE, L"Timer check thread event has been started");

		if (gs_pkTimerChecker.diff() > 60000) // 60 sec
		{
			const auto bIsWatchdogReady = gs_abWatchdogTimerFirstWorkCompleted.load();
			APP_TRACE_LOG(LL_SYS, L"Watchdog timer check started! Diff: %u Result: %d", gs_pkTimerChecker.diff(), bIsWatchdogReady ? 1 : 0);

			if (bIsWatchdogReady == false)
			{
				APP_TRACE_LOG(LL_ERR, L"Watchdog timer is not ready, timeout!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WATCHDOG_TIMER_INTEGRITY_FAIL, g_winAPIs->GetLastError());
			}
			
			APP_TRACE_LOG(LL_SYS, L"Watchdog timer load check succesfully completed!");
			
			const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_TIMER_CHECKER);
			if (IS_VALID_SMART_PTR(currentThread))
			{
				CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
			}

			return 0;
		}

		return 0;
	}

#pragma endregion ClientTimerCheckThread

	// --------------------------------------------------------------------------------------------------------------------------------------------

	// Client initilization checker watchdog timer
#pragma region ClientWatchdogTimer

	inline void WatchdogRoutineEx()
	{
		if (!gs_abWatchdogTimerFirstWorkCompleted.load())
			gs_abWatchdogTimerFirstWorkCompleted.store(true);

		static auto s_iWatchdogLoopIdx = 0;
		if (s_iWatchdogLoopIdx >= INT_MAX - 1)
			s_iWatchdogLoopIdx = 1;

		APP_TRACE_LOG(LL_SYS, L"Watchdog timer is running! Idx: %d Threads ready: %d", s_iWatchdogLoopIdx++, gs_abThreadsInitialized.load() ? 1 : 0);

		// Initialize routine after than setup game's wndproc
		if (gs_abThreadsInitialized.load() == false)
		{
			APP_TRACE_LOG(LL_SYS, L"Threads are initializing...");
			
			if (CApplication::InstancePtr() && IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			{
				if (CApplication::Instance().AppIsInitializedThreadCompleted())
				{
					if (IS_VALID_SMART_PTR(CApplication::Instance().FunctionsInstance()))
					{
						const auto hMainWnd = CApplication::Instance().FunctionsInstance()->GetMainWindow(g_winAPIs->GetCurrentProcessId());
						APP_TRACE_LOG(LL_SYS, L"Main window handle: %p", hMainWnd);

						if (hMainWnd)
						{
							static std::once_flag s_kOnceFlag;
							std::call_once(s_kOnceFlag, [&]() {
								gs_abThreadsInitialized.store(true);

								APP_TRACE_LOG(LL_SYS, L"Window handle register started!");
								NoMercyCore::CApplication::Instance().DataInstance()->SetClientMainWindow(hMainWnd);
								CApplication::Instance().InputInjectMonitorInstance()->SetWindowHandle(hMainWnd);

								const auto bIsProtectedWnd = CApplication::Instance().WatchdogInstance()->IsWatchdogWindow(hMainWnd);
								APP_TRACE_LOG(LL_SYS, L"Main window: %p protected result: %d", hMainWnd, bIsProtectedWnd);

								APP_TRACE_LOG(LL_SYS, L"Session ID forwading started!");
								const auto wstSessionID = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID();
								const auto stSessionID = stdext::to_ansi(wstSessionID);
								CApplication::Instance().SDKHelperInstance()->SendSessionIDToClient(stSessionID.c_str());

								//						APP_TRACE_LOG(LL_SYS, L"Shutdown block reason register started!");
								//						NoMercyCore::CApplication::Instance().RegisterShutdownBlockReason(hMainWnd);

#ifdef __EXPERIMENTAL__
								InitializeExperimentalWindowHook();
								APP_TRACE_LOG(LL_SYS, L"Experimental window hook initialized!");
#endif

#ifdef __EXPERIMENTAL__
								APP_TRACE_LOG(LL_SYS, L"Window message hook initialization started!");
								if (CApplication::Instance().InputInjectMonitorInstance()->InitializeWindowMessageHook() == false)
								{
									APP_TRACE_LOG(LL_ERR, L"Failed to initialize window message hook!");
									CApplication::Instance().OnCloseRequest(EXIT_ERR_INIT_WINDOW_MESSAGE_HOOK_FAIL, g_winAPIs->GetLastError());
									return;
								}

								APP_TRACE_LOG(LL_SYS, L"Raw window hook initialization started!");
								if (CApplication::Instance().InputInjectMonitorInstance()->InitializeRawWindowHook() == false)
								{
									APP_TRACE_LOG(LL_ERR, L"Failed to initialize raw window hook!");
									CApplication::Instance().OnCloseRequest(EXIT_ERR_INIT_RAW_WINDOW_HOOK_FAIL, g_winAPIs->GetLastError());
									return;
								}
#endif

								// Create websocket connection
								APP_TRACE_LOG(LL_SYS, L"Client websocket connection initilization started!");
								if (CApplication::Instance().CreateWebsocketConnection() == false)
								{
									APP_TRACE_LOG(LL_ERR, L"Failed to create websocket connection!");
#ifdef __EXPERIMENTAL__
									CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_CONNECTION_FAILED, 1);
#endif
									return;
								}

								// Initialize NoMercy threads
								APP_TRACE_LOG(LL_SYS, L"Client thread routines initilization started!");
								if (CApplication::Instance().InitializeClientThreads() == false)
								{
									APP_TRACE_LOG(LL_ERR, L"Client threads initilization fail! Last error: %u", g_winAPIs->GetLastError());
									CApplication::Instance().OnCloseRequest(EXIT_ERR_CLIENT_THREADS_INIT_FAIL, g_winAPIs->GetLastError());
									return;
								}

								// Initialize GUI Watchdog
								APP_TRACE_LOG(LL_SYS, L"GUI watchdog initialization started!");
								if (CApplication::Instance().WatchdogInstance()->InitializeWatchdog() == false)
								{
									APP_TRACE_LOG(LL_ERR, L"Watchdog initilization fail! Last error: %u", g_winAPIs->GetLastError());
									CApplication::Instance().OnCloseRequest(EXIT_ERR_WINDOWS_WATCHDOG_THREAD_FAIL, g_winAPIs->GetLastError());
									return;
								}

								APP_TRACE_LOG(LL_SYS, L"Threads initilizations completed!");

								// Process is ready, Delete timer
								auto hTimerQueue = CApplication::Instance().GetTimerQueueHandle();
								auto hTimer = CApplication::Instance().GetWatchdogTimerHandle();
								if (IS_VALID_HANDLE(hTimerQueue) && IS_VALID_HANDLE(hTimer))
								{
									g_winAPIs->RtlDeleteTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
									CApplication::Instance().ResetWatchdogTimer();
								}
								});
						}
					}
				}
				else if (CApplication::InstancePtr())
				{
					APP_TRACE_LOG(LL_SYS, L"App is not ready yet.. %d %d %d %d",
						CApplication::Instance().AppIsInitiliazed(),
						CApplication::Instance().AppIsFinalized(),
						CApplication::Instance().AppCloseTriggered(),
						CApplication::Instance().AppIsInitializedThreadCompleted()
					);
				}
			}
		}
	}

	VOID CALLBACK WatchdogRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		WatchdogRoutineEx();
	}

#pragma endregion ClientWatchdogTimer

	// --------------------------------------------------------------------------------------------------------------------------------------------

	// Main routine functions
	bool CApplication::FinalizeClient()
	{
		APP_TRACE_LOG(LL_SYS, L"Finalizing client...");
		
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		auto idx = 0;

//		NoMercyCore::CApplication::Instance().UnregisterShutdownBlockReason(
//			NoMercyTelemetry::CApplication::Instance().FunctionsInstance()->GetMainWindow(g_winAPIs->GetCurrentProcessId())
//		);

		const auto initThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_CLIENT_INIT);
		if (IS_VALID_SMART_PTR(initThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(initThread);
		}

#ifdef __EXPERIMENTAL__
		ReleaseExperimentalWindowHook();
#endif
		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 0

		if (IS_VALID_SMART_PTR(m_spSelfThreadIdentifier))
			m_spSelfThreadIdentifier->ReleaseThreadTickChecker();
		
		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 1

		CAntiMacro::DestroyAntiMacro();
		
		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 2

		if (IS_VALID_SMART_PTR(m_spWindowWatcher))
			m_spWindowWatcher->Release();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 3

		if (IS_VALID_SMART_PTR(m_spWinDebugStrMonitor))
			m_spWinDebugStrMonitor->Release();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed //", idx++); // 4

		if (IS_VALID_SMART_PTR(m_spSelfHooks))
			m_spSelfHooks->CleanupHooks();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 5

		if (IS_VALID_HANDLE(gs_hTimerCheckerThread))
		{
			g_winAPIs->TerminateThread(gs_hTimerCheckerThread, 0);
			gs_hTimerCheckerThread = nullptr;
		}

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 6

		if (IS_VALID_SMART_PTR(m_spTickCounter))
			m_spTickCounter->ReleaseThread();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 7

		/*
		auto hTimerQueue = CApplication::Instance().GetTimerQueueHandle();
		auto hTimer = CApplication::Instance().GetWatchdogTimerHandle();
		if (IS_VALID_HANDLE(hTimerQueue) && IS_VALID_HANDLE(hTimer))
		{
			g_winAPIs->RtlDeleteTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
			CApplication::Instance().ResetWatchdogTimer();
		}
		*/

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 8

		if (IS_VALID_SMART_PTR(m_spScannerInterface))
			m_spScannerInterface->FinalizeScanner();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed //", idx++); // 9

		if (IS_VALID_SMART_PTR(m_spManualMapScanner))
			m_spManualMapScanner->ReleaseThread();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 10

		if (IS_VALID_SMART_PTR(m_spInputInjectMonitor))
		{
			m_spInputInjectMonitor->DestroyWindowMessageHook();
			m_spInputInjectMonitor->DestroyRawWindowHook();
		}

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 11

		// FIX ATTEMPT FOR #79, #84
//		/*
		if (CApplication::Instance().WatchdogInstance())
			CApplication::Instance().WatchdogInstance()->CleanupWatchdog();
//		*/

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 12
		

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 13

		if (IS_VALID_SMART_PTR(m_spCheatQueueManager))
			m_spCheatQueueManager->ReleaseThread();

		if (IS_VALID_SMART_PTR(m_spCheatQueue))
			m_spCheatQueue->ReleaseThread();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 14

		// m_kClientMutex.CloseInstance();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 15
		
		if (IS_VALID_SMART_PTR(m_spHwbpWatcher))
			m_spHwbpWatcher->ReleaseWatcher();
		
		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 16

		if (IS_VALID_SMART_PTR(m_spGameRegionMonitor))
			m_spGameRegionMonitor->ReleaseThread();

		if (IS_VALID_SMART_PTR(m_spModuleSectionMonitor))
			m_spModuleSectionMonitor->ReleaseThread();

		APP_TRACE_LOG(LL_SYS, L"Client finalization step %d completed", idx++); // 17

		return true;
	}

	DWORD CApplication::ClientInitThreadRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Client init thread event has been started!");

		do
		{
			// Antis

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer10: %u", kTimer.diff());

			std::wstring wstBadModuleName;
			auto dwModuleCheckRet = 0UL;
			if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->CheckModulesIntegrity(&wstBadModuleName, &dwModuleCheckRet))
			{
				m_dwInitStatusCode = INIT_ERR_WIN_MOD_CHECK_FAIL;
				m_dwInitSubErrorCode = dwModuleCheckRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Module check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer11: %u", kTimer.diff());

#ifndef _RELEASE_DEBUG_MODE_
#ifdef _DEBUG
			if (g_winAPIs->IsDebuggerPresent() == false) // Allow debugging for debug build but still run anti debug routine if a debugger not attached
#endif
			{
				auto dwDebugRet = 0UL;
				if (CAntiDebug::InitAntiDebug(&dwDebugRet) == false)
				{
					m_dwInitStatusCode = INIT_ERR_DEBUG_CHECK_FAIL;
					m_dwInitSubErrorCode = dwDebugRet;
					break;
				}
			}
#endif
			APP_TRACE_LOG(LL_SYS, L"Anti debug init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer12: %u", kTimer.diff());

			auto dwKernelDebugRet = 0UL;
			if (CAntiDebug::InitAntiKernelDebug(&dwKernelDebugRet) == false)
			{
				m_dwInitStatusCode = INIT_ERR_KERNEL_DEBUG_CHECK_FAIL;
				m_dwInitSubErrorCode = dwKernelDebugRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti kernel debug init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer13: %u", kTimer.diff());

			auto dwEmulationRet = 0UL;
			if (CAntiEmulation::InitAntiEmulation(&dwEmulationRet) == false)
			{
				m_dwInitStatusCode = INIT_ERR_EMULATION_CHECK_FAIL;
				m_dwInitSubErrorCode = dwEmulationRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti emulation init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer14: %u", kTimer.diff());

			auto dwVirtualizeRet = 0UL;
			if (CAntiDebug::AntiVirtualize(&dwVirtualizeRet) == false)
			{
#ifndef ALLOW_VIRTUAL_ENVIRONMENT
				m_dwInitStatusCode = INIT_ERR_VIRTUALIZE_CHECK_FAIL_BASE + dwVirtualizeRet;
				break;
#endif
			}
			APP_TRACE_LOG(LL_SYS, L"Anti virtualize init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer15: %u", kTimer.diff());

			auto dwBootkitRet = 0UL;
			if (CAntiDebug::AntiBootkit(&dwBootkitRet) == false)
			{
				if (!NoMercyCore::CApplication::Instance().DataInstance()->IsAdminEnvironment())
				{
					APP_TRACE_LOG(LL_CRI, L"Corrupted boot configration detected with return code: %u", dwBootkitRet);
				}

				m_dwInitStatusCode = INIT_ERR_BOOTKIT_CHECK_FAIL;
				m_dwInitSubErrorCode = dwBootkitRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti bootkit init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer16: %u", kTimer.diff());

			if (CAntiBreakpoint::HasHardwareBreakpoint())
			{
				APP_TRACE_LOG(LL_WARN, L"Hardware breakpoint detected!");

				const auto spThread = std::make_shared<CThread>(NtCurrentThread());
				if (IS_VALID_SMART_PTR(spThread))
				{
					spThread->ClearDebugRegisters();

					if (spThread->HasDebugRegisters())
					{
						m_dwInitStatusCode = INIT_ERR_HWBP_CHECK_FAIL;
						break;
					}
				}
			}
			APP_TRACE_LOG(LL_SYS, L"Anti hwbp check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer17: %u", kTimer.diff());

			if (CAntiBreakpoint::HasEntrypointBreakpoint())
			{
				m_dwInitStatusCode = INIT_ERR_EPBP_CHECK_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti entrypoint bp check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer18: %u", kTimer.diff());

			DWORD dwHVRet = 0;
			if (!CAntiDebug::LowLevelHypervisorChecksPassed(&dwHVRet))
			{
				m_dwInitStatusCode = INIT_ERR_LOW_LEVEL_HYPERVISOR_CHECK_FAIL;
				m_dwInitSubErrorCode = dwHVRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step 1 completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer19: %u", kTimer.diff());

			CExceptionHandlers::RemoveSingleStepHandler();
			APP_TRACE_LOG(LL_SYS, L"Single step handler remove completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer20: %u", kTimer.diff());

			auto dwHypervisorRet = 0UL;
			if (CAntiDebug::IsHypervisorPresent(&dwHypervisorRet))
			{
#ifndef ALLOW_VIRTUAL_ENVIRONMENT
				m_dwInitStatusCode = INIT_ERR_HYPERVISOR_PRESENT;
				m_dwInitSubErrorCode = dwHypervisorRet;
				break;
#endif
			}
			APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step 2 completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer21: %u", kTimer.diff());

			if (!CExceptionHandlers::InitSingleStepHandler())
			{
				m_dwInitStatusCode = INIT_ERR_SINGLE_STEP_HANDLER_INIT_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Single step handler init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer22: %u", kTimer.diff());

			// Compatible mode check
			if (m_spFunctions->IsRunningCompatMode())
			{
				m_dwInitStatusCode = INIT_ERR_COMPATIBLE_MODE;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Compatible mode check step 1 completed!");

			const auto hAclayers = g_winAPIs->GetModuleHandleW_o(xorstr_(L"aclayers.dll"));
			if (hAclayers)
			{
				if ((HMODULE)&g_winAPIs->GetVersionExW > hAclayers && (HMODULE)&g_winAPIs->GetVersionExW <= hAclayers + 0x24000)
				{
					m_dwInitStatusCode = INIT_ERR_COMPATIBLE_MODE_2;
					break;
				}
			}
			APP_TRACE_LOG(LL_SYS, L"Compatible mode check step 2 completed!");

			// OS Check
			if (!IsWindowsXPOrGreater()) // older than xp
			{
				m_dwInitStatusCode = INIT_ERR_UNSUPPORTED_OS;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 1 completed!");

			if (IsWindowsXPOrGreater() && !IsWindowsVistaOrGreater() && GetWindowsServicePackVersion() != 3) // xp && sp != 3
			{
				m_dwInitStatusCode = INIT_ERR_UNSUPPORTED_XP_SP;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 2 completed!");

			if (IsWindowsXPOrGreater() && !IsWindowsVistaOrGreater() && m_spFunctions->IsX64System()) // x64 xp
			{
				m_dwInitStatusCode = INIT_ERR_UNSUPPORTED_XP_ARCH;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 3 completed!");

			if (IsWindowsVistaOrGreater() && !IsWindows7OrGreater() && GetWindowsServicePackVersion() != 2) // vista && sp != 2
			{
				m_dwInitStatusCode = INIT_ERR_UNSUPPORTED_VISTA;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 4 completed!");

			if (IsWindowsVistaOrGreater() == false && g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("NtCreateThreadEx"))) // Any not XP supported windows api
			{
				m_dwInitStatusCode = INIT_ERR_FAKE_OS;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 5 completed!");

			if (g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("RegisterServiceProcess")))
			{
				m_dwInitStatusCode = INIT_ERR_OLDEST_OS;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 6 completed!");

			if (IsFakeConditionalVersion())
			{
				m_dwInitStatusCode = INIT_ERR_FAKE_OS_VERSION;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"OS check step 7 completed!");

#ifdef __EXPERIMENTAL__ // saltanat#6267
			LPWKSTA_INFO_100 pWkstaInfo = nullptr;
			if (g_winAPIs->NetWkstaGetInfo(nullptr, 100, (LPBYTE*)&pWkstaInfo) == NERR_Success)
			{
				const auto dwKnownMajorVer = GetWindowsMajorVersion();
				const auto dwKnownMinorVersion = GetWindowsMinorVersion();

				APP_TRACE_LOG(LL_SYS, L"WinVer: %u.%u - %u.%u", dwKnownMajorVer, dwKnownMinorVersion, pWkstaInfo->wki100_ver_major, pWkstaInfo->wki100_ver_minor);

				if (dwKnownMajorVer != pWkstaInfo->wki100_ver_major || dwKnownMinorVersion != pWkstaInfo->wki100_ver_minor)
				{
					m_dwInitStatusCode = INIT_ERR_CORRUPTED_OS_VERSION_INFO;
					break;
				}

				g_winAPIs->NetApiBufferFree(pWkstaInfo);
				pWkstaInfo = nullptr;
			}
#endif
			APP_TRACE_LOG(LL_SYS, L"OS check step 8 completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer24: %u", kTimer.diff());

			// Safe mode check
			if (m_spFunctions->IsSafeModeEnabled())
			{
				m_dwInitStatusCode = INIT_ERR_SAFE_MODE;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Safe mode check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer25: %u", kTimer.diff());

			// DEP status validation
			if (!g_winAPIs->GetSystemDEPPolicy())
			{
				m_dwInitStatusCode = INIT_ERR_SYSTEM_DEP_NOT_ACTIVE;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"System DEP check step completed!");

			DWORD dwProcDepStatus = 0;
			BOOL bIsPermaDEP = FALSE;
			if (!g_winAPIs->GetProcessDEPPolicy(NtCurrentProcess(), &dwProcDepStatus, &bIsPermaDEP))
			{
				m_dwInitStatusCode = INIT_ERR_PROCESS_DEP_QUERY_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Process DEP query step completed!");

			/*
			if (!dwProcDepStatus)
			{
				m_dwInitStatusCode = INIT_ERR_PROCESS_DEP_NOT_ACTIVE;
				break;
			}
			*/
			APP_TRACE_LOG(LL_SYS, L"Process DEP check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer26: %u", kTimer.diff());

			// Main thread handle
			DWORD dwMainThreadID = NoMercyCore::CApplication::Instance().DataInstance()->GetMainThreadId();
			SafeHandle pkMainThread = g_winAPIs->OpenThread(THREAD_ALL_ACCESS, FALSE, dwMainThreadID);
			if (!pkMainThread)
			{
				m_dwInitStatusCode = INIT_ERR_MAIN_THREAD_HANDLE_FAIL;
				break;
			}

			// Access Rules
			if (m_spAccessHelper->BlockAccess(NtCurrentProcess()) == false)
			{
				m_dwInitStatusCode = INIT_ERR_ACCESS_ADJUST_1_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Access rule 1 adjust step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer27: %u", kTimer.diff());

			if (m_spAccessHelper->BlockAccess(pkMainThread.get()) == false)
			{
				m_dwInitStatusCode = INIT_ERR_ACCESS_ADJUST_2_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Access rule 2 adjust step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer28: %u", kTimer.diff());

			if (m_spAccessHelper->ChangeAccessRights(NtCurrentProcess(), EACLTargetType::PROCESS) == false)
			{
				m_dwInitStatusCode = INIT_ERR_ACCESS_ADJUST_3_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Access rule 3 adjust step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer29: %u", kTimer.diff());

			if (m_spAccessHelper->ChangeAccessRights(pkMainThread.get(), EACLTargetType::THREAD) == false)
			{
				m_dwInitStatusCode = INIT_ERR_ACCESS_ADJUST_4_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Access rule 4 adjust step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer30: %u", kTimer.diff());


			APP_TRACE_LOG(LL_SYS, L"Access rule 5 adjust step completed!");

			if (IsWindowsVistaOrGreater())
			{
				m_spAccessHelper->EnablePermanentDep();
				m_spAccessHelper->EnableNullPageProtection();
			}
			APP_TRACE_LOG(LL_SYS, L"Access rule 6 adjust step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer31: %u", kTimer.diff());

			// Initialize HWID manager
			if (NoMercyCore::CApplication::Instance().HWIDManagerInstance()->Initilize() == false)
			{
				m_dwInitStatusCode = INIT_ERR_HWID_INIT_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Hwid manager initialized.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer32: %u", kTimer.diff());

			// Fill sentry user informations
			if (NoMercyCore::CApplication::Instance().GetSentryManagerInstance())
			{
				NoMercyCore::CApplication::Instance().GetSentryManagerInstance()->SetUserData(
					stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSimpleHwid()),
					stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID()),
					stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetBootID()),
					stdext::to_ansi(CApplication::Instance().GetAntivirusInfo())
				);
			}
			APP_TRACE_LOG(LL_SYS, L"Sentry user informations filled.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer33: %u", kTimer.diff());

			// Check test digital sign is enabled
			DWORD dwTestSignRet = 0;
			if (m_spScannerInterface->IsTestSignEnabled(&dwTestSignRet))
			{
				m_dwInitStatusCode = INIT_ERR_TEST_SIGN_ENABLED;
				m_dwInitSubErrorCode = dwTestSignRet;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Test sign check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer34: %u", kTimer.diff());

#ifdef __EXPERIMENTAL__
			// Check if secure boot is capable but disabled
			if (m_spScannerInterface->IsSecureBootEnabled() == false)
			{
				m_dwInitStatusCode = INIT_ERR_SCR_BOOT_CHECK_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Secure boot check step completed!");
#endif

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer35: %u", kTimer.diff());

			// Check custom signed driver is enabled
			if (m_spScannerInterface->IsCustomKernelSignersAllowed())
			{
				m_dwInitStatusCode = INIT_ERR_CUSTOM_KERNEL_SIGN_ENABLED;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Custom kernel signer check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer36: %u", kTimer.diff());

			// Check HVCI(CFG policy) with query LSASS
			if (IsWindows10OrGreater())
			{
				const auto dwLsassPID = CProcessFunctions::GetProcessIdFromProcessName(xorstr_(L"lsass.exe"));
				if (dwLsassPID)
				{
					APP_TRACE_LOG(LL_SYS, L"LSASS process found: %u", dwLsassPID);

					auto hLsassProc = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwLsassPID);
					if (IS_VALID_HANDLE(hLsassProc))
					{
						APP_TRACE_LOG(LL_SYS, L"LSASS process opened: %p", hLsassProc);

						PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy{ 0 };
						if (!g_winAPIs->GetProcessMitigationPolicy(hLsassProc, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy)))
						{
							APP_TRACE_LOG(LL_WARN, L"GetProcessMitigationPolicy failed with status: %u", g_winAPIs->GetLastError());

							m_dwInitStatusCode = INIT_ERR_CFG_POLICY_DISABLED;
							m_dwInitSubErrorCode = 1;
							break;
						}

						if (cfgPolicy.EnableControlFlowGuard == 0)
						{
							APP_TRACE_LOG(LL_WARN, L"CFG policy disabled!");

							m_dwInitStatusCode = INIT_ERR_CFG_POLICY_DISABLED;
							m_dwInitSubErrorCode = 2;
							break;
						}

						NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hLsassProc);
					}
				}
			}
			APP_TRACE_LOG(LL_SYS, L"CFG policy check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer37: %u", kTimer.diff());

			// Check TPM
			if (IsWindows11OrGreater())
			{
				TPM_DEVICE_INFO tpmDevInfo{ 0 };
				const auto nTpmRet = g_winAPIs->Tbsi_GetDeviceInfo(sizeof(tpmDevInfo), &tpmDevInfo);
				if (nTpmRet == TBS_E_TPM_NOT_FOUND)
				{
					m_dwInitStatusCode = INIT_ERR_TPM_NOT_FOUND;
					break;
				}
			}
			APP_TRACE_LOG(LL_SYS, L"TPM check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer38: %u", kTimer.diff());

			// Memory watchdog
			if (m_spScannerInterface->InitializeMemoryWatchdogs(NtCurrentProcess()) == false)
			{
				m_dwInitStatusCode = INIT_ERR_MEM_WATCHDOG_INIT_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Memory watchdog init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer39: %u", kTimer.diff());

			// Send ping to SDK
			if (IS_VALID_SMART_PTR(m_spSDKHelper))
			{
				const auto c_stMessage = std::to_string(static_cast<uint32_t>(ENMMsgCodes::NM_GAME_STARTED));
				const auto bSDKMsgRet = m_spSDKHelper->SendMessageToClient(ENMDataCodes::NM_SIGNAL, c_stMessage.c_str(), nullptr);
				APP_TRACE_LOG(LL_SYS, L"SDK message step completed! Ret: %d", bSDKMsgRet);
			}

			APP_TRACE_LOG(LL_SYS, L"SDK processing completed, Initializng timer check thread.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer40: %u", kTimer.diff());

			// Mark init thread completed
			m_abInitThreadCompleted = true;

			// Timer checker
			gs_pkTimerChecker.reset();

			auto pTimerCheckerThread = m_spThreadMgr->CreateCustomThread(SELF_THREAD_TIMER_CHECKER, TimerCheckThreadRoutine, nullptr, 3000, true);
			if (!IS_VALID_SMART_PTR(pTimerCheckerThread) || pTimerCheckerThread->IsValid() == false)
			{
				m_dwInitStatusCode = INIT_ERR_TIMER_CHECK_THREAD_CREATE_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Timer check thread step completed! Info - %u[%p->%p][%d-%s] - Completed! Thread:%p", pTimerCheckerThread->GetID(), pTimerCheckerThread->GetHandle(),
				pTimerCheckerThread->GetStartAddress(), pTimerCheckerThread->GetCustomCode(), pTimerCheckerThread->GetThreadCustomName().c_str(), pTimerCheckerThread.get()
			);

			gs_hTimerCheckerThread = pTimerCheckerThread->GetHandle();
			APP_TRACE_LOG(LL_SYS, L"Timer check thread watcher init step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer41: %u", kTimer.diff());

			// Main loop for test phase
			__EnterToClientMainRoutine();
		} while (false);

		APP_TRACE_LOG(LL_SYS, L"Client initilization thread routine completed! Status: %u", m_dwInitStatusCode);

		// LogfA(CUSTOM_LOG_FILENAME_A, "Timer0: %u", kTimer.diff());

		// Complete
		if (m_dwInitStatusCode == INIT_STATUS_UNDEFINED)
		{
			m_dwInitStatusCode = INIT_STATUS_SUCCESS;
			return 0;
		}
		else if (m_dwInitStatusCode == INIT_STATUS_SUCCESS)
		{
			return 0;
		}
		else
		{
			__OnCoreInitilizationFail(2);
			return 1;
		}

		return 0;
	}

	DWORD WINAPI CApplication::StartClientInitThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CApplication*>(lpParam);
		return This->ClientInitThreadRoutine();
	}

	bool CApplication::InitializeClient()
	{
		// CStopWatch <std::chrono::milliseconds> kTimer;

#ifdef _RELEASE_DEBUG_MODE_
		if (std::filesystem::exists(xorstr_(L"NM_ATTACH")))
		{
			while (!g_winAPIs->IsDebuggerPresent())
			{
				APP_TRACE_LOG(LL_WARN, L"Waiting for debugger to attach...");
				g_winAPIs->Sleep(1000);
			}
		}
#endif

		APP_TRACE_LOG(LL_SYS, L"Client initilization routine started!");

		m_kClientMutex = CLimitSingleInstance(CLIENT_MUTEX);
		APP_TRACE_LOG(LL_SYS, L"Mutex instance created");

		// LogfA(CUSTOM_LOG_FILENAME_A, "Timer1: %u", kTimer.diff());

		do
		{
#ifndef _DEBUG
			if (NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() != GAME_CODE_DUMMYAPP)
			{
				if (!m_kClientMutex.CreateInstance())
				{
					APP_TRACE_LOG(LL_WARN, L"Mutex create failed with error: %u", g_winAPIs->GetLastError());
				}
				APP_TRACE_LOG(LL_SYS, L"Mutex instance create step completed!");
			}
#endif

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer2: %u", kTimer.diff());

			auto iElevationRet = NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->CheckElevation();
			if (iElevationRet == 1)
			{
				m_dwInitStatusCode = INIT_ERR_ELEVATION_FAIL_FIRST;
				break;
			}
			else if (iElevationRet == 2)
			{
				m_dwInitStatusCode = INIT_ERR_ELEVATION_FAIL_SECOND;
				break;
			}
			else if (iElevationRet == 3)
			{
				m_dwInitStatusCode = INIT_ERR_ELEVATION_FAIL_THIRD;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Elevation check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer3: %u", kTimer.diff());

			if (NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->RequestPrivilege(SE_DEBUG_PRIVILEGE) == false)
			{
				m_dwInitStatusCode = INIT_ERR_DEBUG_PRIV_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Request debug priv step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer4: %u", kTimer.diff());

			// Required for hidden memory executor
			if (NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->RequestPrivilege(SE_INCREASE_QUOTA_PRIVILEGE) == false && !g_winAPIs->IsDebuggerPresent())
			{
				m_dwInitStatusCode = INIT_ERR_INCREASE_QUOTA_PRIV_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Request increase quota priv step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer5: %u", kTimer.diff());

			if (CAntiBreakpoint::HasMemoryBreakpoint())
			{
				m_dwInitStatusCode = INIT_ERR_MEMBP_CHECK_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Anti memory bp check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer6: %u", kTimer.diff());

			if (CExceptionHandlers::InitExceptionHandlers() == false)
			{
				m_dwInitStatusCode = INIT_ERR_EXCEPTION_HANDLER_SETUP_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Exception handler setup step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer7: %u", kTimer.diff());

			// Check process packed status
			const auto stExecutable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
			const auto bPackedResult = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsPackedExecutable(stExecutable);
			APP_TRACE_LOG(LL_SYS, L"Main process packed result: %d", bPackedResult ? 1 : 0);
			NoMercyCore::CApplication::Instance().DataInstance()->SetPackedProcess(bPackedResult);

#ifdef __EXPERIMENTAL__
			if (!bPackedResult)
			{
				m_dwInitStatusCode = INIT_ERR_NON_PACKED_HOST_APP;
				break;
			}
#endif
			APP_TRACE_LOG(LL_SYS, L"Packer check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer8: %u", kTimer.diff());

			// Check wow64 callgate redirection
			if (stdext::is_wow64())
			{
				const auto pCurrTeb = NtCurrentTeb();
				if (pCurrTeb && pCurrTeb->WOW32Reserved)
				{
					// Disables file system redirection for the calling thread.
					PVOID OldValue = nullptr;
					if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
					{
						wchar_t wszSystemDirectory[MAX_PATH]{ L'\0' };
						g_winAPIs->GetSystemDirectoryW(wszSystemDirectory, MAX_PATH);

						const auto stWow64Cpu = stdext::to_lower_wide(wszSystemDirectory) + xorstr_(L"\\wow64cpu.dll");
						if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stWow64Cpu))
						{
							const auto stWow32Owner = m_spFunctions->GetModuleOwnerName(NtCurrentProcess(), pCurrTeb->WOW32Reserved);
							APP_TRACE_LOG(LL_SYS, L"stWow32Owner: %s --- stWow64Cpu: %s", stWow32Owner.c_str(), stWow64Cpu.c_str());

							if (stWow64Cpu != stWow32Owner)
							{
								m_dwInitStatusCode = INIT_ERR_WOW64_RDR_CHECK_FAIL;
								break;
							}
						}

						// Restore file system redirection for the calling thread.
						NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
					}

					// Check opcode of the callgate
					const auto pOpcode = reinterpret_cast<const BYTE*>(pCurrTeb->WOW32Reserved);
					if (pOpcode && pOpcode[0] != 0xEA)
					{
						APP_TRACE_LOG(LL_WARN, L"Wow64 callgate opcode is malformed: 0x%X", pOpcode[0]);

						/*
						m_dwInitStatusCode = INIT_ERR_WOW64_CALLGATE_CHECK_FAIL;
						break;
						*/
					}
				}
			}
			APP_TRACE_LOG(LL_SYS, L"Wow64 callgate check step completed!");

			// Watchdog timer
			auto ntStatus = g_winAPIs->RtlCreateTimer(m_hTimerQueue, &m_hWatchdogTimer, WatchdogRoutine, NULL, 0, 3000, WT_EXECUTELONGFUNCTION);
			if (!NT_SUCCESS(ntStatus) || !IS_VALID_HANDLE(m_hWatchdogTimer))
			{
				m_dwInitStatusCode = INIT_ERR_WATCHDOG_TIMER_SETUP_FAIL;
				break;
			}
			APP_TRACE_LOG(LL_SYS, L"Watchdog timer created! Handle: %p", m_hWatchdogTimer);

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer9: %u", kTimer.diff());

			const auto dwAppType = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
			const auto dwGameCode = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
			if (/* dwAppType == NM_STANDALONE || */ dwGameCode == GAME_CODE_DUMMYAPP)
			{
				StartClientInitThreadRoutine(this);
			}
			else
			{
				// Run other initialization steps in a separate thread for performance
				const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_CLIENT_INIT, StartClientInitThreadRoutine, (void*)this, 0, true);
				if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
				{
					m_dwInitStatusCode = INIT_FATAL_CLIENT_INIT_THREAD_CREATE_FAIL;
					m_dwInitSubErrorCode = g_winAPIs->GetLastError();
					break;
				}

				APP_TRACE_LOG(LL_SYS, L"Client init threda info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
					thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
				);
			}

			NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->CloseSplashImage();
		} while (false);

		APP_TRACE_LOG(LL_SYS, L"InitializeClient routine completed! Status: %u", m_dwInitStatusCode);

		// LogfA(CUSTOM_LOG_FILENAME_A, "Timer0: %u", kTimer.diff());

		// Complete
		if (m_dwInitStatusCode == INIT_STATUS_UNDEFINED)
		{
			m_dwInitStatusCode = INIT_STATUS_SUCCESS;
			return true;
		}
		else if (m_dwInitStatusCode == INIT_STATUS_SUCCESS)
		{
			return true;
		}

		return false;
	}

	// -----------------

	// Run some client side checks only for current(connected to server) client
	bool CApplication::RunClientSingleScanInstances()
	{
		APP_TRACE_LOG(LL_SYS, L"Run single scan instances routine started!");

		// ...

		// FIXME: blocking sentry crash handling
		/*
		// Run debug message monitor
		if (m_spWinDebugStrMonitor->Initialize() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WIN_DEBUG_STR_MON_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		*/

		return true;
	}

	bool CApplication::InitializeClientThreads()
	{		
		APP_TRACE_LOG(LL_SYS, L"Initialize client thread routine started");

//		return true;

		// Initialize cheat queue
		if (m_spCheatQueue->InitializeThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_QUEUE_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Cheat queue thread initialized.");

		// Initialize cheat queue manager
		if (m_spCheatQueueManager->InitializeThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_QUEUE_MGR_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Cheat queue manager thread initialized.");

		/*
		// FIXME: Possible crash
		// Run tick counter scan for HV checks
		if (m_spTickCounter->InitializeThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_TICK_COUNTER_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Initialize tick counter thread completed");
		*/

		// Run macro prevention with global message hook
		if (g_winAPIs->IsDebuggerPresent() == false)
		{
			if (CAntiMacro::InitAntiMacro() == false)
			{
				CApplication::Instance().OnCloseRequest(EXIT_ERR_ANTI_MACRO_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
				return false;
			}
		}
		APP_TRACE_LOG(LL_SYS, L"Initialize anti macro thread completed");

		// Check memory section-es integritys
		if (m_spGameRegionMonitor->InitializeMonitorThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SOFTBP_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Initialize game region monitor thread completed");

		// Run module integrity monitor(software breakpoint scanner, codecave scanner etc)
		if (m_spModuleSectionMonitor->InitializeMonitorThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CHECKSUM_SCAN_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Initialize module section monitor thread completed");

		// Run scanner manager thread
		if (m_spScannerInterface->InitializeScanner() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SCANNER_MGR_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Scanner interface initialized.");

		auto hScanProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_winAPIs->GetCurrentProcessId());
		if (!IS_VALID_HANDLE(hScanProcess))
			hScanProcess = g_winAPIs->GetCurrentProcess();

		CApplication::Instance().ScannerInstance()->InitializeMemoryWatchdogs(hScanProcess);
		CApplication::Instance().GameRegionMonitorInstance()->AddProcessToCheckList(hScanProcess);
		CApplication::Instance().ModuleSectionMonitorInstance()->AddProcessToCheckList(hScanProcess);

		// Run manual map scanner thread
		if (m_spManualMapScanner->InitializeThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_MMAP_SCANNER_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Manual map scanner initialized.");

		// Run Async WMI watcher queries
		if (m_spWMIManager->InitWMIWatcher() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WMI_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Initialize WMI watcher completed.");

		// Run filter manager thread
		if (m_spFilterMgr->Initialize() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_FILTER_MGR_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Filter manager initialized.");

		// Run window watcher thread
		if (m_spWindowWatcher->Initialize() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WINDOW_WATCHER_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Window watcher initialized.");

		if (!CApplication::Instance().IsHooksInitialized())
		{
			CApplication::Instance().SetHooksInitialized();

			if (CApplication::Instance().SelfHooksInstance()->InitializeSelfAPIHooks() == false)
			{
				APP_TRACE_LOG(LL_ERR, L"Self inline hooks initialize failed!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_INIT_HOOKS_FAIL, g_winAPIs->GetLastError());
				return false;
			}

			if (CApplication::Instance().AccessHelperInstance()->SetMitigationPolicys() == false)
			{
				APP_TRACE_LOG(LL_ERR, L"Set mitigation policys failed!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_MITIGATION_INIT_FAIL, g_winAPIs->GetLastError());
				return false;
			}

#ifdef __EXPERIMENTAL__
			if (InitMemoryAccessDetector(g_winModules->hBaseModule) == false)
			{
				APP_TRACE_LOG(LL_ERR, L"Memory access detector initialize failed!");
			}
#endif
		}

		// Run first time scans from cheat DB
		uint8_t pFailStep = 0;
		if (CApplication::Instance().ScannerInstance()->RunFirstTimeScans(pFailStep) == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_LOCAL_FILE_PARSE_FAIL, pFailStep);
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"First time scans succesfully completed");



		// Run client check routines thread
		if (InitializeClientMainCheckThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_MAIN_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		// Run tick checker thread for check self created threads identifier
		if (m_spSelfThreadIdentifier->InitThreadTickChecker() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_TICK_CHECK_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Initialize main check thread routine completed");
		return true;
	}
};
