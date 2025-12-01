#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Watchdog.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	extern void CallHwbpTrapFuncs();

	LRESULT CALLBACK HookWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		auto fnCallOriginalWndProcEx = [&](WNDPROC pWndProc) -> LRESULT {
			if (g_winAPIs->IsWindowUnicode(hWnd))
				return g_winAPIs->CallWindowProcW(pWndProc, hWnd, uMsg, wParam, lParam);
			else
				return g_winAPIs->CallWindowProcA(pWndProc, hWnd, uMsg, wParam, lParam);
		};
		auto fnSafeCallOriginalWndProc = [&](WNDPROC pWndProc) -> LRESULT {
			__try
			{
				return fnCallOriginalWndProcEx(pWndProc);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return 0;
			}
		};

		static auto mBackups = CApplication::Instance().WatchdogInstance()->GetWindowBackups();
		auto it = mBackups.find(hWnd);
		if (it == mBackups.end())
		{
			APP_TRACE_LOG(LL_ERR, L"Window not found in backup list: %p", hWnd);
			
			if (g_winAPIs->IsWindowUnicode(hWnd))
				return g_winAPIs->DefWindowProcW(hWnd, uMsg, wParam, lParam);
			else
				return g_winAPIs->DefWindowProcA(hWnd, uMsg, wParam, lParam);
		}

		if ((uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST) ||
			(uMsg >= WM_KEYFIRST && uMsg <= WM_KEYLAST) ||
			(uMsg >= WM_TOUCH && uMsg <= WM_POINTERWHEEL))
		{
			INPUT_MESSAGE_SOURCE src;
			if (IsWindows8OrGreater() && g_winAPIs->GetCurrentInputMessageSource(&src))
			{
				if (src.originId == IMO_INJECTED)
				{
					APP_TRACE_LOG(LL_TRACE, L"Injected message: %u from device: %p origin: %p", uMsg, src.deviceType, src.originId);
					uMsg = WM_NULL;
				}
			}
		}
		
		static auto pWatchdogTimer = CStopWatch<std::chrono::milliseconds>();

		static auto i = 0;
		if (pWatchdogTimer.diff() > 10000)
		{
			if (i >= INT_MAX - 1)
				i = 0;

//#ifdef __EXPERIMENTAL__
			if (stdext::is_debug_env() == false && 
				IS_VALID_SMART_PTR(CApplication::Instance().HwbpWatcherInstance()) &&
				CApplication::Instance().HwbpWatcherInstance()->IsInitialized() == false)
			{
				if (CApplication::Instance().HwbpWatcherInstance()->InitWatcher() == false)
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_WATCHER_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
					return false;
				}
			}
//#endif
			
			// APP_TRACE_LOG(LL_SYS, L"Watchdog event called [%d] - Window: 0x%X Proc: 0x%X", i++, hWnd, mBackups[hWnd]);

			// Skip checking in idle
			if (g_winAPIs->IsHungAppWindow(hWnd) || g_winAPIs->IsIconic(hWnd))
			{
				// APP_TRACE_LOG(LL_TRACE, L"Window is hung or minimized: 0x%X", hWnd);
				return fnSafeCallOriginalWndProc(it->second);
			}
			
			// Current process thread tick checker thread validator
			if (CApplication::Instance().SelfThreadIdentifierInstance()->IsTickCheckerThreadIntegrityCorrupted())
			{
				APP_TRACE_LOG(LL_ERR, L"Tick checker thread integrity check fail!");

				CApplication::Instance().OnCloseRequest(EXIT_ERR_TICK_CHECKER_THREAD_CORRUPTED, g_winAPIs->GetLastError());
				return 0;
			}

//#ifdef __EXPERIMENTAL__
			// Trigger HWBP watcher trap
			CallHwbpTrapFuncs();
//#endif

			// Set flag
			const auto dwTimeStamp = CApplication::Instance().FunctionsInstance()->GetCurrentTimestamp();
			CApplication::Instance().WatchdogInstance()->SetLastCheckTime(dwTimeStamp);

			// Reset timer
			pWatchdogTimer.reset();

			APP_TRACE_LOG(LL_SYS, L"Watchdog event succesfully completed [%d] - TID: %u Window: 0x%X Proc: 0x%X. Timer cleaned.", i, g_winAPIs->GetCurrentThreadId(), hWnd, mBackups[hWnd]);
		}

		return fnSafeCallOriginalWndProc(mBackups[hWnd]);
	}


	CWatchdog::CWatchdog() :
		m_bInitialized(false), m_iWatchDogCheckCount(0), m_dwLastCheckTime(0)
	{
		m_windowBackupMap.clear();
	}

	bool CWatchdog::LoadWatchdog()
	{
		// Start timers
		m_watchdogTimer.reset();
		m_tickCheckTimer.reset();

		if (!CApplication::InstancePtr() || CApplication::Instance().AppCloseTriggered() || CApplication::Instance().AppIsFinalized())
			return true;

		// Create window enumerator
		auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto vWindows = windowEnumerator->EnumerateWindows(g_winAPIs->GetCurrentProcessId());
		if (vWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Can not found any window for: %u", g_winAPIs->GetCurrentProcessId());
			return false;
		}

		// Enum windows
		bool bWatchdogCreatedToAnyWindow = false;
		for (auto hWnd : vWindows)
		{
			auto dwPID = 0UL;
			auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwPID);
			if (dwThreadId == g_winAPIs->GetCurrentThreadId())
				continue;

			if (!g_winAPIs->IsWindowVisible(hWnd))
				continue;

			if (g_winAPIs->IsIconic(hWnd))
				continue;

			wchar_t wszTitle[MAX_PATH]{ L'\0' };
			g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);
#ifdef _DEBUG
			if (wcsstr(wszTitle, L"debug console"))
				continue;
#endif

			auto lptrResult = g_winAPIs->GetWindowLongW(hWnd, GWL_WNDPROC);
			if (!lptrResult)
			{
				APP_TRACE_LOG(LL_ERR, L"GetWindowLongA fail! Last error: %u Target hwnd: %p", g_winAPIs->GetLastError(), hWnd);
				continue;
			}

			if (m_windowBackupMap.find(hWnd) != m_windowBackupMap.end() /* current loop window's watchdog ptr already has backup */ &&
				m_windowBackupMap[hWnd] == &HookWndProc /* current loop window's backup equal to our hooked wndproc */)
			{
				APP_TRACE_LOG(LL_SYS, L"Watchdog is already created! Skipped on this window! Hwnd: %p", hWnd);
				continue;
			}

			// Create watchdog
			if (lptrResult != reinterpret_cast<LONG_PTR>(&HookWndProc))
			{
				APP_TRACE_LOG(LL_SYS, L"Non-protected window found! Watchdog creation has been started! Hwnd: %p", hWnd);

				auto lpOldProc = reinterpret_cast<WNDPROC>(g_winAPIs->SetWindowLongA(hWnd, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&HookWndProc)));
				m_windowBackupMap.emplace(hWnd, lpOldProc);

				APP_TRACE_LOG(LL_SYS, L"Watchdog successfully created to: %p(%s)", hWnd, wszTitle);
			}

			// Check new window result
			lptrResult = g_winAPIs->GetWindowLongW(hWnd, GWL_WNDPROC);
			if (!lptrResult)
			{
				APP_TRACE_LOG(LL_ERR, L"GetWindowLongA(Second attempt) fail! Last error: %u Target hwnd: %p", g_winAPIs->GetLastError(), hWnd);
				continue;
			}

			if (lptrResult != reinterpret_cast<LONG_PTR>(&HookWndProc))
			{
				APP_TRACE_LOG(LL_ERR, L"Watchdog can NOT created to: %p(%s) Last Error: %u", hWnd, wszTitle, g_winAPIs->GetLastError());
				continue;
			}

			bWatchdogCreatedToAnyWindow = true;
		}

		APP_TRACE_LOG(LL_SYS, L"Watchdog creation completed!");
		return bWatchdogCreatedToAnyWindow;
	}

	bool CWatchdog::PreCheckLoadedWatchdogs()
	{
		if (!CApplication::InstancePtr() || CApplication::Instance().AppCloseTriggered() || CApplication::Instance().AppIsFinalized())
			return true;
		
		// Create window enumerator
		auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto vWindows = windowEnumerator->EnumerateWindows(g_winAPIs->GetCurrentProcessId());
		if (vWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Can not found any window for: %u", g_winAPIs->GetCurrentProcessId());
			return false;
		}

		// Enum windows
		bool bWatchdogCreatedToAnyWindow = false;
		for (const auto& hWnd : vWindows)
		{
			auto dwPID = 0UL;
			auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwPID);
			if (dwThreadId == g_winAPIs->GetCurrentThreadId())
				continue;

			if (g_winAPIs->IsWindowVisible(hWnd) == FALSE)
				continue;

			wchar_t wszTitle[MAX_PATH]{ L'\0' };
#ifdef _DEBUG
			g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);
			if (wcsstr(wszTitle, L"debug console"))
				continue;
#endif

			auto lptrResult = g_winAPIs->GetWindowLongW(hWnd, GWL_WNDPROC);
			if (!lptrResult)
			{
				APP_TRACE_LOG(LL_ERR, L"GetWindowLongA fail! Last error: %u Target hwnd: %p", g_winAPIs->GetLastError(), hWnd);
				return false;
			}

			auto hThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
			if (!IS_VALID_HANDLE(hThread))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenThread fail! Last error: %u Target thread: %u", g_winAPIs->GetLastError(), dwThreadId);
				return false;
			}

			auto dwThreadStartAddr = CThreadFunctions::GetThreadStartAddress(hThread);
			if (!dwThreadStartAddr)
			{
				APP_TRACE_LOG(LL_ERR, L"GetThreadStartAddress fail! Last error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hThread);
				return false;
			}

			auto wstThreadOwner = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress(dwThreadStartAddr));
			auto wstWndPtrOwner = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)lptrResult));

			APP_TRACE_LOG(LL_SYS, L"Current thread: %u Current window: %p(%s) Thread: %p(%s) Window ptr: %p(%s)",
				dwThreadId, hWnd, wszTitle, dwThreadStartAddr, wstThreadOwner.c_str(), lptrResult, wstWndPtrOwner.c_str()
			);

			if (NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() == GAME_CODE_METIN2)
			{
				if ((wstThreadOwner.find(xorstr_(L"user32.dll")) != std::wstring::npos && wstWndPtrOwner.find(xorstr_(L"mss32.dll")) != std::wstring::npos) ||
					wstWndPtrOwner.find(xorstr_(L"user32.dll")) != std::wstring::npos)
				{
					APP_TRACE_LOG(LL_SYS, L"Pre watchdog check passed, whitelisted module names.");
					g_winAPIs->CloseHandle(hThread);
					return true;
				}
			}
			
			const auto wstLowerAntiFilename = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFullName());
			const auto wstLowerExecutableFilename = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath());

			APP_TRACE_LOG(LL_SYS, L"Current module: %s Executable: %s", wstLowerAntiFilename.c_str(), wstLowerExecutableFilename.c_str());

			if (wstWndPtrOwner.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Can not found module name for window owner");
				g_winAPIs->CloseHandle(hThread);
				continue;
			}

			if (wstWndPtrOwner == wstLowerAntiFilename && (wstThreadOwner == wstLowerExecutableFilename || wstThreadOwner == wstLowerExecutableFilename))
			{
				APP_TRACE_LOG(LL_SYS, L"Pre watchdog check passed, owned module access.");
				g_winAPIs->CloseHandle(hThread);
				return true;
			}
			
			if (wstThreadOwner != wstWndPtrOwner && wstLowerExecutableFilename != wstWndPtrOwner)
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown watchdog owner: %s Thread: %s", wstWndPtrOwner.c_str(), wstThreadOwner.c_str());
				g_winAPIs->CloseHandle(hThread);
				return false;
			}

			g_winAPIs->CloseHandle(hThread);
		}

		APP_TRACE_LOG(LL_SYS, L"Watchdog check completed!");
		return true;
	}

	size_t CWatchdog::GetWatchdogCount()
	{
		return m_windowBackupMap.size();
	}

	bool CWatchdog::IsWatchdogWindow(HWND hWnd)
	{
		return m_windowBackupMap.find(hWnd) != m_windowBackupMap.end();
	}

	std::map <HWND, WNDPROC> CWatchdog::GetWindowBackups()
	{
		return m_windowBackupMap;
	}

	DWORD WINAPI InitializeWatchdogEx(LPVOID)
	{
		APP_TRACE_LOG(LL_TRACE, L"Watchdog thread event has been started");

		static bool s_bOnceWait = false;
		if (!s_bOnceWait)
		{
			g_winAPIs->Sleep(5000);
			s_bOnceWait = true;
		}

		// Check environment
		if (NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() == GAME_CODE_DUMMYAPP)
		{
			APP_TRACE_LOG(LL_SYS, L"Watchdog creation has been passed on test console!");
			CApplication::Instance().WatchdogInstance()->ReleaseWatchdogThread();
			return 0;
		}

		static int iAttemptCount = 0;

		auto ulCount = CApplication::Instance().WatchdogInstance()->GetWatchdogCount();
		if (ulCount == 0)
		{
			if (CApplication::Instance().WatchdogInstance()->PreCheckLoadedWatchdogs() == false)
			{
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WATCHDOG_CHECK_FAIL, g_winAPIs->GetLastError());
				return 0;
			}

			const auto bRet = CApplication::Instance().WatchdogInstance()->LoadWatchdog();
			if (bRet == false)
			{
				if (iAttemptCount++ > 3)
				{
					CApplication::Instance().WatchdogInstance()->SetInitilizationStatus(false);

					APP_TRACE_LOG(LL_ERR, L"Watchdog load fail!");
					CApplication::Instance().WatchdogInstance()->ReleaseWatchdogThread();
					return 0;
				}
			}
			else
			{
				CApplication::Instance().WatchdogInstance()->SetInitilizationStatus(true);
				APP_TRACE_LOG(LL_SYS, L"Watchdog succesfully loaded to: %d window(s)", CApplication::Instance().WatchdogInstance()->GetWatchdogCount());
			}
		}

		return 0;
	}

	bool CWatchdog::InitializeWatchdog()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_WATCHDOG, InitializeWatchdogEx, nullptr, 30000, true);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get());

		return true;
	}
	void CWatchdog::ReleaseWatchdogThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_WATCHDOG);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}

	void CWatchdog::CleanupWatchdog()
	{
		for (const auto& [hWnd, oldProc] : m_windowBackupMap)
		{
			g_winAPIs->SetWindowLongA(hWnd, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(oldProc));
		}

		m_windowBackupMap.clear();
	}
}
