#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "WindowWatcher.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	static std::vector <HWND> gs_vecKnownWindows;

	uint8_t GetErrorLevel(DWORD dwLastError)
	{
		return dwLastError == ERROR_FILE_NOT_FOUND ? LL_TRACE : LL_WARN;
	}

	void CALLBACK HandleWinEvent(HWINEVENTHOOK hook, DWORD dwEventCode, HWND hWnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
	{
		if (hWnd)
		{
			switch (dwEventCode)
			{
				// case EVENT_OBJECT_CREATE:
				case EVENT_OBJECT_REORDER:		// window create
				case EVENT_SYSTEM_MINIMIZEEND:	// window maximize
				{
					if (stdext::in_vector(gs_vecKnownWindows, hWnd))
					{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
						APP_TRACE_LOG(LL_SYS, L"Window event: %u for: %p", dwEventCode, hWnd);
#endif
						return;
					}
					gs_vecKnownWindows.emplace_back(hWnd);

					if (!g_winAPIs->IsWindow(hWnd))
					{
						const auto dwError = g_winAPIs->GetLastError();
						APP_TRACE_LOG(GetErrorLevel(dwError), L"IsWindow for: %p failed with error: %u", hWnd, dwError);
						return;
					}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
					APP_TRACE_LOG(LL_SYS, L"Window event: %u for: %p", dwEventCode, hWnd);
#endif

					// Quarentine check
					auto bWhitelisted = false;
					const auto vecWindowWhitelist = CApplication::Instance().QuarentineInstance()->WindowQuarentine()->GetWhitelist();
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
					APP_TRACE_LOG(LL_SYS, L"Window whitelist size: %u", vecWindowWhitelist.size());
#endif

					if (!vecWindowWhitelist.empty())
					{
						wchar_t wszTitle[MAX_PATH]{ L'\0' };
						if (!g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH))
						{
							const auto dwError = g_winAPIs->GetLastError();
							APP_TRACE_LOG(GetErrorLevel(dwError), L"GetWindowTextW for: %p failed with error: %u", hWnd, dwError);
						}
						const auto wstTitleName = stdext::to_lower_wide(wszTitle);

						wchar_t wszClassName[MAX_PATH]{ L'\0' };
						if (!g_winAPIs->GetClassNameW(hWnd, wszClassName, MAX_PATH))
						{
							const auto dwError = g_winAPIs->GetLastError();
							APP_TRACE_LOG(GetErrorLevel(dwError), L"GetClassNameW for: %p failed with error: %u", hWnd, dwError);
						}
						const auto wstClassName = stdext::to_lower_wide(wszClassName);

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
						APP_TRACE_LOG(LL_SYS, L"Window title: %s, class: %s", wstTitleName.c_str(), wstClassName.c_str());
#endif

						for (const auto& obj : vecWindowWhitelist)
						{
							if (!wstTitleName.empty() && !obj.window_name.empty() && wstTitleName.find(obj.window_name) != std::wstring::npos)
							{
								APP_TRACE_LOG(LL_WARN, L"Whitelisted window name found: %s(%s)", wstTitleName.c_str(), obj.window_name.c_str());
								bWhitelisted = true;
								break;
							}

							if (!wstClassName.empty() && !obj.class_name.empty() && wstClassName.find(obj.class_name) != std::wstring::npos)
							{
								APP_TRACE_LOG(LL_WARN, L"Whitelisted class name found: %s(%s)", wstClassName.c_str(), obj.class_name.c_str());
								bWhitelisted = true;
								break;
							}
						}
					}
					if (!bWhitelisted)
					{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
						APP_TRACE_LOG(LL_ERR, L"Window not whitelisted: %p", hWnd);
#endif

						const auto vecWindowBlacklist = CApplication::Instance().QuarentineInstance()->WindowQuarentine()->GetBlacklist();
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
						APP_TRACE_LOG(LL_SYS, L"Window blacklist size: %u", vecWindowBlacklist.size());
#endif

						if (!vecWindowBlacklist.empty())
						{
							wchar_t wszTitle[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH))
							{
								const auto dwError = g_winAPIs->GetLastError();
								APP_TRACE_LOG(GetErrorLevel(dwError), L"GetWindowTextW for: %p failed with error: %u", hWnd, dwError);
							}
							const auto wstTitleName = stdext::to_lower_wide(wszTitle);

							wchar_t wszClassName[MAX_PATH]{ L'\0' };
							if (!g_winAPIs->GetClassNameW(hWnd, wszClassName, MAX_PATH))
							{
								const auto dwError = g_winAPIs->GetLastError();
								APP_TRACE_LOG(GetErrorLevel(dwError), L"GetClassNameW for: %p failed with error: %u", hWnd, dwError);
							}
							const auto wstClassName = stdext::to_lower_wide(wszClassName);

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
							APP_TRACE_LOG(LL_SYS, L"Window title: %s, class: %s", wstTitleName.c_str(), wstClassName.c_str());
#endif

							for (const auto& [obj, opts] : vecWindowBlacklist)
							{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
								APP_TRACE_LOG(LL_SYS, L"Blacklisted window name: %s, class: %s", obj.window_name.c_str(), obj.class_name.c_str());
#endif

								const auto wstObjLowerTitle = stdext::to_lower_wide(obj.window_name);
								const auto wstObjLowerClass = stdext::to_lower_wide(obj.class_name);

								if (!wstTitleName.empty() && !obj.window_name.empty() && wstTitleName == wstObjLowerTitle)
								{
									APP_TRACE_LOG(LL_ERR, L"Blaclisted window name found: %s(%s)", wstTitleName.c_str(), wstObjLowerTitle.c_str());
									const auto details = fmt::format(xorstr_(L"2--#{0}>{1}({2})"), obj.idx, obj.window_name, wstTitleName);
									CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WINDOW_HEURISTIC, obj.idx, details);
									break;
								}

								if (!wstClassName.empty() && !obj.class_name.empty() && wstClassName == wstObjLowerClass)
								{
									APP_TRACE_LOG(LL_ERR, L"Blaclisted class name found: %s(%s)", wstClassName.c_str(), wstObjLowerClass.c_str());
									const auto details = fmt::format(xorstr_(L"3--#{0}>{1}({2})"), obj.idx, obj.class_name, wstClassName);
									CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WINDOW_HEURISTIC, obj.idx, details);
									break;
								}
							}
						}
					}
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
					APP_TRACE_LOG(LL_SYS, L"Window event: %u for: %p completed", dwEventCode, hWnd);
#endif

					// Game window check
					auto dwProcessId = 0UL;
					const auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessId);

					if (g_winAPIs->GetCurrentProcessId() == dwProcessId)
					{
						wchar_t wszFileName[MAX_PATH]{ L'\0' };
						g_winAPIs->GetWindowModuleFileNameW(hWnd, wszFileName, MAX_PATH);

						wchar_t wszExeName[MAX_PATH]{ L'\0' };
						g_winAPIs->GetModuleFileNameExW(NtCurrentProcess(), nullptr, wszExeName, MAX_PATH);

						auto wstWndFileName = stdext::to_lower_wide(wszFileName);
						auto wstExeName = stdext::to_lower_wide(wszExeName);

						APP_TRACE_LOG(LL_SYS, L"Game window: %p (%s) created to %u (%s)", hWnd, wstWndFileName.c_str(), dwProcessId, wstExeName.c_str());

						if (wstWndFileName == wstExeName)
							return;

						if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(wstWndFileName))
						{
							const auto wstModuleName = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(wstWndFileName));
							if (wstModuleName == xorstr_(L"mshtml.dll") || wstModuleName == xorstr_(L"libcef.dll"))
								return;
						}

						APP_TRACE_LOG(LL_ERR, L"Unknown game (%s) window owner: %s", wstExeName.c_str(), wstWndFileName.c_str());
						CApplication::Instance().OnCloseRequest(EXIT_ERR_UNKNOWN_GAME_WINDOW, 0, (void*)wstWndFileName.c_str());
					}

					if (CApplication::Instance().ScannerInstance())
					{
						CApplication::Instance().ScannerInstance()->OnWatcherWindowScan(hWnd, dwEventCode);
					}
				
				} break;
			}
		}
	}


	CWindowWatcher::CWindowWatcher() :
		m_bInitialized(false), m_hWndHandlerHook(nullptr)
	{
	}
	CWindowWatcher::~CWindowWatcher()
	{
	}

	DWORD CWindowWatcher::ThreadRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Window watcher thread event has been started");

		if (!m_bInitialized)
		{
			m_hWndHandlerHook = g_winAPIs->SetWinEventHook(EVENT_MIN, EVENT_MAX, NULL, HandleWinEvent, 0, 0, WINEVENT_OUTOFCONTEXT);
			if (!m_hWndHandlerHook)
			{
				APP_TRACE_LOG(LL_ERR, L"SetWinEventHook fail! Error: %u", g_winAPIs->GetLastError());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WinEventHook_FAIL, g_winAPIs->GetLastError());
				return 0;
			}

			APP_TRACE_LOG(LL_TRACE, L"Window watcher event succesfully initialized: %p", m_hWndHandlerHook);
			m_bInitialized = true;
		}

		static auto pCheckTimer = CStopWatch<std::chrono::milliseconds>();

		MSG msg{};
		while (g_winAPIs->PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
		{
			g_winAPIs->Sleep(10);

			g_winAPIs->TranslateMessage(&msg);
			g_winAPIs->DispatchMessageW(&msg);

			if (pCheckTimer.diff() > 5000)
				break;
		}

		pCheckTimer.reset();
		return 0;
	}

	DWORD WINAPI CWindowWatcher::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CWindowWatcher*>(lpParam);
		return This->ThreadRoutine();
	}

	bool CWindowWatcher::Initialize()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_WINDOW_CHECK, StartThreadRoutine, this, 5000, false);
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

	void CWindowWatcher::Release()
	{
		if (m_hWndHandlerHook)
		{
			g_winAPIs->UnhookWinEvent(m_hWndHandlerHook);
			m_hWndHandlerHook = nullptr;
		}

		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_WINDOW_CHECK);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
}
