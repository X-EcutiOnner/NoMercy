#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"

namespace NoMercy
{
	BOOL CALLBACK DesktopChildWindowEnumerator(HWND hwnd, LPARAM lparam)
	{
		CApplication::Instance().ScannerInstance()->WindowScanner()->ScanAsync(hwnd);

		g_winAPIs->Sleep(1);
		return TRUE;
	}
	BOOL CALLBACK DesktopWindowEnumerator(HWND hwnd, LPARAM lParam)
	{
		CApplication::Instance().ScannerInstance()->WindowScanner()->ScanAsync(hwnd);

		g_winAPIs->EnumChildWindows(hwnd, DesktopChildWindowEnumerator, NULL);

		g_winAPIs->Sleep(1);
		return TRUE;
	}
	BOOL CALLBACK DesktopEnumerator(LPWSTR desk, LPARAM lParam)
	{
		auto hDesktop = g_winAPIs->OpenDesktopW(desk, 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
		if (hDesktop)
		{
			auto hCurrentDeskop = g_winAPIs->GetThreadDesktop(g_winAPIs->GetCurrentThreadId());

			g_winAPIs->SetThreadDesktop(hDesktop);
			g_winAPIs->EnumDesktopWindows(hDesktop, &DesktopWindowEnumerator, lParam);
			g_winAPIs->SetThreadDesktop(hCurrentDeskop);
			g_winAPIs->CloseDesktop(hDesktop);
		}
		return TRUE;
	}
	BOOL CALLBACK WinStationEnumerator(LPWSTR winsta, LPARAM lParam)
	{
		auto hwCurrentStation = g_winAPIs->GetProcessWindowStation();
		if (hwCurrentStation)
		{
			auto hwTargetStation = g_winAPIs->OpenWindowStationW(winsta, FALSE, WINSTA_ENUMDESKTOPS);
			if (hwTargetStation)
			{
				if (g_winAPIs->SetProcessWindowStation(hwTargetStation))
				{
					g_winAPIs->EnumDesktopsW(hwTargetStation, &DesktopEnumerator, lParam);
					g_winAPIs->SetProcessWindowStation(hwCurrentStation);
				}
				g_winAPIs->CloseWindowStation(hwTargetStation);
			}
		}
		return TRUE;
	}


	IWindowScanner::IWindowScanner()
	{
	}
	IWindowScanner::~IWindowScanner()
	{
	}

	bool IWindowScanner::IsScanned(HWND hWnd)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_WINDOW, fmt::format(xorstr_(L"{0}"), fmt::ptr(hWnd)));
	}
	void IWindowScanner::AddScanned(HWND hWnd)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_WINDOW, fmt::format(xorstr_(L"{0}"), fmt::ptr(hWnd)));
	}

	void IWindowScanner::ScanSync(HWND hWnd)
	{
		SCANNER_LOG(LL_SYS, L"Window scanner has been started! Target wnd: %p", hWnd);
		
		const auto vecWindowBlacklist = CApplication::Instance().QuarentineInstance()->WindowQuarentine()->GetBlacklist();
		if (vecWindowBlacklist.empty())
			return;

		if (!hWnd)
			return;

		if (IsScanned(hWnd))
		{
			SCANNER_LOG(LL_SYS, L"Window: %p already scanned!", hWnd);
			return;
		}
		AddScanned(hWnd);

		if (!g_winAPIs->IsWindow(hWnd))
		{
			SCANNER_LOG(LL_WARN, L"Window: %p is not a valid window!", hWnd);
			return;
		}

		auto dwProcessId = 0UL;
		const auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessId);

		if (!dwProcessId || !dwThreadId)
		{
			SCANNER_LOG(LL_ERR, L"Window: %p has invalid process or thread id! Error: %u", hWnd, g_winAPIs->GetLastError());
			return;
		}

		WINDOWINFO wi{ 0 };
		if (!GetWindowInfoSafe(hWnd, &wi))
		{
			SCANNER_LOG(LL_ERR, L"GetWindowInfoSafe for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
			return;
		}

		const auto stOwnerProc = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);
		const auto bVisible = g_winAPIs->IsWindowVisible(hWnd);
		const auto bMinimized = g_winAPIs->IsIconic(hWnd);
		const auto bStucked = g_winAPIs->IsHungAppWindow(hWnd);

		DWORD dwAffinity = 0;
		const auto bCanAffinityCheck = !!g_winAPIs->GetWindowDisplayAffinity;
		if (bCanAffinityCheck && !g_winAPIs->GetWindowDisplayAffinity(hWnd, &dwAffinity))
		{
			SCANNER_LOG(LL_WARN, L"GetWindowDisplayAffinity for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
		}

		wchar_t wszOwnerModule[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->GetWindowModuleFileNameW(hWnd, wszOwnerModule, MAX_PATH))
		{
			SCANNER_LOG(LL_WARN, L"GetWindowModuleFileNameA for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
		}

		wchar_t wszTitle[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH))
		{
			SCANNER_LOG(LL_WARN, L"GetWindowTextA for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
		}
		const auto wstTitleName = stdext::to_lower_wide(wszTitle);

		wchar_t wszClassName[MAX_PATH]{ L'\0' };
		if (g_winAPIs->GetClassNameW(hWnd, wszClassName, MAX_PATH))
		{
			SCANNER_LOG(LL_SYS, L"Window: %p has class name: %s", hWnd, wszClassName);
		}
		const auto wstClassName = stdext::to_lower_wide(wszClassName);

		uint8_t byWndBaseCopy[12]{ 0x0 };
		const auto pkWndBase = g_winAPIs->GetWindowLongW(hWnd, GWL_WNDPROC);
		if (!pkWndBase)
		{
			SCANNER_LOG(LL_WARN, L"GetWindowLongA for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
		}
		else
		{
			SafeHandle pkProcess = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(PROCESS_VM_READ, dwProcessId);
			if (!IS_VALID_HANDLE(pkProcess.get()))
			{
				SCANNER_LOG(LL_ERR, L"Open window owner process: %u failed with error: %u", dwProcessId, g_winAPIs->GetLastError());
			}
			else
			{
				SIZE_T cbReadSize = 0;
				const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
					pkProcess.get(), (PVOID64)pkWndBase, &byWndBaseCopy, sizeof(byWndBaseCopy), &cbReadSize
				);
				if (!NT_SUCCESS(ntStatus))
				{
					SCANNER_LOG(LL_ERR, L"Read window owner process: %u window base mem: %p failed with error: %u", dwProcessId, pkWndBase, g_winAPIs->GetLastError());
				}
			}
		}
		const auto stMemCopy = stdext::dump_hex(byWndBaseCopy, sizeof(byWndBaseCopy));

		APP_TRACE_LOG(LL_SYS,
			L"Window ptr: %p Owner: %s(%u) Thread: %u Visible: %d-%d-%d Wnd (%s/%s) Base: %p (%s) Affinity: %d (%u)",
			hWnd, stOwnerProc.c_str(), dwProcessId, dwThreadId, bVisible, bMinimized, bStucked, wszTitle, wszClassName,
			pkWndBase, stMemCopy.c_str(), bCanAffinityCheck ? 1 : 0, dwAffinity
		);

		for (const auto& [obj, opts] : vecWindowBlacklist)
		{
			if (!obj.class_name.empty() && obj.class_name == wstClassName)
			{
				const auto details = fmt::format(xorstr_(L"#{0}>{1}({2})"), obj.idx, obj.class_name, wstClassName);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WINDOW_SCAN, obj.idx, details);
				break;
			}
			else if (!obj.window_name.empty() && obj.window_name == wstTitleName)
			{
				const auto details = fmt::format(xorstr_(L"#{0}>{1}({2})"), obj.idx, obj.window_name, wstTitleName);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WINDOW_SCAN, obj.idx, details);
				break;
			}

			// TODO: Other matching criteria
		}

		// Forward to overlay scan
		this->ScanOverlayWindow(hWnd);

		// Forward to process scan
		CApplication::Instance().ScannerInstance()->ProcessScanner()->ScanAsync(dwProcessId);
	}

	void IScanner::CheckGameWindows()
	{
		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			SCANNER_LOG(LL_ERR, L"Create window enumerator failed! Error: %u", errno);
			return;
		}

		auto vWindows = windowEnumerator->EnumerateWindowsNative();
		if (vWindows.empty())
		{
			vWindows = windowEnumerator->EnumerateWindows();
			if (vWindows.empty())
			{
				SCANNER_LOG(LL_ERR, L"Enumerate windows failed! Have not found any window!");
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MALFORMED_SYS_QUERY_RESULT, MALFORMED_RESULT_WINDOW_SCAN, std::to_wstring(g_winAPIs->GetLastError()));
				return;
			}
		}
		
		DWORD dwVisibleWindowCounter = 0UL;

		for (const auto& hWnd : vWindows)
		{
			DWORD dwProcessID = 0;
			g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessID);
			if (dwProcessID != g_winAPIs->GetCurrentProcessId())
				continue;
			
			if (this->WindowScanner())
				this->WindowScanner()->ScanSync(hWnd);
			
			if (g_winAPIs->IsWindowVisible(hWnd))
			{
				dwVisibleWindowCounter++;

				wchar_t wszOwnerModule[MAX_PATH]{ L'\0' };
				if (!g_winAPIs->GetWindowModuleFileNameW(hWnd, wszOwnerModule, MAX_PATH))
				{
					SCANNER_LOG(LL_ERR, L"GetWindowModuleFileNameA for: %p failed with error: %u", hWnd, g_winAPIs->GetLastError());
					continue;
				}

				SCANNER_LOG(LL_SYS, L"Window: %p has owner module: %s", hWnd, wszOwnerModule);

				const auto stOwnerModule = stdext::to_lower_ansi(wszOwnerModule);
				const auto stExecutable = stdext::to_lower_ansi(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeName());

				if (stOwnerModule.find(stExecutable) == std::wstring::npos)
				{
					SCANNER_LOG(LL_ERR, L"Window: %p has owner module: %s, but it is not executable: %s", hWnd, wszOwnerModule, stExecutable.c_str());
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_UNKNOWN_GAME_WINDOW, 0, wszOwnerModule);
				}
			}
		}

		if (!dwVisibleWindowCounter)
		{
			SCANNER_LOG(LL_ERR, L"Have not found any visible window!");
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MALFORMED_SYS_QUERY_RESULT, MALFORMED_RESULT_WINDOW_SCAN, std::to_wstring(g_winAPIs->GetLastError()));
		}
	}

	bool IWindowScanner::ScanProcessWindows(HANDLE hProcess)
	{
		const auto dwTargetPID = g_winAPIs->GetProcessId(hProcess);
		if (!dwTargetPID)
		{
			SCANNER_LOG(LL_ERR, L"GetProcessId for: %p failed with error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}
		
		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			SCANNER_LOG(LL_ERR, L"Create window enumerator failed! Error: %u", errno);
			return false;
		}
		
		const auto vWindows = windowEnumerator->EnumerateWindows(dwTargetPID);
		if (vWindows.empty())
		{
			SCANNER_LOG(LL_WARN, L"Enumerate windows failed! Have not found any window for: %u", dwTargetPID);
			return false;
		}

		for (const auto& hWnd : vWindows)
			ScanAsync(hWnd);

		return true;
	}

	bool IWindowScanner::ScanAll(/* bool bExtended */)
	{
		bool bExtended = false;
		
		SCANNER_LOG(LL_SYS, L"Window scanner started! Ext: %d", bExtended ? 1 : 0);

		if (bExtended)
		{
			if (!g_winAPIs->EnumWindowStationsW(&WinStationEnumerator, 0))
			{
				SCANNER_LOG(LL_ERR, L"EnumWindowStationsW failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}
		else
		{
			const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
			if (!IS_VALID_SMART_PTR(windowEnumerator))
			{
				SCANNER_LOG(LL_ERR, L"Create window enumerator failed! Error: %u", errno);
				return false;
			}
			
			auto vWindows = windowEnumerator->EnumerateWindows();
			if (vWindows.empty())
			{
				vWindows = windowEnumerator->EnumerateWindows();
				if (vWindows.empty())
				{
					SCANNER_LOG(LL_ERR, L"Enumerate windows failed! Have not found any window!");
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MALFORMED_SYS_QUERY_RESULT, MALFORMED_RESULT_WINDOW_SCAN, std::to_wstring(g_winAPIs->GetLastError()));
					return false;
				}
			}

			for (const auto& hWnd : vWindows)
			{
				ScanAsync(hWnd);

				// TODO: check menus
				//  GetMenu/GetMenuItemCount/GetMenuStringA/GetSubMenu
			}
		}

		return true;
	}

	void IScanner::CheckWindowHeuristic()
	{
		SCANNER_LOG(LL_SYS, L"Checking window heuristic...");
		
		const auto vecWindowBlacklist = CApplication::Instance().QuarentineInstance()->WindowQuarentine()->GetBlacklist();
		if (vecWindowBlacklist.empty())
			return;

		for (int qy = 0; qy < 100; qy++)
		{
			for (int qx = 0; qx < 100; qx++)
			{
				POINT p{ 0 };
				p.x = qx * 20;
				p.y = qy * 20;

				const auto hWnd = g_winAPIs->WindowFromPoint(p);
				if (!hWnd)
					continue;

				wchar_t wszWndTitle[MAX_PATH]{ '\0' };
				if (g_winAPIs->GetWindowTextW(hWnd, wszWndTitle, MAX_PATH) && wszWndTitle[0] != L'\0')
				{
					const auto wstWndTitle = stdext::to_lower_wide(wszWndTitle);

					for (const auto& [obj, opts] : vecWindowBlacklist)
					{
						if (wstWndTitle.find(obj.window_name) != std::wstring::npos)
						{
							APP_TRACE_LOG(LL_ERR, L"Blaclisted window name found: %s(%s)", wstWndTitle.c_str(), obj.window_name.c_str());
							const auto details = fmt::format(xorstr_(L"1--#{0}>{1}({2})"), obj.idx, obj.window_name, wstWndTitle);
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WINDOW_HEURISTIC, obj.idx, details);
							break;
						}
					}
				}
				else
				{
					SCANNER_LOG(LL_ERR, L"GetWindowTextA failed with error: %u", g_winAPIs->GetLastError());
				}
			}
		}
	}

	void IScanner::CheckForegroundWindowOwners()
	{
		SCANNER_LOG(LL_SYS, L"Checking foreground window owners...");
		
		const auto vecWindowBlacklist = CApplication::Instance().QuarentineInstance()->WindowQuarentine()->GetBlacklist();
		if (vecWindowBlacklist.empty())
			return;

		auto mapWindows = std::map <HWND, std::wstring>();
		mapWindows.emplace(g_winAPIs->GetDesktopWindow(), xorstr_(L"GetDesktopWindow"));
		mapWindows.emplace(g_winAPIs->GetForegroundWindow(), xorstr_(L"GetForegroundWindow"));
		mapWindows.emplace(g_winAPIs->GetShellWindow(), xorstr_(L"GetShellWindow"));
		mapWindows.emplace(g_winAPIs->GetTopWindow(0), xorstr_(L"GetTopWindow"));
		mapWindows.emplace(g_winAPIs->GetActiveWindow(), xorstr_(L"GetActiveWindow"));
		mapWindows.emplace(g_winAPIs->FindWindowExW(0, 0, xorstr_(L"Progman"), xorstr_(L"Program Manager")), L"Progman");

		uint32_t idx = 0;
		for (const auto& [hWnd, stWindowName] : mapWindows)
		{
			if (hWnd)
			{
				wchar_t wszWndTitle[MAX_PATH]{ L'\0' };
				if (g_winAPIs->GetWindowTextW(hWnd, wszWndTitle, MAX_PATH))
				{
					const auto wstWndTitle = stdext::to_lower_wide(wszWndTitle);
					SCANNER_LOG(LL_SYS, L"Checking window: %s (%S)", wstWndTitle.c_str(), stWindowName.c_str());
					
					for (const auto& [obj, opts] : vecWindowBlacklist)
					{
						if (wstWndTitle.find(obj.window_name) != std::wstring::npos)
						{
							const auto details = fmt::format(xorstr_(L"#{0}>{1}({2})"), obj.idx, obj.window_name, wstWndTitle);
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_FOREGROUND_WINDOW, obj.idx, details);
							break;
						}
					}
				}
				else
				{
					SCANNER_LOG(LL_ERR, L"GetWindowTextA failed with error: %u", g_winAPIs->GetLastError());
				}
			}
		}
	}
};
