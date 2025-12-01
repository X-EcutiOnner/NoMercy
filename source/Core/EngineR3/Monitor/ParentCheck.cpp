#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Anti/AntiDebug.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../../Common/StdExtended.hpp"

namespace NoMercy
{
	inline bool GetExplorerPIDbyProgman(LPDWORD pdwExplorerPID)
	{
		const auto hWnd = g_winAPIs->FindWindowExW(NULL, NULL, xorstr_(L"Progman"), NULL);
		if (!hWnd)
			return false;

		auto dwPID = 0UL;
		const auto dwTID = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwPID);
		if (!dwTID || !dwPID)
			return false;

		if (pdwExplorerPID)
			*pdwExplorerPID = dwPID;
		return true;
	}
	inline bool GetExplorerPIDbyShellWindow(LPDWORD pdwExplorerPID)
	{
		const auto hWnd = g_winAPIs->GetShellWindow();
		if (!hWnd)
			return false;

		auto dwPID = 0UL;
		const auto dwTID = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwPID);
		if (!dwTID || !dwPID)
			return false;

		if (pdwExplorerPID)
			*pdwExplorerPID = dwPID;
		return true;
	}

	inline bool ParentOfParentPIDIsLegit(HANDLE hOwnProcess, DWORD dwProcessId)
	{
		// Process informations
		const auto dwParentPid = CProcessFunctions::GetParentProcessIdNative(hOwnProcess);
		if (!dwParentPid) 
		{
			APP_TRACE_LOG(LL_ERR, L"Parent of parent pid is null! Last error: %u", g_winAPIs->GetLastError());
			return true;
		}

		auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (!IS_VALID_SMART_PTR(processEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"Process enumerator allocate failed with error: %u", g_winAPIs->GetLastError());
			return true;
		}

		auto hProcess = processEnumerator->FindProcessFromPID(dwParentPid);
		if (!IS_VALID_HANDLE(hProcess)) 
		{
			APP_TRACE_LOG(LL_ERR, L"Parent of parent process not found on process list! PID: %u", dwParentPid);

			hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentPid);
			if (!IS_VALID_HANDLE(hProcess)) 
			{
				auto bIsAlive = CProcessFunctions::ProcessIsItAlive(dwParentPid);
				APP_TRACE_LOG(LL_ERR, L"Parent of parent process can not open! Last error: %u IsAlive: %d", g_winAPIs->GetLastError(), bIsAlive);
				processEnumerator.reset();
				return true;
			}
		}
		
		processEnumerator.reset();

		const auto szParentOfParentName = CProcessFunctions::GetProcessName(hProcess);
		if (szParentOfParentName.empty()) 
		{
			APP_TRACE_LOG(LL_ERR, L"Parent of parent process name not found!");
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);
			return true;
		}
		const auto szLowerParentOfParentName	= stdext::to_lower_wide(szParentOfParentName);
		const auto szParentOfParentProcessPath	= NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetPathFromProcessName(szLowerParentOfParentName);
		const auto szParentOfParentProcessName	= NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(szLowerParentOfParentName);
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);

		APP_TRACE_LOG(LL_SYS, L"Parent of parent process: %s(%u)", szLowerParentOfParentName.c_str(), dwParentPid);

		// Windows informations
		const auto szWindowsPath		= NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
		const auto szLowerWindowsPath	= stdext::to_lower_wide(szWindowsPath);

		if (szLowerWindowsPath.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Windows path not found!");
			return true;
		}

		auto dwExplorerPID = 0UL;
		if (!GetExplorerPIDbyShellWindow(&dwExplorerPID)) 
		{
			APP_TRACE_LOG(LL_CRI, L"Explorer.exe pid not found! Last Error: %u", g_winAPIs->GetLastError());
			return true;
		}
		APP_TRACE_LOG(LL_SYS, L"Explorer pid: %u", dwExplorerPID);

		if (szParentOfParentProcessPath != szLowerWindowsPath ||
			wcscmp(szParentOfParentProcessName.c_str(), xorstr_(L"explorer.exe")) ||
			dwExplorerPID != dwParentPid)
		{
			APP_TRACE_LOG(LL_CRI, L"Parent process is not from windows or is not explorer.exe or restarted explorer.exe!");
			return false;
		}

		return true;
	}


	bool CAntiDebug::ParentCheck(const std::wstring& c_stPatcherName, const std::wstring& c_stPatcherHash)
	{
		const auto stLowerPatcherName = stdext::to_lower_wide(c_stPatcherName);
		const auto stLowerPatcherHash = stdext::to_lower_wide(c_stPatcherHash);
		APP_TRACE_LOG(LL_SYS, L"Patcher Name: '%s', Hash: '%s'", stLowerPatcherName.c_str(), stLowerPatcherHash.c_str());

		// Process informations
		STARTUPINFOW si{ 0 };
		si.cb = sizeof(si);
		g_winAPIs->GetStartupInfoW(&si);

		const auto dwCurrentPID		  = g_winAPIs->GetCurrentProcessId();
		const auto dwParentPID		  = CProcessFunctions::GetProcessParentProcessId(dwCurrentPID);
		const auto dwParentPIDFromPEB = CProcessFunctions::GetParentProcessIdNative(NtCurrentProcess());
		APP_TRACE_LOG(LL_SYS, L"Current PID: %u Parent PID: %u/%u", dwCurrentPID, dwParentPID, dwParentPIDFromPEB);

		if (dwParentPID != dwParentPIDFromPEB) // Anti Parent pid manipulation
		{
			APP_TRACE_LOG(LL_ERR, L"Parent PID manipulation detected! IsVista/+: %d Parent pid: %u Parent pid PEB: %u", IsWindowsVistaOrGreater(), dwParentPID, dwParentPIDFromPEB);
			return false;
		}

		static constexpr auto ACCESS_MASK = PROCESS_QUERY_INFORMATION;

		auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(ACCESS_MASK);
		if (!IS_VALID_SMART_PTR(processEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"processEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto hProcess = processEnumerator->FindProcessFromPID(dwParentPID);
		if (!IS_VALID_HANDLE(hProcess)) 
		{
			hProcess = g_winAPIs->OpenProcess(ACCESS_MASK, FALSE, dwParentPID);
			if (!IS_VALID_HANDLE(hProcess))
			{
				const auto bIsAlive = CProcessFunctions::ProcessIsItAlive(dwParentPID);
				APP_TRACE_LOG(LL_ERR, L"Parent process(%u) can not open! Last error: %u IsAlive: %d", dwParentPID, g_winAPIs->GetLastError(), bIsAlive);
				processEnumerator.reset();
				return false;
			}
		}
		
		const auto szParentName = CProcessFunctions::GetProcessName(hProcess);
		if (szParentName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Parent process name not found!");
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);
			processEnumerator.reset();
			return false;
		}

		const auto szLowerParentName	= stdext::to_lower_wide(szParentName);
		const auto szParentProcessPath	= NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetPathFromProcessName(szLowerParentName);
		const auto szParentProcessName	= stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(szLowerParentName));
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hProcess);

		APP_TRACE_LOG(LL_SYS, L"Parent process: %s(%u)", szLowerParentName.c_str(), dwParentPID);

		// Windows informations
		const auto szWindowsPath		= NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
		const auto szLowerWindowsPath	= stdext::to_lower_wide(szWindowsPath);

		if (szLowerWindowsPath.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Windows path not found!");
			return false;
		}

		auto dwExplorerPID1 = 0UL;
		if (!GetExplorerPIDbyShellWindow(&dwExplorerPID1))
		{
			APP_TRACE_LOG(LL_CRI, L"Explorer.exe pid not found by Shell! Last Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Shell Explorer pid: %u", dwExplorerPID1);

		auto dwExplorerPID2 = 0UL;
		if (!GetExplorerPIDbyProgman(&dwExplorerPID2))
		{
			APP_TRACE_LOG(LL_CRI, L"Explorer.exe pid not found by Progman! Last Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Progman Explorer pid: %u", dwExplorerPID2);

		if (dwExplorerPID1 != dwExplorerPID2)
		{
			APP_TRACE_LOG(LL_CRI, L"Explorer.exe pid mismatch! %u - %u", dwExplorerPID1, dwExplorerPID2);
			return false;
		}

#ifdef _DEBUG
		if (stdext::is_known_debugger_process(szParentProcessName))
			return true;
#endif

		std::wstring stAllowedParent;
		
		const auto nAppType = NoMercyCore::CApplication::Instance().GetAppType();
		if (nAppType == NM_CLIENT) // should be service
		{
			if (!stLowerPatcherName.empty()) // custom defined launcher
			{
				if (stLowerPatcherName != szParentProcessName)
				{
					APP_TRACE_LOG(LL_CRI, L"Parent process name mismatch! %s - %s", stLowerPatcherName.c_str(), szParentProcessName.c_str());
					return false;
				}
				
				if (!c_stPatcherHash.empty())
				{
					const auto stParentProcessHash = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileMd5(szLowerParentName));
					if (stParentProcessHash.empty())
					{
						APP_TRACE_LOG(LL_CRI, L"Parent process hash not found!");
						return false;
					}

					if (stParentProcessHash != stLowerPatcherHash)
					{
						APP_TRACE_LOG(LL_CRI, L"Parent process hash mismatch! %s - %s", stParentProcessHash.c_str(), stLowerPatcherHash.c_str());
						return false;
					}
				}

				if (!ParentOfParentPIDIsLegit(hProcess, dwParentPID))
				{
					APP_TRACE_LOG(LL_CRI, L"Parent of parent PID is not legit!");
					return false;
				}
			}
			else // explorer
			{
				if (szParentProcessPath != szLowerWindowsPath ||
					wcscmp(szParentProcessName.c_str(), xorstr_(L"explorer.exe")) ||
					dwExplorerPID1 != dwParentPID)
				{
					APP_TRACE_LOG(LL_CRI, L"Parent process is not from windows or is not explorer.exe or restarted explorer.exe!");
					return false;
				}

				if (IsWindows10OrGreater())
				{
					const auto wszParentName = std::wstring(szLowerParentName.begin(), szLowerParentName.end());
					const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wszParentName);
					if (obHasCert.has_value())
					{
						HOOK_LOG(LL_SYS, L"Cert query completed with result: %d", obHasCert.value());

						if (!obHasCert.value())
						{
							APP_TRACE_LOG(LL_CRI, L"Parent process is not a digital signed file!");
							return false;
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to query certificate informations for file %ls", wszParentName.c_str());
					}
				}

				// check startup params
				if (si.dwX != 0 || si.dwY != 0 ||
					si.dwXCountChars != 0 || si.dwYCountChars != 0 ||
					si.dwFillAttribute != 0 ||
					si.dwXSize != 0 || si.dwYSize != 0)
				{
					APP_TRACE_LOG(LL_CRI, L"Startup info: %u-%u %u-%u %u %u-%u", si.dwX, si.dwY, si.dwXCountChars, si.dwYCountChars, si.dwFillAttribute, si.dwXSize, si.dwYSize);
					return false;
				}
				
#ifdef __EXPERIMENTAL__
				// check with sfc
				if (!g_winAPIs->SfcIsFileProtected(nullptr, szParentName.c_str()))
				{
					APP_TRACE_LOG(LL_CRI, L"Parent process is not protected by SFC!");
					return false;
				}
#endif
			}
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"Unknown app type: %u", nAppType);
			return true;
		}

		if (!stAllowedParent.empty())
		{
			if (stAllowedParent != szParentProcessName)
			{
				APP_TRACE_LOG(LL_CRI, L"Parent process name mismatch! %s - %s", stAllowedParent.c_str(), szParentProcessName.c_str());
				return false;
			}

			const auto stNoMercyPath = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->GetNoMercyPath());
			const auto stCurrentPath = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->CurrentPath());
			if (stNoMercyPath != szParentProcessPath && stCurrentPath != szParentProcessPath)
			{
				APP_TRACE_LOG(LL_CRI, L"Parent process path mismatch! %s - %s", stNoMercyPath.c_str(), szParentProcessPath.c_str());
				return false;
			}
		}

		return true;
	}
};
