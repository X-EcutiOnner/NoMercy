#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Access.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../Common/ExceptionHandlers.hpp"
#include "../../../Common/StdExtended.hpp"

namespace NoMercy
{
	using TDecreasePrivilege = std::function<bool(HANDLE)>;
	
	bool __SetTokenPrivilege(HANDLE TokenHandle, PWSTR PrivilegeName, PLUID PrivilegeLuid, ULONG Attributes)
	{
		TOKEN_PRIVILEGES privileges;
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Attributes = Attributes;
		privileges.Privileges[0].Luid = *PrivilegeLuid;

		const auto ntStat = g_winAPIs->NtAdjustPrivilegesToken(TokenHandle, FALSE, &privileges, sizeof(privileges) /* 0 */, NULL, NULL);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtAdjustPrivilegesToken fail! Ntstat: %p", ntStat);
		}
#if 0
		if (ntStat == STATUS_NOT_ALL_ASSIGNED)
		{
			APP_TRACE_LOG(LL_ERR, L"NtAdjustPrivilegesToken returned with: STATUS_NOT_ALL_ASSIGNED");
		}
#endif
		return true;
	}

	bool CAccess::DecreasePrivilege(HANDLE hProcess)
	{
		auto DecreasePrivilegeImpl = [](HANDLE hProcess)
		{
			HANDLE hToken = nullptr;
			const auto ntStat = g_winAPIs->NtOpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
			if (NT_SUCCESS(ntStat))
			{
				LUID luid{};
				if (g_winAPIs->LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
				{
					auto bRet = __SetTokenPrivilege(hToken, NULL, &luid, SE_PRIVILEGE_REMOVED);
					
					g_winAPIs->CloseHandle(hToken);
					return bRet;
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"LookupPrivilegeValueA fail! Error: %u", g_winAPIs->GetLastError());
					g_winAPIs->CloseHandle(hToken);
					return false;
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"NtOpenProcessToken fail! Status: %p", ntStat);
				return false;
			}
		};

#ifdef _DEBUG
		auto bRet = DecreasePrivilegeImpl(hProcess);
#else
		auto bRet = false;
		__try
		{
			bRet = DecreasePrivilegeImpl(hProcess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
#endif

		return true;
	}

	bool CAccess::RemoveProcessDebugPriv(DWORD dwProcessId, HANDLE hProcess)
	{
		APP_TRACE_LOG(LL_SYS, L"Remove debug privilege started for: %u", dwProcessId);

		if (std::find(m_vBlockedProcessIds.begin(), m_vBlockedProcessIds.end(), dwProcessId) != m_vBlockedProcessIds.end())
			return true;

		if (dwProcessId == g_winAPIs->GetCurrentProcessId())
		{
			m_vBlockedProcessIds.emplace_back(dwProcessId);
			return true;
		}

		const auto szProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (!szProcessName.empty())
		{
			const auto szLowerProcessName = stdext::to_lower_wide(szProcessName);

			const auto szExeNameWithPath = CDirFunctions::Instance().ExeNameWithPath();
			const auto szLowerExeNameWithPath = stdext::to_lower_wide(szExeNameWithPath);

			if (!wcscmp(szLowerProcessName.c_str(), szLowerExeNameWithPath.c_str()))
			{
				APP_TRACE_LOG(LL_SYS, L"Itself access adjust passed! %u", dwProcessId);

				m_vBlockedProcessIds.emplace_back(dwProcessId);
				return true;
			}
			
#ifdef _DEBUG
			if ((wcsstr(szLowerProcessName.c_str(), xorstr_(L"conhost.exe")) ||
				wcsstr(szLowerProcessName.c_str(), xorstr_(L"devenv.exe"))))
			{
				APP_TRACE_LOG(LL_SYS, L"Console access adjust passed! %u", dwProcessId);

				m_vBlockedProcessIds.emplace_back(dwProcessId);
				return true;
			}
#endif

			if (wcsstr(szLowerProcessName.c_str(), xorstr_(L"crashsender1402.exe")))
			{
				APP_TRACE_LOG(LL_SYS, L"Whitelist access adjust passed! %u:%s", dwProcessId, szLowerProcessName.c_str());

				m_vBlockedProcessIds.emplace_back(dwProcessId);
				return true;
			}

			const auto& vecWhiteList = CApplication::Instance().QuarentineInstance()->DebugPrivRemovedProcessQuarentine()->GetWhitelist();
			if (!vecWhiteList.empty())
			{
				for (const auto& pkRefWhiteListItem : vecWhiteList)
				{
					const auto stLowerData = stdext::to_lower_wide(pkRefWhiteListItem.data);
					if (wcsstr(szLowerProcessName.c_str(), stLowerData.c_str()))
					{
						APP_TRACE_LOG(LL_SYS, L"Whitelist access adjust passed! %u:%s WhiteList ID: %u(%s)",
							dwProcessId, szLowerProcessName.c_str(), pkRefWhiteListItem.idx, stLowerData.c_str()
						);

						m_vBlockedProcessIds.emplace_back(dwProcessId);
						return true;
					}
				}
			}
		}

		if (CApplication::Instance().AccessHelperInstance()->DecreasePrivilege(hProcess) == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Process decrease debug privilege fail! Target PID: %u Last error: %u", dwProcessId, g_winAPIs->GetLastError());

			m_vBlockedProcessIds.emplace_back(dwProcessId);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Access rules adjusted to PID: %u Name: %s", dwProcessId, szProcessName.c_str());
		m_vBlockedProcessIds.emplace_back(dwProcessId);

		return true;
	}
};
