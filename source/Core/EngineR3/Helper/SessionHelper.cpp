#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SessionHelper.hpp"

namespace NoMercy
{
	CSessionHelper::CSessionHelper(std::wstring stServerName) :
		m_server_name(stServerName), m_server_handle(NULL)
	{
		OpenServer();
	}
	CSessionHelper::~CSessionHelper()
	{
		CloseServer();
	}

	bool CSessionHelper::OpenServer()
	{
		if (m_server_name.empty())
		{
			m_server_handle = WTS_CURRENT_SERVER_HANDLE;
			return true;
		}

		m_server_handle = g_winAPIs->WTSOpenServerW(const_cast<wchar_t*>(m_server_name.c_str()));
		return !!m_server_handle;
	}
	void CSessionHelper::CloseServer()
	{
		if (WTS_CURRENT_SERVER_HANDLE != m_server_handle)
		{
			g_winAPIs->WTSCloseServer(m_server_handle);
		}
		m_server_handle = NULL;
	}

	bool CSessionHelper::GetSessions(std::vector <SWtsSessionInfo>& sessions)
	{
		DWORD dwCount = 0;
		PWTS_SESSION_INFOW pSessionInfo = NULL;
		if (g_winAPIs->WTSEnumerateSessionsW(m_server_handle, 0, 1, &pSessionInfo, &dwCount))
		{
			for (auto i = 0u; i < dwCount; i++)
			{
				SWtsSessionInfo session{};
				session.session_id = pSessionInfo[i].SessionId;
				session.state = pSessionInfo[i].State;

				auto length = wcslen(pSessionInfo[i].pWinStationName);
				if (length > gsc_nWtsNameLength)
					length = gsc_nWtsNameLength;
				
				wcsncpy(session.winstation_name, pSessionInfo[i].pWinStationName, length);
				sessions.emplace_back(session);
			}
		}

		if (pSessionInfo)
		{
			g_winAPIs->WTSFreeMemory(pSessionInfo);
			pSessionInfo = NULL;
		}
		return !!dwCount;
	}
	bool CSessionHelper::GetSessionUser(DWORD dwSessionId, std::wstring& stUserName)
	{
		bool bRet = false;
		
		if (stUserName.empty())
			return bRet;
		
		DWORD dwCount = 0;
		LPWSTR lpszName = NULL;
		if (g_winAPIs->WTSQuerySessionInformationW(m_server_handle, dwSessionId, WTSUserName, &lpszName, &dwCount))
		{
			stUserName = std::wstring(lpszName, dwCount);
			bRet = true;
		}

		if (lpszName)
		{
			g_winAPIs->WTSFreeMemory(lpszName);
			lpszName = NULL;
		}
		return bRet;
	}
	uint32_t CSessionHelper::GetProcesses(SWtsProcInfo* pProcesses, uint32_t count)
	{
		if (!pProcesses)
			return 0;

		DWORD dwCount = 0;
		PWTS_PROCESS_INFOW pProcessInfo = NULL;
		if (g_winAPIs->WTSEnumerateProcessesW(m_server_handle, 0, 1, &pProcessInfo, &dwCount))
		{
			dwCount = (dwCount <= count) ? dwCount : count;
			for (std::size_t i = 0; i < dwCount; i++)
			{
				pProcesses[i].session_id = pProcessInfo[i].SessionId;
				pProcesses[i].process_id = pProcessInfo[i].ProcessId;

				if (pProcessInfo[i].pUserSid)
					pProcesses[i].sid = *(SID*)(pProcessInfo[i].pUserSid);
				else
					memset(&(pProcesses[i].sid), 0, sizeof(SID));

				if (pProcessInfo[i].pProcessName)
					wcscpy(pProcesses[i].process_name, pProcessInfo[i].pProcessName);
				else
					memset(pProcesses[i].process_name, 0, sizeof(wchar_t) * gsc_nWtsNameLength);

				DWORD dwNameLen = gsc_nWtsNameLength;
				SID_NAME_USE nameuse = SidTypeUser;
				g_winAPIs->LookupAccountSidW(m_server_name.c_str(), pProcessInfo[i].pUserSid, pProcesses[i].user_name, &dwNameLen, pProcesses[i].domain_name, &dwNameLen, &nameuse);
			}
		}

		if (pProcessInfo)
		{
			g_winAPIs->WTSFreeMemory(pProcessInfo);
			pProcessInfo = NULL;
		}
		return dwCount;
	}
	uint32_t CSessionHelper::GetProcesses(DWORD dwSessionId, SWtsProcInfo* pProcesses, uint32_t count)
	{
		if (!pProcesses)
			return 0;

		std::size_t rst = 0;
		SWtsProcInfo pi[512]{ 0 };
		DWORD dwCount = GetProcesses(pi, 512);

		for (std::size_t i = 0; i < dwCount; i++)
		{
			if (dwSessionId == pi[i].session_id)
			{
				pProcesses[rst++] = pi[i];
				if (rst >= count)
					break;
			}
		}

		return rst;
	}


	bool CSessionHelper::DisconnectSession(DWORD dwSessionId, bool bWait)
	{
		return g_winAPIs->WTSDisconnectSession(m_server_handle, dwSessionId, bWait);
	}
	bool CSessionHelper::DisconnectSession(bool bWait)
	{
		DWORD dwSessionId = 0;
		if (!g_winAPIs->ProcessIdToSessionId(g_winAPIs->GetCurrentProcessId(), &dwSessionId))
			return false;
		return this->DisconnectSession(dwSessionId, bWait);
	}

	bool CSessionHelper::LogoffSession(DWORD dwSessionId, bool bWait)
	{
		return g_winAPIs->WTSLogoffSession(m_server_handle, dwSessionId, bWait);
	}
	bool CSessionHelper::LogoffSession(bool bWait)
	{
		DWORD dwSessionId = 0;
		if (!g_winAPIs->ProcessIdToSessionId(g_winAPIs->GetCurrentProcessId(), &dwSessionId))
			return false;
		return this->LogoffSession(dwSessionId, bWait);
	}

	bool CSessionHelper::LogoffUser(const std::wstring& stUserName, bool bWait)
	{
		bool bReturn = false;
		
		if (stUserName.empty())
			return bReturn;

		DWORD dwCount = 0;
		PWTS_SESSION_INFOW pSessionInfo = NULL;
		if (g_winAPIs->WTSEnumerateSessionsW(m_server_handle, 0, 1, &pSessionInfo, &dwCount))
		{
			bReturn = true;

			for (std::size_t i = 0; i < dwCount; i++)
			{
				DWORD dwRet = 0;
				LPWSTR lpszName = NULL;
				if (g_winAPIs->WTSQuerySessionInformationW(m_server_handle, pSessionInfo[i].SessionId, WTSUserName, &lpszName, &dwRet))
				{
					if (!wcscmp(stUserName.c_str(), lpszName))
						g_winAPIs->WTSLogoffSession(m_server_handle, pSessionInfo[i].SessionId, bWait);
				}
				g_winAPIs->WTSFreeMemory(lpszName);
			}
		}

		if (pSessionInfo)
		{
			g_winAPIs->WTSFreeMemory(pSessionInfo);
			pSessionInfo = NULL;
		}
		return bReturn;
	}
};
