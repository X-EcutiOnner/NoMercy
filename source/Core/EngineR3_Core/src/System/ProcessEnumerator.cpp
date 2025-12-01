#include "../../include/PCH.hpp"
#include "../../include/ProcessEnumerator.hpp"
#include "../../include/WinVerHelper.hpp"

namespace NoMercyCore
{
	CProcessEnumerator::CProcessEnumerator(DWORD dwAccess) :
		m_dwAccess(dwAccess)
	{
		CloseUselessHandles();
	}
	CProcessEnumerator::~CProcessEnumerator()
	{
		CloseUselessHandles();
	}

	void CProcessEnumerator::CloseUselessHandles()
	{
		ADMIN_DEBUG_LOG(LL_SYS, L"Closing useless handles (%u)", m_vecCreatedHandleList.size());
		
		if (m_vecCreatedHandleList.empty())
			return;

		for (auto hObject : m_vecCreatedHandleList)
		{
			CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hObject, true);
		}
		m_vecCreatedHandleList.clear();
		m_vecReturnedHandleList.clear();
	}

	HANDLE CProcessEnumerator::FindProcessFromPID(DWORD dwProcessID, bool bAliveOnly)
	{
		if (!IsWindowsVistaOrGreater())
			return INVALID_HANDLE_VALUE;

		auto dwExitCode = 0UL;
		HANDLE hCurrent = nullptr;

		while (g_winAPIs->NtGetNextProcess(hCurrent, m_dwAccess, 0, 0, &hCurrent) == STATUS_SUCCESS)
		{
			m_vecCreatedHandleList.push_back(hCurrent);
			
			if (bAliveOnly && (!g_winAPIs->GetExitCodeProcess(hCurrent, &dwExitCode) || dwExitCode != STILL_ACTIVE))
				continue;

			if (dwProcessID == g_winAPIs->GetProcessId(hCurrent))
				return hCurrent;
		}

		return INVALID_HANDLE_VALUE;
	}


	std::vector <HANDLE> CProcessEnumerator::EnumerateProcesses(bool bAliveOnly)
	{
		if (!IsWindowsVistaOrGreater())
			return {};

		auto dwExitCode = 0UL;
		HANDLE hCurrent = nullptr;

		while (g_winAPIs->NtGetNextProcess(hCurrent, m_dwAccess, 0, 0, &hCurrent) == STATUS_SUCCESS)
		{
			m_vecCreatedHandleList.push_back(hCurrent);

			if (bAliveOnly && (!g_winAPIs->GetExitCodeProcess(hCurrent, &dwExitCode) || dwExitCode != STILL_ACTIVE))
				continue;

			m_vecReturnedHandleList.push_back(hCurrent);
		}

		return m_vecReturnedHandleList;
	}
};
