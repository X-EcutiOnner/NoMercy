#include "../../include/PCH.hpp"
#include "../../include/ThreadEnumerator.hpp"
#include "../../include/ProcessEnumerator.hpp"
#include "../../include/WinVerHelper.hpp"

namespace NoMercyCore
{
	CThreadEnumerator::CThreadEnumerator(DWORD dwAccess) :
		m_dwAccess(dwAccess)
	{
		CloseUselessHandles();
	}
	CThreadEnumerator::~CThreadEnumerator()
	{
		CloseUselessHandles();
	}

	void CThreadEnumerator::CloseUselessHandles()
	{
		if (m_vHandleList.empty())
			return;

		for (std::size_t i = 0UL; i < m_vHandleList.size(); ++i)
		{
			CWinAPIManager::Instance().SafeCloseHandle(m_vHandleList[i]);
		}
		m_vHandleList.clear();
	}

	HANDLE CThreadEnumerator::FindThread(HANDLE hOwnerProcess, DWORD dwTargetTID)
	{
		if (!IsWindowsVistaOrGreater())
			return INVALID_HANDLE_VALUE;

		HANDLE hCurrent = nullptr;

		while (g_winAPIs->NtGetNextThread(hOwnerProcess, hCurrent, m_dwAccess, 0, 0, &hCurrent) == STATUS_SUCCESS)
		{
			if (g_winAPIs->GetThreadId(hCurrent) == dwTargetTID)
				return hCurrent;

			m_vHandleList.push_back(hCurrent);
		}

		return INVALID_HANDLE_VALUE;
	}

	std::vector <HANDLE> CThreadEnumerator::EnumerateThreads(HANDLE hOwnerProcess)
	{
		if (!IsWindowsVistaOrGreater())
			return m_vHandleList;

		HANDLE hCurrent = nullptr;

		while (g_winAPIs->NtGetNextThread(hOwnerProcess, hCurrent, m_dwAccess, 0, 0, &hCurrent) == STATUS_SUCCESS)
		{
			m_vHandleList.push_back(hCurrent);
		}

		return m_vHandleList;
	}

	std::vector <HANDLE> CThreadEnumerator::EnumerateThreads()
	{
		if (!IsWindowsVistaOrGreater())
			return m_vHandleList;

		auto processEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>();
		if (!processEnumerator)
			return m_vHandleList;
		
		const auto vProcesses = processEnumerator->EnumerateProcesses(true);
		if (vProcesses.empty())
			return m_vHandleList;

		HANDLE hCurrent = nullptr;
		for (auto& hCurrentProcess : vProcesses)
		{
			while (g_winAPIs->NtGetNextThread(hCurrentProcess, hCurrent, m_dwAccess, 0, 0, &hCurrent) == STATUS_SUCCESS)
			{
				m_vHandleList.push_back(hCurrent);
			}
		}
		return m_vHandleList;
	}
}
