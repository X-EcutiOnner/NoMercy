#include "../../include/PCH.hpp"
#include "../../include/ThreadEnumeratorNT.hpp"
#include "../../include/ExitHelper.hpp"
#include "../../include/ErrorIDs.hpp"

namespace NoMercyCore
{
	CThreadEnumeratorNT::CThreadEnumeratorNT(DWORD dwProcessId) :
		m_dwProcessId(dwProcessId)
	{
		m_Cap = InitializeQuery();
	}
	CThreadEnumeratorNT::~CThreadEnumeratorNT()
	{
		m_dwProcessId = 0;

		if (m_Cap)
			free(m_Cap);
		m_Cap = nullptr;
	}


	BYTE* CThreadEnumeratorNT::InitializeQuery()
	{
		BYTE* mp_Data = nullptr;
		DWORD mu32_DataSize = 1024 * 1024;
		NTSTATUS ntStat = 0;

		while (true)
		{
			mp_Data = (BYTE*)malloc(mu32_DataSize);
			if (!mp_Data)
				break;

			ULONG ntNeeded = 0;
			ntStat = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, mp_Data, mu32_DataSize, &ntNeeded);

			if (ntStat == STATUS_INFO_LENGTH_MISMATCH)
			{
				mu32_DataSize *= 2;
				mp_Data = (BYTE*)realloc((PVOID)mp_Data, mu32_DataSize);
				continue;
			}

			return mp_Data;
		}

		if (!mp_Data)
			OnPreFail(0, CORE_ERROR_THREAD_ENUM_QUERY_FAIL, ntStat);

		return mp_Data;
	}

	LPVOID CThreadEnumeratorNT::GetProcInfo()
	{
		auto pk_Proc = (SYSTEM_PROCESS_INFORMATION*)m_Cap;

		while (true)
		{
			if (reinterpret_cast<DWORD_PTR>(pk_Proc->UniqueProcessId) == m_dwProcessId)
				return pk_Proc;

			if (!pk_Proc->NextEntryOffset)
				return nullptr;

			pk_Proc = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
		}

		return nullptr;
	}

	LPVOID CThreadEnumeratorNT::GetThreadList(LPVOID procInfo)
	{
		const auto pProcInfo = (SYSTEM_PROCESS_INFORMATION*)procInfo;
		const auto pk_Thread = pProcInfo->Threads;
		return pk_Thread;
	}

	DWORD CThreadEnumeratorNT::GetThreadCount(LPVOID procInfo)
	{
		const auto pProcInfo = (SYSTEM_PROCESS_INFORMATION*)procInfo;
		return pProcInfo->NumberOfThreads;
	}

	LPVOID CThreadEnumeratorNT::FindThread(LPVOID procInfo, DWORD dwThreadId)
	{
		const auto pProcInfo = (SYSTEM_PROCESS_INFORMATION*)procInfo;
		auto pk_Thread = pProcInfo->Threads;
		if (!pk_Thread)
			return nullptr;

		for (DWORD i = 0; i < pProcInfo->NumberOfThreads; i++)
		{
			if (reinterpret_cast<DWORD_PTR>(pk_Thread->ClientId.UniqueThread) == dwThreadId)
				return pk_Thread;

			pk_Thread++;
			g_winAPIs->Sleep(10);
		}

		return nullptr;
	}
};