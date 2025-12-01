#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Thread/SelfThreadIdentifier.hpp"
#include "../Common/ExceptionHandlers.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumeratorNT.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	static const auto gsc_dwTimeoutDelay = 60; // 60 seconds

	CSelfThreadIdentifier::CSelfThreadIdentifier()
	{
		m_threadTimeMap.clear();
		m_threadTicksMap.clear();
	}

	DWORD CSelfThreadIdentifier::GetLastCheckTime(DWORD dwThreadCode)
	{
		if (m_threadTimeMap.find(dwThreadCode) == m_threadTimeMap.end())
		{
			APP_TRACE_LOG(LL_ERR, L"Unknown thread ID: %u", dwThreadCode);
			return (DWORD)-1;
		}
		return m_threadTimeMap[dwThreadCode];
	};
	void CSelfThreadIdentifier::SetLastCheckTime(DWORD dwThreadCode, DWORD dwTime)
	{
		m_threadTimeMap[dwThreadCode] = dwTime;
	};

	void CSelfThreadIdentifier::IncreaseThreadTick(DWORD dwThreadCode)
	{
		if (m_threadTicksMap.find(dwThreadCode) == m_threadTicksMap.end())
		{
			m_threadTicksMap[dwThreadCode] = 1;
			return;
		}
		m_threadTicksMap[dwThreadCode] += 1;
	}
	void CSelfThreadIdentifier::DecreaseThreadTick(DWORD dwThreadCode)
	{
		if (m_threadTicksMap.find(dwThreadCode) == m_threadTicksMap.end())
		{
			APP_TRACE_LOG(LL_ERR, L"Unknown thread ID: %u", dwThreadCode);
			return;
		}
		m_threadTicksMap[dwThreadCode] -= 1;
	}
	void CSelfThreadIdentifier::ReleaseThreadTicks(DWORD dwThreadCode)
	{
		if (m_threadTicksMap.find(dwThreadCode) == m_threadTicksMap.end())
			return;
		m_threadTicksMap[dwThreadCode] = 0;
	}
	DWORD CSelfThreadIdentifier::GetThreadTick(DWORD dwThreadCode)
	{
		if (m_threadTicksMap.find(dwThreadCode) == m_threadTicksMap.end())
		{
			APP_TRACE_LOG(LL_ERR, L"Unknown thread ID: %u", dwThreadCode);
			return (DWORD)-1;
		}
		return m_threadTicksMap[dwThreadCode];
	}
	void CSelfThreadIdentifier::InitializeThreadChecks(DWORD dwThreadCode)
	{
		this->SetLastCheckTime(dwThreadCode, 0);
		this->IncreaseThreadTick(dwThreadCode);
	}


	DWORD WINAPI InitExThreadTickCheck(LPVOID)
	{
		APP_TRACE_LOG(LL_TRACE, L"Thread tick checker thread event has been started");

		const auto vThreadList = CApplication::Instance().ThreadManagerInstance()->GetThreadList();
		if (vThreadList.size() > 0)
		{
			for (const auto& pThread : vThreadList)
			{
				if (IS_VALID_SMART_PTR(pThread))
				{
					const auto bTemporary = pThread->bIsTemporaryThread;
					if (bTemporary == false)
					{
						const auto nThreadIndex = pThread->nThreadIdx;
						auto dwDelay = gsc_dwTimeoutDelay;

						const auto dwMaxDelay = (pThread->dwMaxDelay / 1000) + dwDelay;
						const auto dwThreadTickCount = CApplication::Instance().SelfThreadIdentifierInstance()->GetThreadTick(nThreadIndex);
						const auto dwLastCheckTime = CApplication::Instance().SelfThreadIdentifierInstance()->GetLastCheckTime(nThreadIndex);
						const auto dwCurrentTime = stdext::get_current_epoch_time();
						const auto dwTimeDiff = dwCurrentTime - dwLastCheckTime;

						APP_TRACE_LOG(LL_TRACE, L"Thread[#%d-%u] Temporary: %d Bind'd tick count is: %u Max Delay: %u Last check: %u Current: %u Dif: %u",
							nThreadIndex, pThread->dwThreadID, bTemporary, dwThreadTickCount, dwMaxDelay, dwLastCheckTime, dwCurrentTime, dwTimeDiff
						);

						if (!dwLastCheckTime)
						{
							CApplication::Instance().SelfThreadIdentifierInstance()->SetLastCheckTime(nThreadIndex, stdext::get_current_epoch_time());
							continue;
						}

						if (dwTimeDiff >= dwMaxDelay)
						{
							APP_TRACE_LOG(LL_ERR, L"Thread code: %d Temporary thread: %d Bind'd tick count is: %u Max Delay: %u Last check: %u Current: %u Dif: %u",
								nThreadIndex, bTemporary, dwThreadTickCount, dwMaxDelay, dwLastCheckTime, dwCurrentTime, dwTimeDiff
							);
							
							if (dwThreadTickCount == 0)
							{
								if (nThreadIndex == SELF_THREAD_WEBSOCKET) // FIXME
									continue;
								if (nThreadIndex == SELF_THREAD_MEMORY_MONITOR) // FIXME
									continue;

//								if (nThreadIndex == SELF_THREAD_WMI) // infinite wait
//									continue;

								if (nThreadIndex == SELF_THREAD_WATCHDOG && CApplication::Instance().WatchdogInstance()->IsInitialized() == false)
									continue;

								// if (nThreadIndex == SELF_THREAD_CHEAT_QUEUE_MANAGER && CProcessFunctions::IsThreadInProgress(g_winAPIs->GetCurrentProcessId(), pThread->dwThreadID))
								if (nThreadIndex == SELF_THREAD_CHEAT_QUEUE_MANAGER)
								{
									CProcessFunctions::IsThreadInProgress(g_winAPIs->GetCurrentProcessId(), pThread->dwThreadID); // Just for log for now
									continue;
								}

								APP_TRACE_LOG(LL_CRI, L"Null tick count on Thread: %d", nThreadIndex);

								/*
								if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(pThread->hThread))
								{
									const auto bRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ResumeThread(pThread->hThread, false);
									APP_TRACE_LOG(LL_WARN, L"Resume ret: %d", bRet)
								}
								else
								*/
								{
									// Enum thread list for find suspended threads
									CProcessFunctions::HasSuspendedThread(g_winAPIs->GetCurrentProcessId(), true, true);

									CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_COMMUNICATION_FAIL, nThreadIndex);
									return 0;
								}
							}
						}

						CApplication::Instance().SelfThreadIdentifierInstance()->ReleaseThreadTicks(nThreadIndex);
					}
				}
			}
		}

		// Current process self-created thread validator
		CApplication::Instance().SelfThreadIdentifierInstance()->CheckSelfThreads();

		return 0;
	}

	bool CSelfThreadIdentifier::InitThreadTickChecker()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_THREAD_TICK_CHECKER, InitExThreadTickCheck, nullptr, 15000, false);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get());

		return true;
	}

	void CSelfThreadIdentifier::ReleaseThreadTickChecker()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_THREAD_TICK_CHECKER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}

	bool CSelfThreadIdentifier::IsTickCheckerThreadIntegrityCorrupted()
	{
		if (!CApplication::InstancePtr() || CApplication::Instance().AppIsFinalized())
			return false;

		const auto pThread = CApplication::Instance().ThreadManagerInstance()->GetThreadInfo(SELF_THREAD_THREAD_TICK_CHECKER);
		if (!IS_VALID_SMART_PTR(pThread) || !IS_VALID_SMART_PTR(pThread->spCustomThread))
			return false;

		if (pThread->spCustomThread->IsValid() == false)
			return true;

		const auto dwMaxDelay = pThread->dwMaxDelay + gsc_dwTimeoutDelay;

		const auto dwThreadTickCount = CApplication::Instance().SelfThreadIdentifierInstance()->GetThreadTick(SELF_THREAD_THREAD_TICK_CHECKER);
		const auto dwLastCheckTime = CApplication::Instance().SelfThreadIdentifierInstance()->GetLastCheckTime(SELF_THREAD_THREAD_TICK_CHECKER);

		const auto dwCurrentTime = stdext::get_current_epoch_time();

		/*
		APP_TRACE_LOG(LL_SYS, L"Tick checker thread integrity check started! Target thread: %u(%p) Max delay: %u Last check: %u Current: %u Dif: %u Tick: %u",
			pThread->spCustomThread->GetID(), pThread->spCustomThread->GetHandle(), dwMaxDelay, dwLastCheckTime,
			dwCurrentTime, dwCurrentTime - dwLastCheckTime, dwThreadTickCount
		);
		*/

		if ((dwCurrentTime - dwLastCheckTime) >= dwMaxDelay)
		{
			if (dwThreadTickCount == 0)
			{
				APP_TRACE_LOG(LL_SYS, L"Tick checker thread integrity check started! Target thread: %u(%p) Max delay: %u Last check: %u Current: %u Dif: %u Tick: %u",
					pThread->spCustomThread->GetID(), pThread->spCustomThread->GetHandle(), dwMaxDelay, dwLastCheckTime,
					dwCurrentTime, dwCurrentTime - dwLastCheckTime, dwThreadTickCount
				);

				APP_TRACE_LOG(LL_ERR, L"Null tick count on tick checker thread !!!");
				return true;
			}
		}

		ReleaseThreadTicks(SELF_THREAD_THREAD_TICK_CHECKER);
		return false;
	}

	/// 
	inline bool CheckThreadEx(HANDLE hThread, LPDWORD pdwErrorCode)
	{
		if (!IS_VALID_HANDLE(hThread))
		{
			if (pdwErrorCode) *pdwErrorCode = 1;
			return false;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hThread))
		{
			if (pdwErrorCode) *pdwErrorCode = 2;
			return false;
//			return true; // temp allow
		}

		auto pThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromHandle(hThread);
		if (IS_VALID_SMART_PTR(pThread) && pThread->IsValid())
		{
			if (pThread->IsItAlive() == false)
			{
				if (pdwErrorCode) *pdwErrorCode = 4;
				return false;
			}

			if (!stdext::is_debug_env() && pThread->HasSuspend())
			{
				pThread->TryResume();
//				if (pdwErrorCode) *pdwErrorCode = 5;
//				return false;
			}

			if (pThread->IsGoodPriority() == false)
			{
				if (pdwErrorCode) *pdwErrorCode = 6;
				return false;
			}

			BOOLEAN bCheckStat = FALSE;
			auto ntStatus = g_winAPIs->NtQueryInformationThread(pThread->GetHandle(), ThreadHideFromDebugger, &bCheckStat, sizeof(BOOLEAN), 0);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_SYS, L"NtQueryInformationThread (ThreadHideFromDebugger) failed with status: %p", ntStatus);
//				if (pdwErrorCode) *pdwErrorCode = 7;
//				return false;
			}
			else
			{
				if (!stdext::is_debug_build() && !bCheckStat)
				{
					if (pdwErrorCode) *pdwErrorCode = 8;
					return false;
				}
			}

			// TODO: Check thread token, ACL and privileges, impersonation
			// TODO: Check thread affinity
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"Thread handle is valid but thread is not exist in thread manager! Handle: %p", hThread);
			if (pdwErrorCode) *pdwErrorCode = 3;
			return false;
		}
		
		return true;
	}

	bool CSelfThreadIdentifier::CheckThreadIntegrity(HANDLE hThread, LPDWORD pdwErrorCode)
	{
#ifdef _DEBUG
		if (!CheckThreadEx(hThread, pdwErrorCode))
			return false;
#else
		__try
		{
			if (!CheckThreadEx(hThread, pdwErrorCode))
				return false;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
#endif

		return true;
	}

	void CSelfThreadIdentifier::CheckSelfThreads()
	{
		APP_TRACE_LOG(LL_SYS, L"Self thread check started!");

		if (!CApplication::InstancePtr())
			return;

		if (!CApplication::Instance().AppIsInitiliazed())
			return;
		if (!IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			return;
		if (!CApplication::Instance().AppIsInitializedThreadCompleted())
			return;

		auto vThreadList = CApplication::Instance().ThreadManagerInstance()->GetThreadList();
		if (vThreadList.size() > 0)
		{
			for (const auto& pThread : vThreadList)
			{
				if (IS_VALID_SMART_PTR(pThread) && !pThread->bIsTemporaryThread && IS_VALID_SMART_PTR(pThread->spCustomThread) && pThread->spCustomThread->IsValid())
				{
					auto dwErrorCode = 0UL;
					if (CheckThreadIntegrity(pThread->hThread, &dwErrorCode) == false)
					{
						APP_TRACE_LOG(LL_ERR, L"Thread integrity failed! Thread: %d Error: %u", pThread->nThreadIdx, dwErrorCode);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_INTEGRITY_FAIL, dwErrorCode);
						return;
					}
				}
				g_winAPIs->Sleep(10);
			}
		}

		APP_TRACE_LOG(LL_TRACE, L"Self thread check completed!");
	}
};
