#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ThreadManagerHelper.hpp"
#include "ThreadExitCallback.hpp"
#include "../Helper/ThreadHelper.hpp"
#include "../Helper/ProcessHelper.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"

namespace NoMercy
{
	static void NTAPI __ThreadTerminateWatcher(PVOID pCtx, BOOLEAN)
	{
		const auto dwThreadId = reinterpret_cast<DWORD_PTR>(pCtx);
		// APP_TRACE_LOG(LL_ERR, L"Access lost to thread: %u", dwThreadId);

		if (CApplication::InstancePtr() && IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			CApplication::Instance().ThreadManagerInstance()->OnThreadTerminated(dwThreadId);
	}
	static void __SetThreadNameViaException(PCSTR name)
	{
#pragma pack(push, 8)
		struct tagTHREADNAME_INFO
		{
			DWORD  dwType;     // Must be 0x1000.
			LPCSTR szName;     // Pointer to name (in user addr space).
			DWORD  dwThreadID; // Thread ID (-1=caller thread).
			DWORD  dwFlags;    // Reserved for future use, must be zero.
		} info{ 0x1000, name, 0xffffffff, 0 };
#pragma pack(pop)

		__try
		{
			g_winAPIs->RaiseException(0x406D1388, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}


	CThreadManager::CThreadManager()
	{
		m_vThreadPool.clear();
		m_mapSelfThreads.clear();
	}
	CThreadManager::~CThreadManager()
	{
		m_vThreadPool.clear();
	}

	std::shared_ptr <CThread> CThreadManager::CreateCustomThread(int nThreadIdx, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwMaxDelay, bool bIsTemporaryThread)
	{
		APP_TRACE_LOG(LL_SYS, L"Custom thread(%u) create has been started!", nThreadIdx);
		
		if (GetThreadFromThreadCode(nThreadIdx))
		{
			APP_TRACE_LOG(LL_CRI, L"Already exist thread with code(%d)!", nThreadIdx);

			CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ALREADY_EXIST, g_winAPIs->GetLastError());
			return nullptr;
		}

		auto spThreadInterface = std::shared_ptr<IThreadInterface>();
		auto dwThreadId = 0UL;
		auto hThread = HANDLE(nullptr);

		if (bIsTemporaryThread)
		{
			hThread = CThreadFunctions::CreateThread(nThreadIdx, pFunc, lpParam, CREATE_SUSPENDED, &dwThreadId);
			if (!IS_VALID_HANDLE(hThread))
			{
				APP_TRACE_LOG(LL_CRI, L"Thread: %d can NOT created! Error: %u", nThreadIdx, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_CREATE_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}
		}
		else
		{
			spThreadInterface = stdext::make_shared_nothrow<IThreadInterface>(nThreadIdx, pFunc, lpParam, dwMaxDelay);
			if (!IS_VALID_SMART_PTR(spThreadInterface))
			{
				APP_TRACE_LOG(LL_CRI, L"Thread interface can NOT created! Thread: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_INTERFACE_ALLOC_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}

			if (spThreadInterface->Initialize() == false)
			{
				APP_TRACE_LOG(LL_CRI, L"Thread can NOT initialized! Thread: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_INTERFACE_INIT_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}

			hThread = spThreadInterface->GetThreadHandle();
			dwThreadId = spThreadInterface->GetThreadID();
		}

		auto spCustomProc = stdext::make_shared_nothrow<CProcess>(NtCurrentProcess());
		auto customThread = stdext::make_shared_nothrow<CThread>(hThread, spCustomProc.get());
		if (!IS_VALID_SMART_PTR(customThread))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread class can NOT created! Thread: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

			CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ALLOC_CLASS_FAIL, g_winAPIs->GetLastError());
			return nullptr;
		}
		customThread->SetCustomCode(nThreadIdx);
		customThread->SetCustomName(this->GetThreadCustomName(nThreadIdx));

		auto threadInfos = stdext::make_shared_nothrow<SSelfThreads>();
		if (!IS_VALID_SMART_PTR(threadInfos))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread data container can NOT created! Thread: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

			CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ALLOC_CONTAINER_FAIL, g_winAPIs->GetLastError());
			return nullptr;
		}

		if (!bIsTemporaryThread)
		{
			auto pExitCallbackHelper = stdext::make_shared_nothrow<CThreadExitWatcher>(hThread);
			if (!IS_VALID_SMART_PTR(pExitCallbackHelper))
			{
				APP_TRACE_LOG(LL_CRI, L"Thread exit watcher can NOT created! Thread: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_EXIT_WATCHER_ALLOC_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}

			if (!pExitCallbackHelper->InitializeExitCallback(__ThreadTerminateWatcher, INFINITE, (PVOID)dwThreadId))
			{
				APP_TRACE_LOG(LL_CRI, L"Thread exit watcher can NOT initialize! Thread: %d(%p) Error: %u", nThreadIdx, hThread, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_EXIT_WATCHER_INIT_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}
			else
			{
				threadInfos->hWaitObj = pExitCallbackHelper->GetWaitObjectHandle();
				APP_TRACE_LOG(LL_SYS, L"Thread exit watchdog initialized: %p", threadInfos->hWaitObj);
			}
		}
		
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		if (!this->SetAntiTrace(customThread, ThreadHideFromDebugger))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread anti trace can NOT set! Thread: %d(%p) Error: %u", nThreadIdx, hThread, g_winAPIs->GetLastError());

			// CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ANTI_TRACE_FAIL, g_winAPIs->GetLastError());
			// return nullptr;
		}
#endif

		/*
		// BSOD on manual thread termination only
		ULONG Enable = 1;
		const auto ntStatus = g_winAPIs->NtSetInformationThread(hThread, ThreadBreakOnTermination, &Enable, sizeof(Enable));
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread access rules(3) can NOT adjusted for: %d Error: %p", nThreadIdx, ntStatus);

			CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ACCESS_2_FAIL, ntStatus);
			return nullptr;
		}
		*/

//		/*
		if (CApplication::Instance().AccessHelperInstance()->BlockAccess(hThread) == false)
		{
			APP_TRACE_LOG(LL_CRI, L"Thread access rules(1) can NOT adjusted for: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

			CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ACCESS_1_FAIL, g_winAPIs->GetLastError());
			return nullptr;
		}

		if (IsWindows10OrGreater())
		{
			if (CApplication::Instance().AccessHelperInstance()->ChangeAccessRights(hThread, EACLTargetType::THREAD) == false)
			{
				APP_TRACE_LOG(LL_CRI, L"Thread access rules(2) can NOT adjusted for: %d Error: %u", nThreadIdx, g_winAPIs->GetLastError());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CUSTOM_THREAD_ACCESS_2_FAIL, g_winAPIs->GetLastError());
				return nullptr;
			}
		}
//		*/

		threadInfos->nThreadIdx = nThreadIdx;
		threadInfos->hThread 	= hThread;
		threadInfos->dwThreadID = dwThreadId;
		if (spThreadInterface)
		{
			threadInfos->dwThreadStartAddress = reinterpret_cast<DWORD_PTR>(spThreadInterface->GetStartAddress());
			threadInfos->ulFuncSize = spThreadInterface->GetThreadFuncSize();
			threadInfos->spThreadInterface = spThreadInterface;
		}
		else
		{
			threadInfos->dwThreadStartAddress = reinterpret_cast<DWORD_PTR>(pFunc);
			threadInfos->ulFuncSize = 5;
		}
		threadInfos->ulFuncHash = CPEFunctions::CalculateMemChecksumFast(pFunc, threadInfos->ulFuncSize);
		threadInfos->dwMaxDelay = dwMaxDelay;
		threadInfos->bIsTemporaryThread = bIsTemporaryThread;
		threadInfos->spCustomThread = customThread;

		AddThreadToPool(threadInfos);

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		const auto wstThreadName = fmt::format(xorstr_(L"Custom thread: {0} ({1})"), this->GetThreadCustomName(nThreadIdx), nThreadIdx);
		const auto stThreadName = stdext::to_ansi(wstThreadName);

		if (g_winAPIs->SetThreadDescription)
			g_winAPIs->SetThreadDescription(hThread, wstThreadName.c_str());
		else
			__SetThreadNameViaException(stThreadName.c_str());
#endif

		CApplication::Instance().SelfThreadIdentifierInstance()->InitializeThreadChecks(nThreadIdx);

		if (spThreadInterface)
			spThreadInterface->Resume();
		else
			g_winAPIs->ResumeThread(hThread);

		APP_TRACE_LOG(LL_SYS, L"Custom thread created! %d) %p (%u) Adr: %p Sum: %p", nThreadIdx, hThread, dwThreadId, pFunc, threadInfos->ulFuncHash);
		return customThread;
	}

	bool CThreadManager::DestroyThread(const std::shared_ptr <CThread>& thread)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		if (!IS_VALID_SMART_PTR(thread) /* || thread->IsValid() == false */)
		{
			APP_TRACE_LOG(LL_CRI, L"Unknown thread! Tid: %u", IS_VALID_SMART_PTR(thread) ? thread->GetID() : (DWORD)-1);
			return false;
		}

		if (m_vThreadPool.empty())
			return true;

		for (const auto& pCurrThread : m_vThreadPool)
		{
			if (pCurrThread->dwThreadID == thread->GetID())
			{
				// APP_TRACE_LOG(LL_SYS, L"Destroying thread: %u (%u)", pCurrThread->dwThreadId, pCurrThread->nThreadIdx);

				auto threadInfo = GetThreadInfo(pCurrThread->nThreadIdx);
				if (IS_VALID_SMART_PTR(threadInfo))
					m_vThreadPool.erase(std::remove(m_vThreadPool.begin(), m_vThreadPool.end(), threadInfo), m_vThreadPool.end());

//				if (IS_VALID_HANDLE(pCurrThread->hWaitObj))
//					g_winAPIs->UnregisterWait(pCurrThread->hWaitObj);

				if (!IS_VALID_SMART_PTR(pCurrThread->spThreadInterface))
					thread->Terminate();

				if (IS_VALID_SMART_PTR(pCurrThread->spCustomThread))
				{
					pCurrThread->spCustomThread.reset();
					pCurrThread->spCustomThread = nullptr;
				}
				if (IS_VALID_SMART_PTR(pCurrThread->spThreadInterface))
				{
					pCurrThread->spThreadInterface->Release();
					pCurrThread->spThreadInterface.reset();
					pCurrThread->spThreadInterface = nullptr;
				}
				return true;
			}
		}

		return false;
	}
	void CThreadManager::DestroyThread(int32_t nThreadIdx)
	{
		if (!this || !CApplication::InstancePtr() || !IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			return;

		auto currentThread = this->GetThreadFromThreadCode(nThreadIdx);
		if (IS_VALID_SMART_PTR(currentThread))
			DestroyThread(currentThread);
	}

	void CThreadManager::DestroyThreads()
	{
		static const auto fnTerminateThread = LI_FN(TerminateThread).forwarded_safe();

		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);
		
		if (m_vThreadPool.empty())
			return;

		for (const auto& pCurrThread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(pCurrThread))
			{
				// APP_TRACE_LOG(LL_SYS, L"Destroying thread: %u (%u)", pCurrThread->dwThreadId, pCurrThread->nThreadIdx);

//				if (IS_VALID_HANDLE(pCurrThread->hWaitObj))
//					g_winAPIs->UnregisterWait(pCurrThread->hWaitObj);

				if (IS_VALID_SMART_PTR(pCurrThread->spCustomThread))
				{
					pCurrThread->spCustomThread->Terminate();
					pCurrThread->spCustomThread.reset();
					pCurrThread->spCustomThread = nullptr;
				}
				if (IS_VALID_SMART_PTR(pCurrThread->spThreadInterface))
				{
					pCurrThread->spThreadInterface->Release();
					pCurrThread->spThreadInterface.reset();
					pCurrThread->spThreadInterface = nullptr;
				}
				if (fnTerminateThread && pCurrThread->hThread)
				{
					fnTerminateThread(pCurrThread->hThread, EXIT_SUCCESS);
				}
			}
		}
		return;
	}
	void CThreadManager::SuspendThreads()
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& pCurrThread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(pCurrThread) && IS_VALID_HANDLE(pCurrThread->hThread))
			{
				g_winAPIs->SuspendThread(pCurrThread->hThread);
			}
			g_winAPIs->Sleep(10);
		}
		return;
	}

	void CThreadManager::OnThreadTerminated(DWORD dwThreadId)
	{
		if (!dwThreadId)
			return;

		if (!this || !CApplication::InstancePtr() || !CApplication::Instance().AppIsInitiliazed() || !CApplication::Instance().ThreadManagerInstance())
			return;

		const auto pThread = GetThreadFromId(dwThreadId);
		if (!IS_VALID_SMART_PTR(pThread))
			return;

		const auto idx = pThread->GetCustomCode();
		const auto pThreadInfo = GetThreadInfo(idx);
		if (!IS_VALID_SMART_PTR(pThreadInfo))
			return;

		APP_TRACE_LOG(LL_CRI, L"Thread: %u terminated. Temporary: %d", dwThreadId, pThreadInfo->bIsTemporaryThread ? 1 : 0);

		if (!pThreadInfo->bIsTemporaryThread)
			CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_TERMINATE_DETECTED, idx);
	}

	void CThreadManager::AddThreadToPool(std::shared_ptr <SSelfThreads> spThreadInfos)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);
		m_vThreadPool.emplace_back(spThreadInfos);
	}

	const std::vector <std::shared_ptr <SSelfThreads>>& CThreadManager::GetThreadList()
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);
		return m_vThreadPool;
	}

	std::shared_ptr <IThreadInterface> CThreadManager::GetThreadInterface(int nThreadIdx)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);
		
		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->nThreadIdx == nThreadIdx)
				{
					return thread->spThreadInterface;
				}
			}
			g_winAPIs->Sleep(10);
		}
		return nullptr;
	}

	std::shared_ptr <CThread> CThreadManager::GetThreadFromThreadCode(int nThreadIdx)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->nThreadIdx == nThreadIdx)
				{
					return thread->spCustomThread;
				}
			}
			g_winAPIs->Sleep(10);
		}
		return nullptr;
	}

	std::shared_ptr <CThread> CThreadManager::GetThreadFromId(DWORD dwThreadId)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->dwThreadID == dwThreadId)
				{
					return thread->spCustomThread;
				}
			}
			g_winAPIs->Sleep(10);
		}
		return nullptr;
	}

	std::shared_ptr <CThread> CThreadManager::GetThreadFromAddress(DWORD dwThreadAddress)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->dwThreadStartAddress == dwThreadAddress)
				{
					return thread->spCustomThread;
				}
			}
			g_winAPIs->Sleep(10);
		}
		return nullptr;
	}

	std::shared_ptr <CThread> CThreadManager::GetThreadFromHandle(HANDLE hThread)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->hThread == hThread)
				{
					return thread->spCustomThread;
				}
			}
			g_winAPIs->Sleep(10);
		}
		return nullptr;
	}

	std::shared_ptr <SSelfThreads> CThreadManager::GetThreadInfo(int nThreadIdx)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (IS_VALID_SMART_PTR(thread))
			{
				if (thread->nThreadIdx == nThreadIdx)
				{
					return thread;
				}
			}
			// WATCHDOG SCREEN STUCK TEST
			// g_winAPIs->Sleep(10);
		}
		return nullptr;
	}


	std::size_t CThreadManager::GetThreadCount()
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);
		return m_vThreadPool.size();
	}

	std::size_t CThreadManager::GetSuspendedThreadCount()
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		std::size_t nCounter = 0;
		for (const auto& thread : m_vThreadPool)
		{
			if (thread->spCustomThread->HasSuspend())
			{
				nCounter++;
			}
			g_winAPIs->Sleep(10);
		}
		return nCounter;
	}

	bool CThreadManager::HasSuspendedThread()
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxLock);

		for (const auto& thread : m_vThreadPool)
		{
			if (thread->spCustomThread->HasSuspend())
			{
				return true;
			}
			g_winAPIs->Sleep(10);
		}
		return false;
	}

	bool CThreadManager::SetAntiTrace(const std::shared_ptr <CThread>& targetThread, DWORD dwFlag)
	{
		BOOL bCheckStat = FALSE;

		const auto Flag = static_cast<THREADINFOCLASS>(dwFlag);

		if (!IS_VALID_SMART_PTR(targetThread) || !IS_VALID_HANDLE(targetThread->GetHandle()))
		{
			APP_TRACE_LOG(LL_SYS, L"Unknown target thread data!");
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Anti trace started for: %u[%p]", targetThread->GetID(), targetThread->GetHandle());

		const auto ntReturnStat = g_winAPIs->NtSetInformationThread(targetThread->GetHandle(), Flag, &bCheckStat, sizeof(ULONG));
		if (NT_SUCCESS(ntReturnStat))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step1!");
			return false;
		}

		const auto ntFakeStat1 = g_winAPIs->NtSetInformationThread(targetThread->GetHandle(), Flag, &bCheckStat, sizeof(UINT));
		if (NT_SUCCESS(ntFakeStat1))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step2!");
			return false;
		}

		const auto ntFakeStat2 = g_winAPIs->NtSetInformationThread(targetThread->GetHandle(), Flag, (PVOID)sizeof(PVOID), sizeof(PVOID));
		if (NT_SUCCESS(ntFakeStat2))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step2!");
			return false;
		}

		const auto ntFakeStat3 = g_winAPIs->NtSetInformationThread((HANDLE)0xFFFFF, Flag, 0, 0);
		if (NT_SUCCESS(ntFakeStat3))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step3!");
			return false;
		}

		const auto ntCorrectStat = g_winAPIs->NtSetInformationThread(targetThread->GetHandle(), Flag, 0, 0);
		if (!NT_SUCCESS(ntCorrectStat))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step4, Status: %p", ntCorrectStat);
			return false;
		}

		const auto ntCorrectStat2 = g_winAPIs->NtQueryInformationThread(targetThread->GetHandle(), Flag, &bCheckStat, sizeof(BOOLEAN), 0);
		if (!NT_SUCCESS(ntCorrectStat))
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step5, Status: %p", ntCorrectStat);
			return false;
		}

		if (!bCheckStat)
		{
			APP_TRACE_LOG(LL_SYS, L"Anti trace failed on Step6!");
			return false;
		}

		return true;
	}

	std::wstring CThreadManager::GetThreadCustomName(int nThreadIdx)
	{
		switch (nThreadIdx)
		{
			case SELF_THREAD_ANTI_MACRO:
				return xorstr_(L"Anti macro thread");
			case SELF_THREAD_WATCHDOG:
				return xorstr_(L"Watchdog thread");
			case SELF_THREAD_WMI:
				return xorstr_(L"WMI thread");
			case SELF_THREAD_CLIENT_MAIN_ROUTINE:
				return xorstr_(L"Client main routine thread");
			case SELF_THREAD_SERVICE_MAIN_ROUTINE:
				return xorstr_(L"Service main routine thread");
			case SELF_THREAD_THREAD_TICK_CHECKER:
				return xorstr_(L"Thread tick checker thread");
			case SELF_THREAD_TIMER_CHECKER:
				return xorstr_(L"Timer checker thread");
			case SELF_THREAD_MEMORY_MONITOR:
				return xorstr_(L"Memory monitor thread");
			case SELF_THREAD_WEBSOCKET:
				return xorstr_(L"Websocket thread");
			case SELF_THREAD_LOG_COLLECTOR:
				return xorstr_(L"Log collector thread");
			case SELF_THREAD_CHEAT_QUEUE:
				return xorstr_(L"Cheat queue thread");
			case SELF_THREAD_MODULE_SECTION_MONITOR:
				return xorstr_(L"Module section monitor thread");
			case SELF_THREAD_MMAPMODULES:
				return xorstr_(L"Manual map thread");
			case SELF_THREAD_SCANNER:
				return xorstr_(L"Scanner thread");
			case SELF_THREAD_TICK_COUNTER:
				return xorstr_(L"Tick counter thread");
			case SELF_THREAD_CHEAT_QUEUE_MANAGER:
				return xorstr_(L"Cheat queue manager thread");
			case SELF_THREAD_MEM_ALLOC_WATCHER:
				return xorstr_(L"Memory allocation watcher thread");
			case SELF_THREAD_PIPE_SERVER_MANAGER:
				return xorstr_(L"Named pipe server manager thread");
			case SELF_THREAD_ETW_WATCHER:
				return xorstr_(L"ETW watcher thread");
			case SELF_THREAD_HOOK_SCANNER:
				return xorstr_(L"Hook scanner thread");
			case SELF_THREAD_MANUAL_MAP_SCANNER:
				return xorstr_(L"Manual map scanner thread");
			case SELF_THREAD_NET_IPC_SERVER:
				return xorstr_(L"Net IPC server thread");
			case SELF_THREAD_NET_IPC_CLIENT:
				return xorstr_(L"Net IPC client thread");
			case SELF_THREAD_ALPC_SERVER:
				return xorstr_(L"ALPC server thread");
			case SELF_THREAD_ALPC_CLIENT:
				return xorstr_(L"ALPC client thread");
			case SELF_THREAD_SYSTEM_TELEMETRY:
				return xorstr_(L"System telemetry thread");
			case SELF_THREAD_CACHE_MANAGER:
				return xorstr_(L"Cache manager thread");
			case SELF_THREAD_PYTHON_APP:
				return xorstr_(L"Python application thread");
		}

		return std::wstring(xorstr_(L"Unknown thread: ")) + std::to_wstring(nThreadIdx);
	}
};
