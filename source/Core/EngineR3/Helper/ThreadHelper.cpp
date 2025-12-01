#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ThreadHelper.hpp"
#include "ProcessHelper.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/ThreadEnumeratorNT.hpp"
#include "../../EngineR3_Core/include/DirFunctions.hpp"



namespace NoMercy
{
	CThread::CThread(const DWORD dwThreadId, const DWORD dwAccessMask, CProcess* Process) :
		m_pOwnerProcess(Process), m_dwThreadId(dwThreadId), m_hThread(INVALID_HANDLE_VALUE), m_dwThreadIdx(0)
	{
		m_hThread = g_winAPIs->OpenThread(dwAccessMask, FALSE, dwThreadId);
		if (!IS_VALID_HANDLE(m_hThread))
		{
			auto threadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>(dwAccessMask);
			if (IS_VALID_SMART_PTR(threadEnumerator))
			{
				const auto vThreads = threadEnumerator->EnumerateThreads(Process ? Process->GetUserHandle() : NtCurrentProcess());
				if (vThreads.empty() == false)
				{
					for (const auto& hCurrThread : vThreads)
					{
						const auto dwCurrThreadId = g_winAPIs->GetThreadId(hCurrThread);
						if (dwCurrThreadId == dwThreadId)
						{
							m_hThread = hCurrThread;
							break;
						}
					}
				}
			}

		}
	}
	CThread::CThread(const HANDLE hThread, CProcess* Process) :
		m_pOwnerProcess(Process), m_hThread(hThread), m_dwThreadId(0), m_dwThreadIdx(0)
	{
		m_dwThreadId = CThreadFunctions::GetThreadID(hThread);
	}

	CThread::~CThread()
	{
		static const auto fnCloseHandle = LI_FN(CloseHandle).forwarded_safe();
		static auto fnSafeCloseHandle = [](HANDLE hObject) {
			if (fnCloseHandle)
			{
				__try
				{
					fnCloseHandle(hObject);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
				}
			}
		};
		
		m_dwThreadId = 0;

		if (m_hThread)
		{
			if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().WinAPIManagerInstance())
			{
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hThread);
			}
			else
			{
				fnSafeCloseHandle(m_hThread);
			}
		}
		
		m_hThread = INVALID_HANDLE_VALUE;
	}

	inline CThread::CThread(CThread&& other) noexcept
	{
		*this = std::forward<CThread>(other);
	}
	inline CThread& CThread::operator=(CThread&& other) noexcept
	{
		std::swap(m_hThread, other.m_hThread);
		std::swap(m_dwThreadId, other.m_dwThreadId);
		std::swap(m_dwThreadIdx, other.m_dwThreadIdx);

		return *this;
	}
	
	inline CThread::operator bool() noexcept
	{
		return IsValid();
	}

	void CThread::Terminate()
	{
		if (!m_hThread)
			return;

		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().WinAPIManagerInstance())
		{
			if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThread))
			{
				g_winAPIs->TerminateThread(m_hThread, EXIT_SUCCESS);
			}
		}
		else
		{
			static const auto fnTerminateThread = LI_FN(TerminateThread).forwarded_safe();
			if (fnTerminateThread)
			{
				fnTerminateThread(m_hThread, EXIT_SUCCESS);
			}
		}
	}

	bool CThread::PutHWBP(const void* address, const bool enable, const EHWBPType type, const EHWBPSize size)
	{
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!g_winAPIs->GetThreadContext(m_hThread, &ctx))
		{
			APP_TRACE_LOG(LL_CRI, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		bool success = false;

		if (enable)
		{
			for (size_t i = 0; i < 4; ++i)
			{
				// is this bp already being used
				if (ctx.Dr7 & (size_t(1) << (i * 2)))
					continue;

				// set the address
				(&ctx.Dr0)[i] = (uintptr_t)address;

				// enable the dr7 flag
				ctx.Dr7 |= size_t(1) << (i * 2);

				// specify the breakpoint size and when should it trigger
				const auto type_size_mask((size_t(size) << 2) | size_t(type));
				ctx.Dr7 &= ~(0b1111 << (16 + i * 4)); // clear old value
				ctx.Dr7 |= type_size_mask << (16 + i * 4);

				success = true;
				break;
			}
		}
		else
		{
			for (size_t i = 0; i < 4; ++i)
			{
				// matching address?
				if ((void*)((&ctx.Dr0)[i]) != address)
					continue;

				// clear the debug register
				(&ctx.Dr0)[i] = 0;

				// disable the dr7 flag
				ctx.Dr7 &= ~(1 << (i * 2));

				// clear out the size/type as well cuz we're nice people
				ctx.Dr7 &= ~(0b1111 << (16 + i * 4));

				success = true;
				break;
			}
		}

		if (!success)
			return false;

		if (!g_winAPIs->SetThreadContext(m_hThread, &ctx))
		{
			APP_TRACE_LOG(LL_CRI, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		return true;
	}
	
	void CThread::ClearDebugRegisters()
	{
		auto __registerCleaner = [](LPVOID lpParam) -> DWORD {
			auto hThread = (HANDLE)lpParam;

			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_ALL;

			if (g_winAPIs->SuspendThread(hThread) == (DWORD)-1)
			{
				APP_TRACE_LOG(LL_CRI, L"SuspendThread failed with error: %u", g_winAPIs->GetLastError());
				return 0;
			}

			if (!g_winAPIs->GetThreadContext(hThread, &ctx))
			{
				APP_TRACE_LOG(LL_CRI, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
				return 0;
			}

			if (ctx.Dr0)
			{
				APP_TRACE_LOG(LL_DEV, L"ctx.Dr0: %p cleaned!", ctx.Dr0);
				ctx.Dr0 = 0;
			}
			if (ctx.Dr1)
			{
				APP_TRACE_LOG(LL_DEV, L"ctx.Dr1: %p cleaned!", ctx.Dr1);
				ctx.Dr1 = 0;
			}
			if (ctx.Dr2)
			{
				APP_TRACE_LOG(LL_DEV, L"ctx.Dr2: %p cleaned!", ctx.Dr2);
				ctx.Dr2 = 0;
			}
			if (ctx.Dr3)
			{
				APP_TRACE_LOG(LL_DEV, L"ctx.Dr3: %p cleaned!", ctx.Dr3);
				ctx.Dr3 = 0;
			}
			if (ctx.Dr7)
			{
				APP_TRACE_LOG(LL_DEV, L"ctx.Dr7: %p cleaned!", ctx.Dr7);
				ctx.Dr7 = 0;
			}

			if (!g_winAPIs->SetThreadContext(hThread, &ctx))
			{
				APP_TRACE_LOG(LL_CRI, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
				return 0;
			}

			if (g_winAPIs->ResumeThread(hThread) == (DWORD)-1)
			{
				APP_TRACE_LOG(LL_CRI, L"ResumeThread failed with error: %u", g_winAPIs->GetLastError());
				return 0;
			}

			return 0;
		};

		if (HasDebugRegisters() == false)
		{
			APP_TRACE_LOG(LL_SYS, L"Has not debug registers!");
			return;
		}

		if (NtCurrentThread() != m_hThread)
		{
			__registerCleaner(m_hThread);
		}
		else
		{
			const auto hCleanerThead = g_winAPIs->CreateThread(nullptr, 0, __registerCleaner, m_hThread, 0, 0);
			if (!hCleanerThead || hCleanerThead == INVALID_HANDLE_VALUE)
			{
				APP_TRACE_LOG(LL_CRI, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
				return;
			}

			const auto dwWaitRet = g_winAPIs->WaitForSingleObject(hCleanerThead, 5000);
			if (dwWaitRet == WAIT_TIMEOUT)
			{
				APP_TRACE_LOG(LL_CRI, L"WaitForSingleObject failed with error: %u", g_winAPIs->GetLastError());
				return;
			}
		}

		if (HasDebugRegisters()) {
			APP_TRACE_LOG(LL_ERR, L"Debug registers can not cleaned");
		} else {
			APP_TRACE_LOG(LL_SYS, L"Debug registers cleaned!");
		}
	}

	void CThread::Join(DWORD dwMSDelay)
	{
		const auto dwWaitRet = g_winAPIs->WaitForSingleObject(m_hThread, dwMSDelay);
		APP_TRACE_LOG(LL_SYS, L"Join completed for: %u, Delay: %u, Ret: %u", m_dwThreadId, dwMSDelay, dwWaitRet);
	}

	void CThread::SetPriority(int iPriority)
	{
		const auto bPriorityRet = g_winAPIs->SetThreadPriority(m_hThread, iPriority);
		APP_TRACE_LOG(LL_SYS, L"Set Priority completed for: %u, New: %u, Ret: %u", m_dwThreadId, iPriority, bPriorityRet ? 1 : g_winAPIs->GetLastError());
	}

	HANDLE CThread::GetHandle()
	{
		return m_hThread;
	}
	DWORD CThread::GetID()
	{
		return m_dwThreadId;
	}
	DWORD CThread::GetCustomCode()
	{
		return m_dwThreadIdx;
	}
	std::wstring CThread::GetThreadCustomName()
	{
		return m_stCustomName;
	}

	PVOID CThread::GetStartAddress()
	{
		PVOID dwThreadStartAddress = nullptr;
		const auto ntStatus = g_winAPIs->NtQueryInformationThread(m_hThread, ThreadQuerySetWin32StartAddress, &dwThreadStartAddress, sizeof(dwThreadStartAddress), NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Thread: %p Status: %p", m_hThread, ntStatus);
		}
		return dwThreadStartAddress;
	}

	int CThread::GetPriority()
	{
		return g_winAPIs->GetThreadPriority(m_hThread);
	}

	DWORD CThread::GetProcessID()
	{
		THREAD_BASIC_INFORMATION tbi{ 0 };
		const auto ntStatus = g_winAPIs->NtQueryInformationThread(m_hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Thread: %p Status: %p", m_hThread, ntStatus);
			return g_winAPIs->GetCurrentProcessId();
		}
		return (DWORD)tbi.ClientId.UniqueProcess;
	}

	std::wstring CThread::GetThreadOwnerFullName()
	{
		const auto dwStartAddress = GetStartAddress();
		if (!dwStartAddress)
			return {};

		wchar_t wszFileName[2048]{ L'\0' };
		if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)dwStartAddress, wszFileName, 2048))
			return {};

		return stdext::to_lower_wide(wszFileName);
	}

	std::wstring CThread::GetThreadOwnerFileName()
	{
		const auto c_stFullName = GetThreadOwnerFullName();
		if (c_stFullName.empty())
			return {};

		const auto c_stFileName = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(c_stFullName);
		if (c_stFileName.empty())
			return {};

		return c_stFileName;
	}

	std::shared_ptr <CONTEXT> CThread::GetContext()
	{
#ifdef _M_IX86
		if (stdext::is_wow64())
		{
			static_assert(sizeof(CONTEXT) == sizeof(WOW64_CONTEXT));

			WOW64_CONTEXT wctx{ 0 };
			wctx.ContextFlags = CONTEXT_ALL;
			if (!g_winAPIs->Wow64GetThreadContext(m_hThread, &wctx))
			{
				const auto dwErrorCode = g_winAPIs->GetLastError();
				if (dwErrorCode != ERROR_ACCESS_DENIED)
				{
					APP_TRACE_LOG(LL_ERR, L"Wow64GetThreadContext fail! Error: %u", g_winAPIs->GetLastError());
				}
				return nullptr;
			}
			
			CONTEXT ctx{ 0 };
			memcpy(&ctx, &wctx, sizeof(wctx));

			return stdext::make_shared_nothrow<CONTEXT>(ctx);
		}
		else
#endif
		{
			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_ALL;
			if (!g_winAPIs->GetThreadContext(m_hThread, &ctx))
			{
				const auto dwErrorCode = g_winAPIs->GetLastError();
				if (dwErrorCode != ERROR_ACCESS_DENIED)
				{
					APP_TRACE_LOG(LL_ERR, L"GetThreadContext fail! Error: %u", g_winAPIs->GetLastError());
				}
				return nullptr;
			}
			
			return stdext::make_shared_nothrow<CONTEXT>(ctx);
		}
	}

	PVOID CThread::GetModuleBaseAddress()
	{
		const auto dwStartAddress = (DWORD_PTR)GetStartAddress();
		if (!dwStartAddress)
			return 0;

		const auto pOwnModule = (LDR_DATA_TABLE_ENTRY*)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->FindOwnModuleFromAddress(dwStartAddress);
		if (!pOwnModule)
			return 0;

		return pOwnModule->DllBase;
	}

	std::size_t CThread::GetModuleSize()
	{
		const auto dwStartAddress = (DWORD_PTR)GetStartAddress();
		if (!dwStartAddress)
			return 0;

		const auto pOwnModule = (LDR_DATA_TABLE_ENTRY*)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->FindOwnModuleFromAddress(dwStartAddress);
		if (!pOwnModule)
			return 0;

		return pOwnModule->SizeOfImage;
	}

	ptr_t CThread::GetThreadTEB()
	{
		// if (this->GetProcessID() != g_winAPIs->GetCurrentProcessId())
		//	return 0; // TODO: implement for other processes
		
		THREAD_BASIC_INFORMATION tbi{ 0 };
		const auto ntStatus = g_winAPIs->NtQueryInformationThread(m_hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Thread: %p Status: %p", m_hThread, ntStatus);
			return 0;
		}
		
		return (ptr_t)tbi.TebBaseAddress;
	}

	bool CThread::IsValid()
	{
		return (m_hThread && m_hThread != INVALID_HANDLE_VALUE);
	}

	bool CThread::IsItAlive()
	{
		auto fnCheckBySingleObj = [this]() {
			const auto dwWaitRet = g_winAPIs->WaitForSingleObject(m_hThread, 0);
			if (dwWaitRet == WAIT_FAILED && g_winAPIs->GetLastError() == ERROR_INVALID_HANDLE)
				return false;
			return dwWaitRet != WAIT_OBJECT_0;
		};
		auto fnCheckByMultipleObj = [this]() {
			HANDLE hThreads[1] = { m_hThread };
			const auto dwWaitRet = g_winAPIs->WaitForMultipleObjects(1, hThreads, TRUE, 0);
			if (dwWaitRet == WAIT_FAILED && g_winAPIs->GetLastError() == ERROR_INVALID_HANDLE)
				return false;
			return dwWaitRet != WAIT_OBJECT_0;
		};
		auto fnCheckByExitCode = [this]() {
			DWORD dwExitCode = 0;
			const auto bWaitRet = g_winAPIs->GetExitCodeThread(m_hThread, &dwExitCode);
			return bWaitRet && dwExitCode == ERROR_NO_MORE_ITEMS;
		};
		auto fnCheckByTEB = [this]() {
			const auto pTEB = GetThreadTEB();
			return pTEB && !IsBadReadPtr(pTEB, 1);
		};

		const auto bSingleWaitRet = fnCheckBySingleObj();
		const auto bMultipleWaitRet = fnCheckByMultipleObj();
		const auto bExitCodeWaitRet = fnCheckByExitCode();
		const auto bTEBWaitRet = fnCheckByTEB();
		
		// const auto bResult = bSingleWaitRet && bMultipleWaitRet; /* && bExitCodeWaitRet && bTEBWaitRet; */
		const auto nCounter = bSingleWaitRet + bMultipleWaitRet + bExitCodeWaitRet + bTEBWaitRet;
		const auto bResult = nCounter >= 2;

		if (!bResult)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread: %u SingleWaitRet: %d MultipleWaitRet: %d ExitCodeWaitRet: %d TEBWaitRet: %d",
				m_dwThreadId, bSingleWaitRet, bMultipleWaitRet, bExitCodeWaitRet, bTEBWaitRet
			);
		}
		
		return bResult;
	}

	bool CThread::IsRemoteThread()
	{
		if (this->GetProcessID() != g_winAPIs->GetCurrentProcessId()) // PEB
			return true;
		return (CThreadFunctions::GetThreadOwnerProcessId(m_dwThreadId) != g_winAPIs->GetCurrentProcessId()); // toolhelp32
	}

	bool CThread::IsGoodPriority()
	{
		return (GetPriority() >= 0);
	}

	bool CThread::HasSuspend()
	{
		const auto dwOwnerPID = CThreadFunctions::GetThreadOwnerProcessId(m_dwThreadId);
		if (dwOwnerPID)
		{
			const auto threadEnumerator = stdext::make_shared_nothrow<CThreadEnumeratorNT>(dwOwnerPID);
			if (IS_VALID_SMART_PTR(threadEnumerator))
			{
				const auto systemThreadOwnerProcInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(threadEnumerator->GetProcInfo());
				if (systemThreadOwnerProcInfo)
				{
					const auto systemThreadInfo = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(threadEnumerator->FindThread(systemThreadOwnerProcInfo, m_dwThreadId));
					if (systemThreadInfo)
					{
						if (systemThreadInfo->ThreadState == Waiting && systemThreadInfo->WaitReason == Suspended)
							return true;
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"FindThread failed!");
					}
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"GetProcInfo failed!");
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"threadEnumerator allocation failed!");
			}
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"dwOwnerPID null!");
		}
		
		// Check by force suspend resume
		return TryResume();
	}

	bool CThread::HasDebugRegisters()
	{
		const auto ctx = GetContext();
		return ctx ? (ctx->Dr0 || ctx->Dr1 || ctx->Dr2 || ctx->Dr3 || ctx->Dr7) : false;
	}

	bool CThread::TrySuspend()
	{
		return (g_winAPIs->SuspendThread(m_hThread) != (DWORD)-1);
	}
	bool CThread::TryResume()
	{
		return (g_winAPIs->ResumeThread(m_hThread) != (DWORD)-1);
	}

	void CThread::SetCustomCode(DWORD dwCode)
	{
		m_dwThreadIdx = dwCode;
	}
	void CThread::SetCustomName(const std::wstring& stName)
	{
		m_stCustomName = stName;
	}
};
