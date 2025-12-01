#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "HardwareBreakpointWatcher.hpp"
#include "../Anti/AntiBreakpoint.hpp"
#include "../../../Common/SimpleTimer.hpp"

#ifdef _M_IX86
#define XIP Eip
#else
#define XIP Rip
#endif

#pragma pack(1)
typedef struct _DEBUG_DR6_
{
	union {
		ULONG32 _DR6;
		struct {
			unsigned B0 : 1;
			unsigned B1 : 1;
			unsigned B2 : 1;
			unsigned B3 : 1;
			unsigned Reverted : 9;
			unsigned BD : 1;
			unsigned BS : 1;
			unsigned BT : 1;
			unsigned Reverted2 : 16;
		}st;
	}u;
}DEBUG_DR6, * PDEBUG_DR6;

typedef struct _DEBUG_DR7_
{
	union {
		ULONG32 _DR7;
		struct {
			unsigned L0 : 1; //0
			unsigned G0 : 1; //1
			unsigned L1 : 1; //2
			unsigned G1 : 1; //3
			unsigned L2 : 1; //4
			unsigned G2 : 1; //5
			unsigned L3 : 1; //6
			unsigned G3 : 1; //7
			unsigned LE : 1; //8
			unsigned GE : 1; //9
			unsigned reserved : 3; //001  //10-11-12
			unsigned GD : 1; //13...
			unsigned reserved2 : 2; //00
			unsigned RW0 : 2;
			unsigned LEN0 : 2;
			unsigned RW1 : 2;
			unsigned LEN1 : 2;
			unsigned RW2 : 2;
			unsigned LEN2 : 2;
			unsigned RW3 : 2;
			unsigned LEN3 : 2;
		}st;
	}u;
}DEBUG_DR7, * PDEBUG_DR7;
#pragma pack()

namespace NoMercy
{
	static DWORD gs_dwCounter = 0;
	static const auto gsc_nHwbpSlotCount = 4; // Only 4 slot for HWBP(DR[0/1/2/3])
	static PVOID gs_pHookAddress[gsc_nHwbpSlotCount] = { nullptr };
	static PVOID gs_pJmpAddress[gsc_nHwbpSlotCount] = { nullptr };

	int HwbpTrapFilter(EXCEPTION_POINTERS* pException)
	{
		if (!pException || !pException->ContextRecord || !pException->ExceptionRecord || !pException->ContextRecord->Dr6)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 99);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		const auto pContext = pException->ContextRecord;
		
		DEBUG_DR6 dr6;
		dr6.u._DR6 = pException->ContextRecord->Dr6;

		ADMIN_DEBUG_LOG(LL_SYS,
			L"[%u] tid = %u, ip = %p exception %p, %p/%p/%p/%p",
			gs_dwCounter++,
			g_winAPIs->GetCurrentThreadId(),
			pContext->XIP,
			pException->ExceptionRecord->ExceptionCode,
			dr6.u.st.B0, dr6.u.st.B1, dr6.u.st.B2, dr6.u.st.B3
		);

		if (dr6.u.st.B0)
		{
			if (pContext->XIP == (DWORD)gs_pHookAddress[0])
				pContext->XIP = (DWORD)gs_pJmpAddress[0];

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		if (dr6.u.st.B1)
		{
			if (pContext->XIP == (DWORD)gs_pHookAddress[1])
				pContext->XIP = (DWORD)gs_pJmpAddress[1];

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		if (dr6.u.st.B2)
		{
			if (pContext->XIP == (DWORD)gs_pHookAddress[2])
				pContext->XIP = (DWORD)gs_pJmpAddress[2];

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		if (dr6.u.st.B3)
		{
			if (pContext->XIP == (DWORD)gs_pHookAddress[3])
				pContext->XIP = (DWORD)gs_pJmpAddress[3];

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}


	inline void HWBP_Normal_Func()
	{
		static uint64_t s_nIndex = 0;
		static auto s_kTimer = CStopWatch<std::chrono::milliseconds>();
		if (s_kTimer.diff() > 10000)
		{
			APP_TRACE_LOG(LL_SYS, L"[%llu] HWBP func called.", s_nIndex++); // DELETEME

			// Current process thread tick checker thread validator
			if (CApplication::Instance().SelfThreadIdentifierInstance()->IsTickCheckerThreadIntegrityCorrupted())
			{
				APP_TRACE_LOG(LL_ERR, L"Tick checker thread integrity check fail!");

				CApplication::Instance().OnCloseRequest(EXIT_ERR_TICK_CHECKER_THREAD_CORRUPTED, g_winAPIs->GetLastError());
			}

			s_kTimer.reset();
		}
	}

	static void HWBP_Trap_Func_0()
	{
		APP_TRACE_LOG(LL_CRI, L"HWBP trap function 1 is triggered! TID: %u", g_winAPIs->GetCurrentThreadId());
		CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_DETECT, 1);
	}
	static void HWBP_Trap_Func_1()
	{
		APP_TRACE_LOG(LL_CRI, L"HWBP trap function 2 is triggered!");
		CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_DETECT, 2);
	}
	static void HWBP_Trap_Func_2()
	{
		APP_TRACE_LOG(LL_CRI, L"HWBP trap function 3 is triggered!");
		CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_DETECT, 3);
	}
	static void HWBP_Trap_Func_3()
	{
		APP_TRACE_LOG(LL_CRI, L"HWBP trap function 4 is triggered!");
		CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_DETECT, 4);
	}

	void CallHwbpTrapFuncs()
	{
		const auto dwInitializedThreadID = CApplication::Instance().HwbpWatcherInstance()->GetInitializedTID();
		APP_TRACE_LOG(LL_TRACE, L"HWBP trap func call triggered Current TID: %u Init TID: %u", g_winAPIs->GetCurrentThreadId(), dwInitializedThreadID);

		if (dwInitializedThreadID != g_winAPIs->GetCurrentThreadId())
			return;

		auto fnTriggerTrap = []() {
			__try
			{
				HWBP_Trap_Func_0();
				HWBP_Trap_Func_3();
				HWBP_Trap_Func_2();
				HWBP_Trap_Func_1();
			}
			__except (HwbpTrapFilter(GetExceptionInformation()))
			{
			}
		};
		fnTriggerTrap();
	}


	CHardwareBreakpointWatcher::CHardwareBreakpointWatcher() :
		m_bIsInitialized(false),  m_dwInitializedThreadID(0)
	{
	}
	CHardwareBreakpointWatcher::~CHardwareBreakpointWatcher()
	{
	}

	bool CHardwareBreakpointWatcher::IsTrapAddress(PVOID pvAddr) const
	{
		if (pvAddr == (PVOID)HWBP_Trap_Func_0 ||
			pvAddr == (PVOID)HWBP_Trap_Func_3 ||
			pvAddr == (PVOID)HWBP_Trap_Func_2 ||
			pvAddr == (PVOID)HWBP_Trap_Func_1)
		{
			return true;
		}

		return false;
	}

	bool CHardwareBreakpointWatcher::SetupHwbpTrap()
	{
		APP_TRACE_LOG(LL_SYS, L"HWBP trap initialize started! TID: %u", g_winAPIs->GetCurrentThreadId());

		if (CAntiBreakpoint::HasHardwareBreakpoint(NtCurrentThread()))
		{
			APP_TRACE_LOG(LL_ERR, L"Already have hwbp in target thread!");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 3);
			return false;
		}

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!g_winAPIs->GetThreadContext(NtCurrentThread(), &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 4);
			return false;
		}

		ctx.Dr0 = (DWORD)gs_pHookAddress[0];
		ctx.Dr1 = (DWORD)gs_pHookAddress[1];
		ctx.Dr2 = (DWORD)gs_pHookAddress[2];
		ctx.Dr3 = (DWORD)gs_pHookAddress[3];
		ctx.Dr7 = 0x455;
		// ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!g_winAPIs->SetThreadContext(NtCurrentThread(), &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 5);
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"HWBP trap succesfully initialized! (%p/%p/%p/%p)", ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3);
		
		m_dwInitializedThreadID = g_winAPIs->GetCurrentThreadId();

		if (!ValidateHwbpTrap())
			return false;

		APP_TRACE_LOG(LL_SYS, L"HWBP trap succesfully validated!");
		return true;
	}

	bool CHardwareBreakpointWatcher::ValidateHwbpTrap()
	{
		APP_TRACE_LOG(LL_TRACE, L"HWBP validation has been started! TID: %u", g_winAPIs->GetCurrentThreadId());

		if (!m_bIsInitialized)
			return true;

		SafeHandle pkThread = g_winAPIs->OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, m_dwInitializedThreadID);
		if (!pkThread.IsValid())
		{
			APP_TRACE_LOG(LL_ERR, L"OpenThread failed with error: %u", g_winAPIs->GetLastError());
			return true; // ignore
		}

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!g_winAPIs->GetThreadContext(pkThread.get(), &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u TID: %u", g_winAPIs->GetLastError(), g_winAPIs->GetCurrentThreadId());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 103);
			return false;
		}

		if (ctx.Dr0 != (DWORD)gs_pHookAddress[0])
		{
			APP_TRACE_LOG(LL_ERR, L"Trap HWBP DR0 register: %p validation failed TID: %u", ctx.Dr0, g_winAPIs->GetCurrentThreadId());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 201);
			return false;
		}
		else if (ctx.Dr1 != (DWORD)gs_pHookAddress[1])
		{
			APP_TRACE_LOG(LL_ERR, L"Trap HWBP DR1 register: %p validation failed TID: %u", ctx.Dr1, g_winAPIs->GetCurrentThreadId());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 202);
			return false;
		}
		else if (ctx.Dr2 != (DWORD)gs_pHookAddress[2])
		{
			APP_TRACE_LOG(LL_ERR, L"Trap HWBP DR2 register: %p validation failed TID: %u", ctx.Dr2, g_winAPIs->GetCurrentThreadId());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 203);
			return false;
		}
		else if (ctx.Dr3 != (DWORD)gs_pHookAddress[3])
		{
			APP_TRACE_LOG(LL_ERR, L"Trap HWBP DR3 register: %p validation failed TID: %u", ctx.Dr3, g_winAPIs->GetCurrentThreadId());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HWBP_TRAP_CHECK_FAIL, 204);
			return false;
		}

		APP_TRACE_LOG(LL_TRACE, L"HWBP validation completed! TID: %u", g_winAPIs->GetCurrentThreadId());
		return true;
	}

	bool CHardwareBreakpointWatcher::InitWatcher()
	{
		if (m_bIsInitialized)
			return false;

		gs_pJmpAddress[0] = (PVOID)HWBP_Normal_Func;
		gs_pHookAddress[0] = (PVOID)HWBP_Trap_Func_0;
		gs_pJmpAddress[1] = (PVOID)HWBP_Normal_Func;
		gs_pHookAddress[1] = (PVOID)HWBP_Trap_Func_3;
		gs_pJmpAddress[2] = (PVOID)HWBP_Normal_Func;
		gs_pHookAddress[2] = (PVOID)HWBP_Trap_Func_2;
		gs_pJmpAddress[3] = (PVOID)HWBP_Normal_Func;
		gs_pHookAddress[3] = (PVOID)HWBP_Trap_Func_1;

		m_bIsInitialized = true;
		
		if (!SetupHwbpTrap())
		{
			APP_TRACE_LOG(LL_ERR, L"Hwbp trap setup fail");
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"HWBP watcher timer initialized! TID: %u [0] %p > %p, [1] %p > %p, [2] %p > %p, [3] %p > %p",
			g_winAPIs->GetCurrentThreadId(),
			gs_pHookAddress[0], gs_pJmpAddress[0], gs_pHookAddress[1], gs_pJmpAddress[1],
			gs_pHookAddress[2], gs_pJmpAddress[2], gs_pHookAddress[3], gs_pJmpAddress[3]
		);
		return true;
	}

	void CHardwareBreakpointWatcher::ReleaseWatcher()
	{
		if (!m_bIsInitialized)
			return;

		SafeHandle pkThread = g_winAPIs->OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwInitializedThreadID);
		if (!pkThread.IsValid())
		{
			APP_TRACE_LOG(LL_ERR, L"OpenThread failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!g_winAPIs->GetThreadContext(pkThread.get(), &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		ctx.Dr0 = 0;
		ctx.Dr1 = 0;
		ctx.Dr2 = 0;
		ctx.Dr3 = 0;
		ctx.Dr7 = 0;

		if (!g_winAPIs->SetThreadContext(pkThread.get(), &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		APP_TRACE_LOG(LL_ERR, L"Breakpoints succesfully removed!");
		m_bIsInitialized = false;
	}
};
