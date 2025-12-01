#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ThreadInterface.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"
#include <crashpad/client/simulate_crash_win.h>

namespace NoMercy
{
	inline void __OnShutdown(uint32_t signal)
	{
		if (gs_abShuttingDown.load())
			return;
		gs_abShuttingDown.store(true);

		APP_TRACE_LOG(LL_CRI, L"Fatal error: %u", signal);

		if (NoMercyCore::CApplication::InstancePtr())
			NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();

		if (CApplication::InstancePtr() && !gs_abShuttingDown)
			OnPreFail(0, CORE_ERROR_ABNORMAL_PROGRAM_TERMINATION_BY_THREAD, signal);
	}
	static void __OnHandleInterruptByThread(int signal)
	{
		APP_TRACE_LOG(LL_CRI, L"Thread signal: %d handled", signal);

		__OnShutdown(signal);
	}
	static void __cdecl __OnHandleTerminateByThread(void)
	{
		APP_TRACE_LOG(LL_CRI, L"Terminate detected!");

		__OnShutdown(static_cast<uint32_t>(-1));
	}
	static void __cdecl __OnHandleUnexpectedByThread(void)
	{
		APP_TRACE_LOG(LL_CRI, L"Unexpected detected!");

		__OnShutdown(static_cast<uint32_t>(-2));
	}

	void __OnSETranslate(unsigned int u, EXCEPTION_POINTERS*)
	{
		APP_TRACE_LOG(LL_CRI, L"SE signal: %u handled", u);

		__OnShutdown(static_cast<uint32_t>(-3));
	}
	inline void __SetThreadExceptionHandlers()
	{
		// Catch terminate() calls.
		// In a multithreaded environment, terminate functions are maintained
		// separately for each thread. Each new thread needs to install its own
		// terminate function. Thus, each thread is in charge of its own termination handling.
		// http://msdn.microsoft.com/en-us/library/t6fk7h29.aspx
		std::set_terminate(&__OnHandleTerminateByThread);

		// Catch unexpected() calls.
		// In a multithreaded environment, unexpected functions are maintained
		// separately for each thread. Each new thread needs to install its own
		// unexpected function. Thus, each thread is in charge of its own unexpected handling.
		// http://msdn.microsoft.com/en-us/library/h46t5b69.aspx
		set_unexpected(&__OnHandleUnexpectedByThread);

		// Catch a floating point error
		std::signal(SIGFPE, &__OnHandleInterruptByThread);

		// Catch an illegal instruction
		std::signal(SIGILL, &__OnHandleInterruptByThread);

		// Catch illegal storage access errors
		std::signal(SIGSEGV, &__OnHandleInterruptByThread);

		return;
	}


	IThreadInterface::IThreadInterface(int32_t nThreadIdx, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwDelay) :
		m_bInitialized(false), m_bRunning(true), m_bPaused(true), m_nThreadIdx(nThreadIdx), m_hThread(nullptr),
		m_dwThreadId(0), m_pFunc(pFunc), m_pParam(lpParam), m_dwDelay(dwDelay) // , m_kSETranslator(nullptr)
	{
		m_dwStartTime = stdext::get_current_epoch_time();
	}
	IThreadInterface::~IThreadInterface()
	{
	}

	void IThreadInterface::Start()
	{
		m_bRunning = true;
	}
	void IThreadInterface::Stop()
	{
		m_bRunning = false;
	}
	void IThreadInterface::Pause()
	{
		m_bPaused = true;
	}
	void IThreadInterface::Resume()
	{
		m_bPaused = false;
	}
	void IThreadInterface::Join()
	{
		g_winAPIs->WaitForSingleObject(m_hThread, INFINITE);
	}

	DWORD IThreadInterface::ThreadProxyRoutine(void)
	{
		/*
		// Impl routine
		auto __ThreadProxyRoutineImpl = [&]() -> DWORD {
			auto ret = 0ul;
			if (m_pFunc)
				ret = m_pFunc(m_pParam);
			return ret;
		};
		*/

		// m_kSETranslator = _set_se_translator(&__OnSETranslate);

		// __SetThreadExceptionHandlers();

		while (m_bRunning)
		{
			if (!m_bPaused)
			{
				// __ThreadProxyRoutineImpl();
				if (m_pFunc)
					m_pFunc(m_pParam);

				/*
				// Thread routine
				const auto spRet = m_upSafeExecutor->SafeExec<DWORD>(SAFE_FUNCTION_ID_SAFE_THREAD_EXEC, &__ThreadProxyRoutineImpl);
				APP_TRACE_LOG(LL_SYS, L"Thread: %u safe execution completed. Ptr: %p Error code: %p", m_nThreadIdx, spRet.get(), spRet ? spRet->error_code : 0);

				if (IS_VALID_SMART_PTR(spRet) && spRet->error_code && IS_VALID_SMART_PTR(spRet->exception))
				{
					APP_TRACE_LOG(LL_CRI, L"Safe executor Exception detected. Address: %p (%s) Code: %p Flags: %u",
						spRet->exception->address, spRet->exception->address_symbol, spRet->exception->code, spRet->exception->flags
					);

					APP_TRACE_LOG(LL_SYS, L"Registers:");
					for (const auto& [reg, val] : spRet->exception->registers)
					{
						APP_TRACE_LOG(LL_SYS, L"%s: %p", reg.c_str(), val);
					}

					APP_TRACE_LOG(LL_SYS, L"Stack:");
					for (const auto& ctx : spRet->exception->stack)
					{
						if (IS_VALID_SMART_PTR(ctx))
						{
							APP_TRACE_LOG(LL_SYS, L"[%llu] %p Module: %s Image: %s Symbol: %s File: %s (%u)", ctx->idx, ctx->frame, ctx->module_name, ctx->image_name, ctx->symbol_name, ctx->file_name, ctx->file_line);
						}
					}
				}

				// Have not returned data container
				if (!IS_VALID_SMART_PTR(spRet))
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_SAFE_EXEC_FAIL, 1);
					return 0;
				}
				// Have a error code (throwed exception)
				if (spRet->error_code)
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_SAFE_EXEC_FAIL, 2);
					return 0;
				}
				// Have not a return value (?)
				if (!spRet->return_value.has_value())
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_SAFE_EXEC_FAIL, 3);
					return 0;
				}
				// 'non 0' return value (execute failed)
				if (spRet->return_value.value())
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_THREAD_SAFE_EXEC_FAIL, 4);
					return 0;
				}
				*/

				// Update ticks
				if (m_dwDelay)
				{
					CApplication::Instance().SelfThreadIdentifierInstance()->IncreaseThreadTick(m_nThreadIdx);
					CApplication::Instance().SelfThreadIdentifierInstance()->SetLastCheckTime(m_nThreadIdx, stdext::get_current_epoch_time());

					g_winAPIs->Sleep(m_dwDelay);
				}
			}
			
			// NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->YieldCPU();
			g_winAPIs->Sleep(10);
		}

		// _set_se_translator(m_kSETranslator);
		return 0;
	}
	DWORD WINAPI IThreadInterface::StartThreadProxyRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<IThreadInterface*>(lpParam);
		return This->ThreadProxyRoutine();
	}

	std::size_t IThreadInterface::GetThreadFuncSize() const
	{
		ldasm_data ld{ 0 };
		auto dwLength = ldasm(&this->StartThreadProxyRoutine, &ld, CApplication::Instance().FunctionsInstance()->IsX64System());

		APP_TRACE_LOG(LL_SYS, L"Thread: %d length: %u", m_nThreadIdx, dwLength);

		if (!dwLength || dwLength > 64)
			dwLength = 5;

		return dwLength;
	}

	bool IThreadInterface::Initialize()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread: %d initilization started! Func: %p (%p)", m_nThreadIdx, m_pFunc, m_pParam);

		if (!(m_nThreadIdx > SELF_THREAD_NONE && m_nThreadIdx < SELF_THREAD_MAX))
		{
			APP_TRACE_LOG(LL_SYS, L"Thread idx: %d is corrupted!", m_nThreadIdx);
			return false;
		}

		if (!m_pFunc)
		{
			APP_TRACE_LOG(LL_SYS, L"Thread: %d func is corrupted!", m_nThreadIdx);
			return false;
		}

		/*
		m_upSafeExecutor = stdext::make_unique_nothrow<CSafeExecutor>(false);
		if (!IS_VALID_SMART_PTR(m_upSafeExecutor))
		{
			APP_TRACE_LOG(LL_SYS, L"Safe executor allocate failed!");
			return false;
		}
		*/

		auto dwThreadId = 0UL;
		auto hThread = CThreadFunctions::CreateThread(m_nThreadIdx, StartThreadProxyRoutine, this, 0, &dwThreadId);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread: %d can NOT created! Error: %u", m_nThreadIdx, g_winAPIs->GetLastError());
			return false;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hThread))
		{
			APP_TRACE_LOG(LL_CRI, L"Thread: %d handle can not verified!", m_nThreadIdx);
			return false;
		}

		const auto dwWaitRet = g_winAPIs->WaitForSingleObject(hThread, 0);
		const auto dwErr = g_winAPIs->GetLastError();
		if (dwWaitRet == WAIT_FAILED && dwErr == ERROR_INVALID_HANDLE)
		{
			APP_TRACE_LOG(LL_CRI, L"Thread: %d wait failed! Ret: %u Err: %u", m_nThreadIdx, dwWaitRet, dwErr);
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Thread: %d initilization completed!", m_nThreadIdx);

		m_hThread = hThread;
		m_dwThreadId = dwThreadId;
		m_bInitialized = true;
		return true;
	}
	void IThreadInterface::Release()
	{
//		static const auto fnWaitForSingleObject = LI_FN(WaitForSingleObject).forwarded_safe();
		
		if (!m_bInitialized)
			return;

		this->Pause();
		this->Stop();

//		if (fnWaitForSingleObject)
//			fnWaitForSingleObject(m_hThread, 2000);

		m_bInitialized = false;
	}
};
