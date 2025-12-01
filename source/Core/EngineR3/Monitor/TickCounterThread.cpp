#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "TickCounterThread.hpp"

namespace NoMercy
{
	CTickCounter::CTickCounter() :
		m_bIsInitialized(false)
	{
	}
	CTickCounter::~CTickCounter()
	{
	}

	DWORD CTickCounter::TickCounterRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Tick counter event has been started");

		// Skip when debugging is active
		if (g_winAPIs->IsDebuggerPresent())
		{
			APP_TRACE_LOG(LL_SYS, L"Skipped in debugging");
			return 0;
		}

		// Save current priority
		const auto dwOldPriority = g_winAPIs->GetThreadPriority(NtCurrentThread());
		if (dwOldPriority == THREAD_PRIORITY_ERROR_RETURN)
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadPriority failed with error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		// Set new priority
		if (!g_winAPIs->SetThreadPriority(NtCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL))
		{
			APP_TRACE_LOG(LL_ERR, L"SetThreadPriority failed with error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		// Calculate cycles
		const auto ulCalibrator = g_winAPIs->NtGetTickCount();
		
		g_winAPIs->Sleep(500);

		const auto ulCalibration = (g_winAPIs->NtGetTickCount() - ulCalibrator);
		
		// Check cycle
		APP_TRACE_LOG(LL_SYS, L"[1] Tick count: %u", ulCalibration);
		if (ulCalibration > 2500)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_TICK_COUNT_VIOLATION, ulCalibration);
			return 0;
		}

		// Calculate cycles
		const auto ullCalibrator = __rdtsc();

		g_winAPIs->Sleep(1000);

		const auto ullCalibration = __rdtsc() - ullCalibrator;

		// Time cpuid
		auto total_time = 0;
		for (std::size_t count = 0; count < 0x6694; count++)
		{
			// Save pre cpuid time
			const auto timestamp_pre = __rdtsc();

			int cpuid_data[4] = {};
			__cpuid(cpuid_data, 0);

			// Save the delta
			total_time += __rdtsc() - timestamp_pre;
		}

		const auto ullReportVal = 10000000 * total_time / ullCalibration / 0x65;
		
		const auto wstReportVal = std::to_wstring(ullReportVal);
		APP_TRACE_LOG(LL_SYS, L"[2] Tick count: %s", wstReportVal.c_str());
		
		// Report
		if (ullReportVal && ullReportVal < 400)
		{
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_TICK_COUNT, 0, wstReportVal);
		}
		
		// Restore priority
		g_winAPIs->SetThreadPriority(NtCurrentThread(), dwOldPriority);
		return 0;
	}

	DWORD WINAPI CTickCounter::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CTickCounter*>(lpParam);
		return This->TickCounterRoutine();
	}

	bool CTickCounter::InitializeThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_TICK_COUNTER, StartThreadRoutine, (void*)this, 18000, false);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
	void CTickCounter::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_TICK_COUNTER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
