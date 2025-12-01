#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Terminator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"

#pragma warning(push) 
#pragma warning(disable: 4702)

namespace NoMercy
{
	inline bool __TerminateProcessWithJobObject(HANDLE hProcess)
	{
		if (!hProcess || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
			return true;

		auto hJobject = g_winAPIs->CreateJobObjectW(NULL, xorstr_(L"NmTJob"));
		if (!IS_VALID_HANDLE(hJobject))
			return false;

		if (!g_winAPIs->AssignProcessToJobObject(hJobject, hProcess))
		{
			g_winAPIs->CloseHandle(hJobject);
			return false;
		}

		if (!g_winAPIs->TerminateJobObject(hJobject, EXIT_SUCCESS))
		{
			g_winAPIs->CloseHandle(hJobject);
			return false;
		}

		g_winAPIs->WaitForSingleObject(hProcess, 1000);
		g_winAPIs->CloseHandle(hJobject);
		return true;
	}
	inline bool __TerminateProcessWithDebugObject(HANDLE hProcess)
	{
		if (!hProcess || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
			return true;
		
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, 0, 0, 0, 0);

		HANDLE hDebugObject;
		auto ntStat = g_winAPIs->NtCreateDebugObject(&hDebugObject, DEBUG_ALL_ACCESS, &oa, DEBUG_KILL_ON_CLOSE);
		if (NT_SUCCESS(ntStat))
		{
			ntStat = g_winAPIs->NtDebugActiveProcess(hProcess, hDebugObject);
			if (NT_SUCCESS(ntStat))
			{
				g_winAPIs->CloseHandle(hDebugObject);
				return true;
			}
		}

		g_winAPIs->CloseHandle(hDebugObject);
		return false;
	}
	inline bool __TerminateThreadWithHijackContext(HANDLE hThread)
	{
		if (!hThread || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hThread))
			return true;
		
		auto bRet = false;

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_CONTROL;

		if (g_winAPIs->GetThreadContext(hThread, &ctx))
		{
#ifdef _M_IX86
			ctx.Eip = (DWORD)g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("RtlExitUserThread"));
#else
			ctx.Rip = (DWORD64)g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("RtlExitUserThread"));
#endif

			bRet = g_winAPIs->SetThreadContext(hThread, &ctx);
		}

		return bRet;
	}
	
	inline bool __IsValidHandle(HANDLE hTarget)
	{
		static const auto fnGetHandleInformation = LI_FN(GetHandleInformation).forwarded_safe_cached();

		auto dwInfo = 0UL;
		if (!hTarget || !fnGetHandleInformation || !fnGetHandleInformation(hTarget, &dwInfo))
			return false;

		return true;
	};
		
	bool CTerminator::TerminateProcess(HANDLE hProcess)
	{
		if (!hProcess || !__IsValidHandle(hProcess))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid process handle: %p", hProcess);
			return true;
		}

		if (hProcess == NtCurrentProcess())
			goto _killSelf;

		NTSTATUS ntStat = 0;

		if (NoMercyCore::CApplication::InstancePtr() &&
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance() &&
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SyscallHelper())
		{
			ntStat = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SyscallHelper()->NtTerminateProcess(hProcess, EXIT_SUCCESS);
			if (NT_SUCCESS(ntStat) || ntStat == STATUS_PROCESS_IS_TERMINATING)
				return true;

			APP_TRACE_LOG(LL_CRI, L"1# Process could not terminated! Status: %p", ntStat);
		}

		ntStat = g_winAPIs->NtTerminateProcess(hProcess, EXIT_SUCCESS);
		if (NT_SUCCESS(ntStat) || ntStat == STATUS_PROCESS_IS_TERMINATING)
			return true;

		APP_TRACE_LOG(LL_CRI, L"2# Process could not terminated! Status: %p", ntStat);

		if (__TerminateProcessWithJobObject(hProcess))
			return true;

		APP_TRACE_LOG(LL_CRI, L"3# Process could not terminated! Error: %u", g_winAPIs->GetLastError());

		const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
		if (dwProcessID && g_winAPIs->WinStationTerminateProcess(NULL, dwProcessID, DBG_TERMINATE_PROCESS))
			return true;

		APP_TRACE_LOG(LL_CRI, L"4# Process could not terminated! Error: %u", g_winAPIs->GetLastError());

		if (__TerminateProcessWithDebugObject(hProcess))
			return true;
		
		APP_TRACE_LOG(LL_CRI, L"5# Process could not terminated! Error: %u", g_winAPIs->GetLastError());

		auto hKillThread = g_winAPIs->CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)g_winAPIs->LdrShutdownProcess, nullptr, 0, nullptr);
		if (IS_VALID_HANDLE(hKillThread) && g_winAPIs->WaitForSingleObject(hKillThread, 2000) != WAIT_TIMEOUT)
		{
			g_winAPIs->CloseHandle(hKillThread);
			return true;
		}

		APP_TRACE_LOG(LL_CRI, L"6# Process could not terminated! Error: %u", g_winAPIs->GetLastError());

		if (IS_VALID_HANDLE(hKillThread))
		{
			g_winAPIs->CloseHandle(hKillThread);
		}

_killSelf:
		// Release logs
		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().LogHelperInstance())
			NoMercyCore::CApplication::Instance().LogHelperInstance()->Release();

		// Terminate current process
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (g_winAPIs->IsDebuggerPresent())
			std::abort();
		else
			std::exit(0);
#endif
		
		if (NoMercyCore::CApplication::InstancePtr() &&
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance() &&
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SyscallHelper())
		{
			ntStat = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SyscallHelper()->NtTerminateProcess(hProcess, EXIT_SUCCESS);
			if (NT_SUCCESS(ntStat) || ntStat == STATUS_PROCESS_IS_TERMINATING)
				return true;
		}

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [1]");

		g_winAPIs->NtTerminateProcess(hProcess, EXIT_SUCCESS);
		
		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [2]");

		if (g_winAPIs->IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE))
			__fastfail(EXIT_FAILURE);

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [3]");
		g_winAPIs->PostQuitMessage(EXIT_SUCCESS);

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [4]");
		g_winAPIs->CorExitProcess(EXIT_SUCCESS);

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [5]");
		g_winAPIs->LdrShutdownProcess();

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [6]");
		g_winAPIs->RaiseException(static_cast<DWORD>(STATUS_INVALID_PARAMETER), EXCEPTION_NONCONTINUABLE, 0, nullptr);

		/*
		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [7]");
		__int2c();

		APP_TRACE_LOG(LL_CRI, L"Shutdown attempt... [8]");
		__ud2();
		*/

		APP_TRACE_LOG(LL_CRI, L"BSOD attempt started.");

		ULONG response;
		const auto ntStatus = g_winAPIs->NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, nullptr, OptionShutdownSystem, &response);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtRaiseHardError fail! Status: %p", ntStatus);
		}

		APP_TRACE_LOG(LL_CRI, L"Force reboot attempt started.");
		
		if (!g_winAPIs->ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG, SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_FLAG_PLANNED))
		{
			APP_TRACE_LOG(LL_ERR, L"ExitWindowsEx fail! Error: %u", g_winAPIs->GetLastError());
		}

		APP_TRACE_LOG(LL_CRI, L"Spawn shutdown cmd process attempt started.");
		std::system(xorstr_("shutdown /r /t 00"));

		APP_TRACE_LOG(LL_CRI, L"Terminate failed...");
		while (true);

		return true;
	}

	bool CTerminator::TerminateThread(HANDLE hThread)
	{
		if (!hThread || !__IsValidHandle(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid thread handle: %p", hThread);
			return true;
		}
		
		const auto dwThreadId = g_winAPIs->GetThreadId(hThread);
		const auto dwStartAddress = CThreadFunctions::GetThreadStartAddress(hThread);
		const auto bIsSelfThread = CThreadFunctions::GetThreadOwnerProcessId(dwThreadId) == g_winAPIs->GetCurrentProcessId();

		// Check at the first
		auto bThreadIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadId);
		if (!bThreadIsAlive)
			return true;

		// First method
		auto ntStat = g_winAPIs->TerminateThread(hThread, EXIT_SUCCESS);
		if (!NT_SUCCESS(ntStat))
			return false;

		// Check 2.time
		bThreadIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadId);
		if (!bThreadIsAlive)
			return true;

		if (!g_winAPIs->PostThreadMessageW(dwThreadId, WM_QUIT, 0, 0))
			return false;

		// Check 3.time
		bThreadIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadId);
		if (!bThreadIsAlive)
			return true;

		if (!__TerminateThreadWithHijackContext(hThread))
			return false;

		// Check 4.time
		bThreadIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadId);
		if (!bThreadIsAlive)
			return true;

		if (bIsSelfThread && dwStartAddress)
			g_winAPIs->NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)dwStartAddress);

		// Check 5.time
		bThreadIsAlive = CThreadFunctions::ThreadIsItAlive(dwThreadId);
		if (!bThreadIsAlive)
			return true;

		return bThreadIsAlive;
	}

	bool CTerminator::TerminateWindow(HWND hWnd)
	{
		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
			return false;

		auto vWindows = windowEnumerator->EnumerateWindows();
		if (vWindows.empty())
			return false;

		// Check at the first
		if (std::find(vWindows.begin(), vWindows.end(), hWnd) == vWindows.end())
			return false;

		// First method
		g_winAPIs->SendMessageW(hWnd, WM_CLOSE, 0, 0);
		g_winAPIs->SendMessageW(hWnd, WM_QUIT, 0, 0);
		g_winAPIs->SendMessageW(hWnd, WM_DESTROY, 0, 0);

		// Check 2.time
		vWindows.clear();
		vWindows = windowEnumerator->EnumerateWindows();
		if (std::find(vWindows.begin(), vWindows.end(), hWnd) == vWindows.end())
			return true;

		// Second method
		g_winAPIs->PostMessageW(hWnd, WM_CLOSE, 0, 0);
		g_winAPIs->PostMessageW(hWnd, WM_QUIT, 0, 0);
		g_winAPIs->PostMessageW(hWnd, WM_DESTROY, 0, 0);

		// Check 3.time
		vWindows.clear();
		vWindows = windowEnumerator->EnumerateWindows();
		if (std::find(vWindows.begin(), vWindows.end(), hWnd) == vWindows.end())
			return true;

		// Third method
		if (!g_winAPIs->DestroyWindow(hWnd))
			return false;

		// Check 3.time
		vWindows.clear();
		vWindows = windowEnumerator->EnumerateWindows();
		if (std::find(vWindows.begin(), vWindows.end(), hWnd) == vWindows.end())
			return true;

		// Last method
		if (!g_winAPIs->EndTask(hWnd, FALSE, TRUE))
			return false;

		// Last check
		vWindows.clear();
		vWindows = windowEnumerator->EnumerateWindows();
		if (std::find(vWindows.begin(), vWindows.end(), hWnd) == vWindows.end())
			return true;

		return false;
	}
}

#pragma warning(pop) 
