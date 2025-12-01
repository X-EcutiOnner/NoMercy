#include "../../include/PCH.hpp"
#include "../../include/ThreadFunctions.hpp"
#include "../../include/ThreadEnumerator.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/PEHelper.hpp"

#ifndef MAKEULONGLONG
	#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
	#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

namespace NoMercyCore
{
	DWORD CThreadFunctions::GetThreadOwnerProcessId(DWORD dwThreadID)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		THREADENTRY32 ti{ 0 };
		ti.dwSize = sizeof(ti);

		if (g_winAPIs->Thread32First(hSnap, &ti))
		{
			do
			{
				if (dwThreadID == ti.th32ThreadID)
				{
					g_winAPIs->CloseHandle(hSnap);
					return ti.th32OwnerProcessID;
				}
			} while (g_winAPIs->Thread32Next(hSnap, &ti));
		}

		g_winAPIs->CloseHandle(hSnap);
		return 0;
	}

	bool CThreadFunctions::ThreadIsItAlive(DWORD dwThreadID)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		THREADENTRY32 ti{ 0 };
		ti.dwSize = sizeof(ti);

		if (g_winAPIs->Thread32First(hSnap, &ti))
		{
			do
			{
				if (dwThreadID == ti.th32ThreadID)
				{
					g_winAPIs->CloseHandle(hSnap);
					return true;
				}
			} while (g_winAPIs->Thread32Next(hSnap, &ti));
		}

		g_winAPIs->CloseHandle(hSnap);
		return false;
	}

	DWORD CThreadFunctions::GetThreadStartAddress(HANDLE hThread)
	{
		DWORD dwCurrentThreadAddress = 0;
		const auto ntStatus = g_winAPIs->NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadStartAddress fail! Thread: %p Status: %p", hThread, ntStatus);
			return dwCurrentThreadAddress;
		}
		return dwCurrentThreadAddress;
	}

	DWORD CThreadFunctions::GetMainThreadIdByStarttime()
	{
		ULONGLONG ullMinCreateTime = MAXULONGLONG;

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		THREADENTRY32 ti{ 0 };
		ti.dwSize = sizeof(ti);

		if (g_winAPIs->Thread32First(hSnap, &ti))
		{
			do {
				if (ti.th32OwnerProcessID == g_winAPIs->GetCurrentProcessId())
				{
					auto hThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
					if (IS_VALID_HANDLE(hThread))
					{
						FILETIME fileTime[4]{ 0 };
						if (g_winAPIs->GetThreadTimes(hThread, &fileTime[0], &fileTime[1], &fileTime[2], &fileTime[3]))
						{
							const auto ullTest = MAKEULONGLONG(fileTime[0].dwLowDateTime, fileTime[0].dwHighDateTime);
							if (ullTest && ullTest < ullMinCreateTime)
							{
								ullMinCreateTime = ullTest;

								g_winAPIs->CloseHandle(hThread);
								g_winAPIs->CloseHandle(hSnap);

								return ti.th32ThreadID;
							}
						}
						g_winAPIs->CloseHandle(hThread);
					}
				}
			} while (g_winAPIs->Thread32Next(hSnap, &ti));
		}

		g_winAPIs->CloseHandle(hSnap);
		return 0;
	}
	DWORD CThreadFunctions::GetMainThreadIdByEntrypoint()
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		THREADENTRY32 ti{ 0 };
		ti.dwSize = sizeof(ti);

		const auto pIDH = (IMAGE_DOS_HEADER*)g_winModules->hBaseModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		const auto pINH = (IMAGE_NT_HEADERS32*)((DWORD_PTR)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		const auto pEntryPoint = pINH->OptionalHeader.AddressOfEntryPoint + pINH->OptionalHeader.ImageBase;
		if (!pEntryPoint)
			return 0;

		if (g_winAPIs->Thread32First(hSnap, &ti))
		{
			do {
				if (ti.th32OwnerProcessID == g_winAPIs->GetCurrentProcessId())
				{
					auto hThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
					if (IS_VALID_HANDLE(hThread))
					{
						const auto dwStartAddress = GetThreadStartAddress(hThread);
						if (dwStartAddress == pEntryPoint)
						{
							g_winAPIs->CloseHandle(hThread);
							g_winAPIs->CloseHandle(hSnap);

							return ti.th32ThreadID;
						}
						g_winAPIs->CloseHandle(hThread);
					}
				}
			} while (g_winAPIs->Thread32Next(hSnap, &ti));
		}

		g_winAPIs->CloseHandle(hSnap);
		return 0;
	}


	DWORD CThreadFunctions::GetThreadIdFromAddress(DWORD dwAddress)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		THREADENTRY32 ti{ 0 };
		ti.dwSize = sizeof(ti);

		if (g_winAPIs->Thread32First(hSnap, &ti))
		{
			do {
				if (ti.th32OwnerProcessID == g_winAPIs->GetCurrentProcessId())
				{
					auto hThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
					if (IS_VALID_HANDLE(hThread))
					{
						const auto dwStartAddress = GetThreadStartAddress(hThread);
						if (dwStartAddress == dwAddress)
						{
							g_winAPIs->CloseHandle(hThread);
							g_winAPIs->CloseHandle(hSnap);

							return ti.th32ThreadID;
						}
						g_winAPIs->CloseHandle(hThread);
					}
				}
			} while (g_winAPIs->Thread32Next(hSnap, &ti));
		}

		g_winAPIs->CloseHandle(hSnap);
		return 0;
	}

	HANDLE CThreadFunctions::CreateThread(int iCustomThreadCode, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwFlags, LPDWORD pdwThreadId)
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started! Thread code: %d Vista+ %d Flags: %p", iCustomThreadCode, IsWindowsVistaOrGreater(), dwFlags);

		auto dwThreadId = DWORD_PTR(0);
		const auto hThread = CWinAPIManager::Instance().NTHelper()->CreateThread(pFunc, lpParam, dwFlags, &dwThreadId);
		APP_TRACE_LOG(LL_SYS, L"Thread creation completed(%d) Result: %d - Thread: %p(%u)", iCustomThreadCode, CWinAPIManager::Instance().IsValidHandle(hThread), hThread, dwThreadId);

		if (pdwThreadId) *pdwThreadId = dwThreadId;
		return hThread;
	}

	DWORD CThreadFunctions::GetLegitThreadStartAddress()
	{
		std::vector <DWORD> vecLegitAddresses;

		const auto dwModuleBase = (DWORD_PTR)g_winModules->hBaseModule;
		if (!dwModuleBase)
			return 0;

		const auto dwSizeofCode = CPEFunctions::GetSizeofCode(g_winModules->hBaseModule);
		if (!dwSizeofCode)
			return 0;

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnap))
			return 0;

		THREADENTRY32 te32{ 0 };
		te32.dwSize = sizeof(te32);
		if (g_winAPIs->Thread32First(hSnap, &te32))
		{
			do
			{
				if (te32.th32OwnerProcessID == g_winAPIs->GetCurrentProcessId())
				{
					auto hThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
					if (IS_VALID_HANDLE(hThread))
					{
						const auto dwStartAddress = GetThreadStartAddress(hThread);
						if (dwStartAddress)
						{
							if (dwStartAddress >= dwModuleBase && dwStartAddress <= (dwModuleBase + dwSizeofCode))
							{
								vecLegitAddresses.push_back(dwStartAddress);
							}
						}

						g_winAPIs->CloseHandle(hThread);
					}
				}
			} while (g_winAPIs->Thread32Next(hSnap, &te32));
		}

		g_winAPIs->CloseHandle(hSnap);

		return vecLegitAddresses.front();
	}

	HANDLE CThreadFunctions::SilentCreateThread(DWORD_PTR dwThreadAddress)
	{
		DWORD dwFlag = THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
#ifndef _DEBUG
		if (GetWindowsBuildNumber() > 18362)
			dwFlag |= THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
		else
			dwFlag |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
#endif

		const auto dwTargetThreadAddr = GetLegitThreadStartAddress();
		if (!dwTargetThreadAddr)
		{
			APP_TRACE_LOG(LL_ERR, L"GetLegitThreadStartAddress fail!");
			return nullptr;
		}

		HANDLE hThread = INVALID_HANDLE_VALUE;
		auto ntStatus = g_winAPIs->NtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, 0, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)dwTargetThreadAddr, 0, dwFlag, 0, 0, 0, 0);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtCreateThreadEx failed with status: %p", ntStatus);
			return nullptr;
		}

		const auto dwThreadID = g_winAPIs->GetThreadId(hThread);

		CONTEXT ctx{ 0 };
		ctx.ContextFlags = CONTEXT_ALL;
		auto bContextRet = g_winAPIs->GetThreadContext(hThread, &ctx);
		if (!bContextRet)
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %d", g_winAPIs->GetLastError());
			g_winAPIs->TerminateThread(hThread, 0);
			return nullptr;
		}

#ifdef _WIN64
		ctx.Rcx = dwThreadAddress;
#else
		ctx.Eax = dwThreadAddress;
#endif

		bContextRet = g_winAPIs->SetThreadContext(hThread, &ctx);
		if (!bContextRet)
		{
			APP_TRACE_LOG(LL_ERR, L"SetThreadContext failed with error: %d", g_winAPIs->GetLastError());
			g_winAPIs->TerminateThread(hThread, 0);
			return nullptr;
		}

		APP_TRACE_LOG(LL_SYS, L"Thread: %u (%p) to: %p sucesfully created!", dwThreadID, hThread, dwThreadAddress);
		
		g_winAPIs->ResumeThread(hThread);
		return hThread;
	}

	DWORD CThreadFunctions::GetThreadID(HANDLE hThread)
	{
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"Thread handle: %p is NOT valid!", hThread);
			return 0;
		}

		THREAD_BASIC_INFORMATION ThreadInfo{ 0 };
		const auto ntStat = g_winAPIs->NtQueryInformationThread(hThread, ThreadBasicInformation, &ThreadInfo, sizeof(ThreadInfo), nullptr);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Status: %p", ntStat);
			return 0;
		}

		return (DWORD)ThreadInfo.ClientId.UniqueThread;
	}

	bool CThreadFunctions::ChangeThreadsStatus(bool bSuspend, bool bControlled)
	{
		auto threadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>();
		if (!IS_VALID_SMART_PTR(threadEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"threadEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto vThreads = threadEnumerator->EnumerateThreads(NtCurrentProcess());
		if (vThreads.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Thread list is null!");
			return false;
		}

		std::vector <HANDLE> vSuspendedThreads;

		// Iterate threads
		for (auto& hThread : vThreads)
		{
			// Skip current thread
			if (g_winAPIs->GetThreadId(hThread) == g_winAPIs->GetCurrentThreadId())
				continue;

			// Suspend
			if (bSuspend)
			{
				const auto bRet = CWinAPIManager::Instance().NTHelper()->SuspendThread(hThread);

				if (bControlled)
				{
					// If could not succesfuly suspend
					if (bRet == false)
					{
						// Resume already suspended other threads
						for (const auto& hThread2 : vSuspendedThreads)
							CWinAPIManager::Instance().NTHelper()->ResumeThread(hThread2, false);

						// Return as unsuccess
						return false;
					}
				}

				// Add for check later
				vSuspendedThreads.emplace_back(hThread);
			}
			// Resume
			else
			{
				CWinAPIManager::Instance().NTHelper()->ResumeThread(hThread, false);
			}
		}

		return true;
	}

	bool CThreadFunctions::IsThreadSuspended(HANDLE threadHandle)
	{
		if (!IS_VALID_HANDLE(threadHandle))
	        return false;

	    CONTEXT context;
	    context.ContextFlags = CONTEXT_ALL;
	    if (g_winAPIs->GetThreadContext(threadHandle, &context))
	    {
	        return (context.ContextFlags == CONTEXT_CONTROL && context.ContextFlags != 0);
	    }

		APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %d", g_winAPIs->GetLastError());
	    return false;
	}
};
