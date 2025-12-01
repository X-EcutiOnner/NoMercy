#include "../../include/PCH.hpp"
#include "../../include/NtAPIWrapper.hpp"
#include "../../include/WinAPIManager.hpp"
#include "../../include/WinVerHelper.hpp"
#include <wow64pp.hpp>

namespace NoMercyCore
{
#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND * 1000)

	static uint8_t gs_iProcessorCount = 0;

	CNtAPI::CNtAPI()
	{
#ifdef _WIN64
		m_bIsX64 = true;
		m_bIsWoW64 = false;
#else
		m_bIsX64 = false;
		m_bIsWoW64 = (DWORD)__readfsdword(0xC0) != 0;
#endif
	}
	CNtAPI::~CNtAPI()
	{
	}

	bool CNtAPI::IsSystemX64()
	{
		SYSTEM_INFO SysInfo{ 0 };
		g_winAPIs->GetNativeSystemInfo(&SysInfo);

		return (SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);
	}

	int CNtAPI::GetProcessorCount()
	{
		SYSTEM_BASIC_INFORMATION sbi{ 0 };
		const auto ntStatus = g_winAPIs->NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), nullptr);
		if (NT_SUCCESS(ntStatus))
			return sbi.NumberOfProcessors;
		return 1;
	}

	ULONG CNtAPI::GetSystemErrorFromNTStatus(NTSTATUS status)
	{
		const auto ntStatus = g_winAPIs->RtlNtStatusToDosError(status);
		if (ntStatus != ERROR_MR_MID_NOT_FOUND)
			return ntStatus;

		return static_cast<ULONG>(-1);
	}

	ULONG CNtAPI::GetSystemErrorFromLSAStatus(NTSTATUS status)
	{
		const auto ulError = g_winAPIs->LsaNtStatusToWinError(status);
		if (ulError != ERROR_MR_MID_NOT_FOUND)
			return ulError;

		return static_cast<ULONG>(-1);
	}

	HANDLE CNtAPI::OpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId)
	{
		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, 0, 0, 0, 0);

		HANDLE hProcess = nullptr;
		CLIENT_ID cid = { reinterpret_cast<HANDLE>(dwProcessId), nullptr };

		const auto ntStatus = g_winAPIs->NtOpenProcess(&hProcess, dwDesiredAccess, &oa, &cid);
		if (NT_SUCCESS(ntStatus))
			return hProcess;

		g_winAPIs->SetLastError(g_winAPIs->RtlNtStatusToDosError(ntStatus));
		return nullptr;
	}

	HANDLE CNtAPI::OpenProcessToken(HANDLE hProcess, ACCESS_MASK desiredAccess)
	{
		HANDLE hProcessToken = 0;

		const auto ntStatus = g_winAPIs->NtOpenProcessToken(hProcess, desiredAccess, &hProcessToken);
		if (NT_SUCCESS(ntStatus))
			return hProcessToken;

		g_winAPIs->SetLastError(g_winAPIs->RtlNtStatusToDosError(ntStatus));
		return nullptr;
	}

	HANDLE CNtAPI::OpenThread(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

		HANDLE hThread = nullptr;
		CLIENT_ID cid = { nullptr, reinterpret_cast<HANDLE>(dwThreadId) };

		const auto ntStatus = g_winAPIs->NtOpenThread(&hThread, dwDesiredAccess, &oa, &cid);
		g_winAPIs->SetLastError(g_winAPIs->RtlNtStatusToDosError(ntStatus));

		return hThread;
	}

// #define OBFUSCATED_THREAD_CREATE
	HANDLE CreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwFlags, PDWORD_PTR pdwThreadId)
	{
#ifdef OBFUSCATED_THREAD_CREATE
		const auto fake_start_entry = reinterpret_cast<LPTHREAD_START_ROUTINE>(g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("RtlUserThreadStart")));
		const auto start_entry = fake_start_entry ? fake_start_entry : lpStartAddress;
#else
		const auto start_entry = lpStartAddress;
#endif

#ifndef _DEBUG
		DWORD dwFlag = dwFlags;
		if (GetWindowsBuildNumber() > 18362)
			dwFlag |= THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
		else
			dwFlag |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;

#ifdef OBFUSCATED_THREAD_CREATE
		if (fake_start_entry)
			dwFlag |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
#endif
#else
		DWORD dwFlag = 0;
#endif

		HANDLE hThread = INVALID_HANDLE_VALUE;
		auto ntStatus = g_winAPIs->NtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, 0, NtCurrentProcess(), start_entry, lpParam, dwFlag, 0, 0, 0, 0);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtCreateThreadEx failed with status: %p", ntStatus);

			const auto bShouldSuspend =
#ifdef OBFUSCATED_THREAD_CREATE
				!!fake_start_entry;
#else
				false;
#endif
			
			CLIENT_ID cid = { 0, 0 };
			ntStatus = g_winAPIs->RtlCreateUserThread(NtCurrentProcess(), nullptr, bShouldSuspend, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)start_entry, lpParam, &hThread, &cid);
			g_winAPIs->SetLastError(g_winAPIs->RtlNtStatusToDosError(ntStatus));

			if (NT_SUCCESS(ntStatus))
			{
#ifdef OBFUSCATED_THREAD_CREATE
				if (fake_start_entry)
				{
					CONTEXT ctx{};
					ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
					if (!g_winAPIs->GetThreadContext(hThread, &ctx))
					{
						APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
						g_winAPIs->TerminateThread(hThread, EXIT_SUCCESS);
						g_winAPIs->CloseHandle(hThread);
						return nullptr;
					}

#ifdef _M_IX86
					ctx.Eip = (DWORD)lpStartAddress;
					ctx.Eax = (DWORD)lpStartAddress;
#else
					// ctx.Rip = ( DWORD64 )start;
					ctx.Rcx = (DWORD64)lpStartAddress;
#endif

					if (!g_winAPIs->SetThreadContext(hThread, &ctx))
					{
						APP_TRACE_LOG(LL_ERR, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
						g_winAPIs->TerminateThread(hThread, EXIT_SUCCESS);
						g_winAPIs->CloseHandle(hThread);
						return nullptr;
					}

					g_winAPIs->ResumeThread(hThread);
				}
#endif

				if (pdwThreadId) *pdwThreadId = DWORD_PTR(cid.UniqueThread);
				return hThread;
			}
			
			APP_TRACE_LOG(LL_ERR, L"RtlCreateUserThread failed with status: %p", ntStatus);
			return nullptr;
		}
		else
		{
			if (pdwThreadId) *pdwThreadId = HandleToUlong(hThread);
			return hThread;
		}

		return nullptr;
	}
	HANDLE CNtAPI::CreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwFlags, PDWORD_PTR pdwThreadId)
	{
		HANDLE hThread = CreateThreadEx(lpStartAddress, lpParam, dwFlags, pdwThreadId);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateThreadEx failed with error: %u", g_winAPIs->GetLastError());
			return nullptr;
		}

#ifdef OBFUSCATED_THREAD_CREATE
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

		if (!g_winAPIs->GetThreadContext(hThread, &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hThread);
			return nullptr;
		}

#ifdef _M_IX86
		ctx.Eip = (DWORD)lpStartAddress;
		ctx.Eax = (DWORD)lpStartAddress;
#else
		// ctx.Rip = ( DWORD64 )start;
		ctx.Rcx = (DWORD64)lpStartAddress;
#endif

		if (!g_winAPIs->SetThreadContext(hThread, &ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"SetThreadContext failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hThread);
			return nullptr;
		}
		g_winAPIs->ResumeThread(hThread);
#endif

		return hThread;
	}

	bool CNtAPI::CreateThreadAndWait(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwDelay, LPDWORD pdwExitCode)
	{
		const auto hThread = CreateThread(lpStartAddress, lpParam, 0, nullptr);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlCreateUserThread fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (WaitObject(hThread, dwDelay) != WAIT_OBJECT_0)
		{
			APP_TRACE_LOG(LL_ERR, L"WaitForSingleObject fail! Error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hThread);
			return false;
		}

		THREAD_BASIC_INFORMATION tbi;
		const auto ntStatus = g_winAPIs->NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Status: %p", ntStatus);
			g_winAPIs->CloseHandle(hThread);
			return false;
		}

		g_winAPIs->CloseHandle(hThread);
		if (pdwExitCode) *pdwExitCode = tbi.ExitStatus;
		return true;
	}

	bool CNtAPI::SuspendThread(HANDLE hThread)
	{
		auto ulCount = 0UL;
		const auto ntStatus = g_winAPIs->NtSuspendThread(hThread, &ulCount);
		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::ResumeThread(HANDLE hThread, bool bLoop)
	{
		static constexpr auto MAXIMUM_RESUME_ATTEMPTS = 10;
		auto ulCount = 0UL;
		auto ulAttempts = 0UL;

		do {
			const auto ntStatus = g_winAPIs->NtResumeThread(hThread, &ulCount);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_WARN, L"NtResumeThread fail! Status: %p", ntStatus);
				break;
			}

			if (!ulCount)
				return true;

			if (ulAttempts++ >= MAXIMUM_RESUME_ATTEMPTS)
			{
				APP_TRACE_LOG(LL_WARN, L"Maximum resume attempts reached! Count: %u", ulAttempts);
				break;
			}
		} while (bLoop && ulCount);

		return false;
	}

	bool CNtAPI::SuspendProcess(HANDLE hThread)
	{
		const auto ntStatus = g_winAPIs->NtSuspendProcess(hThread);
		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::ResumeProcess(HANDLE hProcess)
	{
		const auto ntStatus = g_winAPIs->NtResumeProcess(hProcess);
		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::CloseHandle(HANDLE hTarget)
	{
		const auto ntStatus = g_winAPIs->NtClose(hTarget);
		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::WaitObject(HANDLE hTarget, DWORD dwDelay)
	{
		LARGE_INTEGER liDelay = { DELAY_ONE_MILLISECOND * dwDelay, -1 };

		const auto ntStatus = g_winAPIs->NtWaitForSingleObject(hTarget, FALSE, &liDelay);
		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::Sleep(DWORD dwDelay)
	{
		LARGE_INTEGER liDelay = { DELAY_ONE_MILLISECOND * dwDelay, -1 };

		const auto ntStatus = g_winAPIs->NtDelayExecution(FALSE, &liDelay);
		return NT_SUCCESS(ntStatus);
	}

	void CNtAPI::YieldCPU()
	{
		//if (!gs_iProcessorCount)
		//	gs_iProcessorCount = GetProcessorCount();

		//if (gs_iProcessorCount > 1)
			this->Sleep(10);
		//else
		//	g_winAPIs->NtYieldExecution();
	}

	bool CNtAPI::TerminateThread(HANDLE hThread, NTSTATUS ulExitStatus)
	{
		const auto ntStatus = g_winAPIs->NtTerminateThread(hThread, ulExitStatus);
		const auto bRet = NT_SUCCESS(ntStatus);
		if (!bRet)
			APP_TRACE_LOG(LL_WARN, L"NtTerminateThread(%p) failed with status: %p", hThread, ntStatus);
		return bRet;
	}

	bool CNtAPI::TerminateProcess(HANDLE hProcess, NTSTATUS ulExitStatus)
	{
		const auto ntStatus = g_winAPIs->NtTerminateProcess(hProcess, ulExitStatus);
		return NT_SUCCESS(ntStatus);
	}

	LPVOID CNtAPI::GetProcAddress(HMODULE hModule, const char* c_szApiName)
	{
		auto asName = ANSI_STRING{};
		g_winAPIs->RtlInitAnsiString(&asName, c_szApiName);

		PVOID pvApiPtr = nullptr;
		const auto ntStatus = g_winAPIs->LdrGetProcedureAddress(hModule, &asName, 0, &pvApiPtr);
		if (!NT_SUCCESS(ntStatus))
		{
			const auto wstApiName = stdext::to_wide(c_szApiName);
			APP_TRACE_LOG(ntStatus == STATUS_ENTRYPOINT_NOT_FOUND ? LL_WARN : LL_ERR, L"LdrGetProcedureAddress fail! Target: %p (%s) Status: %p", hModule, wstApiName.c_str(), ntStatus);
			return nullptr;
		}
		return pvApiPtr;
	}

	bool CNtAPI::IsFsRedirectionDisabled()
	{
		const auto it = m_mapFSRedirectionCache.find(HandleToUlong(NtCurrentThreadId()));
		if (it == m_mapFSRedirectionCache.end())
			return false; // dont exist == dont disabled by us

		return it->second;
	}
	void CNtAPI::SetFsRedirectionStatus(bool bDisabled)
	{
		const auto dwThreadID = HandleToUlong(NtCurrentThreadId());

		auto it = m_mapFSRedirectionCache.find(dwThreadID);
		if (it != m_mapFSRedirectionCache.end())
			it->second = bDisabled;
		else
			m_mapFSRedirectionCache.emplace(dwThreadID, bDisabled);
	}

	bool CNtAPI::ManageFsRedirection(bool bDisable, PVOID pCookie, PVOID* ppCookie)
	{		
		if (!IsWindowsVistaOrGreater() || !m_bIsWoW64)
			return true;
	
		const auto it = m_mapFSRedirectionCache.find(HandleToUlong(NtCurrentThreadId()));
		const auto bIsKnownSourceThread = it != m_mapFSRedirectionCache.end();
		if (bIsKnownSourceThread)
		{
			const auto bPrevValue = it->second;
			if (bPrevValue && bDisable)
			{
//				APP_TRACE_LOG(LL_TRACE, L"Filesystem redirection is already disabled!");
				return true;
			}

			if (!bPrevValue && !bDisable)
			{
//				APP_TRACE_LOG(LL_TRACE, L"Filesystem redirection is already enabled!");
				return true;
			}
		}

		if (bDisable)
		{
			/*
			if (!g_winAPIs->Wow64EnableWow64FsRedirection(FALSE))
			{
				APP_TRACE_LOG(LL_ERR, L"Wow64EnableWow64FsRedirection (disable) failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
			SetFsRedirectionStatus(true);
			*/
//			/*
			PVOID OldValue = nullptr;
			if (!g_winAPIs->Wow64DisableWow64FsRedirection(&OldValue))
			{
				APP_TRACE_LOG(LL_ERR, L"Wow64DisableWow64FsRedirection failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
			
			SetFsRedirectionStatus(true);
			if (ppCookie && OldValue) *ppCookie = OldValue;
//			*/
		}
		else
		{
			/*
			if (!g_winAPIs->Wow64EnableWow64FsRedirection(TRUE))
			{
				APP_TRACE_LOG(LL_ERR, L"Wow64EnableWow64FsRedirection (enable) failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
			SetFsRedirectionStatus(false);
			*/
//			/*
			if (!g_winAPIs->Wow64RevertWow64FsRedirection(pCookie))
			{
				APP_TRACE_LOG(LL_ERR, L"Wow64RevertWow64FsRedirection failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
			
			SetFsRedirectionStatus(false);
//			*/
		}

		return true;
	}

	NTSTATUS CNtAPI::CreateFile(PHANDLE hFile, LPWSTR FilePath, ACCESS_MASK AccessMask, ULONG FileAttributes, ULONG ShareAccess, ULONG DispositionFlags, ULONG CreateOptions)
	{
		NTSTATUS			ntStatus = { STATUS_SUCCESS };
		OBJECT_ATTRIBUTES	ObjectAttributes = { 0 };
		IO_STATUS_BLOCK		IoStatusBlock = { 0 };
		LARGE_INTEGER		AllocationSize = { 0 };

		// Disables file system redirection for the calling thread.
		PVOID OldValue = nullptr;
		if (this->ManageFsRedirection(true, nullptr, &OldValue))
		{
			ntStatus = g_winAPIs->NtCreateFile(hFile, AccessMask, &ObjectAttributes, &IoStatusBlock, &AllocationSize, FileAttributes, ShareAccess, DispositionFlags, CreateOptions, nullptr, 0);

			// Restore file system redirection for the calling thread.
			this->ManageFsRedirection(false, OldValue, nullptr);
		}

		return ntStatus;
	}

	NTSTATUS CNtAPI::QueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID64 ProcessInformation, ULONG64 ProcessInformationLength, PULONG ReturnLength)
	{
		if (m_bIsX64)
			return g_winAPIs->NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		else if (m_bIsWoW64)
			return g_winAPIs->NtWow64QueryInformationProcess64(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		else // x86
			return g_winAPIs->NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, Ptr64ToPtr(ProcessInformation), static_cast<ULONG>(ProcessInformationLength), ReturnLength);
	}

	NTSTATUS CNtAPI::ReadVirtualMemory(HANDLE hProcess, PVOID64 lpBaseAddress, PVOID lpBuffer, ULONG64 nSize, PSIZE_T lpNumberOfBytesRead)
	{
		if (m_bIsX64)
		{
			return g_winAPIs->NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		}
		else if (m_bIsWoW64)
		{
			ULONG64 ulSize = 0;
			const auto ntStatus = g_winAPIs->NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, &ulSize);
			if (lpNumberOfBytesRead) *lpNumberOfBytesRead = ulSize;
			return ntStatus;
		}
		else // x86
		{
			auto cbSize = static_cast<SIZE_T>(nSize);
			return g_winAPIs->NtReadVirtualMemory(hProcess, Ptr64ToPtr(lpBaseAddress), lpBuffer, cbSize, lpNumberOfBytesRead);
		}
	}

	NTSTATUS CNtAPI::WriteVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PSIZE_T ReturnLength)
	{
		if (m_bIsX64)
		{
			return g_winAPIs->NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
		}
		else if (m_bIsWoW64)
		{
			ULONG64 ulSize = 0;
			const auto ntStatus = g_winAPIs->NtWow64WriteVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferLength, &ulSize);
			if (ReturnLength) *ReturnLength = ulSize;
			return ntStatus;
		}
		else // x86
		{
			auto cbSize = static_cast<ULONG>(BufferLength);
			return g_winAPIs->NtWriteVirtualMemory(ProcessHandle, Ptr64ToPtr(BaseAddress), Buffer, cbSize, ReturnLength);
		}
	}

	ptr_t CNtAPI::AllocateVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG Protection)
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;
		ptr_t pvAllocatedMemory = nullptr;
		
		if (m_bIsX64)
		{
			PVOID pvProxyAddress = BaseAddress;
			SIZE_T cbProxySize = Size;
			ntStatus = g_winAPIs->NtAllocateVirtualMemory(ProcessHandle, &pvProxyAddress, 0, &cbProxySize, AllocationType, Protection);
			pvAllocatedMemory = pvProxyAddress;
		}
		else if (m_bIsWoW64)
		{
			static const auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return nullptr;
			}

			static const auto x64_NtAllocateVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtAllocateVirtualMemory"));
			if (!x64_NtAllocateVirtualMemory)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtAllocateVirtualMemory could not handled.");
				return nullptr;
			}

			PVOID64 pvProxyAddress = BaseAddress;
			ULONG64 cbProxySize = Size;
			ntStatus = wow64pp::call_function(x64_NtAllocateVirtualMemory, ProcessHandle, &pvProxyAddress, 0, &cbProxySize, AllocationType, Protection);
			pvAllocatedMemory = pvProxyAddress;
		}
		else // x86
		{
			PVOID pvProxyAddress = Ptr64ToPtr(BaseAddress);
			SIZE_T cbProxySize = Size;
			ntStatus = g_winAPIs->NtAllocateVirtualMemory(ProcessHandle, &pvProxyAddress, 0, &cbProxySize, AllocationType, Protection);
			pvAllocatedMemory = pvProxyAddress;
		}
		
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtAllocateVirtualMemory failed with status: %p", ntStatus);
			return nullptr;
		}

		return pvAllocatedMemory;
	}

	bool CNtAPI::FreeVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, DWORD FreeType)
	{
		PVOID64 pvOutAddr = nullptr;
		SIZE_T cbOutSize = 0;
		
		auto __FreeVirtualMemoryEx = [&]() -> NTSTATUS {
			if (m_bIsX64)
			{
				PVOID pvProxyAddress = BaseAddress;
				SIZE_T cbProxySize = Size;

				const auto ntStatus = g_winAPIs->NtFreeVirtualMemory(ProcessHandle, &pvProxyAddress, &cbProxySize, FreeType);

				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
			else if (m_bIsWoW64)
			{
				static const auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
				if (!x64_ntdll_handle)
				{
					APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
					return STATUS_INTERNAL_ERROR;
				}
				
				static const auto x64_NtFreeVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtFreeVirtualMemory"));
				if (!x64_NtFreeVirtualMemory)
				{
					APP_TRACE_LOG(LL_ERR, L"x64_NtFreeVirtualMemory could not handled.");
					return STATUS_INTERNAL_ERROR;
				}
				
				PVOID64 pvProxyAddress = BaseAddress;
				ULONG64 cbProxySize = Size;

				const NTSTATUS ntStatus = wow64pp::call_function(x64_NtFreeVirtualMemory, ProcessHandle, &pvProxyAddress, &cbProxySize, FreeType);
				
				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
			else // x86
			{
				PVOID pvProxyAddress = BaseAddress;
				SIZE_T cbProxySize = Size;
				
				const auto ntStatus = g_winAPIs->NtFreeVirtualMemory(ProcessHandle, &pvProxyAddress, &cbProxySize, FreeType);

				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
		};
		
		if (FreeType & 0xFFFF3FFC || (FreeType & 0x8003) == 0x8000 && Size) 
			return false;

		auto ntStatus = __FreeVirtualMemoryEx();
		if (ntStatus == STATUS_INVALID_PAGE_PROTECTION)
		{
			if (!g_winAPIs->RtlFlushSecureMemoryCache(pvOutAddr, cbOutSize))
			{
				return false;
			}

			ntStatus = __FreeVirtualMemoryEx();
		}

		return NT_SUCCESS(ntStatus);
	}

	bool CNtAPI::ProtectVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, DWORD NewProtection, PDWORD OldProtect)
	{
		PVOID64 pvOutAddr = nullptr;
		SIZE_T cbOutSize = 0;

		auto __ProtectVirtualMemoryEx = [&]() -> NTSTATUS {
			if (m_bIsX64)
			{
				PVOID pvProxyAddress = BaseAddress;
				SIZE_T cbProxySize = Size;

				const auto ntStatus = g_winAPIs->NtProtectVirtualMemory(ProcessHandle, &pvProxyAddress, &cbProxySize, NewProtection, OldProtect);

				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
			else if (m_bIsWoW64)
			{
				static const auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
				if (!x64_ntdll_handle)
				{
					APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
					return STATUS_INTERNAL_ERROR;
				}

				static const auto x64_NtProtectVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtProtectVirtualMemory"));
				if (!x64_NtProtectVirtualMemory)
				{
					APP_TRACE_LOG(LL_ERR, L"x64_NtProtectVirtualMemory could not handled.");
					return STATUS_INTERNAL_ERROR;
				}

				PVOID64 pvProxyAddress = BaseAddress;
				ULONG64 cbProxySize = Size;

				const NTSTATUS ntStatus = wow64pp::call_function(x64_NtProtectVirtualMemory, ProcessHandle, &pvProxyAddress, &cbProxySize, NewProtection, OldProtect);

				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
			else // x86
			{
				PVOID pvProxyAddress = BaseAddress;
				SIZE_T cbProxySize = Size;

				const auto ntStatus = g_winAPIs->NtProtectVirtualMemory(ProcessHandle, &pvProxyAddress, &cbProxySize, NewProtection, OldProtect);

				pvOutAddr = pvProxyAddress;
				cbOutSize = cbProxySize;
				return ntStatus;
			}
		};

		auto ntStatus = __ProtectVirtualMemoryEx();
		if (NT_SUCCESS(ntStatus))
			return true;

		if (ntStatus == STATUS_INVALID_PAGE_PROTECTION) 
		{
			if (!g_winAPIs->RtlFlushSecureMemoryCache(pvOutAddr, cbOutSize))
			{
				return false;
			}

			ntStatus = __ProtectVirtualMemoryEx();
		}

		return NT_SUCCESS(ntStatus);
	}

	NTSTATUS CNtAPI::QueryVirtualMemory(HANDLE ProcessHandle, PVOID64 pvBaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength)
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;

		if (m_bIsX64)
		{
			SIZE_T cbReturnLength = 0;
			ntStatus = g_winAPIs->NtQueryVirtualMemory(ProcessHandle, pvBaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, &cbReturnLength);
		}
		else if (m_bIsWoW64)
		{
			static const auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return STATUS_INTERNAL_ERROR;
			}

			static const auto x64_NtQueryVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtQueryVirtualMemory"));
			if (!x64_NtQueryVirtualMemory)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtQueryVirtualMemory could not handled.");
				return STATUS_INTERNAL_ERROR;
			}

			ULONGLONG cbReturnLength = 0;
			ntStatus = wow64pp::call_function(x64_NtQueryVirtualMemory, ProcessHandle, pvBaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, &cbReturnLength);
		}
		else // x86
		{
			SIZE_T cbReturnLength = 0;
			ntStatus = g_winAPIs->NtQueryVirtualMemory(ProcessHandle, Ptr64ToPtr(pvBaseAddress), MemoryInformationClass, MemoryInformation, MemoryInformationLength, &cbReturnLength);
		}

#ifdef _DEBUG
		if (!NT_SUCCESS(ntStatus) &&
			ntStatus != STATUS_INVALID_PARAMETER &&
			ntStatus != STATUS_OBJECT_TYPE_MISMATCH &&
			ntStatus != STATUS_PROCESS_IS_TERMINATING)
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryVirtualMemory failed with status: %p", ntStatus);
		}
#endif

		return ntStatus;
	}

	bool CNtAPI::FlushVirtualMemory(HANDLE ProcessHandle, PVOID64 pvBaseAddress, SIZE_T cbSize)
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;

		if (m_bIsX64)
		{
			ntStatus = g_winAPIs->NtFlushInstructionCache(ProcessHandle, pvBaseAddress, cbSize);
		}
		else if (m_bIsWoW64)
		{
			static const auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return false;
			}

			static const auto x64_NtFlushInstructionCache = wow64pp::import(x64_ntdll_handle, xorstr_("NtFlushInstructionCache"));
			if (!x64_NtFlushInstructionCache)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtFlushInstructionCache could not handled.");
				return false;
			}

			ntStatus = wow64pp::call_function(x64_NtFlushInstructionCache, ProcessHandle, pvBaseAddress, cbSize);
		}
		else // x86
		{
			ntStatus = g_winAPIs->NtFlushInstructionCache(ProcessHandle, Ptr64ToPtr(pvBaseAddress), cbSize);
		}

		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtFlushInstructionCache failed with status: %p", ntStatus);
			return false;
		}

		return NT_SUCCESS(ntStatus);
	}
};
