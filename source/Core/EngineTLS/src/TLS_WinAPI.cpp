#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Cleancall.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"

namespace NoMercyTLS
{
	// Modules
	HMODULE gs_hNtdll		= nullptr;
	HMODULE gs_hKernel32	= nullptr;

	// Syscalls
	static DWORD idx_NtAllocateVirtualMemory = 0;
	static DWORD idx_NtCreateSection = 0;
	static DWORD idx_NtMapViewOfSection = 0;
	static DWORD idx_NtUnmapViewOfSection = 0;
	static DWORD idx_NtLockVirtualMemory = 0;
	static DWORD idx_NtProtectVirtualMemory = 0;
	static DWORD idx_NtFreeVirtualMemory = 0;
	static DWORD idx_NtQueryInformationProcess = 0;
	static DWORD idx_NtSetInformationProcess = 0;
	static DWORD idx_NtQueryVirtualMemory = 0;
	static DWORD idx_NtReadVirtualMemory = 0;
	static DWORD idx_NtSetInformationThread = 0;
	static DWORD idx_NtWriteVirtualMemory = 0;
	static DWORD idx_NtDuplicateObject = 0;
	static DWORD idx_NtCreateThreadEx = 0;
	static DWORD idx_NtClose = 0;
	static DWORD idx_NtSetInformationDebugObject = 0;
	static DWORD idx_NtRemoveProcessDebug = 0;
	static DWORD idx_NtQuerySystemInformation = 0;
	static DWORD idx_NtGetContextThread = 0;
	static DWORD idx_NtQueryInformationThread = 0;
	static DWORD idx_NtOpenThread = 0;
	static DWORD idx_NtTerminateThread = 0;

	// Custom funcs
	LPVOID TLS_GetProcAddress(HMODULE hModule, const char* c_szApiName)
	{
		const auto fnRtlInitAnsiString = LI_FN(RtlInitAnsiString).nt_safe_cached();
		const auto fnLdrGetProcedureAddress = LI_FN(LdrGetProcedureAddress).nt_safe_cached();
		if (!fnRtlInitAnsiString)
		{
			TLS_LOG("fnRtlInitAnsiString not found!");
			return nullptr;
		}
		else if (!fnLdrGetProcedureAddress)
		{
			TLS_LOG("fnLdrGetProcedureAddress not found!");
			return nullptr;
		}

		auto asName = ANSI_STRING{};
		fnRtlInitAnsiString(&asName, c_szApiName);

		PVOID pvApiPtr = nullptr;
		const auto ntStatus = fnLdrGetProcedureAddress(hModule, &asName, 0, &pvApiPtr);
		if (!NT_SUCCESS(ntStatus))
		{
			TLS_LOG("LdrGetProcedureAddress: (%p:%s) failed with error: %p", hModule, c_szApiName, ntStatus);
			return nullptr;
		}

#ifdef _DEBUG
		TLS_LOG("%p:%s -> %p", hModule, c_szApiName, pvApiPtr);
#endif
		return pvApiPtr;
	}

	PVOID __GetRealAddress(PVOID pAddress)
	{
#ifdef _M_IX86
		if (*(PBYTE)pAddress == 0xE9 || *(PBYTE)pAddress == 0xE8)
			return Relative2Absolute(pAddress, 1, 5);

		if (*(PBYTE)pAddress == 0x68 && *((PBYTE)pAddress + 5) == 0xC3)
			return GetAbsolutePtr(pAddress, 1);

		if (*(PBYTE)pAddress == 0xB8 && *(PWORD)((PBYTE)pAddress + 5) == 0xE0FF)
			return GetAbsolutePtr(pAddress, 1);

		if (*(PWORD)pAddress == 0xFF2E)
			return GetAbsolutePtr(pAddress, 2);

#elif _M_X64

		if (*(PBYTE)pAddress == 0xE9)
			return Relative2Absolute(pAddress, 1, 5);

		if (*(PWORD)pAddress == 0xB849 && *(PWORD)((PBYTE)pAddress + 10) == 0xE0FF)
			return GetAbsolutePtr(pAddress, 2);

		if (*(PWORD)pAddress == 0x25FF && *(PULONG)((PBYTE)pAddress + 2) == 0x00000000)
			return GetAbsolutePtr(pAddress, 6);

		if (*(PWORD)pAddress == 0xB848 && *(PWORD)((PBYTE)pAddress + 10) == 0xC350)
			return GetAbsolutePtr(pAddress, 2);
#endif

		return pAddress;
	}

	DWORD TLS_GetSyscallID(const char* c_szAPIName)
	{
		auto dwAddress = (DWORD_PTR)TLS_GetProcAddress(gs_hNtdll, c_szAPIName);
		if (!dwAddress)
			return 0;

		const auto dwRealAddress = (DWORD_PTR)__GetRealAddress((PVOID)dwAddress);
		if (!dwRealAddress)
			return 0;

		if (dwAddress != dwRealAddress)
		{
			TLS_LOG("Real address of %s is %p", c_szAPIName, dwRealAddress);
			dwAddress = dwRealAddress;
		}

		DWORD dwSyscall = 0;
#ifdef _WIN64
		if (*(uint8_t*)dwAddress == 0x49 || *(uint8_t*)dwAddress == 0x4C)
			dwSyscall = *(DWORD*)(dwAddress + 4);
#else
		if (*(uint8_t*)dwAddress == 0xB8)
			dwSyscall = *(DWORD*)(dwAddress + 1);
#endif

#ifdef _DEBUG
		TLS_LOG("SYSCALL %s : %u", c_szAPIName, dwSyscall);
#endif
		return dwSyscall;
	}

	// Setup func
	bool InitializeWinAPIs()
	{
		const auto fnLoadLibraryA = LI_FN(LoadLibraryA).forwarded_safe();
		if (!fnLoadLibraryA)
		{
			TLS_LOG("fnLoadLibraryA not found!");
			return false;
		}
		gs_hNtdll = fnLoadLibraryA(xorstr_("ntdll.dll"));
		if (!gs_hNtdll)
		{
			TLS_LOG("ntdll not found!");
			return false;
		}
		gs_hKernel32 = fnLoadLibraryA(xorstr_("kernel32.dll"));
		if (!gs_hKernel32)
		{
			TLS_LOG("kernel32 not found!");
			return false;
		}

		idx_NtAllocateVirtualMemory = TLS_GetSyscallID(xorstr_("NtAllocateVirtualMemory"));
		idx_NtCreateSection = TLS_GetSyscallID(xorstr_("NtCreateSection"));
		idx_NtMapViewOfSection = TLS_GetSyscallID(xorstr_("NtMapViewOfSection"));
		idx_NtUnmapViewOfSection = TLS_GetSyscallID(xorstr_("NtUnmapViewOfSection"));
		idx_NtLockVirtualMemory = TLS_GetSyscallID(xorstr_("NtLockVirtualMemory"));
		idx_NtProtectVirtualMemory = TLS_GetSyscallID(xorstr_("NtProtectVirtualMemory"));
		idx_NtFreeVirtualMemory = TLS_GetSyscallID(xorstr_("NtFreeVirtualMemory"));
		idx_NtQueryInformationProcess = TLS_GetSyscallID(xorstr_("NtQueryInformationProcess"));
		idx_NtSetInformationProcess = TLS_GetSyscallID(xorstr_("NtSetInformationProcess"));
		idx_NtQueryVirtualMemory = TLS_GetSyscallID(xorstr_("NtQueryVirtualMemory"));
		idx_NtReadVirtualMemory = TLS_GetSyscallID(xorstr_("NtReadVirtualMemory"));
		idx_NtSetInformationThread = TLS_GetSyscallID(xorstr_("NtSetInformationThread"));
		idx_NtWriteVirtualMemory = TLS_GetSyscallID(xorstr_("NtWriteVirtualMemory"));
		idx_NtDuplicateObject = TLS_GetSyscallID(xorstr_("NtDuplicateObject"));
		idx_NtCreateThreadEx = TLS_GetSyscallID(xorstr_("NtCreateThreadEx"));
		idx_NtClose = TLS_GetSyscallID(xorstr_("NtClose"));
		idx_NtSetInformationDebugObject = TLS_GetSyscallID(xorstr_("NtSetInformationDebugObject"));
		idx_NtRemoveProcessDebug = TLS_GetSyscallID(xorstr_("NtRemoveProcessDebug"));
		idx_NtQuerySystemInformation = TLS_GetSyscallID(xorstr_("NtQuerySystemInformation"));
		idx_NtGetContextThread = TLS_GetSyscallID(xorstr_("NtGetContextThread"));
		idx_NtQueryInformationThread = TLS_GetSyscallID(xorstr_("NtQueryInformationThread"));
		idx_NtOpenThread = TLS_GetSyscallID(xorstr_("NtOpenThread"));
		idx_NtTerminateThread = TLS_GetSyscallID(xorstr_("NtTerminateThread"));

		if (!idx_NtAllocateVirtualMemory)
		{
			TLS_LOG("NtAllocateVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtCreateSection)
		{
			TLS_LOG("NtCreateSection syscall not found!");
			return false;
		}
		else if (!idx_NtMapViewOfSection)
		{
			TLS_LOG("NtMapViewOfSection syscall not found!");
			return false;
		}
		else if (!idx_NtUnmapViewOfSection)
		{
			TLS_LOG("NtUnmapViewOfSection syscall not found!");
			return false;
		}
		else if (!idx_NtLockVirtualMemory)
		{
			TLS_LOG("NtLockVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtProtectVirtualMemory)
		{
			TLS_LOG("NtProtectVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtFreeVirtualMemory)
		{
			TLS_LOG("NtFreeVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtQueryInformationProcess)
		{
			TLS_LOG("NtQueryInformationProcess syscall not found!");
			return false;
		}
		else if (!idx_NtSetInformationProcess)
		{
			TLS_LOG("NtSetInformationProcess syscall not found!");
			return false;
		}
		else if (!idx_NtQueryVirtualMemory)
		{
			TLS_LOG("NtQueryVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtReadVirtualMemory)
		{
			TLS_LOG("NtReadVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtSetInformationThread)
		{
			TLS_LOG("NtSetInformationThread syscall not found!");
			return false;
		}
		else if (!idx_NtWriteVirtualMemory)
		{
			TLS_LOG("NtWriteVirtualMemory syscall not found!");
			return false;
		}
		else if (!idx_NtDuplicateObject)
		{
			TLS_LOG("NtDuplicateObject syscall not found!");
			return false;
		}
		else if (!idx_NtCreateThreadEx)
		{
			TLS_LOG("NtCreateThreadEx syscall not found!");
			return false;
		}
		else if (!idx_NtClose)
		{
			TLS_LOG("NtClose syscall not found!");
			return false;
		}
		else if (!idx_NtSetInformationDebugObject)
		{
			TLS_LOG("NtSetInformationDebugObject syscall not found!");
			return false;
		}
		else if (!idx_NtRemoveProcessDebug)
		{
			TLS_LOG("NtRemoveProcessDebug syscall not found!");
			return false;
		}
		else if (!idx_NtQuerySystemInformation)
		{
			TLS_LOG("NtQuerySystemInformation syscall not found!");
			return false;
		}
		else if (!idx_NtGetContextThread)
		{
			TLS_LOG("NtGetContextThread syscall not found!");
			return false;
		}
		else if (!idx_NtQueryInformationThread)
		{
			TLS_LOG("NtQueryInformationThread syscall not found!");
			return false;
		}
		else if (!idx_NtOpenThread)
		{
			TLS_LOG("NtOpenThread syscall not found!");
			return false;
		}
		else if (!idx_NtTerminateThread)
		{
			TLS_LOG("NtTerminateThread syscall not found!");
			return false;
		}

		return true;
	}

	// Wrapper funcs
	NTSTATUS _RtlAcquirePrivilege(PULONG Privilege, ULONG NumPriv, ULONG Flags, PVOID* ReturnedState)
	{
		static const auto ptr = (decltype(&RtlAcquirePrivilege))TLS_GetProcAddress(gs_hNtdll, xorstr_("RtlAcquirePrivilege"));
		if (!ptr)
			return STATUS_PROCEDURE_NOT_FOUND;
		return ptr(Privilege, NumPriv, Flags, ReturnedState);
	}
	VOID _RtlReleasePrivilege(PVOID StatePointer)
	{
		static const auto ptr = (decltype(&RtlReleasePrivilege))TLS_GetProcAddress(gs_hNtdll, xorstr_("RtlReleasePrivilege"));
		if (!ptr)
			return;
		return ptr(StatePointer);
	}

	// Helper funcs
	PVOID TLS_AllocateMemory(ULONG ulSize)
	{
		PVOID pvProxyAddress = nullptr;
		SIZE_T cbProxySize = ulSize;
		const auto ntStatus = NT::NtAllocateVirtualMemory(NtCurrentProcess(), &pvProxyAddress, 0, &cbProxySize, MEM_COMMIT, PAGE_READWRITE);
		if (NT_SUCCESS(ntStatus))
		{
			return pvProxyAddress;
		}
		return nullptr;
	}
	bool TLS_FreeMemory(LPVOID lpBase, ULONG ulSize)
	{
		PVOID pvProxyAddress = lpBase;
		SIZE_T cbProxySize = ulSize;

		const auto ntStatus = NT::NtFreeVirtualMemory(NtCurrentProcess(), &pvProxyAddress, &cbProxySize, MEM_FREE);
		return NT_SUCCESS(ntStatus);
	}
	bool TLS_MessageBox(const wchar_t* c_wszTitle, const wchar_t* c_wszMessage)
	{
		typedef enum HardErrorResponseButton {
			ResponseButtonOK,
			ResponseButtonOKCancel,
			ResponseButtonAbortRetryIgnore,
			ResponseButtonYesNoCancel,
			ResponseButtonYesNo,
			ResponseButtonRetryCancel,
			ResponseButtonCancelTryAgainContinue
		} HardErrorResponseButton;

		UNICODE_STRING wTitle;
		RtlInitUnicodeString(&wTitle, c_wszTitle);

		UNICODE_STRING wText;
		RtlInitUnicodeString(&wText, c_wszMessage);

		ULONG_PTR params[4] = {
			(ULONG_PTR)&wText,
			(ULONG_PTR)&wTitle,
			(ULONG)ResponseButtonOK,
			INFINITE
		};

		ULONG res = 0;
		return NT_SUCCESS(NtRaiseHardError(STATUS_SERVICE_NOTIFICATION, 4, 0x3, params, 0, &res));
	}

	// Syscall wrappers
	namespace NT
	{
		NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
		{
			return cleancall::call(idx_NtAllocateVirtualMemory, 6, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		}
		NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
		{
			return cleancall::call(idx_NtCreateSection, 7, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
		}
		NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
		{
			return cleancall::call(idx_NtMapViewOfSection, 10, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
		}
		NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
		{
			return cleancall::call(idx_NtUnmapViewOfSection, 2, ProcessHandle, BaseAddress);
		}
		NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
		{
			return cleancall::call(idx_NtFreeVirtualMemory, 4, ProcessHandle, BaseAddress, RegionSize, FreeType);
		}
		NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
		{
			return cleancall::call(idx_NtProtectVirtualMemory, 5, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
		}
		NTSTATUS NtLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType)
		{
			return cleancall::call(idx_NtLockVirtualMemory, 4, ProcessHandle, BaseAddress, RegionSize, MapType);
		}
		NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
		{
			return cleancall::call(idx_NtQueryInformationProcess, 5, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		}
		NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
		{
			return cleancall::call(idx_NtSetInformationProcess, 4, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
		}
		NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
		{
			return cleancall::call(idx_NtQueryVirtualMemory, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
		}
		NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
		{
			return cleancall::call(idx_NtReadVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
		}
		NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
		{
			return cleancall::call(idx_NtSetInformationThread, 4, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		}
		NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
		{
			return cleancall::call(idx_NtWriteVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
		}
		NTSTATUS NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
		{
			return cleancall::call(idx_NtDuplicateObject, 7, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
		}
		NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
		{
			return cleancall::call(idx_NtCreateThreadEx, 11, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		}
		NTSTATUS NtClose(HANDLE Handle)
		{
			return cleancall::call(idx_NtClose, 1, Handle);
		}
		NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
		{
			return cleancall::call(idx_NtRemoveProcessDebug, 2, ProcessHandle, DebugObjectHandle);
		}
		NTSTATUS NtSetInformationDebugObject(HANDLE DebugObjectHandle, DEBUGOBJECTINFOCLASS DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength)
		{
			return cleancall::call(idx_NtSetInformationDebugObject, 5, DebugObjectHandle, DebugObjectInformationClass, DebugInformation, DebugInformationLength, ReturnLength);
		}
		NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
		{
			return cleancall::call(idx_NtQuerySystemInformation, 4, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		}
		NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
		{
			return cleancall::call(idx_NtGetContextThread, 2, ThreadHandle, ThreadContext);
		}
		NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
		{
			return cleancall::call(idx_NtQueryInformationThread, 5, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
		}
		NTSTATUS NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
		{
			return cleancall::call(idx_NtOpenThread, 4, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
		NTSTATUS NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)
		{
			return cleancall::call(idx_NtTerminateThread, 2, ThreadHandle, ExitStatus);
		}
	};
}
