#pragma once
#include "SyscallIndexHelper.hpp"

namespace NoMercyCore
{
	class CSyscall : public std::enable_shared_from_this <CSyscall>
	{
		public:
			CSyscall();
			virtual ~CSyscall();

			bool Initialize();

			NTSTATUS NtClose(HANDLE);
			NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
			NTSTATUS NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
			NTSTATUS NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
			NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, CONST VOID*, SIZE_T, PSIZE_T);
			NTSTATUS NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
			NTSTATUS NtProtectVirtualMemory(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
			NTSTATUS NtFlushInstructionCache(HANDLE, PVOID, SIZE_T);
			NTSTATUS NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
			NTSTATUS NtSuspendThread(HANDLE, PULONG);
			NTSTATUS NtResumeThread(HANDLE, PULONG);
			NTSTATUS NtSuspendProcess(HANDLE);
			NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
			NTSTATUS NtTerminateProcess(HANDLE, NTSTATUS);
			NTSTATUS NtGetContextThread(HANDLE, PCONTEXT);
			NTSTATUS NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
			NTSTATUS NtCreateSection(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
			NTSTATUS NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,	SECTION_INHERIT, ULONG, ULONG);

			auto SyscallIndexHelperInstance() { return m_spSyscallIndexHelper; };

		private:
			std::shared_ptr <CSyscallIndexHelper> m_spSyscallIndexHelper;
	};
};
