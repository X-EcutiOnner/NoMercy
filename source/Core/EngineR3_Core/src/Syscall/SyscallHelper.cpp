#include "../../include/PCH.hpp"
#include "../../include/Defines.hpp"
#include "../../include/SyscallIndexHelper.hpp"
#include "../../include/SyscallHelper.hpp"
#include "../../include/Cleancall.hpp"

namespace NoMercyCore
{
	CSyscall::CSyscall()
	{
		m_spSyscallIndexHelper = stdext::make_shared_nothrow<CSyscallIndexHelper>();
		assert(m_spSyscallIndexHelper != nullptr);
	}
	CSyscall::~CSyscall()
	{
	}

	bool CSyscall::Initialize()
	{
		if (!m_spSyscallIndexHelper->BuildSyscallList(true))
			return false;

		PVOID pvBaseAddress = nullptr;
		SIZE_T stRegionSize = 0x1000; // 4KB
		NTSTATUS ntStatus = NtAllocateVirtualMemory(NtCurrentProcess(), &pvBaseAddress, 0, &stRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!NT_SUCCESS(ntStatus) || !pvBaseAddress || stRegionSize != 0x1000)
		{
			APP_TRACE_LOG(LL_ERR, L"NtAllocateVirtualMemory test failed! Status: 0x%X, BaseAddress: %p, RegionSize: %zu", ntStatus, pvBaseAddress, stRegionSize);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"NtAllocateVirtualMemory test passed! BaseAddress: %p, RegionSize: %zu", pvBaseAddress, stRegionSize);

		// TODO: Redirect syscall wrappers to g_winAPI table funcs

		/*
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtAllocateVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 6, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

		*/
		
		// Try FS operations with NtCreateFile / NtWriteFile / NtReadFile
		{
			const auto idxCreateFile = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtCreateFile"));
			const auto idxWriteFile = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtWriteFile"));
			const auto idxReadFile = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtReadFile"));
			const auto idxClose = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtClose"));
			const auto idxWait = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtWaitForSingleObject"));

			if (!idxCreateFile || !idxWriteFile || !idxReadFile || !idxClose)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get one or more syscall indices (Create/Write/Read/Close).");
				return false;
			}

			UNICODE_STRING fileName;
			RtlInitUnicodeString(&fileName, L"\\??\\C:\\testfile.txt");

			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

			HANDLE hFile = nullptr;
			IO_STATUS_BLOCK iosCreate{};
			NTSTATUS stCreate = cleancall::call(
				idxCreateFile, 11,
				&hFile,
				FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
				&oa,
				&iosCreate,
				nullptr,       
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OVERWRITE_IF,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				nullptr, 0
			);
			if (!NT_SUCCESS(stCreate) || !hFile)
			{
				APP_TRACE_LOG(LL_ERR, L"NtCreateFile failed! Status: 0x%X, FileHandle: %p", stCreate, hFile);
				return false;
			}
			APP_TRACE_LOG(LL_SYS, L"NtCreateFile succeeded! FileHandle: %p", hFile);

			// --- Write ---
			const char* dataToWrite = "Hello, World!";
			ULONG toWrite = static_cast<ULONG>(strlen(dataToWrite));
			IO_STATUS_BLOCK iosWrite{};
			NTSTATUS stWrite = cleancall::call(
				idxWriteFile, 9,
				hFile,
				nullptr, nullptr, nullptr,
				&iosWrite,
				(PVOID)dataToWrite,
				toWrite,
				nullptr,                    
				nullptr  
			);
			if (stWrite == STATUS_PENDING && idxWait)
			{
				cleancall::call(idxWait, 3, hFile, FALSE, nullptr);
				stWrite = iosWrite.Status;
			}
			SIZE_T bytesWritten = static_cast<SIZE_T>(iosWrite.Information);

			if (!NT_SUCCESS(stWrite) || bytesWritten != toWrite)
			{
				APP_TRACE_LOG(LL_ERR, L"NtWriteFile failed! Status: 0x%X, BytesWritten: %zu", stWrite, bytesWritten);
				cleancall::call(idxClose, 1, hFile);
				return false;
			}
			APP_TRACE_LOG(LL_SYS, L"NtWriteFile succeeded! BytesWritten: %zu", bytesWritten);

			char buffer[256] = {};
			ULONG toRead = sizeof(buffer) - 1;
			IO_STATUS_BLOCK iosRead{};
			LARGE_INTEGER off{};         

			NTSTATUS stRead = cleancall::call(
				idxReadFile, 9,
				hFile,
				nullptr, nullptr, nullptr,
				&iosRead,
				buffer,
				toRead,
				&off,                  
				nullptr
			);

			SIZE_T bytesRead = static_cast<SIZE_T>(iosRead.Information);

			if (!NT_SUCCESS(stRead) || bytesRead == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"NtReadFile failed! Status: 0x%X, BytesRead: %zu", stRead, bytesRead);
				cleancall::call(idxClose, 1, hFile);
				return false;
			}

			buffer[bytesRead] = '\0';
			APP_TRACE_LOG(LL_SYS, L"NtReadFile OK. BytesRead: %zu, Data: %hs", bytesRead, buffer);

			if (!NT_SUCCESS(stRead) || bytesRead == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"NtReadFile failed! Status: 0x%X, BytesRead: %zu", stRead, bytesRead);
				cleancall::call(idxClose, 1, hFile);
				return false;
			}

			if (bytesRead < sizeof(buffer)) buffer[bytesRead] = '\0';
			else buffer[sizeof(buffer) - 1] = '\0';

			APP_TRACE_LOG(LL_SYS, L"NtReadFile succeeded! BytesRead: %zu, Data: %hs", bytesRead, buffer);

			NTSTATUS stClose = cleancall::call(idxClose, 1, hFile);
			if (!NT_SUCCESS(stClose))
			{
				APP_TRACE_LOG(LL_ERR, L"NtClose failed! Status: 0x%X", stClose);
				return false;
			}
			APP_TRACE_LOG(LL_SYS, L"NtClose succeeded! FileHandle: %p", hFile);
		}

		return true;
	}

	NTSTATUS CSyscall::NtClose(HANDLE Handle)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtClose"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 1, Handle);
	}

	NTSTATUS CSyscall::NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtAllocateVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 6, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	NTSTATUS CSyscall::NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtFreeVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 4, ProcessHandle, BaseAddress, RegionSize, FreeType);
	}

	NTSTATUS CSyscall::NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtReadVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	}

	NTSTATUS CSyscall::NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtWriteVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 5, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	}

	NTSTATUS CSyscall::NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtQueryVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}

	NTSTATUS CSyscall::NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtProtectVirtualMemory"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 5, ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

	NTSTATUS CSyscall::NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtFlushInstructionCache"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 3, ProcessHandle, BaseAddress, Length);
	}

	NTSTATUS CSyscall::NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtOpenThread"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 4, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	NTSTATUS CSyscall::NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtSuspendThread"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 2, ThreadHandle, PreviousSuspendCount);
	}

	NTSTATUS CSyscall::NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtResumeThread"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 2, ThreadHandle, PreviousSuspendCount);
	}

	NTSTATUS CSyscall::NtSuspendProcess(HANDLE ProcessHandle)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtSuspendProcess"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 1, ProcessHandle);
	}

	NTSTATUS CSyscall::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtQuerySystemInformation"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 4, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	NTSTATUS CSyscall::NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtTerminateProcess"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 2, ProcessHandle, ExitStatus);
	}

	NTSTATUS CSyscall::NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtGetContextThread"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 2, ThreadHandle, ThreadContext);
	}

	NTSTATUS CSyscall::NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtOpenFile"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 6, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	}

	NTSTATUS CSyscall::NtCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
		ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtCreateSection"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 7, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle);
	}

	NTSTATUS CSyscall::NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
		SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
	{
		static const auto idx = m_spSyscallIndexHelper->GetSyscallId(xorstr_("NtMapViewOfSection"));
		if (!idx)
			return STATUS_PROCEDURE_NOT_FOUND;

		return cleancall::call(idx, 10, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	}
};

