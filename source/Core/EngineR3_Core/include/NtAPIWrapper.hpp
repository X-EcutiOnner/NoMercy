#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <mutex>
#include <vector>
#include <optional>
#include "../../EngineR3_Core/include/Defines.hpp"

#undef CreateFile

namespace NoMercyCore
{
	class CNtAPI : std::enable_shared_from_this <CNtAPI>
	{
	public:
		CNtAPI();
		virtual ~CNtAPI();

		auto IsProcessWoW64() const { return m_bIsWoW64; };
		auto IsProcessX64() const { return m_bIsX64; };
		bool IsSystemX64();

		ULONG GetSystemErrorFromNTStatus(NTSTATUS status);
		ULONG GetSystemErrorFromLSAStatus(NTSTATUS status);

		HANDLE OpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId);
		bool SuspendProcess(HANDLE hThread);
		bool ResumeProcess(HANDLE hProcess);
		HANDLE OpenProcessToken(HANDLE processHandle, ACCESS_MASK desiredAccess);
		bool TerminateProcess(HANDLE hProcess, NTSTATUS ulExitStatus);

		HANDLE OpenThread(DWORD dwDesiredAccess, DWORD dwThreadId);
		HANDLE CreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwFlags, PDWORD_PTR pdwThreadId);
		bool CreateThreadAndWait(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParam, DWORD dwDelay, LPDWORD pdwExitCode);
		bool SuspendThread(HANDLE hThread);
		bool ResumeThread(HANDLE hThread, bool bLoop);
		bool TerminateThread(HANDLE hThread, NTSTATUS ulExitStatus);

		bool CloseHandle(HANDLE hTarget);
		bool WaitObject(HANDLE hTarget, DWORD dwDelay);
		bool Sleep(DWORD dwDelay);
		int GetProcessorCount();
		void YieldCPU();
		bool ManageFsRedirection(bool bDisable, PVOID pCookie, PVOID* ppCookie);
		bool IsFsRedirectionDisabled();
		void SetFsRedirectionStatus(bool bDisabled);

		LPVOID GetProcAddress(HMODULE hModule, const char* c_szApiName);

		NTSTATUS CreateFile(PHANDLE hFile, LPWSTR FilePath, ACCESS_MASK AccessMask, ULONG FileAttributes, ULONG ShareAccess, ULONG DispositionFlags, ULONG CreateOptions);
		NTSTATUS QueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID64 ProcessInformation, ULONG64 ProcessInformationLength, PULONG ReturnLength);
		NTSTATUS ReadVirtualMemory(HANDLE hProcess, PVOID64 lpBaseAddress, PVOID lpBuffer, ULONG64 nSize, PSIZE_T lpNumberOfBytesRead);
		NTSTATUS WriteVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PSIZE_T ReturnLength);
		ptr_t AllocateVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG Protection);
		bool FreeVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, DWORD FreeType);
		bool ProtectVirtualMemory(HANDLE ProcessHandle, PVOID64 BaseAddress, SIZE_T Size, DWORD NewProtection, PDWORD OldProtect);
		NTSTATUS QueryVirtualMemory(HANDLE ProcessHandle, PVOID64 pvBaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength);
		bool FlushVirtualMemory(HANDLE ProcessHandle, PVOID64 pvBaseAddress = nullptr, SIZE_T cbSize = 0);

	private:
		bool m_bIsX64;
		bool m_bIsWoW64;
		std::map <DWORD /* dwThreadID */, bool /* bFSRedirectionDisabled */> m_mapFSRedirectionCache;
	};
};
