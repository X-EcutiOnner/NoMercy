#pragma once
#include <string>
#include <vector>

namespace NoMercyCore
{
	struct SModuleData
	{
		ptr_t	pBaseAddress{ nullptr };
		SIZE_T  cbSize{ 0 };
	};

	class CProcessFunctions
	{
		public:
			static DWORD		GetProcessParentProcessId(DWORD dwMainProcessId);
			static DWORD		FindProcess(const std::wstring& wstProcessName);
			static DWORD		FindAnyProcess(const std::vector <std::wstring>& vecProcessNames);
			static DWORD		GetProcessIdFromProcessName(const std::wstring& wstProcessName, bool bDumpProcesses = false);
			static DWORD		GetProcessCountFromProcessName(const std::wstring& wstProcessName);
			static std::wstring	GetProcessNameFromProcessId(DWORD dwProcessId);
			static bool			ProcessIsItAlive(DWORD dwProcessId);
			static std::wstring	GetProcessFullName(HANDLE hProcess);
			static std::vector <DWORD> GetProcessIdsFromProcessName(const std::wstring& wstProcessName);
			static std::wstring  GetProcessName(HANDLE hProcess);
			static DWORD		GetProcessIdNative(HANDLE hProcess);
			static DWORD		GetParentProcessIdNative(HANDLE hProcess);
			static std::wstring DosDevicePath2LogicalPath(LPCWSTR lpszDosPath);
			static std::wstring	GetParentProcessName(DWORD dwCurrPID, bool bSilent = false);
			static bool			IsValidProcessHandle(HANDLE hProcess);
			static SModuleData	GetProcessBaseData(DWORD dwProcessId);
			static HMODULE		GetModuleHandle(DWORD dwProcessId, const std::wstring& stModuleName);
			static bool			HasSuspendedThread(DWORD dwProcessId, bool bDumpThreads = false, bool bKillSuspendedThreads = false);
			static std::wstring	ParentProcessName();
			static bool			EnumerateProcessesNative(std::function<void(std::wstring, DWORD, PVOID)> fnCallback);
			static uint64_t		GetProcessCreationTime(HANDLE hProcess);
			static bool			IsThreadInProgress(DWORD dwProcessId, DWORD dwThreadId);
	};
};
