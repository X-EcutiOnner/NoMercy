#pragma once

namespace NoMercyCore
{
	class CThreadFunctions
	{
		public:
			static DWORD	GetThreadOwnerProcessId(DWORD dwThreadID);
			static DWORD	GetThreadStartAddress(HANDLE hThread);
			static DWORD	GetMainThreadIdByStarttime();
			static DWORD	GetMainThreadIdByEntrypoint();
			static DWORD	GetThreadIdFromAddress(DWORD dwAddress);
			static bool		ThreadIsItAlive(DWORD dwThreadID);
			static HANDLE	CreateThread(int iCustomThreadCode, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwFlags, LPDWORD pdwThreadId);
			static DWORD	GetLegitThreadStartAddress();
			static HANDLE	SilentCreateThread(DWORD_PTR dwThreadAddress);
			static DWORD	GetThreadID(HANDLE hThread);
			static bool		ChangeThreadsStatus(bool bSuspend, bool bControlled = true);
			static bool		IsThreadSuspended(HANDLE threadHandle);
	};
};
