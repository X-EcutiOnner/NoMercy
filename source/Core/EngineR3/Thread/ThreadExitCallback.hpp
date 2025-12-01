#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace NoMercy
{
	typedef VOID(NTAPI* TThreadExitCallbackTemplate)(PVOID, BOOLEAN);

	class CThreadExitWatcher
	{
		public:
			CThreadExitWatcher(HANDLE hThread);

			bool InitializeExitCallback(TThreadExitCallbackTemplate pCallback, DWORD dwTimeout = INFINITE, PVOID pContext = nullptr);
			bool ReleaseExitCallback();

			auto GetThreadHandle() 		{ return m_hThread; };
			auto GetWaitObjectHandle() 	{ return m_hWaitObj; };

		private:
			bool m_bInitialized;
			HANDLE m_hThread;
			HANDLE m_hWaitObj;
			LPVOID m_pCallback;
	};
};
