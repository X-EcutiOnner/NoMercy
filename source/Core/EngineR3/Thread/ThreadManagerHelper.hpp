#pragma once
#include <map>
#include "ThreadInterface.hpp"
#include "../Helper/ThreadHelper.hpp"

namespace NoMercy
{
	enum ESelfThreads
	{
		SELF_THREAD_NONE,
		SELF_THREAD_ANTI_MACRO,
		SELF_THREAD_WATCHDOG,
		SELF_THREAD_WMI,
		SELF_THREAD_WINDOW_CHECK,
		SELF_THREAD_CLIENT_MAIN_ROUTINE,
		SELF_THREAD_SERVICE_MAIN_ROUTINE,
		SELF_THREAD_THREAD_TICK_CHECKER,
		SELF_THREAD_TIMER_CHECKER,
		SELF_THREAD_MODULE_SECTION_MONITOR,
		SELF_THREAD_WEBSOCKET,
		SELF_THREAD_LOG_COLLECTOR,
		SELF_THREAD_CHEAT_QUEUE,
		SELF_THREAD_MEMORY_MONITOR,
		SELF_THREAD_MMAPMODULES,
		SELF_THREAD_SCANNER,
		SELF_THREAD_TICK_COUNTER,
		SELF_THREAD_CHEAT_QUEUE_MANAGER,
		SELF_THREAD_MEM_ALLOC_WATCHER,
		SELF_THREAD_PIPE_SERVER_MANAGER,
		SELF_THREAD_ETW_WATCHER,
		SELF_THREAD_HOOK_SCANNER,
		SELF_THREAD_MANUAL_MAP_SCANNER,
		SELF_THREAD_NET_IPC_SERVER,
		SELF_THREAD_NET_IPC_CLIENT,
		SELF_THREAD_ALPC_SERVER,
		SELF_THREAD_ALPC_CLIENT,
		SELF_THREAD_SYSTEM_TELEMETRY,
		SELF_THREAD_CACHE_MANAGER,
		SELF_THREAD_PYTHON_APP,
		SELF_THREAD_CLIENT_INIT,
		SELF_THREAD_GAME_INITIAL_CHECK,
		SELF_THREAD_MAX
	};

	struct SSelfThreads
	{
		int									nThreadIdx{ 0 };
		HANDLE								hThread{ nullptr };
		DWORD								dwThreadID{ 0 };
		DWORD_PTR							dwThreadStartAddress{ 0 };
		std::size_t							ulFuncSize{ 0 };
		DWORD								ulFuncHash{ 0 };
		DWORD								dwMaxDelay{ 0 };
		bool								bIsTemporaryThread{ false };
		HANDLE								hWaitObj{ nullptr };
		std::shared_ptr <CThread>			spCustomThread{};
		std::shared_ptr <IThreadInterface>	spThreadInterface{};
	};

	class CThreadManager : public std::enable_shared_from_this <CThreadManager>
	{
		public:
			CThreadManager();
			virtual ~CThreadManager();

			std::shared_ptr <CThread> CreateCustomThread(int nThreadIdx, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwMaxDelay, bool bIsTemporaryThread);
			bool DestroyThread(const std::shared_ptr <CThread> & thread);
			void DestroyThread(int32_t nThreadIdx);

			void DestroyThreads();
			void SuspendThreads();

			void OnThreadTerminated(DWORD dwThreadId);

			void AddThreadToPool(std::shared_ptr <SSelfThreads> spThreadInfos);
			const std::vector <std::shared_ptr <SSelfThreads>>& GetThreadList();

			std::shared_ptr <IThreadInterface> GetThreadInterface(int nThreadIdx);
			std::shared_ptr <CThread> GetThreadFromThreadCode(int nThreadIdx);
			std::shared_ptr <CThread> GetThreadFromId(DWORD dwThreadId);
			std::shared_ptr <CThread> GetThreadFromAddress(DWORD dwThreadAddress);
			std::shared_ptr <CThread> GetThreadFromHandle(HANDLE hThread);
			std::shared_ptr <SSelfThreads> GetThreadInfo(int nThreadIdx);

			std::size_t		GetThreadCount();
			std::size_t		GetSuspendedThreadCount();
			bool			HasSuspendedThread();

			bool SetAntiTrace(const std::shared_ptr <CThread>& targetThread, DWORD dwFlag);

			std::wstring GetThreadCustomName(int nThreadIdx);

		private:
			mutable std::recursive_mutex m_mtxLock;
			std::vector < std::shared_ptr <SSelfThreads> >			m_vThreadPool;
			std::map <DWORD, /* dwThreadId */ HANDLE /* hThread */>	m_mapSelfThreads;
	};
};
