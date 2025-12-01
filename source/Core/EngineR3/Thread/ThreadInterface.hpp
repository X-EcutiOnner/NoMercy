#pragma once
#include "../../EngineR3_Core/include/SafeExecutor.hpp"

namespace NoMercy
{
	class IThreadInterface
	{
	public:
		IThreadInterface(int32_t nThreadIdx, LPTHREAD_START_ROUTINE pFunc, LPVOID lpParam, DWORD dwDelay);
		~IThreadInterface();

		bool Initialize();
		void Release();

		void Start();
		void Stop();
		void Pause();
		void Resume();
		void Join();

		auto IsInitialized() const          { return m_bInitialized;			};
		auto IsRunning() const              { return m_bRunning;				};
		auto IsPaused() const               { return m_bPaused;					};

		auto GetThreadIndex() const         { return m_nThreadIdx;				};
		auto GetThreadHandle() const        { return m_hThread;					};
		auto GetThreadID() const            { return m_dwThreadId;				};
		auto GetStartAddress() const        { return &StartThreadProxyRoutine;	};
		auto GetRealStartAddress() const    { return m_pFunc;                   };
		std::size_t GetThreadFuncSize() const;

	protected:
		DWORD					ThreadProxyRoutine(void);
		static DWORD WINAPI		StartThreadProxyRoutine(LPVOID lpParam);

	private:
		bool	m_bInitialized;
		bool    m_bRunning;
		bool    m_bPaused;

		int32_t m_nThreadIdx;
		HANDLE	m_hThread;
		DWORD	m_dwThreadId;
		DWORD   m_dwStartTime;

		// std::unique_ptr <NoMercyCore::CSafeExecutor> m_upSafeExecutor;
		LPTHREAD_START_ROUTINE m_pFunc;
		LPVOID m_pParam;
		DWORD m_dwDelay;

		// _se_translator_function m_kSETranslator;
	};
};
