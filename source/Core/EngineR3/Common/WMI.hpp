#pragma once

namespace NoMercy
{
	enum class EWMIThreads : uint8_t
	{
//		DRIVER_LOAD_WATCHER,
//		SERVICE_LOAD_WATCHER,
		PROCESS_CREATE_WATCHER,
		PROCESS_TERMINATE_WATCHER,
//		THREAD_LOAD_WATCHER,
//		MODULE_LOAD_WATCHER,
		MAX
	};

	class CWMI : public std::enable_shared_from_this <CWMI>
	{
	public:
		CWMI();
		virtual ~CWMI();

		bool	InitWMIWatcher();
		void    ReleaseWMIWatcherThread();

		auto	IsInitialized() const { return m_bInitialized; };
		
		std::map <std::wstring, std::wstring> ParseWMIResponse(const std::wstring& wstResponse);

	protected:
		DWORD					ThreadRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool	m_bInitialized;
		bool	m_bThreadsCreated;
		HANDLE	m_hThreads[static_cast<uint8_t>(EWMIThreads::MAX)];
	};
};
