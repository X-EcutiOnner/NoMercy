#pragma once
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	class CWatchdog : public std::enable_shared_from_this <CWatchdog>
	{
	public:
		CWatchdog();
		virtual ~CWatchdog() = default;

		size_t						GetWatchdogCount();
		bool						IsWatchdogWindow(HWND hWnd);
		std::map <HWND, WNDPROC>	GetWindowBackups();

		void SetInitilizationStatus(bool bNewStat) { m_bInitialized = bNewStat; };
		auto IsInitialized() const { return m_bInitialized; };

		void SetLastCheckTime(DWORD dwTime) { m_dwLastCheckTime = dwTime; };
		auto GetLastCheckTime() const { return m_dwLastCheckTime; };

		bool PreCheckLoadedWatchdogs();
		bool LoadWatchdog();

		bool InitializeWatchdog();
		void ReleaseWatchdogThread();
		void CleanupWatchdog();

	private:
		mutable std::recursive_mutex m_mutex;

		bool  m_bInitialized;
		DWORD m_dwLastCheckTime;

		CStopWatch <std::chrono::milliseconds> m_watchdogTimer;
		CStopWatch <std::chrono::milliseconds> m_tickCheckTimer;

		std::map <HWND, WNDPROC> m_windowBackupMap;
		int						 m_iWatchDogCheckCount;
	};
};
