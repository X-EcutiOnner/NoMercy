#pragma once

namespace NoMercy
{
	class CWinDebugMonitor : std::enable_shared_from_this <CWinDebugMonitor>
	{
		static constexpr auto TIMEOUT_WIN_DEBUG = 100;

		struct SDBWinBuffer
		{
			DWORD   dwProcessID{ 0 };
			char    szDataBuffer[4096 - sizeof(dwProcessID)]{ '\0' };
		};
		
	public:
		CWinDebugMonitor();
		~CWinDebugMonitor();

		bool Initialize();
		void Release();
		
		void OutputWinDebugString(const DWORD dwSourcePID, const std::wstring& stBuffer);
		
	protected:
		DWORD WinDebugMonitorProcess();
		static DWORD WINAPI WinDebugMonitorThread(LPVOID lpData);

	private:
		bool m_bIsInitialized;
		
		HANDLE m_hDBWinMutex;
		HANDLE m_hDBMonBuffer;
		HANDLE m_hEventBufferReady;
		HANDLE m_hEventDataReady;

		HANDLE m_hWinDebugMonitorThread;
		bool m_bWinDebugMonStopped;
		std::shared_ptr <SDBWinBuffer> m_spDBBuffer;
	};
};
