#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Helper/PatternScanner.hpp"
#include "WinDebugMonitor.hpp"

#ifdef _DEBUG
#define ENABLE_STRING_LOGGING
#endif

namespace NoMercy
{
	CWinDebugMonitor::CWinDebugMonitor() :
		m_bIsInitialized(false), m_bWinDebugMonStopped(true), m_hDBWinMutex(nullptr), m_hDBMonBuffer(nullptr), m_hEventBufferReady(nullptr), m_hEventDataReady(nullptr), m_hWinDebugMonitorThread(nullptr)
	{
	}
	CWinDebugMonitor::~CWinDebugMonitor()
	{
	}

	bool CWinDebugMonitor::Initialize()
	{
		g_winAPIs->SetLastError(0);

		// Mutex: DBWin
		m_hDBWinMutex = g_winAPIs->OpenMutexW(SYNCHRONIZE, FALSE, xorstr_(L"DBWinMutex"));
		if (!IS_VALID_HANDLE(m_hDBWinMutex))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenMutexW (DBWinMutex) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Event: buffer ready
		// ---------------------------------------------------------
		const auto DBWIN_BUFFER_READY = xorstr_(L"DBWIN_BUFFER_READY");
		m_hEventBufferReady = g_winAPIs->OpenEventW(EVENT_ALL_ACCESS, FALSE, DBWIN_BUFFER_READY);
		if (!IS_VALID_HANDLE(m_hEventBufferReady))
		{
			APP_TRACE_LOG(LL_WARN, L"OpenEventW (DBWIN_BUFFER_READY) failed with error: %u", g_winAPIs->GetLastError());
			
			m_hEventBufferReady = g_winAPIs->CreateEventW(NULL, FALSE, TRUE, DBWIN_BUFFER_READY);
			if (!IS_VALID_HANDLE(m_hEventBufferReady))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateEventW (DBWIN_BUFFER_READY) failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}

		// Event: data ready
		// ---------------------------------------------------------
		const auto DBWIN_DATA_READY = xorstr_(L"DBWIN_DATA_READY");
		m_hEventDataReady = g_winAPIs->OpenEventW(SYNCHRONIZE, FALSE, DBWIN_DATA_READY);
		if (!IS_VALID_HANDLE(m_hEventDataReady))
		{
			APP_TRACE_LOG(LL_WARN, L"OpenEventW (DBWIN_DATA_READY) failed with error: %u", g_winAPIs->GetLastError());
			
			m_hEventDataReady = g_winAPIs->CreateEventW(NULL, FALSE, FALSE, DBWIN_DATA_READY);
			if (!IS_VALID_HANDLE(m_hEventDataReady))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateEventW (DBWIN_DATA_READY) failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}

		// Shared memory
		// ---------------------------------------------------------
		const auto DBWIN_BUFFER = xorstr_(L"DBWIN_BUFFER");
		m_hDBMonBuffer = g_winAPIs->OpenFileMappingW(FILE_MAP_READ, FALSE, DBWIN_BUFFER);
		if (!IS_VALID_HANDLE(m_hDBMonBuffer))
		{
			APP_TRACE_LOG(LL_WARN, L"OpenFileMappingW (DBWIN_BUFFER) failed with error: %u", g_winAPIs->GetLastError());
			
			m_hDBMonBuffer = g_winAPIs->CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SDBWinBuffer), DBWIN_BUFFER);
			if (!IS_VALID_HANDLE(m_hDBMonBuffer))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileMappingA (DBWIN_BUFFER) failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}

		const auto lpBuffer = g_winAPIs->MapViewOfFile(m_hDBMonBuffer, SECTION_MAP_READ, 0, 0, 0);
		if (!lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"MapViewOfFile (DBWIN_BUFFER) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}		

		m_spDBBuffer = stdext::make_shared_nothrow<SDBWinBuffer>(*reinterpret_cast<SDBWinBuffer*>(lpBuffer));
		if (!m_spDBBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"stdext::make_shared_nothrow<SDBWinBuffer> failed");
			return false;
		}

		// Monitoring thread
		// ---------------------------------------------------------
		m_bWinDebugMonStopped = false;
		
		m_hWinDebugMonitorThread = g_winAPIs->CreateThread(NULL, 0, WinDebugMonitorThread, this, 0, NULL);
		if (!m_hWinDebugMonitorThread)
		{
			m_bWinDebugMonStopped = true;
			
			APP_TRACE_LOG(LL_ERR, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// set monitor thread's priority to highest
		// ---------------------------------------------------------
		if (!g_winAPIs->SetPriorityClass(NtCurrentProcess(), REALTIME_PRIORITY_CLASS))
		{
			APP_TRACE_LOG(LL_WARN, L"SetPriorityClass failed with error: %u", g_winAPIs->GetLastError());
		}
		if (!g_winAPIs->SetThreadPriority(m_hWinDebugMonitorThread, THREAD_PRIORITY_TIME_CRITICAL))
		{
			APP_TRACE_LOG(LL_WARN, L"SetThreadPriority failed with error: %u", g_winAPIs->GetLastError());
		}

		APP_TRACE_LOG(LL_SYS, L"WinDebugMonitor initialized");
		m_bIsInitialized = true;
		return true;
	}

	void CWinDebugMonitor::Release()
	{
		m_bWinDebugMonStopped = true;
		
		if (IS_VALID_HANDLE(m_hWinDebugMonitorThread))
		{
			g_winAPIs->WaitForSingleObject(m_hWinDebugMonitorThread, INFINITE);
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hWinDebugMonitorThread);
			m_hWinDebugMonitorThread = nullptr;
		}

		if (IS_VALID_HANDLE(m_hDBWinMutex))
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hDBWinMutex);
			m_hDBWinMutex = NULL;
		}

		if (IS_VALID_SMART_PTR(m_spDBBuffer))
		{
			g_winAPIs->UnmapViewOfFile(m_spDBBuffer.get());
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hDBMonBuffer);
			m_hDBMonBuffer = NULL;
		}

		if (m_hEventBufferReady)
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hEventBufferReady);
			m_hEventBufferReady = NULL;
		}

		if (m_hEventDataReady)
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hEventDataReady);
			m_hEventDataReady = NULL;
		}

		m_spDBBuffer.reset();
	}

	void CWinDebugMonitor::OutputWinDebugString(const DWORD dwSourcePID, const std::wstring& stBuffer)
	{
		ADMIN_DEBUG_LOG(LL_SYS, L"[%u] >> %s", dwSourcePID, stBuffer.c_str());
		
		auto vecBlacklist = CApplication::Instance().QuarentineInstance()->DebugStringQuarentine()->GetBlacklist();
		if (vecBlacklist.empty())
			return;
		
		for (auto& [obj, opts] : vecBlacklist)
		{
			if (!obj.data.empty() && stBuffer.find(obj.data) != std::wstring::npos)
			{
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_DEBUG_STRING, obj.idx, obj.data);
				break;
			}
		}
	}

	DWORD CWinDebugMonitor::WinDebugMonitorProcess()
	{
		// wait for data ready
		const auto ret = g_winAPIs->WaitForSingleObject(m_hEventDataReady, TIMEOUT_WIN_DEBUG);
		if (ret == WAIT_OBJECT_0)
		{
//			if (m_spDBBuffer->dwProcessID == g_winAPIs->GetCurrentProcessId())
//			{
				this->OutputWinDebugString(m_spDBBuffer->dwProcessID, stdext::to_wide(m_spDBBuffer->szDataBuffer));
//			}

			// signal buffer ready
			g_winAPIs->SetEvent(m_hEventBufferReady);
		}

		return ret;
	}

	DWORD WINAPI CWinDebugMonitor::WinDebugMonitorThread(LPVOID lpData)
	{
		const auto This = reinterpret_cast<CWinDebugMonitor*>(lpData);

		while (!This->m_bWinDebugMonStopped)
		{
			This->WinDebugMonitorProcess();
		}

		return 0;
	}
};
