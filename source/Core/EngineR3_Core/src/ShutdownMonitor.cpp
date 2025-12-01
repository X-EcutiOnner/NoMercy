#include "../include/PCH.hpp"
#include "../include/Application.hpp"

namespace NoMercyCore
{
	bool CApplication::RegisterShutdownBlockReason(HWND hWnd)
	{
		if (!hWnd)
			return false;
		
		if (!g_winAPIs->ShutdownBlockReasonCreate(hWnd, xorstr_(L"NoMercy didn't yet exit safely...")))
		{
			APP_TRACE_LOG(LL_ERR, L"Register shutdown block reason failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Shutdown block reason registered successfully!");
		m_bShutdownBlockInitialized = true;
		return true;
	}

	void CApplication::UnregisterShutdownBlockReason(HWND hWnd)
	{
		if (m_bShutdownBlockInitialized && hWnd)
		{
			g_winAPIs->ShutdownBlockReasonDestroy(hWnd);
			m_bShutdownBlockInitialized = false;
		}
	}
};
