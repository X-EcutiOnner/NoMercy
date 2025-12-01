#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ThreadExitCallback.hpp"

namespace NoMercy
{
	CThreadExitWatcher::CThreadExitWatcher(HANDLE hThread) :
		m_bInitialized(false), m_hThread(hThread), m_hWaitObj(INVALID_HANDLE_VALUE), m_pCallback(nullptr)
	{
	}

	bool CThreadExitWatcher::InitializeExitCallback(TThreadExitCallbackTemplate pCallback, DWORD dwTimeout, PVOID pContext)
	{
		APP_TRACE_LOG(LL_SYS, L"Initializing thread exit callback for: %p", m_hThread);
			
		if (!m_hThread || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid thread handle: %p", m_hThread);
			return false;
		}
		
		const auto bWaitRet = g_winAPIs->RegisterWaitForSingleObject(&m_hWaitObj, m_hThread, pCallback, pContext, dwTimeout, WT_EXECUTEONLYONCE);
		if (!bWaitRet)
		{
			APP_TRACE_LOG(LL_ERR, L"RegisterWaitForSingleObject failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		m_pCallback = pCallback;
		m_bInitialized = true;
		APP_TRACE_LOG(LL_SYS, L"Thread exit callback initialized successfully!");
		return true;
	}
	bool CThreadExitWatcher::ReleaseExitCallback()
	{
		if (m_hWaitObj)
		{
			const auto bUnregisterRet =
				true;
			// https://stackoverflow.com/questions/48049314/registerwaitforsingleobject-crash-sometime-if-handle-is-closed-immediately
			/*
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hWaitObj) ?
				g_winAPIs->UnregisterWait(m_hWaitObj) :
				true;
			*/

			m_bInitialized = false;
			m_hThread = nullptr;
			m_hWaitObj = nullptr;

			return bUnregisterRet;
		}
		return false;
	}
};
