#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"

namespace NoMercy
{
	bool CApplication::ChangeScreenProtectionStatus(HWND hWnd, bool bEnabled)
	{
		if (!IsWindows7SP1OrGreater())
			return true;

		const auto bRet = g_winAPIs->SetWindowDisplayAffinity(hWnd, bEnabled ? WDA_MONITOR : WDA_NONE);
		APP_TRACE_LOG(LL_SYS, L"hWnd: %p New status: %d Protection ret: %d Last error: %u", hWnd, bEnabled, bRet, g_winAPIs->GetLastError());

		NoMercyCore::CApplication::Instance().DataInstance()->UpdateScreenProtectionStatus(hWnd, bEnabled);
		return bRet;
	}

	void CApplication::CheckScreenProtection(HWND hWnd)
	{
		if (!IsWindows7SP1OrGreater())
			return;

		if (!NoMercyCore::CApplication::Instance().DataInstance()->IsProtectedWindow(hWnd) ||
			!NoMercyCore::CApplication::Instance().DataInstance()->GetScreenProtectionStatus(hWnd))
		{
			return;
		}

		auto dwAffinity = 0UL;
		const auto bRet = g_winAPIs->GetWindowDisplayAffinity(hWnd, &dwAffinity);
		APP_TRACE_LOG(LL_SYS, L"hWnd: %p Current protection status ret: %d affinity: %u", bRet, dwAffinity);

		if (!bRet)
			return;

		if (dwAffinity != WDA_MONITOR)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SCREEN_PROTECTION_STATUS_CORRUPTED, g_winAPIs->GetLastError());
			return;
		}
	}

	void CApplication::InitScreenProtection(HWND hWnd)
	{
		if (!IsWindows7SP1OrGreater())
			return;

		if (!hWnd || !g_winAPIs->IsWindow(hWnd))
		{
			APP_TRACE_LOG(LL_ERR, L"Target window: %p is NOT valid!", hWnd);
			return;
		}

		wchar_t wszClass[MAX_PATH]{ L'\0' };
		g_winAPIs->GetClassNameW(hWnd, wszClass, MAX_PATH);

		wchar_t wszTitle[MAX_PATH]{ L'\0' };
		g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);

		APP_TRACE_LOG(LL_SYS, L"Target window found! %p | %s-%s", hWnd, wszTitle, wszClass);

		if (!ChangeScreenProtectionStatus(hWnd, true))
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SCREEN_PROTECTION_FAILED_INIT, g_winAPIs->GetLastError());
			return;
		}
	}

	void CApplication::RemoveScreenProtection(HWND hWnd)
	{
		if (!IsWindows7SP1OrGreater())
			return;

		if (!hWnd || !g_winAPIs->IsWindow(hWnd))
		{
			APP_TRACE_LOG(LL_ERR, L"Target window: %p is NOT valid!", hWnd);
			return;
		}

		wchar_t wszClass[MAX_PATH]{ L'\0' };
		g_winAPIs->GetClassNameW(hWnd, wszClass, MAX_PATH);

		wchar_t wszTitle[MAX_PATH]{ L'\0' };
		g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);

		APP_TRACE_LOG(LL_SYS, L"Target window found! %p | %s-%s", hWnd, wszTitle, wszClass);

		if (!ChangeScreenProtectionStatus(hWnd, false))
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SCREEN_PROTECTION_FAILED_RELEASE, g_winAPIs->GetLastError());
			return;
		}
	}

	bool CApplication::IsProtectedScreen(HWND hWnd)
	{
		return NoMercyCore::CApplication::Instance().DataInstance()->IsProtectedWindow(hWnd);
	}
};
