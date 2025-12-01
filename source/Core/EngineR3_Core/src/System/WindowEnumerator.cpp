#include "../../include/PCH.hpp"
#include "../../include/WindowEnumerator.hpp"

namespace NoMercyCore
{
	HWND CWindowEnumerator::FindWindowWithClassName(const std::wstring& szClassName, bool bSubstrCheck)
	{
		HWND hTargetWnd = nullptr;

		if (szClassName.empty())
			return hTargetWnd;

		const auto vWindowList = EnumerateWindows();
		for (const auto& hWnd : vWindowList)
		{
			wchar_t wszClass[MAX_PATH]{ L'\0' };
			g_winAPIs->GetClassNameW(hWnd, wszClass, MAX_PATH);

			if ((!bSubstrCheck && !wcscmp(wszClass, szClassName.c_str())) ||
				 (bSubstrCheck && wcsstr(wszClass, szClassName.c_str()))
				)
			{
				hTargetWnd = hWnd;
			}
		}

		return hTargetWnd;
	}

	HWND CWindowEnumerator::FindWindowWithTitleName(const std::wstring& szTitleName, bool bSubstrCheck)
	{
		HWND hTargetWnd = nullptr;

		if (szTitleName.empty())
			return hTargetWnd;

		const auto vWindowList = EnumerateWindows();
		for (const auto& hWnd : vWindowList)
		{
			wchar_t wszTitle[MAX_PATH]{ L'\0' };
			g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);

			if ((!bSubstrCheck && !wcscmp(wszTitle, szTitleName.c_str())) ||
				 (bSubstrCheck && wcsstr(wszTitle, szTitleName.c_str()))
				)
			{
				hTargetWnd = hWnd;
			}
		}

		return hTargetWnd;
	}

	std::vector <HWND> CWindowEnumerator::EnumerateWindows(DWORD dwOwnerPID)
	{
		auto vWindowList = std::vector<HWND>();

		HWND hWnd = nullptr;
		do
		{
			hWnd = g_winAPIs->FindWindowExW(nullptr, hWnd, nullptr, nullptr);

			DWORD dwPID = 0;
			g_winAPIs->GetWindowThreadProcessId(hWnd, &dwPID);

			if (dwPID == dwOwnerPID)
				vWindowList.push_back(hWnd);

		} while (hWnd);

		return vWindowList;
	}

	std::vector <HWND> CWindowEnumerator::EnumerateWindows()
	{
		auto vWindowList = std::vector<HWND>();

		HWND hWnd = nullptr;
		do
		{
			hWnd = g_winAPIs->FindWindowExW(nullptr, hWnd, nullptr, nullptr);
			vWindowList.push_back(hWnd);
		} while (hWnd);

		return vWindowList;
	}

	std::vector <HWND> CWindowEnumerator::EnumerateWindowsNative()
	{
		auto vWindowList = std::vector<HWND>();

		for (HWND hWnd = g_winAPIs->GetTopWindow(0); hWnd; hWnd = g_winAPIs->GetNextWindow(hWnd, GW_HWNDNEXT))
		{
			vWindowList.push_back(hWnd);
		}

		return vWindowList;	
	}
}
