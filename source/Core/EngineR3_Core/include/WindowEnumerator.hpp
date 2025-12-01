#pragma once

namespace NoMercyCore
{
	class CWindowEnumerator
	{
		public:
			CWindowEnumerator() = default;
			~CWindowEnumerator() = default;

			HWND FindWindowWithClassName(const std::wstring& szClassName, bool bSubstrCheck);
			HWND FindWindowWithTitleName(const std::wstring& szTitleName, bool bSubstrCheck);

			std::vector <HWND> 	EnumerateWindows(DWORD dwOwnerPID);
			std::vector <HWND> 	EnumerateWindows();
			std::vector <HWND> 	EnumerateWindowsNative();
	};
};
