#pragma once

namespace NoMercy
{
	class CTerminator
	{
		public:
			static bool TerminateProcess(HANDLE hProcess);
			static bool TerminateThread(HANDLE hThread);
			static bool TerminateWindow(HWND hWnd);
	};
}
