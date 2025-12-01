#pragma once

namespace NoMercy
{
	class CFunctions : public std::enable_shared_from_this <CFunctions>
	{
		public:
			HMODULE GetCurrentModule();

			const char* GetTime();
			DWORD GetCurrentTimestamp();
			DWORD SystemTimeToTimestamp(SYSTEMTIME st);
			std::wstring GetDate();
			std::wstring FixedBuildDate();
			std::wstring GetSystemLocale();

			void MessageBoxAf(HWND hWnd, DWORD dwTimeout, const char* c_szTitle, const char* c_szArgFormat, ...);

			std::wstring GetErrorDetailsA(int nErrorCode);
			std::wstring GetErrorDetailsW(int nErrorCode);
			std::wstring DisplayError(DWORD dwErrorCode);
			std::wstring DisplaySystemError(DWORD dwErrorCode);

			std::wstring GetFirstArgument(bool bLower, bool bFirst = true);
			std::wstring GetProcessCommandLine(bool bPassFirstArg = false);

			bool IsX64System();
			bool IsWow64Process(HANDLE hProcess);
			uint16_t CheckProcessorArch();
			uint32_t CheckProcessorType();
			std::wstring RunSystemCommand(const std::wstring& wstCommand);

			float GetEntropy(BYTE* byBuffer, DWORD dwLength);
			double GetShannonEntropy(const std::string& str);
			
			bool IsInModuleRange(HMODULE hModule, DWORD_PTR dwAddress);
			bool IsInModuleRange(const char* c_szModuleName, DWORD_PTR dwAddress);
			std::wstring GetModuleOwnerName(HANDLE hProcess, LPVOID pModuleBase);

			bool InvokeBSOD();

			bool IsSafeModeEnabled();
			bool IsRunningCompatMode();

			bool ExecuteApplication(const std::wstring& stPath, const std::wstring& stParams, bool bElevate, std::size_t nTimeout, DWORD& dwRefExitCode);
			
			std::wstring GetNoMercyHashList();

			bool IsMainWindow(HWND hWnd);
			HWND GetFirstWindow(DWORD dwProcessID);
			HWND GetMainWindow(DWORD dwProcessID);
			std::wstring GetMainWindowTitle(DWORD dwProcessID);
	};
};
