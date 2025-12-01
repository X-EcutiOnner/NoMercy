#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Functions.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"

namespace NoMercy
{
	static void __DummyFunc()
	{
	}
	HMODULE CFunctions::GetCurrentModule()
	{
		HMODULE hModule = nullptr;
		g_winAPIs->GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)__DummyFunc, &hModule);
		return hModule;
	}

	const char* CFunctions::GetTime()
	{
		time_t rawtime = { 0 };
		std::time(&rawtime);

		struct tm* timeinfo = { 0 };
		timeinfo = std::localtime(&rawtime);

		return std::asctime(timeinfo);
	}
	DWORD CFunctions::GetCurrentTimestamp()
	{
		time_t curTime = { 0 };
		std::time(&curTime);
		return (DWORD)curTime;
	}
	DWORD CFunctions::SystemTimeToTimestamp(SYSTEMTIME st)
	{
		std::tm tm = { 0 };
		tm.tm_sec = st.wSecond;
		tm.tm_min = st.wMinute;
		tm.tm_hour = st.wHour;
		tm.tm_mday = st.wDay;
		tm.tm_mon = st.wMonth - 1;
		tm.tm_year = st.wYear - 1900;
		tm.tm_isdst = -1;

		std::time_t fileCreatedTime = std::mktime(&tm);
		return (DWORD)fileCreatedTime;
	}
	std::wstring CFunctions::GetDate()
	{
		const auto now = std::chrono::system_clock::now();
		const auto t = std::chrono::system_clock::to_time_t(now);

		(void)std::put_time(std::localtime(&t), xorstr_(L"%F %T"));

		const auto tm = *std::localtime(&t);

		wchar_t wszTime[128]{ L'\0' };
		wcsftime(wszTime, 128, xorstr_(L"%H:%M:%S - %d:%m:%y"), &tm);

		return wszTime;
	}
	std::wstring CFunctions::FixedBuildDate()
	{
		wchar_t wszFixedDate[128]{ L'\0' };
		swprintf(wszFixedDate, xorstr_(L"%hs-%hs"), xorstr_(__DATE__), xorstr_(__TIME__));

		std::wstring wstFixedDate(wszFixedDate);
		stdext::replace_all<std::wstring>(wstFixedDate, xorstr_(L":"), L"");
		stdext::replace_all<std::wstring>(wstFixedDate, xorstr_(L" "), L"");
		return wstFixedDate;
	}

	void CFunctions::MessageBoxAf(HWND hWnd, DWORD dwTimeout, const char* c_szTitle, const char* c_szArgFormat, ...)
	{
		char szTmpString[8096]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, c_szArgFormat);
		vsprintf(szTmpString, c_szArgFormat, vaArgList);
		va_end(vaArgList);

		if (dwTimeout)
			g_winAPIs->MessageBoxTimeout(hWnd, szTmpString, c_szTitle, NULL, 0, dwTimeout);
		else
			g_winAPIs->MessageBoxA(hWnd, szTmpString, c_szTitle, NULL);
	}

	std::wstring CFunctions::GetErrorDetailsA(int nErrorCode)
	{
		wchar_t wszBuffer[1024]{ L'\0' };
		if (_wcserror_s(wszBuffer, 1024, nErrorCode))
			return wszBuffer;
		return {};
	}
	std::wstring CFunctions::GetErrorDetailsW(int nErrorCode)
	{
		wchar_t wszBuffer[1024]{ L'\0' };
		if (_wcserror_s(wszBuffer, 1024, nErrorCode))
			return wszBuffer;
		return {};
	}
	std::wstring CFunctions::DisplayError(DWORD dwErrorCode)
	{
		wchar_t wszErrorMessage[4096]{ L'\0' };

		const auto dwFlags = DWORD(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS);
		g_winAPIs->FormatMessageW(dwFlags, NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wszErrorMessage, sizeof(wszErrorMessage) / sizeof(wchar_t), nullptr);

		const auto wstMessage = std::wstring(wszErrorMessage);
		g_winAPIs->LocalFree(wszErrorMessage);

		return wstMessage;
	}

	std::wstring CFunctions::DisplaySystemError(DWORD dwErrorCode)
	{
		wchar_t wszErrorMessage[4096]{ L'\0' };

		const auto dwFlags = DWORD(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS);
		const auto dwDosErr = g_winAPIs->RtlNtStatusToDosError(dwErrorCode);
		g_winAPIs->FormatMessageW(dwFlags, g_winModules->hNtdll, dwDosErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wszErrorMessage, sizeof(wszErrorMessage) / sizeof(wchar_t), nullptr);

		const auto wstMessage = std::wstring(wszErrorMessage);
		g_winAPIs->LocalFree(wszErrorMessage);
		
		return wstMessage;
	}

	std::wstring CFunctions::GetFirstArgument(bool bLower, bool bFirst)
	{
		int iArgCount = 0;
		const auto wcArgs = g_winAPIs->CommandLineToArgvW(g_winAPIs->GetCommandLineW(), &iArgCount);
		if (!iArgCount)
			return {};

		std::wstring wszArgLaunch = wcArgs[bFirst ? 0 : 1];
		const auto wstArgLaunch = std::wstring(wszArgLaunch.begin(), wszArgLaunch.end());

		if (wstArgLaunch.empty())
			return {};

		if (bLower)
			return stdext::to_lower_wide(wstArgLaunch);
		return wstArgLaunch;
	}

	bool CFunctions::IsX64System()
	{
		SYSTEM_INFO SysInfo = { 0 };;
		g_winAPIs->GetNativeSystemInfo(&SysInfo);

		return (SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);
	}

	bool CFunctions::IsWow64Process(HANDLE hProcess)
	{
		BOOL bRet = FALSE;
		if (!g_winAPIs->IsWow64Process(hProcess, &bRet) || !bRet)
			return false;

		return true;
	}

	uint16_t CFunctions::CheckProcessorArch()
	{
		SYSTEM_INFO SysInfo = { 0 };
		g_winAPIs->GetNativeSystemInfo(&SysInfo);

		const auto arch = SysInfo.wProcessorArchitecture;
		APP_TRACE_LOG(LL_SYS, L"Processor arch: %u", arch);
		switch (arch)
		{
		case PROCESSOR_ARCHITECTURE_INTEL:
		case PROCESSOR_ARCHITECTURE_IA64:
		case PROCESSOR_ARCHITECTURE_AMD64:
			return 0;
		}
		return arch;
	}
	uint32_t CFunctions::CheckProcessorType()
	{
		SYSTEM_INFO SysInfo = { 0 };;
		g_winAPIs->GetNativeSystemInfo(&SysInfo);

		const auto type = SysInfo.dwProcessorType;
		APP_TRACE_LOG(LL_SYS, L"Processor type: %u", type);
		switch (type)
		{
		case PROCESSOR_INTEL_PENTIUM:
		case PROCESSOR_INTEL_386:
		case PROCESSOR_INTEL_IA64:
		case PROCESSOR_AMD_X8664:
			return 0;
		}
		return type;
	}

	float CFunctions::GetEntropy(BYTE* byBuffer, DWORD dwLength)
	{
		DWORD dwSize = 0;
		long lBuff[0xFF + 1] = { 0 };
		float fTemp, fEntropy = 0;

		for (DWORD i = 0; i < dwLength; i++)
		{
			lBuff[byBuffer[i]]++;
			dwSize++;
		}

		for (DWORD i = 0; i < 256; i++)
		{
			if (lBuff[i])
			{
				fTemp = (float)lBuff[i] / (float)dwSize;
				fEntropy += (-fTemp * log2(fTemp));
			}
		}

		return fEntropy;
	}

	bool CFunctions::IsInModuleRange(HMODULE hModule, DWORD_PTR dwAddress)
	{
		auto bRet = false;

		MODULEINFO mi = { 0 };
		if (g_winAPIs->GetModuleInformation(NtCurrentProcess(), hModule, &mi, sizeof(mi)))
		{
			const auto dwBase = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll);
			const auto dwHi = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll) + mi.SizeOfImage;

			bRet = (dwAddress >= dwBase && dwAddress <= dwHi);
		}
		return bRet;
	}

	bool CFunctions::IsInModuleRange(const char* c_szModuleName, DWORD_PTR dwAddress)
	{
		auto bRet = false;

		MODULEINFO mi = { 0 };
		if (g_winAPIs->GetModuleInformation(NtCurrentProcess(), g_winAPIs->GetModuleHandleA(c_szModuleName), &mi, sizeof(mi)))
		{
			const auto dwBase = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll);
			const auto dwHi = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll) + mi.SizeOfImage;

			bRet = (dwAddress >= dwBase && dwAddress <= dwHi);
		}
		return bRet;
	}

	bool CFunctions::InvokeBSOD()
	{
		BOOLEAN bPrev = FALSE;
		auto ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, true, false, &bPrev);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlAdjustPrivilege fail! Status: %p", ntStatus);
			return false;
		}

		ULONG response = 0;
		ntStatus = g_winAPIs->NtRaiseHardError(STATUS_ASSERTION_FAILURE, NULL, NULL, nullptr, OptionShutdownSystem, &response);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtRaiseHardError fail! Status: %p", ntStatus);
			return false;
		}
		return true;
	}

	std::wstring CFunctions::GetModuleOwnerName(HANDLE hProcess, LPVOID pModuleBase)
	{
		wchar_t wszFileName[2048]{ L'\0' };
		if (!g_winAPIs->GetMappedFileNameW(hProcess, pModuleBase, wszFileName, 2048))
			return {};

		const auto wstRealName = CProcessFunctions::DosDevicePath2LogicalPath(wszFileName);
		if (wstRealName.empty())
			return {};

		const auto stLowerName = stdext::to_lower_wide(wstRealName);
		return stLowerName;
	}

	bool CFunctions::IsSafeModeEnabled()
	{
		const auto nMetrics = g_winAPIs->GetSystemMetrics(SM_CLEANBOOT);
		return nMetrics > 0;
	}

	bool CFunctions::IsRunningCompatMode()
	{
		const auto lstDirectorys = {
			HKEY_CURRENT_USER,
			HKEY_LOCAL_MACHINE
		};

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		std::vector <std::wstring> vKeyList;
		for (const auto& hDirKey : lstDirectorys)
		{
			HKEY hKey{};
			auto res = g_winAPIs->RegOpenKeyExW(hDirKey, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"), NULL, dwFlags, &hKey);
			if (res == ERROR_SUCCESS)
			{
				DWORD dwIndex = 0;
				while (true)
				{
					DWORD dwValueLen = MAX_PATH;
					wchar_t wszValueName[MAX_PATH]{ L'\0' };

					res = g_winAPIs->RegEnumValueW(hKey, dwIndex, wszValueName, &dwValueLen, 0, NULL, NULL, NULL);
					if (ERROR_SUCCESS != res)
						break;

					if (wszValueName[0] != L'\0')
						vKeyList.push_back(wszValueName);
					dwIndex++;
				}

				g_winAPIs->RegCloseKey(hKey);
			}
		}

		const auto stCurrApp = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
		const auto stNoMercyPath = NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->GetNoMercyPath();
		for (const auto& stExecutable : vKeyList)
		{
			APP_TRACE_LOG(LL_SYS, L"Compat mode applied executable: %s", stExecutable.c_str());

			if (stExecutable == stCurrApp)
				return true;

			if (stExecutable.find(stNoMercyPath) != std::wstring::npos && !g_winAPIs->IsDebuggerPresent())
				return true;
		}

		return false;
	};

	std::wstring CFunctions::RunSystemCommand(const std::wstring& wstCommand)
	{
		std::wstring wstResult;

		auto fpPipe = _wpopen(wstCommand.c_str(), xorstr_(L"r"));
		if (!fpPipe)
			return {};

		try
		{
			wchar_t buffer[128]{ L'\0' };
			while (fgetws(buffer, _countof(buffer), fpPipe))
			{
				wstResult += buffer;
			}
		}
		catch (...)
		{
			_pclose(fpPipe);
			throw;
		}

		_pclose(fpPipe);
		return wstResult;
	}

	bool CFunctions::ExecuteApplication(const std::wstring& stPath, const std::wstring& stParams, bool bElevate, std::size_t nTimeout, DWORD& dwRefExitCode)
	{
		if (stPath.empty())
			return false;

		HRESULT hr = S_OK;
		if (FAILED(hr = g_winAPIs->CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) && hr != RPC_E_CHANGED_MODE)
		{
			APP_TRACE_LOG(LL_ERR, L"CoInitializeEx fail! Status: %p", hr);
			return false;
		}

		SHELLEXECUTEINFOW sinfo{ 0 };
		sinfo.cbSize = sizeof(sinfo);
		sinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NO_CONSOLE /* | SEE_MASK_NOASYNC*/;
		sinfo.lpVerb = bElevate ? xorstr_(L"runas") : xorstr_(L"open");
		sinfo.lpFile = stPath.c_str();
		sinfo.lpParameters = stParams.data();
		// sinfo.lpDirectory = stDirectory.c_str();
		sinfo.nShow = SW_HIDE;

		if (!g_winAPIs->ShellExecuteExW(&sinfo))
		{
			APP_TRACE_LOG(LL_ERR, L"ShellExecuteExW fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!sinfo.hProcess)
		{
			APP_TRACE_LOG(LL_ERR, L"Process can not started! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (nTimeout && WAIT_FAILED == g_winAPIs->WaitForSingleObject(sinfo.hProcess, nTimeout))
		{
			APP_TRACE_LOG(LL_ERR, L"Process wait failed! Error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(sinfo.hProcess);
			return false;
		}

		if (!g_winAPIs->GetExitCodeProcess(sinfo.hProcess, &dwRefExitCode))
		{
			APP_TRACE_LOG(LL_ERR, L"GetExitCodeProcess failed! Error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(sinfo.hProcess);
			return false;
		}

		g_winAPIs->CloseHandle(sinfo.hProcess);
		return true;
	}

	// Code from https://rosettacode.org/wiki/Entropy#C.2B.2B
	double CFunctions::GetShannonEntropy(const std::string& str)
	{
		std::map <char, int> frequencies;
		
		for (char c : str)
			frequencies[c]++;
		
		int numlen = str.length();
		double infocontent = 0;
		
		for (std::pair <char, int> p : frequencies)
		{
			double freq = static_cast<double>(p.second) / numlen;
			infocontent -= freq * (log(freq) / log(2));
		}

		return infocontent;
	}

	std::wstring CFunctions::GetSystemLocale()
	{
		const auto dwLocale = g_winAPIs->GetACP();
		return std::to_wstring(dwLocale);
	}

	std::wstring CFunctions::GetProcessCommandLine(bool bPassFirstArg)
	{
		std::wstring wstOutput = L"";

		int iArgCount = 0;
		const auto wcArgs = g_winAPIs->CommandLineToArgvW(g_winAPIs->GetCommandLineW(), &iArgCount);
		if (!iArgCount)
			return wstOutput;

		for (int i = bPassFirstArg ? 1 : 0; i < iArgCount; ++i)
		{
			std::wstring wstArgLaunch = wcArgs[i];
			if (wstArgLaunch.empty())
				continue;

			wstOutput += wstArgLaunch;
			wstOutput += L" ";
		}

		return wstOutput;
	}

	std::wstring CFunctions::GetNoMercyHashList()
	{
		auto container = std::map <std::wstring, std::wstring>();

		auto add_file = [&](const std::wstring& filename) {
			if (std::filesystem::exists(filename))
				container.emplace(filename, NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(filename));
			else
				container.emplace(filename, xorstr_(L"<not_exist>"));
		};

		add_file(NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFullName());
		container.emplace(xorstr_(L"version"), stdext::to_wide(xorstr_(__PRODUCT_VERSION__)));
		container.emplace(xorstr_(L"build"), FixedBuildDate());
		add_file(GAME_DATA_FILENAME);
		add_file(CHEAT_DB_FILENAME);
		add_file(FILE_DB_FILENAME);
		add_file(HB_PUB_KEY_FILENAME);

		GenericStringBuffer<UTF16<> > s;
		Writer <GenericStringBuffer<UTF16<> >> writer(s);

		writer.StartObject();
		for (const auto& [key_w, value_w] : container)
		{
			const auto key = stdext::to_ansi(key_w);
			const auto value = stdext::to_ansi(value_w);

			writer.Key(key.c_str());
			writer.String(value.c_str());
		}
		writer.EndObject();

		std::wostringstream oss;
		oss << std::setw(4) << s.GetString() << std::endl;
		return oss.str();
	}

	bool CFunctions::IsMainWindow(HWND hWnd)
	{
		if (g_winAPIs->IsWindowVisible(hWnd))
			return (g_winAPIs->GetWindow(hWnd, GW_OWNER) == (HWND)0);
		return false;
	}

	HWND CFunctions::GetFirstWindow(DWORD dwProcessID)
	{
		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return nullptr;
		}

		const auto vWindows = windowEnumerator->EnumerateWindows(dwProcessID);
		if (vWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Can not found any window for: %u", dwProcessID);
			return nullptr;
		}

		for (const auto& hWnd : vWindows)
		{
			if (g_winAPIs->IsWindowVisible(hWnd))
			{
				return hWnd;
			}
		}
		return nullptr;
	}

	HWND CFunctions::GetMainWindow(DWORD dwProcessID)
	{
		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return nullptr;
		}

		const auto vWindows = windowEnumerator->EnumerateWindows(dwProcessID);
		if (vWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Can not found any window for: %u", dwProcessID);
			return nullptr;
		}

		for (const auto& hWnd : vWindows)
		{
			if (g_winAPIs->IsWindowVisible(hWnd))
			{
#ifdef _DEBUG
				wchar_t wszTitle[MAX_PATH]{ L'\0' };
				g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);
				if (wcsstr(wszTitle, L"debug "))
					continue;
#endif

				if (IsMainWindow(hWnd))
					return hWnd;
			}
		}
		return nullptr;
	}

	std::wstring CFunctions::GetMainWindowTitle(DWORD dwProcessID)
	{
		std::wstring wstOutput = L"";

		const auto windowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(windowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"windowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return wstOutput;
		}

		const auto vWindows = windowEnumerator->EnumerateWindows(dwProcessID);
		if (vWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Can not found any window for: %u", dwProcessID);
			return wstOutput;
		}

		wchar_t wszTitle[MAX_PATH]{ L'\0' };
		for (const auto& hWnd : vWindows)
		{
			if (g_winAPIs->IsWindowVisible(hWnd))
			{
				g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);

				if (IsMainWindow(hWnd) && wszTitle)
				{
					wstOutput = wszTitle;
					break;
				}
			}
		}
		return wstOutput;
	}
};
