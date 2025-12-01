#include "../include/PCH.hpp"
#include "../include/Application.hpp"
#include "../include/ExitHelper.hpp"
#include "../include/WinVerHelper.hpp"
#include "../include/Elevation.hpp"
#include "../include/SafeExecutor.hpp"

// DISABLED FOR DUE THAN RAM USAGE
// #define LOAD_MODULE_SYMBOLS

namespace NoMercyCore
{
	extern bool __CheckIATHooks(HMODULE hModule);
	extern bool __CheckEATHooks(HMODULE hModule);

	DWORD __GetProcessParentProcessId(DWORD dwMainProcessId)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return 0;
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				if (pe.th32ProcessID == dwMainProcessId)
				{
					g_winAPIs->CloseHandle(hSnap);
					return pe.th32ParentProcessID;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hSnap);
		return 0;
	}
	std::wstring __GetProcessNameFromProcessId(DWORD dwProcessId)
	{
		if (!dwProcessId)
			return {};

		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!IS_VALID_HANDLE(hSnap))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot fail! Error: %u", g_winAPIs->GetLastError());
			return {};
		}

		PROCESSENTRY32W pe{ 0 };
		pe.dwSize = sizeof(pe);

		if (g_winAPIs->Process32FirstW(hSnap, &pe))
		{
			do {
				if (dwProcessId == pe.th32ProcessID)
				{
					const auto wstCurrProcessName = stdext::to_lower_wide(pe.szExeFile);

					g_winAPIs->CloseHandle(hSnap);
					return wstCurrProcessName;
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Process32NextW(hSnap, &pe));
		}

		g_winAPIs->CloseHandle(hSnap);
		return {};
	}

	inline std::wstring __GetTimeStr()
	{
		const auto fnGetTime = LI_FN(GetLocalTime).forwarded_safe();
		if (!fnGetTime)
			return {};

		SYSTEMTIME sysTime{ 0 };
		fnGetTime(&sysTime);

		wchar_t wszTimeBuf[1024 * 2]{ L'\0' };
		_snwprintf_s(
			wszTimeBuf, sizeof(wszTimeBuf) / sizeof(*wszTimeBuf), 
			xorstr_(L"%02d-%02d-%02d_%02d-%02d-%d"),
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wDay, sysTime.wMonth, sysTime.wYear
		);
		return wszTimeBuf;
	}
	inline DWORD __GetLastError()
	{
		static const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe();
		if (!fnGetLastError)
			return ERROR_NOT_FOUND;

		return fnGetLastError();
	}

	// cotr & dotr
	CApplication::CApplication(const uint8_t nAppType, const HINSTANCE hInstance, LPCVOID c_lpModuleInfo) :
		m_nAppType(nAppType), m_hInstance(hInstance), m_lpModuleInfo(c_lpModuleInfo), m_bInitialized(false), m_bEnableLogCollector(false), m_bLogCollectorCompleted(false),
		m_bShutdownBlockInitialized(false), m_fnOnFatalError(nullptr), m_nInitErrCode(0), m_nInitErrSubCode(0)
	{
		m_nStartTimestamp = stdext::get_current_epoch_time();
	}
	CApplication::~CApplication()
	{
	}

	// Shutdown handlers
	void __OnFatalError(int32_t signal)
	{
#ifdef _DEBUG
		if (IsDebuggerPresent())
			__debugbreak();
#endif

		if (gs_abShuttingDown.load())
			return;
		gs_abShuttingDown.store(true);

		if (stdext::is_debug_env() && signal == SIGABRT)
			return;

//		if (signal != -5) // do not send sentry logs for new() exceptions
		{
			if (CApplication::InstancePtr())
				CApplication::Instance().InvokeFatalErrorCallback();
		}
		
		if (signal != -3) // do not log purecall, it's stuck on console log
		{
			APP_TRACE_LOG(LL_CRI, L"Fatal error: %d", signal);
		}
		
		CMiniDump::TriggerSEH(signal);
	}

	static BOOL WINAPI __OnHandleConsoleInput(DWORD signal)
	{
		APP_TRACE_LOG(LL_CRI, L"Console signal: %u handled", signal);

		const auto c_nAppType = CApplication::Instance().GetAppType();
		if (c_nAppType == NM_STANDALONE)
			return TRUE;

#ifdef _DEBUG
		if (IsDebuggerPresent())
			return TRUE;
#endif

		switch (signal)
		{
			case CTRL_C_EVENT:
			case CTRL_BREAK_EVENT:
			case CTRL_CLOSE_EVENT:
			{
				__OnFatalError(100 + signal);
			} break;

			default:
				break;
		}

		return TRUE;
	}
	static void __OnHandleInterrupt(int signal)
	{
		APP_TRACE_LOG(LL_CRI, L"System signal: %d handled", signal);

		__OnFatalError(signal);
	}
	static void __cdecl __OnHandleTerminate(void)
	{
		APP_TRACE_LOG(LL_CRI, L"Terminate detected!");

		__OnFatalError(-1);
	}
	static void __cdecl __OnHandleUnexpected(void)
	{
		APP_TRACE_LOG(LL_CRI, L"Unexpected detected!");

		__OnFatalError(-2);
	}
	static void __OnHandlePureCall(void)
	{
//		APP_TRACE_LOG(LL_CRI, L"Pure call detected!");

		__OnFatalError(-3);
	}
	static void __OnHandleInvalidParameter(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t)
	{
		APP_TRACE_LOG(LL_CRI, L"Invalid parameter detected in function: %ls File: %ls:%u Expression: %ls", function, file, line, expression);
	
		__OnFatalError(-4);
	}
	static int __cdecl __OnHandleCrtNewException(size_t param)
	{
		APP_TRACE_LOG(LL_CRI, L"New exception detected! Param: %p", param);

		__OnFatalError(-5);
		return 0;
	}
	static int __OnHandleRtcError(int errorType, const wchar_t* filename, int linenumber, const wchar_t* moduleName, const wchar_t* format, ...)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (IsDebuggerPresent())
			__debugbreak();

		va_list vaArgList;
		va_start(vaArgList, format);

		static auto s_cbBufferSize = 0x1000;

		const auto dwFormatSize = _vscwprintf(format, vaArgList) + 1;
		if (dwFormatSize > s_cbBufferSize)
		{
			s_cbBufferSize = dwFormatSize + 0x100;
		}

		const auto lpwszBuffer = static_cast<wchar_t*>(calloc(s_cbBufferSize, sizeof(wchar_t)));
		if (!lpwszBuffer)
		{
			const auto err = errno;
			const auto c_stBuffer = fmt::format(xorstr_(L"Memory allocation failed for log operation! Last error: {0}"), err);
			APP_TRACE_LOG(LL_CRI, L"%s", c_stBuffer.c_str());
			std::abort();
		}

		const auto cbBufferLength = _vsnwprintf_s(lpwszBuffer, s_cbBufferSize, s_cbBufferSize - 1, format, vaArgList);
		if (cbBufferLength < 0)
		{
			const auto err = errno;
			const auto c_stBuffer = fmt::format(xorstr_(L"_vsnprintf_s returned with negative value. Last error: {0} Length: {1}"), err, cbBufferLength);
			APP_TRACE_LOG(LL_CRI, L"%s", c_stBuffer.c_str());
			std::abort();
		}

		LogfW(CUSTOM_LOG_FILENAME_W, L"RTC failure detected! Type: %d At: %s (%d) In: %s Message: %s", errorType, filename, linenumber, moduleName, lpwszBuffer);

		free(lpwszBuffer);
		va_end(vaArgList);	
#endif
		
		APP_TRACE_LOG(LL_CRI, L"RTC failure detected! Type: %d At: %s (%d) In: %s", errorType, filename, linenumber, moduleName);

		__OnFatalError(-6);
		return 1;
	}

	// Exit handlers
	inline void __OnExitEx(uint32_t id)
	{
		if (gs_abExitHandled)
			return;
		gs_abExitHandled = true;

#ifdef _DEBUG
		LogfW(CUSTOM_LOG_FILENAME_W, L"Exit handled! ID: %u", id);
#endif

		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().LogHelperInstance())
			NoMercyCore::CApplication::Instance().LogHelperInstance()->Release();
	}

	static int __cdecl __OnExit()
	{
		__OnExitEx(1);
		return 0;
	}
	static void __AtExit()
	{
		__OnExitEx(2);
	}

	void CApplication::__InitializeShutdownWatcher()
	{
		if (!stdext::is_debug_env())
		{
			// Exit handler
			onexit(&__OnExit);
			std::atexit(&__AtExit);

			// Crash handler
			std::set_terminate(&__OnHandleTerminate);
			set_unexpected(&__OnHandleUnexpected);

			_set_purecall_handler(&__OnHandlePureCall);
			// _set_invalid_parameter_handler(&__OnHandleInvalidParameter);

			_RTC_SetErrorFuncW(&__OnHandleRtcError);
		}

		// Change memory allocation mode
//		_set_new_mode(1); // Force malloc() to call new handler too
//		_set_new_handler(&__OnHandleCrtNewException);

		// Signal handlers
#ifdef _DEBUG
		if (!IsDebuggerPresent())
#endif
		{
			std::signal(SIGINT, &__OnHandleInterrupt);
			std::signal(SIGILL, &__OnHandleInterrupt);
			std::signal(SIGFPE, &__OnHandleInterrupt);
			std::signal(SIGSEGV, &__OnHandleInterrupt);
			std::signal(SIGTERM, &__OnHandleInterrupt);
			std::signal(SIGBREAK, &__OnHandleInterrupt);
			std::signal(SIGABRT, &__OnHandleInterrupt);
		}

		// ConIO handler
#ifdef _DEBUG
		SetConsoleCtrlHandler(&__OnHandleConsoleInput, TRUE);
#endif

		const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe();
		if (fnGetLastError)
		{
			// Heap exception
			const auto fnHeapSetInformation = LI_FN(HeapSetInformation).forwarded_safe();
			if (fnHeapSetInformation)
			{
				if (!fnHeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0))
				{
					const auto stBuffer = fmt::format(xorstr_(L"fnHeapSetInformation failed with error: {0}"), fnGetLastError());
					LogfW(CUSTOM_LOG_FILENAME_W, stBuffer.c_str());
				}
			}

			// DEP policy
			const auto fnSetProcessDEPPolicy = LI_FN(SetProcessDEPPolicy).forwarded_safe();
			if (fnSetProcessDEPPolicy)
			{
				if (!fnSetProcessDEPPolicy(PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION))
				{
					const auto dwError = fnGetLastError();
					if (dwError != ERROR_ACCESS_DENIED)
					{
						const auto stBuffer = fmt::format(xorstr_(L"fnSetProcessDEPPolicy failed with error: {0}"), fnGetLastError());
						LogfW(CUSTOM_LOG_FILENAME_W, stBuffer.c_str());
					}
				}
			}

			/*
			if (stdext::is_wow64())
			{
				// The following code is intended to fix the issue with 32-bit applications WndProc crash in 64-bit environment.
				// https://web.archive.org/web/20121130012357/http://blog.paulbetts.org/index.php/2010/07/20/the-case-of-the-disappearing-onload-exception-user-mode-callback-exceptions-in-x64/
				// https://web.archive.org/web/20190228152721/https://support.microsoft.com/en-us/help/976038/exceptions-that-are-thrown-from-an-application-that-runs-in-a-64-bit-v
				const auto hKernel32 = (HMODULE)LI_MODULE("kernel32.dll").safe();
				if (hKernel32)
				{
					const auto fnGetProcAddress = LI_FN(GetProcAddress).forwarded_safe();
					if (fnGetProcAddress)
					{
						const auto fnSetProcessUserModeExceptionPolicy = (WinAPI::TSetProcessUserModeExceptionPolicy)fnGetProcAddress(hKernel32, xorstr_(L"SetProcessUserModeExceptionPolicy"));
						const auto fnGetProcessUserModeExceptionPolicy = (WinAPI::TGetProcessUserModeExceptionPolicy)fnGetProcAddress(hKernel32, xorstr_(L"GetProcessUserModeExceptionPolicy"));

						if (fnSetProcessUserModeExceptionPolicy && fnGetProcessUserModeExceptionPolicy)
						{
							DWORD dwFlags = 0;
							if (fnGetProcessUserModeExceptionPolicy(&dwFlags))
							{
								if (!fnSetProcessUserModeExceptionPolicy(dwFlags & ~PROCESS_CALLBACK_FILTER_ENABLED))
								{
									const auto stBuffer = fmt::format(xorstr_(L"fnSetProcessUserModeExceptionPolicy failed with error: {0}"), fnGetLastError());
									SEND_TELEMETRY_LOG_SHADOW(LL_ERR, LT_RING3_CORE, stBuffer);
									LogfW(CUSTOM_LOG_FILENAME_W, stBuffer.c_str());
								}
							}
							else
							{
								const auto stBuffer = fmt::format(xorstr_(L"fnGetProcessUserModeExceptionPolicy failed with error: {0}"), fnGetLastError());
								SEND_TELEMETRY_LOG_SHADOW(LL_ERR, LT_RING3_CORE, stBuffer);
								LogfW(CUSTOM_LOG_FILENAME_W, stBuffer.c_str());
							}
						}
					}
				}
			}
			*/
		}
	}

	bool CApplication::Initialize()
	{
		// Check is already initialized
		if (m_bInitialized)
			return false;

#ifdef _DEBUG
		const auto stDebugInitBuffer = fmt::format(
			"Core initilization started for: Application: {0} Process: {1} NoMercy V{2}({3}-{4}) T{5}\n",
			m_nAppType, HandleToUlong(NtCurrentProcessId()), __PRODUCT_VERSION__, __DATE__, __TIME__, TEST_MODE ? 1 : 0
		);
		LogfA(CUSTOM_LOG_FILENAME_A, "%s", stDebugInitBuffer.c_str());
#endif

		// Create log folder path name
#ifdef _DEBUG
		const std::wstring wstLogPath = xorstr_(L"Log");
#else
		auto wstLogPath = stdext::to_lower_wide(std::filesystem::current_path().wstring());
		if (wstLogPath.find(xorstr_(L"\\nomercy")) == std::wstring::npos)
		{
			wstLogPath = fmt::format(xorstr_(L"{0}\\NoMercy\\Log"), wstLogPath);

			const auto wstBasePath = fmt::format(xorstr_(L"{0}\\NoMercy"), std::filesystem::current_path().wstring());
			std::error_code ec{};
			if (!std::filesystem::exists(wstBasePath, ec))
				std::filesystem::create_directory(wstBasePath, ec);
		}
		else
		{
			wstLogPath = fmt::format(xorstr_(L"{0}\\Log"), wstLogPath);
		}
#endif

		// Create logger filename
		const auto c_wstLoggerFileName = fmt::format(xorstr_(L"{0}\\NoMercy_{1}_{2}_v{3}_{4}.log"),
			wstLogPath, m_nAppType, HandleToUlong(NtCurrentProcessId()), __NOMERCY_VERSION__, __GetTimeStr()
		);
		LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Log file: %s initializing...\n"), c_wstLoggerFileName.c_str());

		// Allocate instances
		auto nInstanceErrCode = 0;

		m_spLogHelper			= stdext::make_shared_nothrow<CLogHelper>(m_nAppType, c_wstLoggerFileName);
		m_spWinAPIManager		= stdext::make_shared_nothrow<CWinAPIManager>();
		m_spFunctions			= stdext::make_shared_nothrow<CFunctions>();
		m_spDirFuncs			= stdext::make_shared_nothrow<CDirFunctions>();
		m_spInitilizationMgr	= stdext::make_shared_nothrow<CInitilizationManager>();
		m_spCryptoFuncs			= stdext::make_shared_nothrow<CCryptFunctions>();
		m_spDataManager			= stdext::make_shared_nothrow<CData>();
		m_spScreenshotManager	= stdext::make_shared_nothrow<CScreenshotMgr>();
		m_spWMIHelper			= stdext::make_shared_nothrow<CWMIHelper>();
		m_spHWIDManager			= stdext::make_shared_nothrow<CHwidManager>();
		m_spErrMsgHelper		= stdext::make_shared_nothrow<CErrorMessageHelper>();
		m_spSentryManager		= stdext::make_shared_nothrow<CSentryManager>();

		m_upMiniDumpHelper		= stdext::make_unique_nothrow<CMiniDump>();

		// Validate instances
		if (!IS_VALID_SMART_PTR(m_spLogHelper) || !CLogHelper::InstancePtr())
			nInstanceErrCode = 1;
		else if (!IS_VALID_SMART_PTR(m_spWinAPIManager) || !CWinAPIManager::InstancePtr())
			nInstanceErrCode = 2;
		else if (!IS_VALID_SMART_PTR(m_spFunctions) || !CFunctions::InstancePtr())
			nInstanceErrCode = 3;
		else if (!IS_VALID_SMART_PTR(m_spDirFuncs) || !CDirFunctions::InstancePtr())
			nInstanceErrCode = 4;
		else if (!IS_VALID_SMART_PTR(m_spInitilizationMgr) || !CInitilizationManager::InstancePtr())
			nInstanceErrCode = 5;
		else if (!IS_VALID_SMART_PTR(m_spCryptoFuncs) || !CCryptFunctions::InstancePtr())
			nInstanceErrCode = 6;
		else if (!IS_VALID_SMART_PTR(m_spDataManager) || !CData::InstancePtr())
			nInstanceErrCode = 7;
		else if (!IS_VALID_SMART_PTR(m_spScreenshotManager) || !CScreenshotMgr::InstancePtr())
			nInstanceErrCode = 8;
		else if (!IS_VALID_SMART_PTR(m_spWMIHelper) || !CWMIHelper::InstancePtr())
			nInstanceErrCode = 9;
		else if (!IS_VALID_SMART_PTR(m_spHWIDManager) || !CHwidManager::InstancePtr())
			nInstanceErrCode = 10;
		else if (!IS_VALID_SMART_PTR(m_spErrMsgHelper) || !CErrorMessageHelper::InstancePtr())
			nInstanceErrCode = 11;
		else if (!IS_VALID_SMART_PTR(m_spSentryManager) || !CSentryManager::InstancePtr())
			nInstanceErrCode = 12;
		else if (!IS_VALID_SMART_PTR(m_upMiniDumpHelper))
			nInstanceErrCode = 13;

		if (nInstanceErrCode)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Instance: {0} allocation failed for application: {1} Error: {2}"), nInstanceErrCode, m_nAppType, errno);

			m_nInitErrCode = PREPARE_ERROR_INSTANCE_ALLOC_FAIL;
			m_nInitErrSubCode = nInstanceErrCode;
			
			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		// Simple debug functions for basic stuffs and possible memory leak analysis
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (IS_VALID_SMART_PTR(m_spFunctions))
			m_spFunctions->OpenConsoleWindow();

		_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
		_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
		
		auto hMemLeakLogFile = CreateFileW(xorstr_(L"NoMercyMemLeaks.log"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!IS_VALID_HANDLE(hMemLeakLogFile))
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Failed to create memory leak log file: {0}"), errno);		
			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());

			_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
			_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
			_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
		}
		else
		{
			_CrtSetReportFile(_CRT_ASSERT, hMemLeakLogFile);
			_CrtSetReportFile(_CRT_ERROR, hMemLeakLogFile);
			_CrtSetReportFile(_CRT_WARN, hMemLeakLogFile);
		}

//		if (!m_bUnitTest)
			_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_CRT_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

#ifdef LOAD_MODULE_SYMBOLS
		SymInitialize(GetCurrentProcess(), 0, true);
		SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
#endif
		
		SymInitialize(NtCurrentProcess(), nullptr, true);

		// Initialize early anti debugger checks
		auto nDebuggerIdx = 0;
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		const auto pPEB = NtCurrentPeb();
		if (pPEB && pPEB->BeingDebugged)
		{
			nDebuggerIdx = 1;
		}
		else if (pPEB && pPEB->NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
		{
			nDebuggerIdx = 2;
		}
#endif
		if (nDebuggerIdx)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Core initilization internal error: {0} for application: {1}"), nDebuggerIdx, m_nAppType);

			m_nInitErrCode = PREPARE_ERROR_EARLY_DEBUGGER_DETECT;
			m_nInitErrSubCode = nDebuggerIdx;
			
			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		// Initialize abnormal termination handlers
		__InitializeShutdownWatcher();

		// Initialize miniump handler
		if (!m_upMiniDumpHelper->InitMiniDumpHandler())
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Mini dump handler initilization failed for application: {0}"), m_nAppType);

			m_nInitErrCode = PREPARE_ERROR_MINIDUMP_HANDLER_INIT_FAIL;
			m_nInitErrSubCode = __GetLastError();

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}
		
		// Anti emulation
		const auto nEmulatorIdx = __InitializeAntiEmulation();
		if (nEmulatorIdx)
		{
#ifdef __EXPERIMENTAL__
			const auto c_stBuffer = fmt::format(xorstr_(L"Self protection initilization failed for application: {0} Error: {1}"), m_nAppType, nEmulatorIdx);

			m_nInitErrCode = PREPARE_ERROR_ANTI_EMULATION_INIT_FAIL;
			m_nInitErrSubCode = nEmulatorIdx;

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
#else
			m_spDataManager->SetDetectedEmulatorID(nEmulatorIdx);
#endif
		}

		// Create log folder
		std::error_code ec;
		if (!std::filesystem::exists(wstLogPath, ec) && !std::filesystem::create_directories(wstLogPath, ec))
		{
			const auto c_wstBuffer = fmt::format(xorstr_(L"Log folder create failed with error: {0} ('{1}')"), ec.value(), stdext::to_wide(ec.message()));

			m_nInitErrCode = PREPARE_ERROR_LOG_FOLDER_CREATE_FAIL;
			m_nInitErrSubCode = ec.value();
		
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"%s"), c_wstBuffer.c_str());
			return false;
		}

		// Initialize instances
		m_spDataManager->SetMainThreadId(HandleToUlong(NtCurrentThreadId()));
		m_spDataManager->SetAppType(m_nAppType);
		m_spDataManager->SetNoMercyVersion(__NOMERCY_VERSION__);

		if (!m_spLogHelper->Initialize())
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Logger initilization failed for application: {0} Error: {1}"), m_nAppType, errno);

			m_nInitErrCode = PREPARE_ERROR_LOGGER_INIT_FAIL;
			m_nInitErrSubCode = errno;
	
			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		const auto stAppTypeName = GetAppTypeNameW(m_nAppType);
		const auto stOSInfo = GetWindowsInfoString();
		const auto stNGVersion = stdext::to_wide(__PRODUCT_VERSION__);
		const auto stBuildDate = stdext::to_wide(__DATE__);
		const auto stBuildTime = stdext::to_wide(__TIME__);

		APP_TRACE_LOG(LL_SYS, L"Log engine initialized for Application: %u (%s) PID: %u NoMercy V%s(%s-%s) T%d OS: %s CWD: %s",
			m_nAppType, stAppTypeName.c_str(), HandleToUlong(NtCurrentProcessId()), stNGVersion.c_str(), stBuildDate.c_str(), 
			stBuildTime.c_str(), TEST_MODE ? 1 : 0, stOSInfo.c_str(), std::filesystem::current_path().wstring().c_str()
		);

		if (!m_spWinAPIManager->Initialize())
		{
			APP_TRACE_LOG(LL_CRI, L"WinAPI Manager initilization failed for application: %u", m_nAppType);

			m_nInitErrCode = PREPARE_ERROR_WINAPI_MANAGER_INIT_FAIL;
			m_nInitErrSubCode = __GetLastError();
			
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"WinAPI Manager succesfully initialized!");

		CMiniDump::RegisterMiniDumpCallback([](bool bSuccess, int nReqID, std::wstring wstDumpFile) {
			// Message box
			auto wstBuffer = fmt::format(xorstr_(L"Fatal error!!!\nApplication crash detected!\nID: {0}"), nReqID);
			if (bSuccess)
				wstBuffer += fmt::format(xorstr_(L"\nPlease send the crash dump file to the game staff;\n\nCrash dump: {0}"), wstDumpFile);
			else
				wstBuffer += std::wstring(xorstr_(L"\nCrash dump file create failed!"));

			ServiceMessageBox(xorstr_(L"NoMercy"), wstBuffer.c_str(), MB_ICONERROR);
		});

		const auto dwParentPID = __GetProcessParentProcessId(g_winAPIs->GetCurrentProcessId());
		const auto wstParentName = __GetProcessNameFromProcessId(dwParentPID);

		DWORD dwSessionID = 0;
		if (!g_winAPIs->ProcessIdToSessionId(g_winAPIs->GetCurrentProcessId(), &dwSessionID))
			dwSessionID = -1;

		APP_TRACE_LOG(LL_SYS, L"Parent process: %u (%s) SID: %u", dwParentPID, wstParentName.c_str(), dwSessionID);

		if (!m_spSentryManager->Initialize())
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"Sentry initilization failed for application: {0}"), m_nAppType);

			m_nInitErrCode = PREPARE_ERROR_SENTRY_INIT_FAIL;
			m_nInitErrSubCode = __GetLastError();

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Sentry succesfully initialized!");

		DWORD dwUserNameLen = 256;
		wchar_t wszUserName[256]{ L'\0' };
		DWORD dwHostNameLen = 256;
		wchar_t wszHostName[256]{ L'\0' };
		if (g_winAPIs->GetUserNameW(wszUserName, &dwUserNameLen) && g_winAPIs->GetComputerNameW(wszHostName, &dwHostNameLen))
		{
			APP_TRACE_LOG(LL_SYS, L"Username: '%s' PC name: '%s'", wszUserName, wszHostName);

			const auto wstLowerUserName = stdext::to_lower_wide(wszUserName);
			const auto wstLowerPCName = stdext::to_lower_wide(wszHostName);

			std::vector <std::tuple <std::wstring /* wstUsername */, std::wstring /* wstPCName */>> vecAdminEnvs;
			vecAdminEnvs.emplace_back(std::make_tuple(xorstr_(L"user"), xorstr_(L"pc")));

			for (const auto& [wstCurrUser, wstCurrPC] : vecAdminEnvs)
			{
				const std::wstring wstSystemUser = xorstr_(L"system");
				if (((wstCurrUser == wstLowerUserName || wstLowerUserName == wstSystemUser) && wstCurrPC == wstLowerPCName) ||
					stdext::is_debug_env())
				{
					APP_TRACE_LOG(LL_SYS, L"Authorized environment found!");

					if (g_winAPIs->PathFileExistsW(xorstr_(L"C:\\NM_ADMIN")) || stdext::is_debug_env())
					{
						APP_TRACE_LOG(LL_SYS, L"Admin identify file found!");
						m_spDataManager->SetAdminEnvironment(true);
					}
					else
					{
						APP_TRACE_LOG(LL_WARN, L"Admin identify file not found! Error: %u", g_winAPIs->GetLastError());
					}
				}
			}
		}

		if (!IsWindows7OrGreater())
		{
			APP_TRACE_LOG(LL_CRI, L"Unsupported OS: %u.%u(%u)", GetWindowsMajorVersion(), GetWindowsMinorVersion(), GetWindowsBuildNumber());

			m_nInitErrCode = PREPARE_ERROR_UNSUPPORTED_OS;
			m_nInitErrSubCode = GetWindowsBuildNumber();
			
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"OS version is supported!");

		if (!CElevationHelper::HasEnoughRights())
		{
			APP_TRACE_LOG(LL_CRI, L"Current user have not own to required rights!");

			m_nInitErrCode = PREPARE_ERROR_INSUFFICIENT_RIGHTS;
			m_nInitErrSubCode = __GetLastError();
				
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"System rights succesfully verified!");
		
		if (__CheckIATHooks(g_winModules->hBaseModule))
		{
			APP_TRACE_LOG(LL_CRI, L"IAT hooks detected!");

			m_nInitErrCode = PREPARE_ERROR_IAT_HOOKS_DETECTED;
				
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"IAT hook check succesfully completed!");
			
#ifdef _DEBUG
		if (__CheckEATHooks(g_winModules->hKernel32))
#else
		if (__CheckEATHooks(g_winModules->hBaseModule))
#endif
		{
			APP_TRACE_LOG(LL_CRI, L"EAT hooks detected!");

			m_nInitErrCode = PREPARE_ERROR_EAT_HOOKS_DETECTED;
				
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"EAT hook check succesfully completed!");

		const auto stNoMercyPath = fmt::format(xorstr_(L"{0}\\NoMercy"), m_spDirFuncs->CurrentPath());
		APP_TRACE_LOG(LL_SYS, L"NoMercy path: %s", stNoMercyPath.c_str());

		if (!m_spDirFuncs->IsDirExist(stNoMercyPath))
		{
			APP_TRACE_LOG(LL_CRI, L"NoMercy path: %s does not exist, error: %u", stNoMercyPath.c_str(), g_winAPIs->GetLastError());
			
			m_nInitErrCode = PREPARE_ERROR_NOMERCY_PATH_CREATE_FAIL;
			m_nInitErrSubCode = g_winAPIs->GetLastError();
			
			return false;
		}
		m_spInitilizationMgr->SetNoMercyPath(stNoMercyPath);

		m_spInitilizationMgr->LoadSplashImage(m_hInstance);

		uint8_t fail_step = 0;
		if (!m_spInitilizationMgr->LoadLocalizationFile(m_nAppType, m_hInstance, fail_step))
		{
			APP_TRACE_LOG(LL_CRI, L"Load localization file failed error: %u", fail_step);
			
			if (m_nAppType != NM_STANDALONE)
			{
				m_nInitErrCode = PREPARE_ERROR_LOCALIZATION_FILE_LOAD_FAIL;
				m_nInitErrSubCode = fail_step;
				
				return false;
			}
		}
		APP_TRACE_LOG(LL_SYS, L"Localization file succesfully loaded!");

		const auto stCurrPath = CDirFunctions::Instance().CurrentPath();
		const auto stExecutable = CDirFunctions::Instance().ExeNameWithPath();
		const auto stWinVer = GetWindowsInfoString();
		APP_TRACE_LOG(LL_SYS, L"Core engine is initialized! Environment: ('%s' - '%s') OS: %s",	stCurrPath.c_str(), stExecutable.c_str(), stWinVer.c_str());

		m_bInitialized = true;
		return true;
	}

	void CApplication::Finalize()
	{
		if (!m_bInitialized)
			return;
		m_bInitialized = false;

		gs_abShuttingDown = true;
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));

		if (CLogHelper::InstancePtr())
			CLogHelper::Instance().Release();

		if (CWinAPIManager::InstancePtr())
			CWinAPIManager::Instance().Release();

		if (IS_VALID_SMART_PTR(m_spDirFuncs)) {
			m_spDirFuncs.reset();
		}
		if (IS_VALID_SMART_PTR(m_spLogHelper)) {
			m_spLogHelper.reset();
		}
		if (IS_VALID_SMART_PTR(m_spWinAPIManager)) {
			m_spWinAPIManager.reset();
		}
		
		return;
	}
};
