#include "PCH.hpp"
#include "Index.hpp"
#include "Application.hpp"
#include "Core.hpp"
#include "Common/ExceptionHandlers.hpp"
#include "Common/Terminator.hpp"
#include "SelfProtection/SelfProtection.hpp"
#include "Anti/AntiMacro.hpp"
#include "Anti/AntiDebug.hpp"
#include "Window/WindowWatcher.hpp"
#include "Thread/ThreadStackWalker.hpp"
#include "../../Common/StdExtended.hpp"
#include "../../Common/SimpleTimer.hpp"
#include "../EngineR3_Core/include/Index.hpp"
#include "../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../EngineR3_Core/include/FileVersion.hpp"
#include "../EngineR3_Core/include/Pe.hpp"
#include "../EngineR3_Core/include/SafeExecutor.hpp"
#include "../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../EngineR3_Core/include/PEHelper.hpp"
#include "../EngineTLS/include/TLS.hpp"
#include <MinHook.h>

#ifdef _DEBUG
#define _dbreak\
	if (g_winAPIs->IsDebuggerPresent())\
		__debugbreak();\
	else if (NoMercyCore::CApplication::InstancePtr())\
		NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();\
	break;
#else
#define _dbreak break;
#endif

namespace NoMercy
{
	static constexpr auto gsc_nMaxLogFileSize = 10'000'000;

	extern void OnThreadAttached();
	void CApplication::OnThreadAttach(DWORD dwThreadID)
	{
		APP_TRACE_LOG(LL_TRACE, L"Thread attached: %u", dwThreadID);

		// OnThreadAttached();
	}
	
	// cotr & dotr
	CApplication::CApplication() :
		m_dwSessionID(0), m_abClientProcess(false), m_abAppIsPrepared(false), m_abAppIsInitiliazed(false), m_abFinalizeTriggered(false),
		m_abIsCloseTriggered(false), m_abWsConnIsReady(false), m_abNetworkReady(false), m_abHooksIntiailized(false),
		m_dwInitStatusCode((DWORD)-1), m_dwInitSubErrorCode(0), m_hTimerQueue(nullptr), m_hWsQueueProcessorTimer(nullptr),
		m_hWatchdogTimer(nullptr), m_hWsHeartbeatTimer(nullptr), m_abInitThreadCompleted(false)
	{
	}
	CApplication::~CApplication()
	{
	}

	bool CApplication::CreateWebsocketConnection()
	{
		auto ws = m_spNetworkMgr->GetWebSocketClient();

		if (!IS_VALID_SMART_PTR(ws) || !ws->IsInitialized())
		{
			const auto stAPIUri = stdext::to_ansi(API_SERVER_URI);
			if (!m_spNetworkMgr->InitializeWebSocketClient(stAPIUri, 0))
			{
				APP_TRACE_LOG(LL_CRI, L"Websocket client could not initialized");
				return false;
			}

			APP_TRACE_LOG(LL_SYS, L"Websocket client created!");

			if (!m_spNetworkMgr->GetWebSocketClient()->InitWebSocketThread())
			{
				APP_TRACE_LOG(LL_CRI, L"Websocket thread could not initialized");
				return false;
			}

			APP_TRACE_LOG(LL_SYS, L"Websocket client initialized!");
		}
		return true;
	}

	bool CApplication::__IsSentSentryLog(const std::wstring& c_stData)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		if (stdext::in_vector(m_vecSentSentryLogs, c_stData))
			return true;

		m_vecSentSentryLogs.emplace_back(c_stData);
		return false;
	}
	void CApplication::__OnLogMessageCreated(uint8_t c_nLevel, const std::wstring& c_wstData)
	{
		if (c_nLevel != LL_CRI)
			return;

		sentry_level_t nLevel = SENTRY_LEVEL_INFO;
		switch (c_nLevel)
		{
			case LL_SYS:
				nLevel = SENTRY_LEVEL_INFO;
				break;
			case LL_ERR:
				nLevel = SENTRY_LEVEL_ERROR;
				break;
			case LL_CRI:
				nLevel = SENTRY_LEVEL_FATAL;
				break;
			case LL_WARN:
				nLevel = SENTRY_LEVEL_WARNING;
				break;
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
#ifdef _DEBUG
			case LL_DEV:
#endif
#ifdef _RELEASE_DEBUG_MODE_
			case LL_TRACE:
#endif
				nLevel = SENTRY_LEVEL_DEBUG;
				break;
#endif
			default:
				break;
		}

		const std::vector <std::string> vecSkippedLogs = {
			xorstr_(" Step: 2 Status: 140 "), // service access lost
			xorstr_(" Step: 2 Status: 218 "), // secure boot
			xorstr_(" 447 "), // time change
			xorstr_(" 456 "), // telemetry client access lost
			xorstr_(" 459 "), // ws disconnect
			xorstr_("Service process access lost"),
			xorstr_("Telemetry process access lost"),
			xorstr_("Telemetry access lost to a client"),
			xorstr_("is not running! Service status"),
			xorstr_("Access lost to API server"),
			xorstr_("Access lost to updater window"),
			xorstr_("Websocket connection closed. Too many disconnections."),
			xorstr_("Internet connection is not available"),
			xorstr_("Zaman de"),
			xorstr_("Time change "),
			xorstr_("Exit notification packet could"),
			xorstr_("CPR internal error: 8"),
			xorstr_("'Outdated version'")
		};
		
		auto stData = stdext::to_ansi(c_wstData);
		for (const auto& stSkippedLog : vecSkippedLogs)
		{
			if (stData.find(stSkippedLog) != std::string::npos)
				return;
		}

		const auto vecSplittedData = stdext::split_string(stData, "|"s);
		// 1 | #43020 | NoMercy::CApplication::__OnCoreInitilizationFail | Core initilization failed! Step: 2 Status: 43 Sub: 8 SysErr: 0 App: 9
		if (vecSplittedData.size() == 4)
			stData = fmt::format(xorstr_("{0} :: {1}"), vecSplittedData[2], vecSplittedData[3]);
		// 1 | #14972 | NoMercy::CApplication::OnCloseRequest | TID: 14972 PID: 40464 | Close request handled. Code: 391 System error: 2 Param: 00000000 Silent: 0
		else if (vecSplittedData.size() == 5)
			stData = fmt::format(xorstr_("{0} :: {1}"), vecSplittedData[2], vecSplittedData[4]);
		/*
		 NoMercy::CApplication::OnCloseRequest  ::  Unknown error handled!

		App: 1(NM_CLIENT)
		Version: 1.19846 - Phase: 3
		Error ID: 351 System error: 0
		*/
		else if (stData.find(xorstr_("\n")) != std::string::npos && stData.find(xorstr_(" :: ")) != std::string::npos)
		{
			stData = stdext::replace(stData, std::string(xorstr_("\n")), std::string(xorstr_(" - ")));
			if (stData.size() == 5)
			{
				const auto vecSplittedData2 = stdext::split_string(stData, std::string(xorstr_(" - ")));
				if (vecSplittedData2.size() >= 2)
				{
					const auto vecSplittedData3 = stdext::split_string(vecSplittedData2.at(0), std::string(xorstr_(" :: ")));
					if (vecSplittedData3.size() >= 5)
					{
						stData = fmt::format(xorstr_("{0}:: {1}"), vecSplittedData2[0], vecSplittedData3[4]);
					}
				}
			}
		}

		if (CApplication::Instance().__IsSentSentryLog(c_wstData))
			return;
		
		// TODO: Send to datadog over REST or API server
		NoMercyCore::CApplication::Instance().GetSentryManagerInstance()->SendLog(nLevel, fmt::format(xorstr_("Client|V{0}"), xorstr_(__PRODUCT_VERSION__)), stData);
	}

	bool CApplication::__InitializeTestMode()
	{
		APP_TRACE_LOG(LL_SYS, L"Test mode initilization started!");

		// Priv
		BOOLEAN bAdjustPrivRet = FALSE;
		const auto ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bAdjustPrivRet);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlAdjustPrivilege fail! Ntstatus: %p", ntStatus);
		}

		// Routine
		__InitTestFunctions();

		m_dwInitStatusCode = INIT_STATUS_SUCCESS;
		return true;
	}

	bool CApplication::Initialize()
	{
		CStopWatch <std::chrono::milliseconds> kTimer;

		auto IsMappedPath = [](const char* szPathName) -> bool
		{
			auto GetType = [](int nDrive) -> UINT
			{
				auto GetRoot = [](int nDrive)
				{
					auto GetLetter = [](int nDrive)
					{
						assert(nDrive > 0 && nDrive <= 26);

						return (char)(nDrive + L'A' - 1);
					};
					
					std::wstring sRoot;
					sRoot = GetLetter(nDrive);
					sRoot += xorstr_(L":\\");

					return sRoot;
				};
				
				assert(nDrive > 0 && nDrive <= 26);

				// shortcut to avoid floppy access
				if (nDrive == 1 || nDrive == 2)
					return DRIVE_REMOVABLE;

				const auto stRoot = GetRoot(nDrive);
				return g_winAPIs->GetDriveTypeW(stRoot.c_str());
			};
			auto GetDrive = [](const char* szPathName) {
				int nDrive = 0;

				if (strstr(szPathName, ":") == szPathName + 1) {
					char cDrive = szPathName[0];
					cDrive = (char)toupper(cDrive);
					nDrive = cDrive - 64;
				}

				return nDrive ? nDrive : -1;
			};
			
			const auto nDrive = GetDrive(szPathName);
			if (nDrive <= 0)
				return false;

			return (GetType(nDrive) == DRIVE_REMOTE);
		};
		auto GetFileLastWriteTime = [](const std::wstring& stFileName, bool bCreateTime) {
			DWORD dwLastWriteTime = 0;
			auto hFile = g_winAPIs->CreateFileW(stFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (IS_VALID_HANDLE(hFile))
			{
				FILETIME lpCreationTime{};
				FILETIME lpLastAccessTime{};
				FILETIME lpLastWriteTime{};
				if (g_winAPIs->GetFileTime(hFile, &lpCreationTime, &lpLastAccessTime, &lpLastWriteTime))
				{
					FILETIME fileTime{};
					FILETIME localFileTime{};

					if (bCreateTime)
					{
						fileTime.dwLowDateTime = lpCreationTime.dwLowDateTime;
						fileTime.dwHighDateTime = lpCreationTime.dwHighDateTime;
					}
					else
					{
						fileTime.dwLowDateTime = lpLastWriteTime.dwLowDateTime;
						fileTime.dwHighDateTime = lpLastWriteTime.dwHighDateTime;
					}
					g_winAPIs->FileTimeToLocalFileTime(&fileTime, &localFileTime);

					SYSTEMTIME SystemTime{};
					g_winAPIs->FileTimeToSystemTime(&localFileTime, &SystemTime);

					tm timeinfo{};
					timeinfo.tm_year = SystemTime.wYear - 1900;
					timeinfo.tm_mon = SystemTime.wMonth - 1;
					timeinfo.tm_mday = SystemTime.wDay;
					timeinfo.tm_hour = SystemTime.wHour;
					timeinfo.tm_min = SystemTime.wMinute;
					timeinfo.tm_sec = SystemTime.wSecond;
					
					dwLastWriteTime = (DWORD)mktime(&timeinfo);
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"GetFileTime failed with error: %u", g_winAPIs->GetLastError());
				}

				g_winAPIs->CloseHandle(hFile);
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileA failed with error: %u", g_winAPIs->GetLastError());
			}
			return dwLastWriteTime;
		};
		auto DumpAntiVirusInfo = []() -> std::wstring {
			if (!NoMercyCore::CApplication::Instance().WMIHelperInstance()->CheckWMIIntegirty())
			{
				APP_TRACE_LOG(LL_ERR, L"WMI integrity corrupted");
				return {};
			}

			const auto vTypeAndQueries = std::vector <std::tuple <std::wstring, std::wstring, std::wstring>>{
				{ xorstr_(L"av"),		xorstr_(L"ROOT\\SecurityCenter"),	xorstr_(L"SELECT * FROM AntiVirusProduct")		},
				{ xorstr_(L"fw"),		xorstr_(L"ROOT\\SecurityCenter"),	xorstr_(L"SELECT * FROM FirewallProduct")		},
				{ xorstr_(L"av2"),		xorstr_(L"ROOT\\SecurityCenter2"),	xorstr_(L"SELECT * FROM AntiVirusProduct")		},
				{ xorstr_(L"fw2"),		xorstr_(L"ROOT\\SecurityCenter2"),	xorstr_(L"SELECT * FROM FirewallProduct")		},
				{ xorstr_(L"aspy2"),	xorstr_(L"ROOT\\SecurityCenter2"),	xorstr_(L"SELECT * FROM AntiSpywareProduct")	}
			};

			std::wstring wstSimpleOutput;

			// Initialize rapidjson (pretty)writer
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			// Root object
			writer.StartObject();

			for (const auto& currDev : vTypeAndQueries)
			{
				const auto wstQueryType = std::get<0>(currDev);
				writer.String(wstQueryType.c_str());
				writer.StartObject();
				{
					uint32_t idx = 0;

					NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
						std::get<1>(currDev),
						std::get<2>(currDev),
						[&](std::map <std::wstring, std::wstring> container)
						{
							idx++;
							const auto stIndex = std::to_wstring(idx);
							writer.String(stIndex.c_str());

							writer.StartObject();
							for (const auto& [key, value] : container)
							{
								if (key == xorstr_(L"displayName"))
									wstSimpleOutput += fmt::format(xorstr_(L"[{0}]({1}){2}|"), idx, wstQueryType, value);
								
								writer.Key(key.c_str());
								writer.String(value.c_str());
							}
							writer.EndObject();
						}
					);
				}
				writer.EndObject();
			}

			// End root object
			writer.EndObject();

			if (wstSimpleOutput.size() > 0)
				CApplication::Instance().SetAntivirusInfo(wstSimpleOutput);

			// Create string output
			std::wostringstream oss;
			oss << std::setw(4) << s.GetString() << std::endl;
			return oss.str();
		};

		APP_TRACE_LOG(LL_SYS, L"Application initialize started! Working directory: %s", std::filesystem::current_path().wstring().c_str());

		// Core initilization
		auto bRet = false;

		const auto c_spAntiModule	= NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		const auto c_nAppType		= NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
		constexpr auto c_dwRequiredSize = 200 * 1000; // 200 MB

		// LogfA(CUSTOM_LOG_FILENAME_A, "Timer1: %u", kTimer.diff());

		do
		{
			APP_TRACE_LOG(LL_SYS, L"Application engine initilization started!");

			// Register log message handler
			NoMercyCore::CApplication::Instance().LogHelperInstance()->RegisterLogCallback(
				std::bind(&CApplication::__OnLogMessageCreated, this, std::placeholders::_1, std::placeholders::_2)
			);
			APP_TRACE_LOG(LL_SYS, L"Service message handler register step completed.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer2: %u", kTimer.diff());

			// Check date
			const auto stCurrentDate = stdext::get_current_date();
			if (stCurrentDate.empty())
			{
				APP_TRACE_LOG(LL_CRI, L"Failed to get current date");

				m_dwInitStatusCode = INIT_FATAL_GET_DATE_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Current date: %s", stCurrentDate.c_str());

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer3: %u", kTimer.diff());

			const auto nCurrentYearStartPos = stCurrentDate.find_last_of(xorstr_(L":"));
			const auto stCurrentYear = stCurrentDate.substr(nCurrentYearStartPos + 1);
			const auto nCurrentYear = stdext::str_to_u32(stCurrentYear);

			constexpr auto nBuildYear = stdext::get_current_year();
			APP_TRACE_LOG(LL_SYS, L"Current year: %u, Build year: %u", nCurrentYear, nBuildYear);

			if (nBuildYear != nCurrentYear && nBuildYear != nCurrentYear - 1)
			{
				APP_TRACE_LOG(LL_ERR, L"Current date is not valid");

				m_dwInitStatusCode = INIT_FATAL_CHECK_DATE_FAIL;
				_dbreak;
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer4: %u", kTimer.diff());

			APP_TRACE_LOG(LL_SYS, L"Current date is valid!");

			DWORD dwTimeAdjustment = 0, dwTimeIncrement = 0;
			BOOL bTimeAdjDisabled = FALSE;
			if (!g_winAPIs->GetSystemTimeAdjustment(&dwTimeAdjustment, &dwTimeIncrement, &bTimeAdjDisabled))
			{
				APP_TRACE_LOG(LL_ERR, L"GetSystemTimeAdjustment failed with error: %u", g_winAPIs->GetLastError());

				m_dwInitStatusCode = INIT_FATAL_QUERY_TIME_ADJ_FAIL;
				_dbreak;
			}

			APP_TRACE_LOG(LL_SYS, L"Time adjustment: %u, Time increment: %u, Time adjustment disabled: %d", dwTimeAdjustment, dwTimeIncrement, bTimeAdjDisabled);

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer5: %u", kTimer.diff());

			// Validate time
			if (bTimeAdjDisabled && g_winAPIs->W32TimeSyncNow)
			{
				wchar_t wszComputerName[1024]{ L'\0' };
				DWORD dwComputerNameSize = 1024;
				if (!g_winAPIs->GetComputerNameW(wszComputerName, &dwComputerNameSize))
				{
					APP_TRACE_LOG(LL_ERR, L"GetComputerNameW failed with error: %u", g_winAPIs->GetLastError());

					m_dwInitStatusCode = INIT_FATAL_QUERY_COMPUTER_NAME_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Computer name: %ls", wszComputerName);

				const auto ret = g_winAPIs->W32TimeSyncNow(wszComputerName, TRUE, WinAPI::TimeSyncFlag_UpdateAndResync);
				if (ret != ERROR_SUCCESS && ret != RPC_S_SERVER_UNAVAILABLE)
				{
					APP_TRACE_LOG(LL_WARN, L"W32TimeSyncNow failed with error: %u, %u", ret, g_winAPIs->GetLastError());

					m_dwInitStatusCode = INIT_FATAL_TIME_SYNC_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Time synchronized successfully!");
			}
			APP_TRACE_LOG(LL_SYS, L"Time is valid!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer6: %u", kTimer.diff());

			// Dump anti-virus info
			const auto stAntiVirusInfo = DumpAntiVirusInfo();
			APP_TRACE_LOG(LL_SYS, L"AntiVirus info: %s", stAntiVirusInfo.c_str());

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer7: %u", kTimer.diff());

			// Check free disk space
			wchar_t wszSystemPath[MAX_PATH]{ L'\0' };
			if (g_winAPIs->GetSystemDirectoryW(wszSystemPath, MAX_PATH))
			{
				DWORD dwSectPerClust = 0, dwBytesPerSect = 0, dwFreeClusters = 0, dwTotalClusters = 0;
				if (g_winAPIs->GetDiskFreeSpaceW(fmt::format(xorstr_(L"{0}:\\"), wszSystemPath[0]).c_str(), &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters))
				{
					auto qwFreeDisk = (uint64_t)dwFreeClusters * dwSectPerClust * dwBytesPerSect;
					qwFreeDisk /= 1024;

					APP_TRACE_LOG(LL_SYS, L"Free disk query completed! Available disk: %llu KB", qwFreeDisk);

					if (qwFreeDisk < c_dwRequiredSize)
					{
						m_dwInitStatusCode = INIT_ERR_INSUFFICIENT_DISK;
						break;
					}
				}
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer8: %u", kTimer.diff());

			// Check free memory
			MEMORYSTATUSEX memInfo{ sizeof(MEMORYSTATUSEX) };
			if (g_winAPIs->GlobalMemoryStatusEx(&memInfo))
			{
				const auto qwFreeRam = memInfo.ullAvailPhys / 1024;

				APP_TRACE_LOG(LL_SYS, L"Free memory query completed! Available memory: %llu KB", qwFreeRam);

				if (qwFreeRam < c_dwRequiredSize)
				{
					m_dwInitStatusCode = INIT_ERR_INSUFFICIENT_MEMORY;
					break;
				}
			}
			APP_TRACE_LOG(LL_SYS, L"Free memory check step completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer9: %u", kTimer.diff());

			// Check REST cert & key files exist
			std::error_code ec{};
			if (!std::filesystem::exists(REST_CERT_FILENAME, ec) || ec)
			{
				APP_TRACE_LOG(LL_ERR, L"REST cert file not found: %hs", REST_CERT_FILENAME);

				m_dwInitStatusCode = INIT_FATAL_REST_CERT_FILE_NOT_FOUND;
				m_dwInitSubErrorCode = 1;
				_dbreak;
			}
			else if (!std::filesystem::exists(REST_CERT_KEY_FILENAME, ec) || ec)
			{
				APP_TRACE_LOG(LL_ERR, L"REST key file not found: %hs", REST_CERT_KEY_FILENAME);

				m_dwInitStatusCode = INIT_FATAL_REST_CERT_FILE_NOT_FOUND;
				m_dwInitSubErrorCode = 2;
				_dbreak;
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer10: %u", kTimer.diff());

			/*
			// Validate anti-cheat module file
			if (IS_VALID_SMART_PTR(c_spAntiModule))
			{
				const auto wstAntiCheatModuleFile = std::wstring(c_spAntiModule->FullDllName.Buffer, c_spAntiModule->FullDllName.Length / sizeof(*c_spAntiModule->FullDllName.Buffer));
				APP_TRACE_LOG(LL_SYS, L"Anti-cheat module file: %s", wstAntiCheatModuleFile.c_str());

				if (!wstAntiCheatModuleFile.empty())
				{
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
					// Validate anti-cheat module certificate
					const auto obHasDriverCert = PeSignatureVerifier::HasValidFileCertificate(wstAntiCheatModuleFile);
					if (obHasDriverCert.has_value())
					{
						APP_TRACE_LOG(LL_SYS, L"Module has certificate check step completed!");

						if (!obHasDriverCert.value())
						{
							APP_TRACE_LOG(LL_ERR, L"Anti-cheat module file has invalid certificate");

							m_dwInitStatusCode = INIT_FATAL_ANTI_MODULE_INVALID_CERT;
							_dbreak;
						}
					}
					APP_TRACE_LOG(LL_SYS, L"Anti-cheat module file has valid certificate!");
#endif
				}
			}
			APP_TRACE_LOG(LL_SYS, L"Anti-cheat module file is valid!");
			*/

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer11: %u", kTimer.diff());

			// Set priority and privileges
			const auto bPriorityRet = g_winAPIs->SetPriorityClass(NtCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
			APP_TRACE_LOG(LL_SYS, L"Process adjust priority ret: %d", bPriorityRet);

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer12: %u", kTimer.diff());

			BOOLEAN bPrevStatus = FALSE;
			auto ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, true, false, &bPrevStatus);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_CRI, L"Shutdown privilege adjust failed with status: %p", ntStatus);

				m_dwInitStatusCode = INIT_FATAL_SHUTDOWN_PRIVILEGE_ADJUST_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Shutdown privilege adjust completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer13: %u", kTimer.diff());

			ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, true, false, &bPrevStatus);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_CRI, L"Environment privilege adjust failed with status: %p", ntStatus);

				m_dwInitStatusCode = INIT_FATAL_ENVIRONMENT_PRIVILEGE_ADJUST_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Environment privilege adjust completed!");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer14: %u", kTimer.diff());

			// Protection check
			if (NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->IsProcessProtected() == false)
			{
				APP_TRACE_LOG(LL_CRI, L"Protection check fail!");

				m_dwInitStatusCode = INIT_FATAL_PROTECTION_CHECK_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Process protection check completed.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer15: %u", kTimer.diff());

			// Early step simple anti debug check
			if (CAntiDebug::CheckPreAntiDebug() == false)
			{
				APP_TRACE_LOG(LL_CRI, L"Pre anti debug check fail!");

				m_dwInitStatusCode = INIT_FATAL_PRE_ANTI_DEBUG_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Pre Anti debug check completed.");

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer16: %u", kTimer.diff());

			// Early step simple anti emulator check
			const auto dwEmulatorIndex = NoMercyCore::CApplication::Instance().DataInstance()->GetDetectedEmulatorIndex();
			if (dwEmulatorIndex)
			{
				APP_TRACE_LOG(LL_CRI, L"Early check emulator detected: %u", dwEmulatorIndex);

				m_dwInitStatusCode = INIT_FATAL_EARLY_EMULATOR_DETECTED;
				m_dwInitSubErrorCode = dwEmulatorIndex;
				_dbreak;
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer17: %u", kTimer.diff());

			// Register current process session id
			if (!g_winAPIs->ProcessIdToSessionId(HandleToUlong(NtCurrentProcessId()), &m_dwSessionID))
			{
				APP_TRACE_LOG(LL_CRI, L"ProcessIdToSessionId failed with error: %u", g_winAPIs->GetLastError());
				
				m_dwInitStatusCode = INIT_FATAL_QUERY_SID_FAIL;
				_dbreak;
			}
			APP_TRACE_LOG(LL_SYS, L"Query SID step completed. Process working on SID: %u", m_dwSessionID);

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer18: %u", kTimer.diff());

			// Network share check
			std::map <std::wstring, HMODULE> mapModules;
			mapModules.emplace(xorstr_(L"anticheat"), (HMODULE)c_spAntiModule->DllBase);
			mapModules.emplace(xorstr_(L"process"), g_winModules->hBaseModule);
			
			for (const auto& [name, mod] : mapModules)
			{
				if (!mod)
				{
					APP_TRACE_LOG(LL_ERR, L"Module: '%s' does not exist!", name.c_str());
					continue;
				}

				wchar_t wszMappedName[MAX_PATH]{ L'\0' };
				const auto dwModuleNameSize = g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), mod, wszMappedName, MAX_PATH);
				if (!dwModuleNameSize)
				{
					APP_TRACE_LOG(LL_ERR, L"GetMappedFileNameW (%s) failed with error: %u", name.c_str(), g_winAPIs->GetLastError());
					continue;
				}
				const auto stMappedName = stdext::to_ansi(wszMappedName);
				const auto c_wstNormalizedName = CProcessFunctions::DosDevicePath2LogicalPath(wszMappedName);

				APP_TRACE_LOG(LL_SYS, L"Module: %s (%p) name query step completed. Name: %ls (%u) Normalized: %ls (%u) Last error: %u",
					name.c_str(), mod, wszMappedName, dwModuleNameSize, c_wstNormalizedName.c_str(), c_wstNormalizedName.size(), g_winAPIs->GetLastError()
				);
				if (dwModuleNameSize)
				{
#ifdef __EXPERIMENTAL__
					const auto dwAttr = g_winAPIs->GetFileAttributesW(c_wstNormalizedName.c_str());

					if (dwAttr == INVALID_FILE_ATTRIBUTES)
					{
						APP_TRACE_LOG(LL_CRI, L"Unallowed path detected! Type: 1 Last error: %u", g_winAPIs->GetLastError());

						m_dwInitStatusCode = INIT_FATAL_NETWORK_PATH_DETECTED;
						m_dwInitSubErrorCode = 1;
						_dbreak;
					}
					else if (dwAttr & FILE_ATTRIBUTE_READONLY)
					{
						APP_TRACE_LOG(LL_CRI, L"Unallowed path detected! Type: 2 Last error: %u", g_winAPIs->GetLastError());

						m_dwInitStatusCode = INIT_FATAL_NETWORK_PATH_DETECTED;
						m_dwInitSubErrorCode = 2;
						_dbreak;
					}
#endif
					if (g_winAPIs->PathIsNetworkPathW(wszMappedName))
					{
						APP_TRACE_LOG(LL_CRI, L"Unallowed path detected! Type: 3 Last error: %u", g_winAPIs->GetLastError());

						m_dwInitStatusCode = INIT_FATAL_NETWORK_PATH_DETECTED;
						m_dwInitSubErrorCode = 3;
						_dbreak;
					}
					else if (g_winAPIs->PathIsUNCW(wszMappedName))
					{
						APP_TRACE_LOG(LL_CRI, L"Unallowed path detected! Type: 4 Last error: %u", g_winAPIs->GetLastError());

						m_dwInitStatusCode = INIT_FATAL_NETWORK_PATH_DETECTED;
						m_dwInitSubErrorCode = 4;
						_dbreak;
					}
					else if (IsMappedPath(stMappedName.c_str()))
					{
						APP_TRACE_LOG(LL_CRI, L"Network path detected! Type: 5 Last error: %u", g_winAPIs->GetLastError());

						m_dwInitStatusCode = INIT_FATAL_NETWORK_PATH_DETECTED;
						m_dwInitSubErrorCode = 5;
						_dbreak;
					}
				}
				APP_TRACE_LOG(LL_SYS, L"Network path check completed.");
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer19: %u", kTimer.diff());

			// Main initilization routines
			{
				// Check processor arch
				const auto wArchCheckRet = m_spFunctions->CheckProcessorArch();
				if (wArchCheckRet)
				{
					APP_TRACE_LOG(LL_CRI, L"Unsupported processor architecture: %u", wArchCheckRet);

					m_dwInitStatusCode = INIT_FATAL_UNSUPPORTED_PROCESSOR_ARCH;
					m_dwInitSubErrorCode = wArchCheckRet;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Processor architecture check has been passed.");

				// Check processor type
				const auto dwProcessorCheckRet = m_spFunctions->CheckProcessorType();
				if (dwProcessorCheckRet)
				{
					APP_TRACE_LOG(LL_CRI, L"Unsupported processor type: %u", dwProcessorCheckRet);

					m_dwInitStatusCode = INIT_FATAL_UNSUPPORTED_PROCESSOR_TYPE;
					m_dwInitSubErrorCode = dwProcessorCheckRet;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Processor type check has been passed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer20: %u", kTimer.diff());

				// Load data packages
				const auto stGameDataFile = fmt::format(xorstr_(L"{0}\\{1}"),
					std::filesystem::current_path().wstring(),
					GAME_DATA_FILENAME
				);

				uint8_t nNmGameDataFailStep = 0;
				if (m_spDataLoader->LoadPackedGameData(stGameDataFile, nNmGameDataFailStep) == false)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy game data file load fail! Error: %u", nNmGameDataFailStep);

					m_dwInitStatusCode = INIT_FATAL_NOMERCY_GAME_DATA_LOAD_FAIL;
					m_dwInitSubErrorCode = nNmGameDataFailStep;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"NoMercy game data file loaded.");

				uint8_t nNmGameIntegrationFailStep = 0;
				if (m_spGameIntegrationMgr->LoadPackedBundleFile(FILE_DB_FILENAME, nNmGameIntegrationFailStep) == false)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy game file bundle file load fail! Error: %u", nNmGameIntegrationFailStep);

					m_dwInitStatusCode = INIT_FATAL_NOMERCY_GAME_BUNDLE_FILE_LOAD_FAIL;
					m_dwInitSubErrorCode = nNmGameIntegrationFailStep;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"NoMercy game file data file loaded.");

				uint8_t nNmRsaKeyLoadFailStep = 0;
				if (m_spDataLoader->LoadRsaPublicKeyFile(HB_PUB_KEY_FILENAME, nNmRsaKeyLoadFailStep) == false)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy RSA public key file load fail! Error: %u", nNmRsaKeyLoadFailStep);

					m_dwInitStatusCode = INIT_FATAL_NOMERCY_RSA_PUBLIC_KEY_LOAD_FAIL;
					m_dwInitSubErrorCode = nNmRsaKeyLoadFailStep;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"NoMercy RSA public key file loaded.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer21: %u", kTimer.diff());

				// Initialize core functions
//				/*
				if (IsWindows8OrGreater())
				{
					PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy{ 0 };
					strictHandlePolicy.HandleExceptionsPermanentlyEnabled = 0;
					strictHandlePolicy.RaiseExceptionOnInvalidHandleReference = 0;
					if (!g_winAPIs->SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy)))
					{
						APP_TRACE_LOG(LL_ERR, L"Strict Handle Mitigation policy disable failed with error: %u", g_winAPIs->GetLastError());
						m_dwInitStatusCode = INIT_FATAL_HANDLE_EXCEPTION_MITIGATION_FAIL;
						_dbreak;
					}
				}
//				*/

				APP_TRACE_LOG(LL_SYS, L"Strict Handle Mitigation policy enabled.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer22: %u", kTimer.diff());


				const auto dwMainThreadId = NoMercyCore::CApplication::Instance().DataInstance()->GetMainThreadId();
				if (!dwMainThreadId)
				{
					APP_TRACE_LOG(LL_CRI, L"Null main thread id");

					m_dwInitStatusCode = INIT_FATAL_NULL_MAIN_THREAD_ID;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Main thread id check completed. TID: %u", dwMainThreadId);

				auto hMainThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, dwMainThreadId);
				if (!IS_VALID_HANDLE(hMainThread))
				{
					APP_TRACE_LOG(LL_CRI, L"Main thread open fail! Error: %u", g_winAPIs->GetLastError());

					m_dwInitStatusCode = INIT_FATAL_MAIN_THREAD_OPEN_FAIL;
					_dbreak;
				}
				NoMercyCore::CApplication::Instance().DataInstance()->SetMainThreadHandle(hMainThread);
				APP_TRACE_LOG(LL_SYS, L"Main thread open completed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer23: %u", kTimer.diff());

				auto wstLauncherExe = NoMercyCore::CApplication::Instance().DataInstance()->GetLauncherExecutable();
				wstLauncherExe = stdext::to_lower_wide(wstLauncherExe);
				const auto bIsEAC = wstLauncherExe.find(xorstr_(L"_eac.exe")) != std::wstring::npos;

				if (!bIsEAC)
				{
					const auto stExePath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->CurrentPath();
					if (!stExePath.empty())
					{
						if (std::filesystem::exists(fmt::format(xorstr_(L"{0}\\.local"), stExePath)))
						{
							m_dwInitStatusCode = INIT_ERR_DOT_LOCAL_REDIRECTION;
							_dbreak;
						}

						for (const auto& entry : std::filesystem::directory_iterator(stExePath, ec))
						{
							if (entry.path().extension() == xorstr_(L".local"))
							{
								APP_TRACE_LOG(LL_ERR, L".local file: %s", entry.path().wstring().c_str());

								m_dwInitStatusCode = INIT_ERR_DOT_LOCAL_REDIRECTION;
								_dbreak;
							}
						}

						if (m_dwInitStatusCode == INIT_ERR_DOT_LOCAL_REDIRECTION)
							break;
					}
				}
				APP_TRACE_LOG(LL_SYS, L"Dot local redirection check completed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer24: %u", kTimer.diff());

				const auto dwParentProcessId = CProcessFunctions::GetParentProcessIdNative(NtCurrentProcess());
				if (dwParentProcessId)
				{
					auto stParentName = L""s;
					auto hParentProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentProcessId);
					if (IS_VALID_HANDLE(hParentProcess))
						stParentName = CProcessFunctions::GetProcessFullName(hParentProcess);
					else
						stParentName = CProcessFunctions::GetParentProcessName(g_winAPIs->GetCurrentProcessId());

					APP_TRACE_LOG(LL_SYS, L"Parent process: %u (%s)", dwParentProcessId, stParentName.c_str());
					NoMercyCore::CApplication::Instance().DataInstance()->SetLauncherName(stParentName);
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hParentProcess);
				}
				APP_TRACE_LOG(LL_SYS, L"Parent process check completed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer25: %u", kTimer.diff());

				std::error_code ec{};
				const auto nNoMercyLogSize = std::filesystem::file_size(CUSTOM_LOG_FILENAME_W, ec);
				if (nNoMercyLogSize)
				{
					APP_TRACE_LOG(LL_SYS, L"NoMercy log file size: %u", nNoMercyLogSize);
					if (nNoMercyLogSize > gsc_nMaxLogFileSize)
					{
						const auto stNewFilename = fmt::format(xorstr_(L"{0}_{1}_backup.log"), CUSTOM_LOG_FILENAME_W, stdext::get_current_epoch_time());
						if (std::filesystem::exists(stNewFilename, ec))
							std::filesystem::remove(stNewFilename, ec);

						std::filesystem::rename(CUSTOM_LOG_FILENAME_W, stNewFilename, ec);
						if (ec)
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy log file rename fail! Error: %u (%hs)", ec.value(), ec.message().c_str());
						}
						else
						{
							APP_TRACE_LOG(LL_SYS, L"NoMercy log file rename completed.");
						}
					}
				}
				APP_TRACE_LOG(LL_SYS, L"NoMercy log file size check completed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer26: %u", kTimer.diff());

				const auto bShouldKeepLogs = KEEP_OLD_LOG_FILES;
				APP_TRACE_LOG(LL_SYS, L"Should keep old log files: %s", bShouldKeepLogs ? xorstr_(L"true") : xorstr_(L"false"));
				if (!bShouldKeepLogs)
				{
					static constexpr auto sc_dwOldMainLogTimeLimitSec = 60 * 60 * 24 * 7;
					const auto c_szMainLogFile = CUSTOM_LOG_FILENAME_W;
					const auto dwMainLogFileCreateTime = GetFileLastWriteTime(c_szMainLogFile, true);
					const auto dwCurrentTime = stdext::get_current_epoch_time();
					int64_t llTimeDiff = dwCurrentTime - dwMainLogFileCreateTime;

					APP_TRACE_LOG(LL_SYS, L"Main log file: %s (create time: %u, current time: %u, time diff: %lld)",
						c_szMainLogFile, dwMainLogFileCreateTime, dwCurrentTime, llTimeDiff
					);
					if (llTimeDiff > sc_dwOldMainLogTimeLimitSec)
					{
						APP_TRACE_LOG(LL_SYS, L"Main log file is too old. Deleting...");
						std::filesystem::remove(c_szMainLogFile, ec);
						if (ec)
						{
							APP_TRACE_LOG(LL_ERR, L"Main log file delete fail! Error: %u (%hs)", ec.value(), ec.message().c_str());
						}
						else
						{
							APP_TRACE_LOG(LL_SYS, L"Main log file delete completed.");
						}
					}

					const auto stNoMercyPath = fmt::format(xorstr_(L"{0}\\NoMercy"), NoMercyCore::CApplication::Instance().DirFunctionsInstance()->CurrentPath());
					const auto stLogPath = fmt::format(xorstr_(L"{0}\\Log"), stNoMercyPath);
					const auto stOldLogPath = fmt::format(xorstr_(L"{0}\\old"), stLogPath);

					APP_TRACE_LOG(LL_SYS, L"NoMercy path: %s Log path: %s", stNoMercyPath.c_str(), stLogPath.c_str());

					if (std::filesystem::exists(stNoMercyPath, ec) && std::filesystem::exists(stLogPath, ec))
					{
//						if (c_bIsService && std::filesystem::exists(stOldLogPath))
//							NoMercyCore::CApplication::Instance().DirFunctionsInstance()->DeleteDirectory(stOldLogPath);

						if (!std::filesystem::exists(stOldLogPath, ec))
						{
							APP_TRACE_LOG(LL_SYS, L"Old log folder created!");

							std::filesystem::create_directory(stOldLogPath, ec);
							if (ec)
							{
								APP_TRACE_LOG(LL_ERR, L"Old log folder create fail! Error: %u (%hs)", ec.value(), ec.message().c_str());
							}
						}
						else if (ec)
						{
							APP_TRACE_LOG(LL_ERR, L"Old log folder exist check fail! Error: %u (%hs)", ec.value(), ec.message().c_str());
						}

						for (const auto& entry : std::filesystem::directory_iterator(stLogPath, ec))
						{
							if (!entry.is_regular_file())
								continue;

							const auto stNewFile = fmt::format(xorstr_(L"{0}\\{1}"), stOldLogPath, entry.path().filename().wstring());
							const auto stOldFile = entry.path().wstring();

							g_winAPIs->SetLastError(0);
							APP_TRACE_LOG(LL_SYS, L"File: %s moving to: %s", stOldFile.c_str(), stNewFile.c_str());
							const auto bMoveRet = g_winAPIs->MoveFileW(stOldFile.c_str(), stNewFile.c_str());
							APP_TRACE_LOG(LL_SYS, L"Move completed! Success: %d Last error: %u", bMoveRet, g_winAPIs->GetLastError());
						}

						static constexpr auto sc_dwOldLogTimeLimitSec = 60 * 60 * 24 * 2; // 2 days
						if (std::filesystem::exists(stOldLogPath, ec))
						{
							for (const auto& entry : std::filesystem::directory_iterator(stOldLogPath, ec))
							{
								if (!entry.is_regular_file())
									continue;

								const auto stFile = entry.path().wstring();
								const auto ullFileSize = entry.file_size();

								if (ullFileSize > 30000000) // 10MB
								{
									g_winAPIs->SetLastError(0);
									const auto bDeleteRet = g_winAPIs->DeleteFileW(stFile.c_str());
									APP_TRACE_LOG(LL_SYS, L"Delete completed! Success: %d Last error: %u", bDeleteRet, g_winAPIs->GetLastError());
									continue;
								}

								const auto dwLastWriteTime = GetFileLastWriteTime(stFile, false);

								if (dwLastWriteTime > dwCurrentTime)
									continue;

								llTimeDiff = dwCurrentTime - dwLastWriteTime;
								APP_TRACE_LOG(LL_TRACE, L"File: %s last write time: %u current time: %u Diff: %lld", stFile.c_str(), dwLastWriteTime, dwCurrentTime, llTimeDiff);

								if (llTimeDiff > 0)
								{
									if (llTimeDiff > sc_dwOldLogTimeLimitSec)
									{
										APP_TRACE_LOG(LL_SYS, L"File: %s deleting!", stFile.c_str());

										if (!std::filesystem::remove(stFile, ec) || ec)
										{
											APP_TRACE_LOG(LL_ERR, L"File: %s delete fail! Error: %u (%hs)", stFile.c_str(), ec.value(), ec.message().c_str());
										}
										else
										{
											APP_TRACE_LOG(LL_SYS, L"File: %s deleted!", stFile.c_str());
										}
									}
								}
							}
						}
					}
				}
				APP_TRACE_LOG(LL_SYS, L"Old log files processed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer27: %u", kTimer.diff());

				// Clear dummy temp files from old launchs
				auto workerThread = [](LPVOID) -> DWORD {
					std::error_code ec{};
					const auto stTempPath = std::filesystem::temp_directory_path(ec);
					if (std::filesystem::exists(stTempPath, ec))
					{
						for (const auto& entry : std::filesystem::directory_iterator(stTempPath, ec))
						{
							if (!entry.is_regular_file(ec))
								continue;

							if (!entry.path().has_filename())
								continue;

							try
							{
								const auto wstFile = entry.path().filename().wstring();
								if (stdext::starts_with(wstFile, std::wstring(xorstr_(L"nm_sll"))) ||
									stdext::starts_with(wstFile, std::wstring(xorstr_(L"nm_hml"))))
								{
									APP_TRACE_LOG(LL_SYS, L"File: %ls deleting!", wstFile.c_str());
									if (!std::filesystem::remove(wstFile, ec) || ec)
									{
										APP_TRACE_LOG(LL_ERR, L"File: %ls delete fail! Error: %u (%hs)", wstFile.c_str(), ec.value(), ec.message().c_str());
									}
									else
									{
										APP_TRACE_LOG(LL_SYS, L"File: %ls deleted!", wstFile.c_str());
									}
								}
							}
							catch (const std::filesystem::filesystem_error& err)
							{
								APP_TRACE_LOG(LL_ERR, L"File: %ls/%ls delete fail! Error: %u (%hs)",
									err.path1().wstring().c_str(), err.path2().wstring().c_str(), err.code().value(), err.code().message().c_str()
								);
							}
						}
					}
					APP_TRACE_LOG(LL_SYS, L"Temp files processed.");
					return 0;
				};
				SafeHandle pkThread = g_winAPIs->CreateThread(nullptr, 0, workerThread, nullptr, 0, nullptr);

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer28: %u", kTimer.diff());

				/*
				* Was required for named pipe integrity check
				// Check DNS service integrity
				if (m_spScannerInterface->CheckDnsServiceIntegrity() == false)
				{
					APP_TRACE_LOG(LL_CRI, L"DNS service integrity check fail!");

					m_dwInitStatusCode = INIT_FATAL_CHECK_DNS_SERVICE_INTEGRITY_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"DNS service integrity completed.");
				*/

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer29: %u", kTimer.diff());

				// Create timer queue
				ntStatus = g_winAPIs->RtlCreateTimerQueue(&m_hTimerQueue);
				if (!NT_SUCCESS(ntStatus) || !IS_VALID_HANDLE(m_hTimerQueue))
				{
					APP_TRACE_LOG(LL_CRI, L"Main timer queue initilization fail! Error: %p", ntStatus);

					m_dwInitStatusCode = INIT_FATAL_TIMER_QUEUE_INIT_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Timer queue created.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer30: %u", kTimer.diff());

				// Initialize quarentine
				if (m_spQuarentineMgr->Initialize() == false)
				{
					APP_TRACE_LOG(LL_CRI, L"Quarentine initilization fail!Error: % p", ntStatus);

					m_dwInitStatusCode = INIT_FATAL_QUARENTINE_INIT_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Quarentine initialized.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer31: %u", kTimer.diff());

				// Initialize network base
				if (m_spNetworkMgr->InitializeNetwork() == false)
				{
					APP_TRACE_LOG(LL_CRI, L"Network manager initilization fail! Error: %u", g_winAPIs->GetLastError());

					m_dwInitStatusCode = INIT_FATAL_NET_INIT_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Network instances initialized.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer32: %u", kTimer.diff());

#ifdef __EXPERIMENTAL__
				if (c_nAppType == NM_CLIENT)
				{
					// Check loaded modules
					auto bHasCorruptedModule = false;
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->EnumerateModules([&](LDR_DATA_TABLE_ENTRY* pEntry) {
						// Sanity check
						if (!pEntry || !pEntry->DllBase || pEntry->DllBase == g_winModules->hBaseModule)
							return;

						if (IS_VALID_SMART_PTR(c_spAntiModule) && pEntry->DllBase == c_spAntiModule->DllBase)
							return;

						// Skip self-loaded modules
						const auto vecSelfLoadedModules = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetSelfModuleList();
						if (stdext::in_vector(vecSelfLoadedModules, (HMODULE)pEntry->DllBase))
							return;

						static const std::vector <std::wstring> vecWhitelist = {
							xorstr_(L"antimalware_provider.dll")
						};

						// Get module name
						const auto wstModuleName = std::wstring(pEntry->FullDllName.Buffer, pEntry->FullDllName.Length / sizeof(wchar_t));
						const auto stModuleName = stdext::to_lower_wide(wstModuleName);

						// Check integrity, if incoming from Windows directory, just forward to winapi manager instance
						if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(stModuleName))
						{
							DWORD dwErrCode = 0;
							if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->CheckModuleIntegrity((HMODULE)pEntry->DllBase, stModuleName, false, &dwErrCode))
							{
								APP_TRACE_LOG(LL_CRI, L"Module integrity check fail! Module: %s Error: %u", stModuleName.c_str(), dwErrCode);
								bHasCorruptedModule = true;
							}
						}
						else if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(stModuleName))
						{
							// TODO: Impl
						}
						else
						{
							auto bSkip = false;
							if (stModuleName.find(xorstr_(L"nomercy")) != std::wstring::npos)
							{
								const auto stParentPath = std::filesystem::path(stModuleName).parent_path().wstring();
								const auto stNoMercyPath = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->GetNoMercyPath());

								if (stNoMercyPath == stParentPath)
									bSkip = true;
							}

							try
							{
								for (const auto& wstSubStr : vecWhitelist)
								{
									if (stModuleName.find(wstSubStr) != std::wstring::npos)
									{
										bSkip = true;
										break;
									}
								}
							}
							catch (const std::regex_error& e)
							{
								APP_TRACE_LOG(LL_ERR, L"Regex error: %s", e.what());
							}

							if (!bSkip)
							{
								APP_TRACE_LOG(LL_CRI, L"Module: %s loaded from unknown source path!", stModuleName.c_str());
								// TODO: Validate
							}
						}

						if (!g_winAPIs->PathFileExistsW(stModuleName.c_str()))
						{
							APP_TRACE_LOG(LL_CRI, L"Module: %s file does not exist! Error: %u", stModuleName.c_str(), g_winAPIs->GetLastError());
						}

						if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(stModuleName))
						{
							const auto pINH = g_winAPIs->RtlImageNtHeader(pEntry->DllBase);
							if (pINH && pINH->Signature == IMAGE_NT_SIGNATURE)
							{
								if (!(pINH->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
								{
									APP_TRACE_LOG(LL_CRI, L"Module: %s does not contain requied flags, DllCharacteristics: %p",
										stModuleName.c_str(), pINH->OptionalHeader.DllCharacteristics
									);
								}
							}
						}
						});
#ifdef __EXPERIMENTAL__
					if (bHasCorruptedModule)
					{
						m_dwInitStatusCode = INIT_FATAL_MODULE_INTEGRITY_FAIL;
						_dbreak;
					}
#endif
					APP_TRACE_LOG(LL_SYS, L"Loaded module integrity check step completed");

					// Initialize APFN filter (used in thread scanner)
					if (m_spSelfHooks->InitializeApfnFilter() == false)
					{
						m_dwInitStatusCode = INIT_FATAL_APFN_FILTER_INITIALIZE_FAIL;
						_dbreak;
					}
					APP_TRACE_LOG(LL_SYS, L"APFN filter initialize step completed");

					// Check open threads
					auto bHasCorruptedThread = false;
					m_spScannerInterface->EnumerateThreads(NtCurrentProcess(), [&](SYSTEM_THREAD_INFORMATION* pThread) {
						// Sanity check
						if (!pThread)
							return;

						// Open thread
						auto hThread = g_winAPIs->OpenThread(THREAD_ALL_ACCESS, FALSE, HandleToUlong(pThread->ClientId.UniqueThread)); // NOTE: It will closed by CThread dotr
						if (!IS_VALID_HANDLE(hThread))
						{
							APP_TRACE_LOG(LL_ERR, L"OpentThread failed with error: %u", g_winAPIs->GetLastError());
							return;
						}

						const auto dwThreadID = g_winAPIs->GetThreadId(hThread);
						if (!dwThreadID)
						{
							APP_TRACE_LOG(LL_ERR, L"GetThreadId failed with error: %u", g_winAPIs->GetLastError());
							g_winAPIs->CloseHandle(hThread);
							return;
						}

						bool bSuspicious = false;
						const auto bCheckRet = m_spAnalyser->OnThreadCreated(dwThreadID, hThread, nullptr, bSuspicious);
						APP_TRACE_LOG(LL_SYS, L"Thread: %u check completed with status: %d, Suspicious: %d", dwThreadID, bCheckRet ? 1 : 0, bSuspicious ? 1 : 0);

						if (bSuspicious)
						{
							APP_TRACE_LOG(LL_CRI, L"Thread integrity check fail! Thread: %u", dwThreadID);
							bHasCorruptedThread = true;
						}

						NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hThread);
					});
#ifdef __EXPERIMENTAL__
					if (bHasCorruptedThread)
					{
						m_dwInitStatusCode = INIT_FATAL_THREAD_INTEGRITY_FAIL;
						_dbreak;
					}
					APP_TRACE_LOG(LL_SYS, L"Loaded thread integrity check step completed");
#endif

					const auto cbLoadedModuleCount = NoMercyTLS::TLS_GetLoadedModuleCount();
					const auto ppLoadedModules = NoMercyTLS::TLS_GetLoadedModules();
					for (std::size_t i = 0; i < cbLoadedModuleCount; ++i)
					{
						const auto pModuleData = ppLoadedModules[i];
						if (!pModuleData->DllBase || !pModuleData->SizeOfImage)
						{
							APP_TRACE_LOG(LL_WARN, L"Corrupted module in: %lu", i);
							continue;
						}

						APP_TRACE_LOG(LL_SYS, L"[%u] Early load module: %p (%p) >> %ls (%ls)",
							i, pModuleData->DllBase, pModuleData->SizeOfImage,
							pModuleData->BaseDllName.Buffer,
							pModuleData->FullDllName.Buffer
						);

						__nop();
						// TODO
						// Get process IAT
						// Get first 3 modules sub IATs
						// Compare with current module list
						// If any current loaded module does not point as an IAT linked module dependency, looks injected

						// For Win8 >=
						// Check PEB->Ldr->LoadReason
						 // https://github.com/nccgroup/DetectWindowsCopyOnWriteForAPI/blob/master/d-peb-dll-loadreason/Engine.cpp
					}

					// Check mapped modules
					m_spScannerInterface->CheckManualMappedModules(true);
					APP_TRACE_LOG(LL_SYS, L"Manual mapped module check step completed");

					// Check exception handlers
					m_spScannerInterface->CheckExceptionHandlers();
					APP_TRACE_LOG(LL_SYS, L"Exception handler check step completed");
				}
#endif

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer33: %u", kTimer.diff());

#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
				// Check remapped memory still valid
				PVOID pvTextBase = nullptr;
				SIZE_T cbTextSize = 0;
				if (NoMercyCore::CPEFunctions::GetTextSectionInformation((HMODULE)g_winModules->hBaseModule, &pvTextBase, &cbTextSize))
				{
					MEMORY_BASIC_INFORMATION mbi{ 0 };
					if (g_winAPIs->VirtualQuery(pvTextBase, &mbi, sizeof(mbi)))
					{
						if (mbi.AllocationProtect != PAGE_EXECUTE_WRITECOPY)
						{
							APP_TRACE_LOG(LL_CRI, L"Text section is not PAGE_EXECUTE_WRITECOPY! Protection: %p", mbi.AllocationProtect);

							m_dwInitStatusCode = INIT_FATAL_TEXT_SECTION_PROTECTION_FAIL;
							m_dwInitSubErrorCode = mbi.AllocationProtect;
							_dbreak;
						}
					}
				}
				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer33-2: %u", kTimer.diff());
#endif

				// [NOTE] CHECKME Themida errors ( https://i.imgur.com/tb99Jub.png )
				if (InitSelfProtection(c_spAntiModule.get()) == false)
				{
					APP_TRACE_LOG(LL_CRI, L"Self protection fail! Error: %u", g_winAPIs->GetLastError());

					m_dwInitStatusCode = INIT_FATAL_SELF_PROT_INIT_FAIL;
					_dbreak;
				}
				APP_TRACE_LOG(LL_SYS, L"Self protection completed.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer34: %u", kTimer.diff());

#ifndef _WIN64 // TODO: Fix PE funcs
				// Scan hooks
				std::vector <std::wstring> vecTargetModules = {
#if 0
					xorstr_(L"kernel32.dll"),
					xorstr_(L"kernelbase.dll"),
					xorstr_(L"advapi32.dll"),
					xorstr_(L"user32.dll"),
					xorstr_(L"ntdll.dll"),
#endif
					// xorstr_(L"winmm.dll"),
					// xorstr_(L"msvcrt.dll")
				};

#if USE_THEMIDA_SDK != 1
				// FIXME Broke themida hooks
				vecTargetModules.emplace_back(xorstr_(L"kernel32.dll"));

				if (g_winModules->hWin32u)
					vecTargetModules.emplace_back(xorstr_(L"win32u.dll"));
				if (g_winModules->hKernelbase)
					vecTargetModules.emplace_back(xorstr_(L"kernelbase.dll"));
#endif

				const auto vecWhitelistedHooks = std::vector <std::wstring>{
					xorstr_(L"acmdln"),
					xorstr_(L"wcmdln"),
					xorstr_(L"_initenv"),
					xorstr_(L"environ"),
					xorstr_(L"osplatform"),
					xorstr_(L"osver"),
					xorstr_(L"winver"),
					xorstr_(L"winmajor"),
					xorstr_(L"winminor"),
					xorstr_(L"_pioinfo"),
					xorstr_(L"aexit_rtn"),
					xorstr_(L"NlsAnsiCodePage"),
					xorstr_(L"OpenMuiStringCache"),
					xorstr_(L"hread"),
					xorstr_(L"lopen"),
					xorstr_(L"lread"),
					xorstr_(L"lclose"),
					xorstr_(L"llseek")
				};

				std::vector <CHookScanner::ExceptionRule> vecExceptionRules;
				for (const auto& stFunc : vecWhitelistedHooks)
				{
					CHookScanner::ExceptionRule exc;
					exc.wstFuncName = stFunc;
					exc.bFindByAddr = FALSE;

					vecExceptionRules.emplace_back(exc);
				}
				CApplication::Instance().HookScannerInstance()->AddExceptionRules(vecExceptionRules);

#if USE_THEMIDA_SDK == 1
				const auto vecWhitelistedThemidaHooks = std::vector <std::wstring>{
					xorstr_(L"LoadLibrary"),
					xorstr_(L"CreateFile"),
					xorstr_(L"FindNextFile"),
					xorstr_(L"FindFirstFile"),
					xorstr_(L"FreeLibrary"),
					xorstr_(L"GetProcAddress"),
					xorstr_(L"GetModuleFilename"),
					xorstr_(L"GetFileInformationByHandle"),
					xorstr_(L"GetModuleHandle"),
					xorstr_(L"CloseHandle"),
					xorstr_(L"DuplicateHandle"),
					xorstr_(L"GetFileType"),
					xorstr_(L"GetFileTime"),
					xorstr_(L"GetFileAttributes"),
					xorstr_(L"OpenFile"),
					xorstr_(L"ReadFile"),
					xorstr_(L"LockFile"),
					xorstr_(L"SetFilePointer"),
					xorstr_(L"GetFileSize"),
					xorstr_(L"CopyFile"),
					xorstr_(L"CreateFileMapping"),
					xorstr_(L"OpenFileMapping"),
					xorstr_(L"MapViewOfFile"),
					xorstr_(L"UnmapViewOfFile"),
					xorstr_(L"SearchPath"),
					xorstr_(L"GetPrivateProfileInt"),
					xorstr_(L"GetPrivateProfileSection"),
					xorstr_(L"GetPrivateProfileString"),
					xorstr_(L"CryptVerifySignature"),
					xorstr_(L"FindClose"),
					xorstr_(L"LoadImage")
				};

				std::vector <CHookScanner::ExceptionRule> vecThemidaExceptionRules;
				for (const auto& stFunc : vecWhitelistedThemidaHooks)
				{
					CHookScanner::ExceptionRule exc;
					exc.wstFuncName = stFunc;
					exc.bFindSubstr = TRUE;
					exc.bFindByAddr = FALSE;

					vecThemidaExceptionRules.emplace_back(exc);
				}
				CApplication::Instance().HookScannerInstance()->AddExceptionRules(vecThemidaExceptionRules);
#endif

				std::vector <LPVOID> vecVEHs;
				// TODO: Add VEHs
				
				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer35: %u", kTimer.diff());

				const auto bHookScanRet = m_spHookScanner->StartScanner(
					CHookScanner::EHookScannerTypes::ALL,
					[&](CHookScanner::HOOK_INFO* hook) {
						auto wstFuncName = L""s;
						const auto bNameQueryRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetFunctionNameFromAddress(
							NtCurrentProcess(), nullptr, hook->pvFunc, wstFuncName
						);

						const auto stDetails = fmt::format(xorstr_(L"Hook details: {0}({1}) Ptr: {2}({3}/{4})"),
							stdext::to_wide(hook->stTypeName), hook->nType, hook->pvFunc, wstFuncName, bNameQueryRet
						);
						APP_TRACE_LOG(LL_WARN, L"%s", stDetails.c_str());

						auto wstModuleName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)hook->pvFunc);
						auto bPatchRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->PatchModuleHook(wstModuleName.c_str(), wstFuncName.c_str());
						APP_TRACE_LOG(LL_WARN, L"Patch result: %d for %s:%s", bPatchRet, wstModuleName.c_str(), wstFuncName.c_str());

						if (!bPatchRet)
						{
							APP_TRACE_LOG(LL_ERR, L"Hook found but patch failed, %s / '%s':'%s'", stDetails.c_str(), wstModuleName.c_str(), wstFuncName.c_str());

							auto wstFixedFuncName = wstFuncName;
							/*
							if (wstFixedFuncName.find(xorstr_(L"+")) != std::wstring::npos)
							{
								const auto vecSplitted = stdext::split_string(wstFixedFuncName, std::wstring(xorstr_(L"+")));
								if (vecSplitted.size() == 2)
								{
									wstFixedFuncName = vecSplitted.at(0);
									APP_TRACE_LOG(LL_WARN, L"Fixed name part1: %s", wstFixedFuncName.c_str());
								}
							}
							*/
							if (wstFixedFuncName.find(xorstr_(L"+")) == std::wstring::npos)
							{
								if (stdext::starts_with(wstFixedFuncName, std::wstring(xorstr_(L"0x"))))
								{
									const auto pFuncAddr = stdext::string_to_pointer(wstFixedFuncName);
									APP_TRACE_LOG(LL_WARN, L"Converted ptr: %p", pFuncAddr);

									if (pFuncAddr)
									{
										CHookScanner::ExceptionRule exc;
										exc.pvProcedureAddr = (PVOID)pFuncAddr;
										exc.bFindByAddr = TRUE;
										CApplication::Instance().HookScannerInstance()->AddExceptionRule(exc);
									}
								}
								else
								{
									const auto pFuncAddr = stdext::string_to_pointer(wstFixedFuncName);
									APP_TRACE_LOG(LL_WARN, L"Final name: %s", wstFixedFuncName.c_str());

									CHookScanner::ExceptionRule exc;
									exc.wstFuncName = wstFixedFuncName;
									exc.bFindByAddr = FALSE;
									CApplication::Instance().HookScannerInstance()->AddExceptionRule(exc);
								}
							}
						}
					},
					nullptr,
					vecTargetModules,
					vecVEHs
				);
#ifndef _DEBUG
				if (!bHookScanRet)
				{
					APP_TRACE_LOG(LL_CRI, L"Hook scanner initilization fail!");

					m_dwInitStatusCode = INIT_FATAL_HOOK_SCAN_INIT_FAIL;
					_dbreak;
				}
#endif
				APP_TRACE_LOG(LL_SYS, L"Hook scanner initialized.");
#endif
				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer36: %u", kTimer.diff());

				// Check suspected registry items from session manager
				auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
				if (stdext::is_wow64())
					dwFlags |= KEY_WOW64_64KEY;

				// TODO: check "\REGISTRY\MACHINE\SYSTEM\CURRENTCONTROLSET\CONTROL\SESSION MANAGER\KERNEL\MitigationOptions" & 0x400

				HKEY hKey = 0;
				auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager"), NULL, dwFlags, &hKey);
				if (lError == ERROR_SUCCESS && hKey)
				{
					DWORD dwDataType = REG_DWORD;
					DWORD dwValue = 0;
					DWORD dwValueSize = sizeof(dwValue);

					lError = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SafeDllSearchMode"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
					if (lError == ERROR_SUCCESS && dwValue == 0)
					{
						APP_TRACE_LOG(LL_CRI, L"Session Manager :: SafeDllSearchMode registry value is 0!");

						m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
						m_dwInitSubErrorCode = 1;
						_dbreak;
					}

					lError = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"CWDIllegalInDLLSearch"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
					if (lError == ERROR_SUCCESS && dwValue == 0xFFFFFFFF)
					{
						APP_TRACE_LOG(LL_CRI, L"Session Manager :: CWDIllegalInDLLSearch registry value is 0xFFFFFFFF!");

						m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
						m_dwInitSubErrorCode = 2;
						_dbreak;
					}

					lError = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"DisableUserModeCallbackFilter"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
					if (lError == ERROR_SUCCESS && dwValue == 1)
					{
						APP_TRACE_LOG(LL_CRI, L"Session Manager :: DisableUserModeCallbackFilter registry value is 1!");

						m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
						m_dwInitSubErrorCode = 3;
						_dbreak;
					}

					g_winAPIs->RegCloseKey(hKey);
				}
				APP_TRACE_LOG(LL_SYS, L"Session Manager registry check done.");

				// Check suspected registry items from GRE_Initialize
				lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize"), NULL, dwFlags, &hKey);
				if (lError == ERROR_SUCCESS && hKey)
				{
					DWORD dwDataType = REG_DWORD;
					DWORD dwValue = 0;
					DWORD dwValueSize = sizeof(dwValue);

					lError = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"DisableMetaFiles"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
					if (lError == ERROR_SUCCESS && dwValue == 1)
					{
						APP_TRACE_LOG(LL_CRI, L"GRE_Initialize :: DisableMetaFiles registry value is 1!");

						m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
						m_dwInitSubErrorCode = 4;
						_dbreak;
					}

					g_winAPIs->RegCloseKey(hKey);
				}
				APP_TRACE_LOG(LL_SYS, L"GRE_Initialize registry check done.");

				// LogfA(CUSTOM_LOG_FILENAME_A, "Timer37: %u", kTimer.diff());

				// Check suspected registry items from file specific registry keys
				lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey);
				if (lError == ERROR_SUCCESS && hKey)
				{
					// Enumerate all subkeys, find 'NoMercy' contained keys and check their suspected key values
					DWORD dwIndex = 0;
					wchar_t wszSubKeyIndex[255]{ L'\0' };
					DWORD dwSubKeyIndexSize = 255;

					while (g_winAPIs->RegEnumKeyExW(hKey, dwIndex, wszSubKeyIndex, &dwSubKeyIndexSize, 0, NULL, NULL, NULL) == ERROR_SUCCESS)
					{
						const auto stLowerKeyName = stdext::to_lower_wide(wszSubKeyIndex);
						if (stLowerKeyName.find(xorstr_(L"nomercy")) != std::wstring::npos)
						{
							HKEY hSubKey = 0;
							lError = g_winAPIs->RegOpenKeyExW(hKey, wszSubKeyIndex, NULL, KEY_QUERY_VALUE, &hSubKey);
							if (lError == ERROR_SUCCESS && hSubKey)
							{
								DWORD dwDataType = REG_DWORD;
								DWORD dwValue = 0;
								DWORD dwValueSize = sizeof(dwValue);

								lError = g_winAPIs->RegQueryValueExW(hSubKey, xorstr_(L"SafeDllSearchMode"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
								if (lError == ERROR_SUCCESS && dwValue == 0)
								{
									APP_TRACE_LOG(LL_CRI, L"SafeDllSearchMode registry value is 0 in key: %s", wszSubKeyIndex);

									m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
									m_dwInitSubErrorCode = 5;
									_dbreak;
								}

								lError = g_winAPIs->RegQueryValueExW(hSubKey, xorstr_(L"CWDIllegalInDLLSearch"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
								if (lError == ERROR_SUCCESS && dwValue == 0xFFFFFFFF)
								{
									APP_TRACE_LOG(LL_CRI, L"CWDIllegalInDLLSearch registry value is 0xFFFFFFFF in key: %s", wszSubKeyIndex);

									m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
									m_dwInitSubErrorCode = 6;
									_dbreak;
								}

								lError = g_winAPIs->RegQueryValueExW(hSubKey, xorstr_(L"DisableUserModeCallbackFilter"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
								if (lError == ERROR_SUCCESS && dwValue == 1)
								{
									APP_TRACE_LOG(LL_CRI, L"DisableUserModeCallbackFilter registry value is 1 in key: %s", wszSubKeyIndex);

									m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
									m_dwInitSubErrorCode = 7;
									_dbreak;
								}

								g_winAPIs->RegCloseKey(hSubKey);
							}
						}

						dwIndex++;
						dwSubKeyIndexSize = sizeof(wszSubKeyIndex);
					}

					g_winAPIs->RegCloseKey(hKey);
				
					APP_TRACE_LOG(LL_SYS, L"Image file execution registry check done.");

					// LogfA(CUSTOM_LOG_FILENAME_A, "Timer38: %u", kTimer.diff());

					// TODO Check Smart App Control registry value
#if 0
					if (IsWindows11OrGreater())
					{
						lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"), NULL, KEY_QUERY_VALUE, &hKey);
						if (lError == ERROR_SUCCESS && hKey)
						{
							DWORD dwDataType = REG_DWORD;
							DWORD dwValue = 0;
							DWORD dwValueSize = sizeof(dwValue);

							lError = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"VerifiedAndReputablePolicyState"), NULL, &dwDataType, (LPBYTE)&dwValue, &dwValueSize);
							if (lError == ERROR_SUCCESS && dwValue == 0)
							{
								APP_TRACE_LOG(LL_CRI, L"Smart App Control registry value is 0");

								m_dwInitStatusCode = INIT_FATAL_SUS_REG_DATA;
								m_dwInitSubErrorCode = 8;
								_dbreak;
							}
							g_winAPIs->RegCloseKey(hKey);
						}
					}
					APP_TRACE_LOG(LL_SYS, L"Smart App Control registry check done.");
#endif
					// LogfA(CUSTOM_LOG_FILENAME_A, "Timer39: %u", kTimer.diff());

					// Initialize cache manager
					if (!m_spCacheManager->InitializeThread())
					{
						APP_TRACE_LOG(LL_CRI, L"Cache manager initilization fail!");

						m_dwInitStatusCode = INIT_FATAL_CACHE_MANAGER_CREATE_THREAD;
						_dbreak;
					}

					// LogfA(CUSTOM_LOG_FILENAME_A, "Timer40: %u", kTimer.diff());

				}
				
#if !defined(_DEBUG) // && !defined(_RELEASE_DEBUG_MODE_)
				if (NoMercyCore::CApplication::Instance().DataInstance()->IsLauncherIntegrityCheckEnabled())
				{
					const auto bParentRet = CAntiDebug::ParentCheck(
						NoMercyCore::CApplication::Instance().DataInstance()->GetLauncherExecutable(),
						NoMercyCore::CApplication::Instance().DataInstance()->GetLauncherExecutableHash()
					);
					if (!bParentRet)
					{
						APP_TRACE_LOG(LL_CRI, L"Parent check failed!");
						m_dwInitStatusCode = INIT_FATAL_PARENT_CHECK_FAIL;
						_dbreak;
					}
				}
#endif
			}

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer41: %u", kTimer.diff());

			// Check core initialization status code
			if (m_dwInitStatusCode != INIT_STATUS_UNDEFINED)
			{
				__OnCoreInitilizationFail(1);
				return false;
			}

			// Core is ready! Go for specific process setups
			TInitializeEx InitializeEx = [&] {
				const auto nAppType = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
				APP_TRACE_LOG(LL_SYS, L"NoMercy Initilization has been started! App type: %d", nAppType);

				auto bRet = false;

				// Forward to sub initialization routines
				switch (nAppType)
				{
					case NM_CLIENT:
					{
						bRet = InitializeClient();
					} break;

					case NM_STANDALONE:
					{
						bRet = __InitializeTestMode();
					} break;

					default:
					{
						APP_TRACE_LOG(LL_CRI, L"Unknown app type: %d", nAppType);
						return bRet;
					}
				}

				APP_TRACE_LOG(LL_SYS, L"NoMercy Initilization completed! Result: %d", bRet ? 1 : 0);
				return bRet;
			};

			// LogfA(CUSTOM_LOG_FILENAME_A, "Timer42: %u", kTimer.diff());

			bRet = InitializeEx();
		} while (false);

		APP_TRACE_LOG(bRet ? LL_SYS : LL_ERR, L"InitializeEx result: %d initilization status: %u", bRet ? 1 : 0, m_dwInitStatusCode);

		// Check process initialization status code
		if (m_dwInitStatusCode != INIT_STATUS_SUCCESS)
		{
			__OnCoreInitilizationFail(2);
			return false;
		}

		// LogfA(CUSTOM_LOG_FILENAME_A, "Timer0: %u", kTimer.diff());

		// Complete initilization
		m_abAppIsInitiliazed = true;
		APP_TRACE_LOG(LL_SYS, L"Initialization function completed! Successed: %d", bRet ? 1 : 0);
		return bRet;
	}

	// Finalization
	bool CApplication::Finalize()
	{
		CTerminator::TerminateProcess(NtCurrentProcess());
		return true; // TODO: Deadlock check

		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		if (m_abFinalizeTriggered.load())
			return true;
		m_abFinalizeTriggered.store(true);

		NoMercyCore::CApplication::Instance().SetShutDownFlag();

		APP_TRACE_LOG(LL_SYS, L"Finalize routine started! InitRet: %d", m_abAppIsInitiliazed.load());

		if (IS_VALID_SMART_PTR(m_spSDKHelper))
		{
			m_spSDKHelper->ReleaseSDK();
			APP_TRACE_LOG(LL_SYS, L"SDKHelper released!");
		}
		
		auto bRet = false;

		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().DataInstance())
		{
			switch (NoMercyCore::CApplication::Instance().DataInstance()->GetAppType())
			{
				case NM_CLIENT:
				{
					bRet = FinalizeClient();
				} break;

				case NM_STANDALONE:
					break;

				default:
				{
					APP_TRACE_LOG(LL_CRI, L"Unknown app type: %d", NoMercyCore::CApplication::Instance().DataInstance()->GetAppType());
					return bRet;
				}
			}
		}
		APP_TRACE_LOG(LL_SYS, L"Application specific release completed! Result: %d", bRet ? 1 : 0);

		auto idx = 0;

		ReleaseWsHeartbeatWorker();

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 1

		if (IS_VALID_SMART_PTR(m_spWindowWatcher))
		{
			m_spWindowWatcher->Release();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 2

		if (IS_VALID_SMART_PTR(m_spSelfHooks))
		{
			m_spSelfHooks->CleanupHooks();
		}
		
		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 3

		if (IS_VALID_SMART_PTR(m_spQuarentineMgr))
		{
			m_spQuarentineMgr->Release();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 4

		if (IS_VALID_SMART_PTR(m_spScannerInterface))
		{
			m_spScannerInterface->FinalizeScanner();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d / 5 completed!", ++idx); // 5


		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 6

		if (IS_VALID_SMART_PTR(m_spCheatQueue))
		{
			m_spCheatQueue->ReleaseThread();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 7

		/*
		if (IS_VALID_SMART_PTR(m_spNetworkMgr))
		{
			m_spNetworkMgr->CleanupNetwork();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 8

		if (IS_VALID_SMART_PTR(m_spCacheManager))
		{
			m_spCacheManager->ReleaseThread();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 9

		if (IS_VALID_SMART_PTR(m_spThreadMgr))
		{
			m_spThreadMgr->DestroyThreads();
		}

		APP_TRACE_LOG(LL_SYS, L"Finalize routine step %d completed!", ++idx); // 10

		if (IS_VALID_HANDLE(m_hTimerQueue))
		{
			g_winAPIs->RtlDeleteTimerQueue(m_hTimerQueue);
			m_hTimerQueue = nullptr;
		}
		*/

		APP_TRACE_LOG(LL_SYS, L"Finalize routine completed!");

#ifdef _DEBUG
//		if (!m_bUnitTest)
//			_CrtDumpMemoryLeaks();

//		if (IsDebuggerPresent())
//			DebugBreak();

//		if (m_spData->GetAppType() != NM_TESTAPP && GetConsoleWindow())
//			FreeConsole();
#endif

		return bRet;
	}

	// Initialization
	bool CApplication::__IsCorePrepared()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

#ifdef _DEBUG
		APP_TRACE_LOG(LL_TRACE, L"m_spSDKHelper:%p",				m_spSDKHelper.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spThreadMgr:%p",				m_spThreadMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spFunctions:%p",				m_spFunctions.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spAccessHelper:%p",				m_spAccessHelper.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spWatchdog:%p",					m_spWatchdog.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spAnalyser:%p",					m_spAnalyser.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spSelfThreadIdentifier:%p",		m_spSelfThreadIdentifier.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spSelfHooks:%p",				m_spSelfHooks.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spNetworkMgr:%p",				m_spNetworkMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spScannerInterface:%p",			m_spScannerInterface.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spQuarentineMgr:%p",			m_spQuarentineMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spFilterMgr:%p",				m_spFilterMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spCheatDBMgr:%p",				m_spCheatDBMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spDataLoader:%p",				m_spDataLoader.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spGameIntegrationMgr:%p",		m_spGameIntegrationMgr.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spCheatQueue:%p",				m_spCheatQueue.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spGameRegionMonitor:%p",		m_spGameRegionMonitor.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spModuleSectionMonitor:%p",		m_spModuleSectionMonitor.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spWindowWatcher:%p",			m_spWindowWatcher.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spTelemetryManager:%p",			m_spTelemetryManager.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spHwbpWatcher:%p",				m_spHwbpWatcher.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spTickCounter:%p",				m_spTickCounter.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spCheatQueueManager:%p",		m_spCheatQueueManager.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spMemoryAllocationWatcher:%p",	m_spMemoryAllocationWatcher.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spWMIManager:%p",				m_spWMIManager.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spHookScanner:%p",				m_spHookScanner.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spManualMapScanner:%p",			m_spManualMapScanner.get());	
		APP_TRACE_LOG(LL_TRACE, L"m_spInputInjectMonitor:%p",		m_spInputInjectMonitor.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spCacheManager:%p",				m_spCacheManager.get());
		APP_TRACE_LOG(LL_TRACE, L"m_spWinDebugStrMonitor:%p",		m_spWinDebugStrMonitor.get());
#endif

		return (
			m_spSDKHelper					&& m_spSDKHelper.get()				&&
			m_spThreadMgr					&& m_spThreadMgr.get()				&&
			m_spFunctions					&& m_spFunctions.get()				&&
			m_spAccessHelper				&& m_spAccessHelper.get()			&&
			m_spWatchdog					&& m_spWatchdog.get()				&&
			m_spAnalyser					&& m_spAnalyser.get()				&&
			m_spSelfThreadIdentifier		&& m_spSelfThreadIdentifier.get()	&&
			m_spSelfHooks					&& m_spSelfHooks.get()				&&
			m_spNetworkMgr					&& m_spNetworkMgr.get()				&&
			m_spScannerInterface			&& m_spScannerInterface.get()		&&
			m_spQuarentineMgr				&& m_spQuarentineMgr.get()			&&
			m_spFilterMgr					&& m_spFilterMgr.get()				&&
			m_spCheatDBMgr					&& m_spCheatDBMgr.get()				&&
			m_spDataLoader					&& m_spDataLoader.get()				&&
			m_spGameIntegrationMgr			&& m_spGameIntegrationMgr.get()		&&
			m_spCheatQueue					&& m_spCheatQueue.get()				&&
			m_spGameRegionMonitor			&& m_spGameRegionMonitor.get()		&&
			m_spModuleSectionMonitor		&& m_spModuleSectionMonitor.get()	&&
			m_spWindowWatcher				&& m_spWindowWatcher.get()			&&
			m_spHwbpWatcher					&& m_spHwbpWatcher.get()			&&
			m_spTickCounter					&& m_spTickCounter.get()			&&
			m_spCheatQueueManager			&& m_spCheatQueueManager.get()		&&
			m_spMemoryAllocationWatcher		&& m_spMemoryAllocationWatcher.get() &&
			m_spWMIManager					&& m_spWMIManager.get()				&&
			m_spHookScanner					&& m_spHookScanner.get()			&&
			m_spManualMapScanner			&& m_spManualMapScanner.get()		&&
			m_spInputInjectMonitor			&& m_spInputInjectMonitor.get()		&&
			m_spCacheManager				&& m_spCacheManager.get()			&&
			m_spWinDebugStrMonitor			&& m_spWinDebugStrMonitor.get()		

		);
	}

	bool CApplication::PrepareCore(uint8_t eAppType)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		if (!NoMercyCore::CCoreIndex::IsInitialized())
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 3);
			return false;
		}

		if (eAppType == NM_CLIENT)
			m_abClientProcess = true;

		const auto spSafeExecutor = stdext::make_unique_nothrow<CSafeExecutor>(false);
		if (!IS_VALID_SMART_PTR(spSafeExecutor))
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_MEMORY_ALLOC_FAIL, 1);
			return false;
		}

		// Alloc main classes
		TPrepareCore PrepareCoreImpl = [&](int32_t eAppType) {
			m_spSDKHelper = stdext::make_shared_nothrow<CSDKManager>();
			m_spThreadMgr = stdext::make_shared_nothrow<CThreadManager>();
			m_spFunctions = stdext::make_shared_nothrow<CFunctions>();
			m_spAccessHelper = stdext::make_shared_nothrow<CAccess>();
			m_spWatchdog = stdext::make_shared_nothrow<CWatchdog>();
			m_spAnalyser = stdext::make_shared_nothrow<CAnalyser>();
			m_spSelfThreadIdentifier = stdext::make_shared_nothrow<CSelfThreadIdentifier>();
			m_spSelfHooks = stdext::make_shared_nothrow<CSelfApiHooks>();
			m_spNetworkMgr = stdext::make_shared_nothrow<CNetworkManager>();
			m_spScannerInterface = stdext::make_shared_nothrow<IScanner>();
			m_spQuarentineMgr = stdext::make_shared_nothrow<CQuarentine>();
			m_spFilterMgr = stdext::make_shared_nothrow<CFilterManager>();
			m_spCheatDBMgr = stdext::make_shared_nothrow<CCheatDBManager>();
			m_spDataLoader = stdext::make_shared_nothrow<CDataLoader>();
			m_spGameIntegrationMgr = stdext::make_shared_nothrow<CGameIntegrationManager>();
			m_spCheatQueue = stdext::make_shared_nothrow<CCheatQueue>();
			m_spGameRegionMonitor = stdext::make_shared_nothrow<CGameMemoryMonitor>();
			m_spModuleSectionMonitor = stdext::make_shared_nothrow<CModuleSectionMonitor>();
			m_spWindowWatcher = stdext::make_shared_nothrow<CWindowWatcher>();
			m_spHwbpWatcher = stdext::make_shared_nothrow<CHardwareBreakpointWatcher>();
			m_spTickCounter = stdext::make_shared_nothrow<CTickCounter>();
			m_spCheatQueueManager = stdext::make_shared_nothrow<CCheatQueueManager>();
			m_spMemoryAllocationWatcher = stdext::make_shared_nothrow<CMemAllocWatcher>();
			m_spWMIManager = stdext::make_shared_nothrow<CWMI>();
			m_spHookScanner = stdext::make_shared_nothrow<CHookScanner>();
			m_spManualMapScanner = stdext::make_shared_nothrow<CManualMapScanner>();
			m_spInputInjectMonitor = stdext::make_shared_nothrow<CInputInjectMonitor>();
			m_spCacheManager = stdext::make_shared_nothrow<CCacheManager>();
			m_spWinDebugStrMonitor = stdext::make_shared_nothrow<CWinDebugMonitor>();


			return true;
		};

		const auto spRet = spSafeExecutor->SafeExecArg<bool>(SAFE_FUNCTION_ID_PREPARE_CORE, PrepareCoreImpl, (int32_t)eAppType);
		APP_TRACE_LOG(LL_SYS, L"PrepareCore safe execution completed. Ptr: %p Error code: %p", spRet.get(), spRet ? spRet->error_code : 0);

		if (IS_VALID_SMART_PTR(spRet) && spRet->error_code && IS_VALID_SMART_PTR(spRet->exception))
		{
			APP_TRACE_LOG(LL_CRI, L"PrepareCore Exception detected. Address: %p (%s) Code: %p Flags: %u", spRet->exception->address, spRet->exception->address_symbol, spRet->exception->code, spRet->exception->flags);

			APP_TRACE_LOG(LL_SYS, L"Registers:");
			for (const auto& [reg, val] : spRet->exception->registers)
			{
				APP_TRACE_LOG(LL_SYS, L"%s: %p", reg.c_str(), val);
			}

			APP_TRACE_LOG(LL_SYS, L"Stack:");
			for (const auto& ctx : spRet->exception->stack)
			{
				if (IS_VALID_SMART_PTR(ctx))
				{
					APP_TRACE_LOG(LL_SYS, L"[%llu] %p Module: %s Image: %s Symbol: %s File: %s (%u)", ctx->idx, ctx->frame, ctx->module_name, ctx->image_name, ctx->symbol_name, ctx->file_name, ctx->file_line);
				}
			}
		}

		// Have not returned data container
		if (!IS_VALID_SMART_PTR(spRet))
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_SAFE_EXECUTOR_FAIL, 1);
			return false;
		}
		// Have a error code (throwed exception)
		if (spRet->error_code)
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_SAFE_EXECUTOR_FAIL, 2);
			return false;
		}
		// Have not a return value (?)
		if (!spRet->return_value.has_value())
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_SAFE_EXECUTOR_FAIL, 3);
			return false;
		}
		// 'false' return value (prepare failed)
		if (!spRet->return_value.value())
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_SAFE_EXECUTOR_FAIL, 4);
			return false;
		}
		// setup is ok but some pointers are seems corrupted
		if (__IsCorePrepared() == false)
		{
			NoMercyCore::OnPreFail(eAppType, CORE_ERROR_SAFE_EXECUTOR_FAIL, 5);
			return false;
		}

		m_abAppIsPrepared = true;
		return true;
	}

	// Self module protection
	bool CApplication::InitSelfProtection(LDR_DATA_TABLE_ENTRY* pModuleInfo)
	{
		const auto c_nAppType = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
		if (c_nAppType != NM_CLIENT)
			return true;

		APP_TRACE_LOG(LL_SYS, L"Self protection routine has been started! Module: %p", pModuleInfo);
		
		if (pModuleInfo)
		{
			const auto stAppType = GetAppTypeNameA(c_nAppType);
			APP_TRACE_LOG(LL_SYS, L"Self protection target: %hs", stAppType.c_str());
			
			const auto hModule = reinterpret_cast<HMODULE>(pModuleInfo->DllBase);
			if (!hModule)
			{
				APP_TRACE_LOG(LL_CRI, L"WHO AM I????");
				return true;
			}

			/*
			if (!CSelfProtection::SetupEntrypointWatchdog())
			{
				OnCloseRequest(EXIT_ERR_ENTRYPOINT_WATCHDOG_INIT_FAIL, g_winAPIs->GetLastError());
				return false;
			}
			*/

			/*
			if (CSelfProtection::InitializeAntiDump(hModule) == false)
			{
				OnCloseRequest(EXIT_ERR_ANTI_DUMP_INIT_FAIL, g_winAPIs->GetLastError());
				return false;
			}
			*/

//			CSelfProtection::HideModuleLinks(hModule);

//			CSelfProtection::CheckSelfPatchs();

//			CSelfProtection::ProtectSelfPE(hModule);

#ifdef __EXPERIMENTAL__
			CSelfProtection::InitializeAntiMemoryTamper();
			CSelfProtection::initialize_protection(hModule, xorstr_(".text"));
			CSelfProtection::DestroyIAT(hModule);
			CSelfProtection::MakePePacked(hModule);
#endif

#ifdef __EXPERIMENTAL__
			CSelfProtection::InitializeMutation(1337);
			CSelfProtection::InitializeCFGHook(hModule);
#endif


			APP_TRACE_LOG(LL_SYS, L"Self protection routine completed!");
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"Self protection routine fail!");
			return false;
		}
		return true;
	}

	// Queue helper
	VOID CALLBACK WsQueueProcessor(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		if (!CApplication::Instance().NetworkIsReady())
			return;

		const auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();
		if (!ws)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_CLIENT_ACCESS_FAIL, 0);
			return;
		}

		const auto msg = CApplication::Instance().DequeueWsMessage();	
		if (!msg.empty())
		{
			if (msg.at(0) == '{')
			{
				auto document = rapidjson::GenericDocument<UTF16<>>{};
				document.Parse(msg.data());
				if (document.HasParseError())
				{
					APP_TRACE_LOG(LL_ERR, L"Queued json message parse failed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
					APP_TRACE_LOG(LL_WARN, L"Message: %s", msg.c_str());
					return;
				}
				else if (!document.IsObject())
				{
					APP_TRACE_LOG(LL_ERR, L"Queued json message base is not an object. Type: %d", document.GetType());
					APP_TRACE_LOG(LL_WARN, L"Message: %s", msg.c_str());
					return;
				}

				if (!document.HasMember(xorstr_(L"id")))
				{
					ws->send_message(msg, true);
					return;
				}
				else
				{
					uint8_t nID = 0;
					const auto& id = document[xorstr_(L"id")];
					if (!id.IsString() && !id.IsNumber())
					{
						APP_TRACE_LOG(LL_ERR, L"Queued json message id type is not string and number. Type: %d", id.GetType());
						return;
					}

					if (id.IsString())
					{
						const auto stID = std::wstring(id.GetString(), id.GetStringLength());
						APP_TRACE_LOG(LL_SYS, L"ID: %s", stID.c_str());

						if (stID.empty())
						{
							APP_TRACE_LOG(LL_ERR, L"Queued json message id value is null!");
							return;
						}
						else if (!stdext::is_number(stID))
						{
							APP_TRACE_LOG(LL_ERR, L"Queued json message id value is not number!");
							return;
						}

						nID = stdext::str_to_u8(stID);
					}
					else if (id.IsNumber())
					{
						nID = id.GetUint();
					}

					switch (nID)
					{
						case QUEUE_MESSAGE_TYPE_CHEAT_DETECT:
						{
							const auto& ref_id = document[xorstr_(L"ref_id")];
							const auto& cheat_id = document[xorstr_(L"cheat_id")];
							const auto& cheat_sub_id = document[xorstr_(L"cheat_sub_id")];
							const auto& cheat_details_msg = document[xorstr_(L"cheat_details_msg")];

							std::vector <std::wstring> vScreenshotPaths{};
							for (std::size_t i = 0; i < MAX_SCREENSHOT_COUNT; ++i)
							{
								const auto stScreenshotKey = xorstr_(L"screenshot_") + std::to_wstring(i);
								if (document.HasMember(stScreenshotKey.c_str()))
								{
									const auto& screenshot = document[stScreenshotKey];
									if (screenshot.IsString())
									{
										const auto stScreenshotPath = std::wstring(screenshot.GetString(), screenshot.GetStringLength());
										if (!stScreenshotPath.empty())
										{
											vScreenshotPaths.push_back(stScreenshotPath);
										}
									}
								}
							}

							ws->send_cheat_detection_message(
								ref_id.GetString(),
								cheat_id.GetString(),
								cheat_sub_id.GetString(),
								cheat_details_msg.GetString(),
								vScreenshotPaths
							);
						} break;

						default:
						{
							APP_TRACE_LOG(LL_ERR, L"Undefined message id: %u", nID);
							break;
						}
					}
				}
			}
			else
			{
				ws->send_message(msg, true);
			}
		}
	}
	void CApplication::EnqueueWsMessage(const std::wstring& stMessage)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		APP_TRACE_LOG(LL_SYS, L"Enqueued websocket message: %s", stMessage.c_str());
		m_kMessageQueue.enqueue(stMessage);
	}
	std::wstring CApplication::DequeueWsMessage()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		std::wstring msg{};
		if (!m_kMessageQueue.try_dequeue(msg))
		{
//			APP_TRACE_LOG(LL_WARN, L"Message dequeue failed!");
			return {};
		}

		APP_TRACE_LOG(LL_SYS, L"Dequeued websocket message: %s", msg.c_str());
		return msg;
	}
	void CApplication::CreateWsQueueWorker()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		if (m_hWsQueueProcessorTimer)
			return;
		
		const auto ntStatus = g_winAPIs->RtlCreateTimer(m_hTimerQueue, &m_hWsQueueProcessorTimer, WsQueueProcessor, nullptr, 0, 5000, WT_EXECUTELONGFUNCTION);
		if (!NT_SUCCESS(ntStatus) || !IS_VALID_HANDLE(m_hWsQueueProcessorTimer))
		{
			OnCloseRequest(EXIT_ERR_WS_QUEUE_WORKER_TIMER_FAIL, ntStatus);
			return;
		}
	}
	void CApplication::ReleaseWsQueueWorker()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		if (IS_VALID_HANDLE(m_hTimerQueue) && IS_VALID_HANDLE(m_hWsQueueProcessorTimer))
		{
			g_winAPIs->RtlDeleteTimer(m_hTimerQueue, m_hWsQueueProcessorTimer, INVALID_HANDLE_VALUE);
			m_hWsQueueProcessorTimer = INVALID_HANDLE_VALUE;
		}
	}

	void CApplication::AppendWsHearbeatRequest(uint8_t byKey)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		m_kWSHeartbeatQueue.enqueue(byKey);
		APP_TRACE_LOG(LL_SYS, L"Enqueued websocket heartbeat request key: %u", byKey);
	}
	uint8_t CApplication::DequeHeartbeatKey()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		uint8_t byHearbeatKey = 0;
		m_kWSHeartbeatQueue.try_dequeue(byHearbeatKey);

		return byHearbeatKey;
	}
	void CApplication::ProcessWsHearbeatRequest()
	{		
		const auto byHearbeatKey = DequeHeartbeatKey();
		if (!byHearbeatKey)
			return;

		APP_TRACE_LOG(LL_SYS, L"Dequeued websocket hearbeat key: %u", byHearbeatKey);
		
		// Check network status
		if (!CApplication::Instance().NetworkIsReady())
		{
			APP_TRACE_LOG(LL_WARN, L"Network is not ready yet, adding the current heartbeat key to the queue again");
			AppendWsHearbeatRequest(byHearbeatKey);
			return; 
		}

		uint8_t nStatus = 0;

		enum class EWSHearbeatStatus : uint8_t
		{
			SELF_INTEGRITY = 0x01,
			COMM_DRIVER_INTEGRITY = 0x02,
			COMM_GAME_CLIENT_INTEGRITY = 0x04,
			TELEMETRY_INTEGRITY = 0x08,
			THREAD_INTEGRITY = 0x10,
		};
		
		// Build heartbeat response for self integrity
		const auto bServiceIsProtected = NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->IsProcessProtected();
		APP_TRACE_LOG(LL_SYS, L"Service is protected: %s", bServiceIsProtected ? xorstr_(L"true") : xorstr_(L"false"));
		if (bServiceIsProtected)
			nStatus |= static_cast<uint8_t>(EWSHearbeatStatus::SELF_INTEGRITY);

		// Build heartbeat response for thread integrity (todo)
		/*
		const auto bThreadIntegrityOK = CApplication::Instance().SelfThreadIdentifierInstance()->IsTickCheckerThreadIntegrityCorrupted();
		APP_TRACE_LOG(LL_SYS, L"Thread integrity is OK: %s", bThreadIntegrityOK ? xorstr_(L"true") : xorstr_(L"false"));
		if (bThreadIntegrityOK)
			nStatus |= static_cast<uint8_t>(EWSHearbeatStatus::THREAD_INTEGRITY);
		*/
		nStatus |= static_cast<uint8_t>(EWSHearbeatStatus::THREAD_INTEGRITY);

		// Send heartbeat response
		CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient()->send_heartbeat_response(nStatus, byHearbeatKey);
	}
	VOID CALLBACK WsHeartbeatRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		if (!CApplication::Instance().NetworkIsReady())
			return; // lost connection, or?

		CApplication::Instance().ProcessWsHearbeatRequest();
	}
	void CApplication::CreateWsHearbeatWorker()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		// Server time: 10 minutes for live, 10 seconds for debug
		static constexpr auto HEARTBEAT_PERIOD = stdext::is_debug_build() ? 5000 : 30000;
		
		if (m_hWsHeartbeatTimer)
			return;
		
		const auto ntStatus = g_winAPIs->RtlCreateTimer(m_hTimerQueue, &m_hWsHeartbeatTimer, WsHeartbeatRoutine, nullptr, 0, HEARTBEAT_PERIOD, WT_EXECUTELONGFUNCTION);
		if (!NT_SUCCESS(ntStatus) || !IS_VALID_HANDLE(m_hWsHeartbeatTimer))
		{
			OnCloseRequest(EXIT_ERR_WS_HEARTBEAT_TIMER_FAIL, ntStatus);
			return;
		}
	}
	void CApplication::ReleaseWsHeartbeatWorker()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);
		
		if (IS_VALID_HANDLE(m_hTimerQueue) && IS_VALID_HANDLE(m_hWsHeartbeatTimer))
		{
			g_winAPIs->RtlDeleteTimer(m_hTimerQueue, m_hWsHeartbeatTimer, INVALID_HANDLE_VALUE);
			m_hWsHeartbeatTimer = INVALID_HANDLE_VALUE;
		}
	}
};
