#include "../../include/PCH.hpp"
#include "../../include/SentryManager.hpp"
#include "../../include/Application.hpp"
#include "../../include/Defines.hpp"
#include "../../include/Application.hpp"
#include "../../include/BasicLog.hpp"
#include "../../include/Elevation.hpp"
#include <crashpad/client/crash_report_database.h>
#include <crashpad/client/settings.h>
#include <crashpad/client/crashpad_client.h>
#include <crashpad/client/simulate_crash_win.h>
using namespace crashpad;

#define DISABLE_SENTRY

namespace NoMercyCore
{
	static constexpr auto gsc_nTimeLimit = 24 * 60 * 60; // 24 hours

	CSentryManager::CSentryManager() :
		m_bInitialized(false), m_bUserCreated(false), m_pSentryOptions(nullptr)
	{
	}
	CSentryManager::~CSentryManager()
	{
	}

	void CSentryManager::SendLog(const sentry_level_t nLevel, const std::string& c_stCategory, const std::string& c_stMessage)
	{
		if (!m_bInitialized)
			return;

//		if (stdext::is_debug_env())
//			return;

		struct SContext
		{
			sentry_level_t nLevel{ SENTRY_LEVEL_DEBUG };
			std::string stCategory;
			std::string stMessage;
		};
		auto workerThread = [](LPVOID lpParam) -> DWORD {
			auto fnSendSentryLogImpl = [](SContext* pContext) -> sentry_uuid_t {
				__try
				{
					return sentry_capture_event(sentry_value_new_message_event(
						pContext->nLevel,
						pContext->stCategory.c_str(),
						pContext->stMessage.c_str()
					));
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return {};
				}
			};
			
			auto pContext = static_cast<SContext*>(lpParam);
			APP_TRACE_LOG(LL_SYS, L"Sentry message :: [%d] %hs - %hs", pContext->nLevel, pContext->stCategory.c_str(), pContext->stMessage.c_str());

			const auto val = fnSendSentryLogImpl(pContext);
			
			char szUUID[38]{ '\0' };
			sentry_uuid_as_string(&val, szUUID);
			szUUID[37] = '\0';

			const auto wstUUID = stdext::to_wide(szUUID);
			APP_TRACE_LOG(LL_SYS, L"Sentry message sent! UUID: %s Thread: %u", wstUUID.c_str(), g_winAPIs->GetCurrentThreadId());

			delete lpParam;
			return 0;
		};

		auto context = new(std::nothrow) SContext{ nLevel, c_stCategory, c_stMessage };
		if (!context)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for sentry message context");
			return;
		}

		DWORD dwThreadID = 0;
		auto hThread = g_winAPIs->CreateThread(nullptr, 0, workerThread, context, 0, &dwThreadID);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to create sentry message thread");
			delete context;
			return;
		}

		g_winAPIs->WaitForSingleObject(hThread, 3000);

		APP_TRACE_LOG(LL_SYS, L"Sentry message thread: %u created", dwThreadID);
		g_winAPIs->CloseHandle(hThread);
	}

	void CSentryManager::SetUserData(const std::string& c_stHwid, const std::string& c_stSID, const std::string& c_stBootID, const std::string& c_stAntivirusInfo)
	{
		auto GetOSBootTime = [](QWORD qwOSUptime) {
			uint64_t timeNow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) * 1000;
			return timeNow - qwOSUptime;
		};
		
		if (!m_bInitialized)
			return;
		
		auto fnCreateUser = [&]() {
			if (m_bUserCreated)
				sentry_remove_user();

			auto user = sentry_value_new_object();

			if (!c_stHwid.empty())
				sentry_value_set_by_key(user, xorstr_("uuid"), sentry_value_new_string(c_stHwid.c_str()));
			if (!c_stSID.empty())
				sentry_value_set_by_key(user, xorstr_("sid"), sentry_value_new_string(c_stSID.c_str()));
			if (!c_stBootID.empty())
				sentry_value_set_by_key(user, xorstr_("boot_id"), sentry_value_new_string(c_stBootID.c_str()));
			if (!c_stAntivirusInfo.empty())
				sentry_value_set_by_key(user, xorstr_("antivirus"), sentry_value_new_string(c_stAntivirusInfo.c_str()));

			if (!m_stEnvironment.empty())
				sentry_value_set_by_key(user, xorstr_("environment"), sentry_value_new_string(m_stEnvironment.c_str()));

			sentry_value_set_by_key(user, xorstr_("cpu"), sentry_value_new_string(
				stdext::is_x64_windows() ?
				stdext::is_wow64() ?
				xorstr_("x86-64") :
				xorstr_("x64") :
				xorstr_("x86")
			));

			const auto stAppType = GetAppTypeNameA(CApplication::Instance().GetAppType());
			sentry_value_set_by_key(user, xorstr_("app"), sentry_value_new_string(stAppType.c_str()));

			const auto stPID = std::to_string(g_winAPIs->GetCurrentProcessId());
			sentry_value_set_by_key(user, xorstr_("pid"), sentry_value_new_string(stPID.c_str()));

			const auto stVersion = std::to_string(__NOMERCY_VERSION__);
			sentry_value_set_by_key(user, xorstr_("ver"), sentry_value_new_string(stVersion.c_str()));

			const auto stStage = stdext::to_ansi(CApplication::Instance().DataInstance()->GetStageStr());
			sentry_value_set_by_key(user, xorstr_("stage"), sentry_value_new_string(stStage.c_str()));

			MEMORYSTATUSEX memStatus{};
			memStatus.dwLength = sizeof(memStatus);
			if (g_winAPIs->GlobalMemoryStatusEx(&memStatus))
			{
				const auto stTotalMemory = stdext::to_ansi(stdext::number_fmt(memStatus.ullTotalPhys));
				sentry_value_set_by_key(user, xorstr_("total_memory"), sentry_value_new_string(stTotalMemory.c_str()));

				const auto stFreeMemory = stdext::to_ansi(stdext::number_fmt(memStatus.ullAvailPhys));
				sentry_value_set_by_key(user, xorstr_("free_memory"), sentry_value_new_string(stFreeMemory.c_str()));

				const auto stTotalVirtualMemory = stdext::to_ansi(stdext::number_fmt(memStatus.ullTotalVirtual));
				sentry_value_set_by_key(user, xorstr_("total_virtual_memory"), sentry_value_new_string(stTotalVirtualMemory.c_str()));

				const auto stFreeVirtualMemory = stdext::to_ansi(stdext::number_fmt(memStatus.ullAvailVirtual));
				sentry_value_set_by_key(user, xorstr_("free_virtual_memory"), sentry_value_new_string(stFreeVirtualMemory.c_str()));
			}

			const auto wstWinPath = CApplication::Instance().DirFunctionsInstance()->WinPath();
			if (!wstWinPath.empty())
			{
				const auto stWinPath = stdext::to_ansi(wstWinPath);
				sentry_value_set_by_key(user, xorstr_("win_path"), sentry_value_new_string(stWinPath.c_str()));
			}

			const auto wstSystemPath = CApplication::Instance().DirFunctionsInstance()->SystemPath();
			if (!wstSystemPath.empty())
			{
				const auto stSystemPath = stdext::to_ansi(wstSystemPath);
				sentry_value_set_by_key(user, xorstr_("system_path"), sentry_value_new_string(stSystemPath.c_str()));
			}

			const auto wstSystemPath2 = CApplication::Instance().DirFunctionsInstance()->SystemPath2();
			if (!wstSystemPath2.empty())
			{
				const auto stSystemPath2 = stdext::to_ansi(wstSystemPath2);
				sentry_value_set_by_key(user, xorstr_("system_path2"), sentry_value_new_string(stSystemPath2.c_str()));
			}

			const auto wstTempPath = CApplication::Instance().DirFunctionsInstance()->TempPath();
			if (!wstTempPath.empty())
			{
				const auto stTempPath = stdext::to_ansi(wstTempPath);
				sentry_value_set_by_key(user, xorstr_("temp_path"), sentry_value_new_string(stTempPath.c_str()));
			}

			const auto wstExePath = CApplication::Instance().DirFunctionsInstance()->ExePath();
			if (!wstExePath.empty())
			{
				const auto stExePath = stdext::to_ansi(wstExePath);
				sentry_value_set_by_key(user, xorstr_("exe_path"), sentry_value_new_string(stExePath.c_str()));
			}

			const auto wstCurrentPath = CApplication::Instance().DirFunctionsInstance()->CurrentPath();
			if (!wstCurrentPath.empty())
			{
				const auto stCurrentPath = stdext::to_ansi(wstCurrentPath);
				sentry_value_set_by_key(user, xorstr_("current_path"), sentry_value_new_string(stCurrentPath.c_str()));
			}

			wchar_t szDrive[MAX_PATH]{ '\0' }, szFolder[MAX_PATH]{ '\0' }, szName[MAX_PATH]{ '\0' }, szExtension[MAX_PATH]{ '\0' };
			const auto err = _wsplitpath_s(
				wstWinPath.c_str(),
				szDrive, MAX_PATH,
				szFolder, MAX_PATH,
				szName, MAX_PATH,
				szExtension, MAX_PATH
			);
			if (err == ERROR_SUCCESS && szDrive[0] != '\0')
			{
				// get disk usage
				ULARGE_INTEGER uliFreeBytesAvailableToCaller{}, uliTotalNumberOfBytes{}, uliTotalNumberOfFreeBytes{};
				if (g_winAPIs->GetDiskFreeSpaceExW(szDrive, &uliFreeBytesAvailableToCaller, &uliTotalNumberOfBytes, &uliTotalNumberOfFreeBytes))
				{
					const auto stTotalDiskSpace = stdext::to_ansi(stdext::number_fmt(uliTotalNumberOfBytes.QuadPart));
					sentry_value_set_by_key(user, xorstr_("total_disk_space"), sentry_value_new_string(stTotalDiskSpace.c_str()));

					const auto stFreeDiskSpace = stdext::to_ansi(stdext::number_fmt(uliFreeBytesAvailableToCaller.QuadPart));
					sentry_value_set_by_key(user, xorstr_("free_disk_space"), sentry_value_new_string(stFreeDiskSpace.c_str()));
				}
			}

			wchar_t szLocale[80]{ L'\0' };
			if (g_winAPIs->GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, szLocale, 80))
			{
				const auto stLocale = stdext::to_ansi(szLocale);
				sentry_value_set_by_key(user, xorstr_("locale"), sentry_value_new_string(stLocale.c_str()));
			}

			const auto bIsUserAdmin = g_winAPIs->IsUserAnAdmin();
			sentry_value_set_by_key(user, xorstr_("is_admin"), sentry_value_new_bool(bIsUserAdmin));

			const auto bIsAdmin = CElevationHelper::IsRunAsAdmin();
			sentry_value_set_by_key(user, xorstr_("as_admin"), sentry_value_new_bool(bIsAdmin));

			const auto bIsElevated = CElevationHelper::IsProcessElevated(NtCurrentProcess());
			sentry_value_set_by_key(user, xorstr_("is_elevated"), sentry_value_new_bool(bIsElevated));

			const auto qwOSUptime = g_winAPIs->GetTickCount64 ? g_winAPIs->GetTickCount64() : 0;
			const auto stOSUptime = std::to_string(qwOSUptime);
			sentry_value_set_by_key(user, xorstr_("os_uptime"), sentry_value_new_string(stOSUptime.c_str()));

			const auto qwOSBoottime = GetOSBootTime(qwOSUptime);
			const auto stOSBoottime = std::to_string(qwOSBoottime);
			sentry_value_set_by_key(user, xorstr_("os_boottime"), sentry_value_new_string(stOSBoottime.c_str()));

			wchar_t wszGeoInfo[1024]{ L'\0' };
			const auto GeoLocation = g_winAPIs->GetUserGeoID(GEOCLASS_NATION);
			if (GeoLocation != GEOID_NOT_AVAILABLE)
			{
				const auto nGeoInfoLength = g_winAPIs->GetGeoInfoW(GeoLocation, GEO_RFC1766, wszGeoInfo, 1024, 0);
				if (nGeoInfoLength == 0)
				{
					std::memset(&wszGeoInfo, 0, sizeof(wszGeoInfo));
				}
			}
			const auto stGeoInfo = stdext::to_ansi(wszGeoInfo);
			sentry_value_set_by_key(user, xorstr_("geo_info"), sentry_value_new_string(stGeoInfo.c_str()));

			DWORD dwUserNameSize = UNLEN + 1;
			wchar_t szLoggedUserName[UNLEN + 1]{ '\0' };
			const auto wstCurrDomain = CElevationHelper::GetCurrentDomain();
			if (g_winAPIs->GetUserNameW(szLoggedUserName, &dwUserNameSize) && !wstCurrDomain.empty())
			{
				const auto stUserName = stdext::to_ansi(szLoggedUserName);
				sentry_value_set_by_key(user, xorstr_("username1"), sentry_value_new_string(stUserName.c_str()));

				const auto stDomain = stdext::to_ansi(wstCurrDomain);
				sentry_value_set_by_key(user, xorstr_("domain1"), sentry_value_new_string(stDomain.c_str()));
			}
			else
			{
				wchar_t wszUserName2[255]{ L'\0' };
				wchar_t wszDomain[255]{ L'\0' };
				DWORD dwUserNameSize2 = 255, dwDomainSize = 255;
				const auto bUserDomainRet = CElevationHelper::GetCurrentUserAndDomain(wszUserName2, &dwUserNameSize2, wszDomain, &dwDomainSize);
				if (bUserDomainRet)
				{
					const auto stUserName = stdext::to_ansi(wszUserName2);
					sentry_value_set_by_key(user, xorstr_("username2"), sentry_value_new_string(stUserName.c_str()));

					auto wstDomain = stdext::strip_unicode(wszDomain);
					if (wstDomain.find(std::wstring(xorstr_(L" "))) != std::wstring::npos)
						wstDomain = stdext::replace(wstDomain, std::wstring(xorstr_(L" ")), std::wstring(xorstr_(L"_")));

					const auto stDomain = stdext::to_ansi(wstDomain);
					sentry_value_set_by_key(user, xorstr_("domain2"), sentry_value_new_string(stDomain.c_str()));
				}
			}

			sentry_set_user(user);
			return true;
		};
		
		__try
		{
			fnCreateUser();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

	void CSentryManager::AddAttachmentSafe(const std::wstring& wstAttachment, bool bTimeCheck)
	{
		// When we try add attachment more than a few hundreds(happened in 2000+), it's cause to fail in crashpad's StartHandler function without any log
		static constexpr auto MAX_ATTACHMENTS = 100;

		if (!m_bInitialized)
			return;
		
		const auto stAttachment = stdext::to_ansi(wstAttachment);

		if (!m_pSentryOptions)
			return;
	
		if (wstAttachment.empty())
			return;

		if (m_vecContainer.size() >= MAX_ATTACHMENTS)
		{
			APP_TRACE_LOG(LL_WARN, L"Max attachments count reached (%d)", MAX_ATTACHMENTS);
			return;
		}

		if (stdext::in_vector(m_vecContainer, stAttachment))
		{
			APP_TRACE_LOG(LL_WARN, L"Attachment already exist (%s)", wstAttachment.c_str());
			return;
		}

		std::error_code ec{};
		if (!std::filesystem::exists(stAttachment, ec))
		{
			APP_TRACE_LOG(LL_WARN, L"Attachment not found (%s)", wstAttachment.c_str());
			return;
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_WARN, L"Attachment exist check failed (%s)", wstAttachment.c_str());
			return;
		}

		if (bTimeCheck)
		{
			auto hFile = g_winAPIs->CreateFileW(
				wstAttachment.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
			);
			if (IS_VALID_HANDLE(hFile))
			{
				FILETIME ftCreate{};
				FILETIME ftAccess{};
				FILETIME ftWrite{};
				if (g_winAPIs->GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
				{
					const auto dwNowTime = stdext::get_current_epoch_time();
					const auto dwCreateTime = stdext::windows_ticks_to_unix_seconds(ftCreate.dwHighDateTime);
					const auto dwTimeDif = dwNowTime - dwCreateTime;
					if (dwTimeDif > gsc_nTimeLimit)
					{
						APP_TRACE_LOG(LL_WARN, L"Attachment (%s) is too old file! Create time: %u Now: %u Dif: %u",
							wstAttachment.c_str(), dwCreateTime, dwNowTime, dwTimeDif
						);
						g_winAPIs->CloseHandle(hFile);
						return;
					}
				}

				LARGE_INTEGER s{ 0 };
				if (!g_winAPIs->GetFileSizeEx(hFile, &s))
				{
					APP_TRACE_LOG(LL_ERR, L"GetFileSize(%s) failed with error: %u", wstAttachment.c_str(), g_winAPIs->GetLastError());
					g_winAPIs->CloseHandle(hFile);
					return;
				}
				
				const double sizeInMB = s.QuadPart / (1024.0 * 1024.0);
				if (sizeInMB > 50.0)
				{
					APP_TRACE_LOG(LL_WARN, L"Attachment (%s) Size: %.2f is greater then limit!", wstAttachment.c_str(), sizeInMB);
					g_winAPIs->CloseHandle(hFile);
					return;
				}

				g_winAPIs->CloseHandle(hFile);
			}
		}

		m_vecContainer.push_back(stAttachment);

		APP_TRACE_LOG(LL_SYS, L"Adding attachment: %s to sentry, Total attachment: %u", wstAttachment.c_str(), m_vecContainer.size());

		sentry_options_add_attachment(m_pSentryOptions, stAttachment.c_str());

		APP_TRACE_LOG(LL_SYS, L"Added attachment: %s to sentry, Total attachment: %u", wstAttachment.c_str(), m_vecContainer.size());
	}

	bool CSentryManager::Initialize()
	{
#ifdef DISABLE_SENTRY
		return true;
#endif

#if defined(_RELEASE_DEBUG_MODE_)
		if (g_winAPIs->IsDebuggerPresent())
		{
			m_bInitialized = true;
			return true;
		}
#endif
		if (m_bInitialized)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Crashpad manager initilization started!");

		m_pSentryOptions = sentry_options_new();
		if (!m_pSentryOptions)
		{
			APP_TRACE_LOG(LL_ERR, L"sentry options memory allocation failed!");
			return false;
		}

		auto wstWorkingPath = L""s;
		auto wstCrashpadHandlerWithPath = L""s;
		const auto c_wstCrashpadHandler = CRASHPAD_NAME;
		if (std::filesystem::exists(c_wstCrashpadHandler))
			wstWorkingPath = std::filesystem::current_path().wstring();
		else
			wstWorkingPath = CApplication::Instance().InitilizationManagerInstance()->GetNoMercyPath();
		wstCrashpadHandlerWithPath = fmt::format(xorstr_(L"{0}\\{1}"), wstWorkingPath, c_wstCrashpadHandler);

		std::error_code ec{};
		if (!std::filesystem::exists(wstCrashpadHandlerWithPath, ec))
		{
			APP_TRACE_LOG(LL_ERR, L"Sentry handler file: %s does not exist", wstCrashpadHandlerWithPath.c_str());
			return false;
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_ERR, L"Sentry handler file: %s exist check failed with error: %hs", wstCrashpadHandlerWithPath.c_str(), ec.message().c_str());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Crashpad handler file: %s, Working path: %s, Final path: %s",
			c_wstCrashpadHandler.c_str(), wstWorkingPath.c_str(), wstCrashpadHandlerWithPath.c_str()
		);

		const auto stCrashpadHandlerWithPath = stdext::to_ansi(wstCrashpadHandlerWithPath);
		const auto stDumpPath = stdext::to_ansi(xorstr_(L"NoMercy\\Dump"));
		const auto stWorkingPath = stdext::to_ansi(wstWorkingPath);
		const auto c_stDumpPath = fmt::format(xorstr_("{0}\\{1}"), stWorkingPath, stDumpPath);
		if (!std::filesystem::exists(c_stDumpPath, ec))
		{
			APP_TRACE_LOG(LL_WARN, L"Sentry handler dump path: %hs does not exist", c_stDumpPath.c_str());
			
			if (!std::filesystem::create_directories(c_stDumpPath, ec))
			{
				APP_TRACE_LOG(LL_ERR, L"Sentry handler dump path: %hs create failed with error: %hs", c_stDumpPath.c_str(), ec.message().c_str());
				return false;
			}
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_ERR, L"Sentry handler dump path: %hs exist check failed with error: %hs", c_stDumpPath.c_str(), ec.message().c_str());
			return false;
		}

		const auto c_stSentryDSN = stdext::to_ansi(SENTRY_DSN);
		APP_TRACE_LOG(LL_SYS, L"Dump path: %hs Sentry handler: %s (%s) Sentry DSN: %hs",
			c_stDumpPath.c_str(), c_wstCrashpadHandler.c_str(), wstCrashpadHandlerWithPath.c_str(), c_stSentryDSN.c_str()
		);

#if defined(_DEBUG)
		m_stEnvironment = xorstr_("debug");
#elif defined(_RELEASE_DEBUG_MODE_)
		m_stEnvironment = xorstr_("release_debug");
#elif defined(CI_RELEASE_BUILD)
		m_stEnvironment = xorstr_("ci_release");
#else
		m_stEnvironment = xorstr_("release");
#endif

		sentry_options_set_dsn(m_pSentryOptions, c_stSentryDSN.c_str());
		sentry_options_set_handler_path(m_pSentryOptions, stCrashpadHandlerWithPath.c_str());
		sentry_options_set_database_path(m_pSentryOptions, c_stDumpPath.c_str());
		sentry_options_set_release(m_pSentryOptions, __PRODUCT_VERSION__);
		sentry_options_set_traces_sample_rate(m_pSentryOptions, 1.0);
		AddAttachmentSafe(fmt::format(xorstr_(L"{0}\\NoMercy.log"), std::filesystem::current_path().wstring()), false);
		
		std::vector <std::string> vLogPaths;
		
		const auto nAppType = CApplication::Instance().GetAppType();
		
		auto wstLogPath = L""s;
		if (nAppType == NM_STANDALONE)
			wstLogPath = fmt::format(xorstr_(L"{0}\\Log"), wstWorkingPath);
		else
			wstLogPath = fmt::format(xorstr_(L"NoMercy\\Log"), std::filesystem::current_path().wstring());

		if (std::filesystem::exists(wstLogPath))
		{
			APP_TRACE_LOG(LL_SYS, L"#1 Log path: %s added to container", wstLogPath.c_str());
			vLogPaths.push_back(stdext::to_ansi(wstLogPath));
		}
		
		APP_TRACE_LOG(LL_SYS, L"Log paths count: %d", vLogPaths.size());

		for (const auto& stPath : vLogPaths)
		{
			APP_TRACE_LOG(LL_SYS, L"Current log path: %hs", stPath.c_str());
			
			try
			{
				for (const auto& entry : std::filesystem::recursive_directory_iterator(stPath, ec))
				{
					if (entry.is_regular_file() && entry.path().extension() == xorstr_(L".log"))
					{
						const auto wstFileName = entry.path().wstring();
						if (wstFileName.find(xorstr_(L"old\\")) != std::wstring::npos)
						{
							// APP_TRACE_LOG(LL_WARN, L"Old log file: %hs found and will be ignored", stFileName.c_str());
							continue;
						}

						AddAttachmentSafe(wstFileName, true);
					}
				}
			}
			catch (const std::filesystem::filesystem_error& ex)
			{
				APP_TRACE_LOG(LL_ERR, L"Log files search failed with error: %hs, Paths: '%s', '%s'",  ex.what(), ex.path1().wstring().c_str(), ex.path2().wstring().c_str());
			}
			catch (...)
			{
				APP_TRACE_LOG(LL_ERR, L"Log files search failed with unknown error");
			}
			
			if (ec)
			{
				APP_TRACE_LOG(LL_ERR, L"Error while iterating through directory: %hs", ec.message().c_str());
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Log files iterating...");

		// Game specific files
		if (nAppType == NM_CLIENT)
		{
			const auto wstCurrentPath = std::filesystem::current_path().wstring();
			std::vector <std::wstring> vecGameLogs = {
				xorstr_(L"syserr.txt"),
				xorstr_(L"debug.log"),
				xorstr_(L"ceflog.txt"),
			};
			const auto wstTlsLogFilename = stdext::to_wide(CUSTOM_TLS_LOG_FILENAME);
			vecGameLogs.emplace_back(wstTlsLogFilename);

			for (const auto& wstFile : vecGameLogs)
			{
				const auto wstFilePath = fmt::format(xorstr_(L"{0}\\{1}"), wstCurrentPath, wstFile);
				if (std::filesystem::exists(wstFilePath))
				{
					AddAttachmentSafe(wstFilePath, false);
				}
			}
		}
		
		APP_TRACE_LOG(LL_SYS, L"All log files added to container");

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		sentry_options_set_symbolize_stacktraces(m_pSentryOptions, 1);
#endif
		sentry_options_set_debug(m_pSentryOptions, 1);

		sentry_options_set_logger(m_pSentryOptions, [](sentry_level_t level, const char* message, va_list args, void* userdata) {
			if (!message || !*message || level < 1 && !strstr(message, xorstr_("fail")))
				return;

			static auto s_cbBufferSize = 0x2000;

			const auto dwFormatSize = _vscprintf(message, args) + 1;
			if (dwFormatSize > s_cbBufferSize)
			{
				s_cbBufferSize = dwFormatSize + 0x100;
			}

			const auto lpszBuffer = static_cast<char*>(calloc(s_cbBufferSize, sizeof(char)));
			if (!lpszBuffer)
			{
				const auto err = errno;
				const auto c_stBuffer = fmt::format(xorstr_(L"Memory allocation failed for sentry log operation! Last error: {0}"), err);
				APP_TRACE_LOG(LL_CRI, L"%s", c_stBuffer.c_str());
				return;
			}

			const auto cbBufferLength = _vsnprintf_s(lpszBuffer, s_cbBufferSize, s_cbBufferSize - 1, message, args);
			if (cbBufferLength < 0)
			{
				const auto err = errno;
				const auto c_stBuffer = fmt::format(
					xorstr_("_vsnprintf_s returned with negative value. Last error: {0} Length: {1} Raw message: {2}"),
					err, cbBufferLength, message
				);
				APP_TRACE_LOG(LL_CRI, L"%hs", c_stBuffer.c_str());
				free(lpszBuffer);
				return;
			}
			
			APP_TRACE_LOG(LL_WARN, L"[Sentry - %d]: %hs", level, lpszBuffer);
			free(lpszBuffer);
		}, nullptr);

		int nSentryInitRet = 0;
		auto fnSentryInitEx = [&]() {
			nSentryInitRet = sentry_init(m_pSentryOptions);
		};
		auto fnSentryInitSafe = [&]() {
			__try
			{
				fnSentryInitEx();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		fnSentryInitSafe();
		if (nSentryInitRet)
		{
			APP_TRACE_LOG(LL_CRI, L"sentry_init failed with code: %d", nSentryInitRet);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Sentry initialized.");

		m_bInitialized = true;

		this->SetUserData("", "", "", "");

		CApplication::Instance().SetFatalErrorCallback([]() {
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Fatal error occurred."));
#ifndef _DEBUG // Debug builds and symbols does not exist in remote server, proxy will already fail when try fetch em
			CRASHPAD_SIMULATE_CRASH();
#endif
		});

		return true;
	}

	bool CSentryManager::Release()
	{
		if (!m_bInitialized)
			return false;

		sentry_close();

		m_bInitialized = false;
		return true;
	}
};
