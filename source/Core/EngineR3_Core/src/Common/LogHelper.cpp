#include "../../include/PCH.hpp"
#include "../../include/BasicLog.hpp"
#include "../../include/LogHelper.hpp"
#include "../../include/LogDBKey.hpp"

#if (defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)) && !defined(USE_SPDLOG)
#define DISABLE_LOG_ENCRYPTION
#endif

// TODO: Encrypted spdlog custom sink

namespace NoMercyCore
{
	static constexpr auto gsc_nFileLimit = 10'000'000; // 10 MB

	static void __LoggerErrorHandler(const std::string& strMessage)
	{
		const auto wstrMessage = stdext::to_wide(strMessage);
		LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Log error handled: '%s'"), wstrMessage.c_str());
	}

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	static std::wstring __GetCategoryName(uint32_t id)
	{
		switch (id)
		{
			case LOG_GENERAL:
				return L"GENERAL";
			case LOG_HOOK:
				return L"HOOK";
			case LOG_SCANNER:
				return L"SCANNER";
			case LOG_SDK:
				return L"SDK";
			case LOG_WMI:
				return L"WMI";
			case LOG_NETWORK:
				return L"NETWORK";
			case LOG_KERNEL:
				return L"KERNEL";
			default:
				return fmt::format(L"<unknown_id> {0}", id);
		}
	}
#endif


	CLogStack::CLogStack(const uint8_t nLimit) :
		m_nLimit(nLimit)
	{
		m_vLogStack.reserve(nLimit + 1);
	}
	CLogStack::~CLogStack()
	{
	}

	void CLogStack::Append(const std::wstring& stMessage)
	{
		m_vLogStack.emplace_back(stMessage);

		const auto nStackSize = m_vLogStack.size();

		/*
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		const auto stDbgMessage = fmt::format("Stack size: {0} First message: {1}\n", nStackSize, m_vLogStack.at(0));
		NoMercyCore::CApplication::Instance().LogHelperInstance()->GetLogger()->info(stDbgMessage);
		NoMercyCore::CApplication::Instance().LogHelperInstance()->GetLogger()->flush();
#endif
		*/

		if (nStackSize >= m_nLimit)
			m_vLogStack.erase(m_vLogStack.begin());
	}

	auto CLogStack::Get() const
	{
		return m_vLogStack;
	}
	auto CLogStack::GetString() const
	{
		std::wstring wstOut;
		auto fnCollectStr = [&]() {
			auto idx = 0;
			std::wstringstream ss;
			for (const auto& stMessage : m_vLogStack)
			{
				ss << '[' << idx++ << '] ' << stMessage << std::endl;
			}
			wstOut = ss.str();
		};
		auto fnCollectStrSafe = [&]() {
			__try
			{
				fnCollectStr();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};

		fnCollectStrSafe();
		return wstOut;
	}
	auto CLogStack::GetJson() const
	{
		GenericStringBuffer<UTF16<> > s;
		PrettyWriter <GenericStringBuffer<UTF16<> >> writer(s);

		writer.StartObject();
		{
			uint8_t idx = 0;
			for (const auto& wstMessage : m_vLogStack)
			{
				const auto stMessage = stdext::to_ansi(wstMessage);
				const auto stIndex = std::to_string(idx++);

				writer.Key(stIndex.c_str());
				writer.String(stMessage.c_str());
			}
		}
		writer.EndObject();

		std::ostringstream oss;
		oss << std::setw(4) << s.GetString() << std::endl;
		return oss.str();
	}


	CLogHelper::CLogHelper(const uint8_t nAppType, const std::wstring& strFileName) :
		m_nAppType(nAppType), m_wstrFileName(strFileName), m_bInitialized(false), m_pvLogCallbackFn(nullptr), m_bLogDisabled(false)
#ifndef USE_SPDLOG
		, m_pkDatabase(nullptr)
#endif
	{
		m_spLogStack = std::make_shared<CLogStack>(5);
		m_wstrLoggerName = fmt::format(xorstr_(L"NM_{0}_Logger"), nAppType);
	}
	CLogHelper::~CLogHelper()
	{
		m_bInitialized = false;
	}

	bool CLogHelper::Initialize()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		std::error_code ec;
		if (std::filesystem::exists(m_wstrFileName, ec))
			std::filesystem::remove(m_wstrFileName, ec);
			
		auto stFileName = stdext::to_ansi(m_wstrFileName);
	
#ifdef USE_SPDLOG
		try
		{
			auto sinks = std::vector<spdlog::sink_ptr>();
			sinks.push_back(stdext::make_shared_nothrow<spdlog::sinks::stdout_color_sink_mt>());
			sinks.push_back(stdext::make_shared_nothrow<spdlog::sinks::msvc_sink_mt>());
			sinks.push_back(stdext::make_shared_nothrow<spdlog::sinks::basic_file_sink_mt>(stFileName.c_str()));

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
			const auto delimiter = "NoMercy\\Log";
			const auto pos = stFileName.find(delimiter);
			if (pos != std::string::npos)
				stFileName = stFileName.substr(pos);
#endif

			m_spLoggerImpl = stdext::make_shared_nothrow<spdlog::logger>(stFileName.c_str(), sinks.begin(), sinks.end());
			assert(m_spLoggerImpl != nullptr);

			m_spLoggerImpl->set_error_handler(&__LoggerErrorHandler);

			spdlog::register_logger(m_spLoggerImpl);
		}
		catch (const spdlog::spdlog_ex& ex)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[1] Exception on InitLogger: '{0}'"), stdext::to_wide(ex.what()));

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			std::abort();
		}
		catch (uint32_t er)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[2] Exception on InitLogger: '{0}'"), fmt::ptr(reinterpret_cast<void*>(er)));

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			std::abort();
		}
		catch (...)
		{
			const auto c_szBuffer = xorstr_(L"[3] Unhandled exception on InitLogger");

			LogfW(CUSTOM_LOG_FILENAME_W, c_szBuffer);
			std::abort();
		}
#else
		if (!__CreateLogDBFile())
			return false;
#endif
		
		m_bInitialized = true;
		return true;
	}
	void CLogHelper::Release()
	{
		if (!this || !CLogHelper::InstancePtr())
			return;

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		if (!m_bInitialized)
			return;

		m_bInitialized = false;

#ifndef USE_SPDLOG
		sqlite3_close(m_pkDatabase);
		m_pkDatabase = nullptr;
#else
		if (m_spLoggerImpl)
			m_spLoggerImpl->flush();
#endif
	}

	bool CLogHelper::__CreateSpamRecordRemoverTriggerForLogDB()
	{
#ifndef USE_SPDLOG
		const auto c_szBuffer = xorstr_(R"(
			CREATE TRIGGER IF NOT EXISTS remove_excess_records
			AFTER INSERT ON Logs
			BEGIN
				DECLARE total_count INTEGER;
				DECLARE matched_count INTEGER;
    
				SELECT COUNT(*) FROM Logs INTO total_count;
    
				SELECT COUNT(*) FROM Logs
				WHERE message LIKE '%Sending packet: HEADER_PONG%'
					OR message LIKE '%OnRecvPingPacket :: PING RECV%'
				INTO matched_count;
    
				IF matched_count > 50 THEN
					DELETE FROM Logs
					WHERE ROWID NOT IN (
						SELECT ROWID
						FROM Logs
						WHERE message LIKE '%Sending packet: HEADER_PONG%'
							OR message LIKE '%OnRecvPingPacket :: PING RECV%'
						ORDER BY ROWID DESC
						LIMIT 20
					);
				END IF;
			END;
		)");

		auto ret = sqlite3_exec(m_pkDatabase, c_szBuffer, nullptr, nullptr, nullptr);
		if (ret != SQLITE_OK)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[4] sqlite3_exec failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}
#endif
		return true;
	}

	bool CLogHelper::__CreateLogDBFile()
	{
#ifndef USE_SPDLOG
		auto ret = sqlite3_open16(m_wstrFileName.c_str(), &m_pkDatabase);
		if (ret != SQLITE_OK || !m_pkDatabase)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"sqlite3_open failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

#ifndef DISABLE_LOG_ENCRYPTION
		ret = sqlite3_key(m_pkDatabase, gsc_pDbKey, gsc_nDbKeySize);
		if (ret != SQLITE_OK)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"sqlite3_key failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}
#endif

		ret = sqlite3_exec(m_pkDatabase, xorstr_("PRAGMA synchronous = OFF"), nullptr, nullptr, nullptr);
		if (ret != SQLITE_OK)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[1] sqlite3_exec failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		ret = sqlite3_exec(m_pkDatabase, xorstr_("PRAGMA journal_mode = MEMORY"), nullptr, nullptr, nullptr);
		if (ret != SQLITE_OK)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[2] sqlite3_exec failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		ret = sqlite3_exec(m_pkDatabase, xorstr_("CREATE TABLE IF NOT EXISTS Logs(category INT, function TEXT, level INT, message TEXT, act_time INT);"), nullptr, nullptr, nullptr);
		if (ret != SQLITE_OK)
		{
			const auto c_stBuffer = fmt::format(xorstr_(L"[3] sqlite3_exec failed! ret: {0} err: {1}"), ret, m_pkDatabase ? sqlite3_errcode(m_pkDatabase) : 0);

			LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			return false;
		}

		// FIXME
//		if (!__CreateSpamRecordRemoverTriggerForLogDB())
//			return false;
#endif
		return true;
	}
	
	void CLogHelper::RegisterLogCallback(TLogCallbackFunc pvCallbackFn)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_pvLogCallbackFn = std::move(pvCallbackFn);
	}

	bool CLogHelper::Log(const uint8_t c_nCategory, const std::string& c_stFunction, const uint8_t c_nLevel, const wchar_t* c_wszFormat, ...)
	{
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		if (c_nLevel == LL_TRACE || c_nLevel == LL_DEV)
			return true;
#endif

		if (!this || !CLogHelper::InstancePtr())
		{
			const auto c_szBuffer = xorstr_(L"Logger instance is not allocated yet!");

			LogfW(CUSTOM_LOG_FILENAME_W, c_szBuffer);
			return false;
		}

		if (IsLogDisabled())
			return true;

		std::string stFunction;
		// Split then last ":" (stupid chars xorstr made)
		{
			auto nPos = c_stFunction.find_last_of(':');
			if (nPos != std::string::npos)
				stFunction = c_stFunction.substr(0, nPos);
			else
				stFunction = c_stFunction;

			nPos = stFunction.find_first_of('?');
			if (nPos != std::string::npos)
				stFunction = stFunction.substr(0, nPos);

			if (stFunction.size() > 100)
				stFunction = stFunction.substr(0, 100);
		}
	
		// FIXME: Log file rename failed with error: Dosya baska bir islem tarafindan kullanildigindan bu islem dosyaya erisilemiyor.
#if 0
		TODO GET/RESET Timer with mutex
		if (m_kSizeCheckTimer.diff() > 10000)
		{
			auto wstrFileName = GetFileName();

			std::error_code ec{};
			const auto nFileSize = std::filesystem::file_size(wstrFileName, ec);
			if (ec)
			{
				const auto c_stBuffer = fmt::format(xorstr_(L"File size check failed with error: {0}"), stdext::to_wide(ec.message()));
				LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
			}
			else if (nFileSize > gsc_nFileLimit)
			{
				ChangeLogDisableState(true);
				
				auto c_stBuffer = fmt::format(xorstr_(L"Log file size is too big! size: {0}"), nFileSize);
				LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());

				const auto stNewFileName = fmt::format(xorstr_(L"{0}_{1}_backup.log"), wstrFileName, stdext::get_current_epoch_time());
				if (std::filesystem::exists(stNewFileName, ec))
					std::filesystem::remove(stNewFileName, ec);

				std::filesystem::rename(wstrFileName, stNewFileName, ec);

				ChangeLogDisableState(false);
				
				if (ec)
				{
					c_stBuffer = fmt::format(xorstr_(L"Log file rename failed with error: {0}"), stdext::to_wide(ec.message()));
					LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
				}
				else if (!__CreateLogDBFile())
				{
					c_stBuffer = xorstr_(L"New log file could not created!");
					LogfW(CUSTOM_LOG_FILENAME_W, c_stBuffer.c_str());
					
					std::abort();
				}
			}

			m_kSizeCheckTimer.reset();
		}
#endif

		va_list vaArgList;
		va_start(vaArgList, c_wszFormat);
		
		static auto s_cbBufferSize = 0x1000;

		const auto dwFormatSize = _vscwprintf(c_wszFormat, vaArgList) + 1;
		if (dwFormatSize > s_cbBufferSize)
		{
			s_cbBufferSize = dwFormatSize + 0x100;
		}
		
		const auto lpwszBuffer = static_cast<wchar_t*>(std::calloc(s_cbBufferSize, sizeof(wchar_t)));
		if (!lpwszBuffer)
		{
			const auto err = errno;
			const auto c_wstBuffer = fmt::format(xorstr_(L"Memory allocation failed for log operation! Last error: {0}"), err);

#ifdef USE_SPDLOG
			std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
			m_spLoggerImpl->critical(stdext::to_ansi(c_wstBuffer));
#else
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"%s"), c_wstBuffer.c_str());
#endif
			std::abort();
		}

		const auto cbBufferLength = _vsnwprintf_s(lpwszBuffer, s_cbBufferSize, s_cbBufferSize - 1, c_wszFormat, vaArgList);
		if (cbBufferLength < 0)
		{
			const auto err = errno;
			const auto c_wstBuffer = fmt::format(xorstr_(L"_vsnprintf_s returned with negative value. Last error: {0} Length: {1} Buffer: {2}"),
				err, cbBufferLength, c_wszFormat
			);

#ifdef USE_SPDLOG
			std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
			m_spLoggerImpl->critical(stdext::to_ansi(c_wstBuffer));
#else
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"%s"), c_wstBuffer.c_str());
#endif

			std::free(lpwszBuffer);
			return false;
		}
		
		va_end(vaArgList);

		if (!IsInitialized())
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"*Logger instance is not initialized yet!*\n"));
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"[PRE_LOG_INIT] %s\n"), lpwszBuffer);

			std::free(lpwszBuffer);
			return false;
		}
		
		const auto c_wstFunction = stdext::to_wide(stFunction);
		const auto c_wstFinalBuffer = fmt::format(xorstr_(L"C{0} | T{1} | {2} | {3}"), c_nCategory, HandleToUlong(NtCurrentThreadId()), c_wstFunction, lpwszBuffer);
		const auto c_stFinalBuffer = stdext::to_ansi(c_wstFinalBuffer);
		const auto c_kCurrTimestamp = std::time(0);

		EmitLogCallback(c_nLevel, c_wstFinalBuffer);

#ifdef USE_SPDLOG
		auto stTelemetryBuffer = c_wstFinalBuffer;

		if (c_nLevel == LL_ERR || c_nLevel == LL_CRI)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
			const auto c_stLogStack = m_spLogStack->GetString();

			stTelemetryBuffer = fmt::format(xorstr_(L"Log: '{0}' Stack: '{1}'"), c_wstFinalBuffer, c_stLogStack);
		}
		
		try
		{
			{
				std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

				switch (c_nLevel)
				{
				case LL_SYS:
					m_spLoggerImpl->info(c_stFinalBuffer.c_str());
					break;
				case LL_CRI:
					m_spLoggerImpl->critical(c_stFinalBuffer.c_str());
					break;
				case LL_ERR:
					m_spLoggerImpl->error(c_stFinalBuffer.c_str());
					break;
				case LL_DEV:
					m_spLoggerImpl->debug(c_stFinalBuffer.c_str());
					break;
				case LL_TRACE:
					m_spLoggerImpl->trace(c_stFinalBuffer.c_str());
					break;
				case LL_WARN:
					m_spLoggerImpl->warn(c_stFinalBuffer.c_str());
					break;
				}

				m_spLoggerImpl->flush();
			}

			AppendLogStack(c_wstFinalBuffer);
		}
		catch (const spdlog::spdlog_ex& ex)
		{
			const auto c_stExcBuffer = fmt::format(xorstr_(L"[4] Exception on InitLogger: {0}"), stdext::to_wide(ex.what()));

			LogfW(CUSTOM_LOG_FILENAME_W, c_stExcBuffer.c_str());
			std::abort();
		}
		catch (uint32_t er)
		{
			const auto c_stExcBuffer = fmt::format(xorstr_(L"[5] Exception on InitLogger: {0}"), fmt::ptr(reinterpret_cast<void*>(er)));

			LogfW(CUSTOM_LOG_FILENAME_W, c_stExcBuffer.c_str());
			std::abort();
		}
		catch (...)
		{
			const auto c_szExcBuffer = xorstr_(L"[6] Unhandled exception on InitLogger");
			
			LogfW(CUSTOM_LOG_FILENAME_W, c_szExcBuffer);
			std::abort();
		}
#else
		auto pDB = GetDatabase();
		if (!pDB)
		{
			std::free(lpwszBuffer);
			return false;
		}

		sqlite3_stmt* statement = nullptr;
		auto ret = sqlite3_prepare(pDB, xorstr_("INSERT INTO Logs (category, function, level, message, act_time) VALUES (?, ?, ?, ?, ?);"), -1, &statement, nullptr);
		if (ret != SQLITE_OK || !statement)
		{
			std::free(lpwszBuffer);
			return false;
		}

		ret = sqlite3_bind_int(statement, 1, (int)c_nCategory);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_bind_text(statement, 2, stFunction.c_str(), stFunction.size(), SQLITE_STATIC);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_bind_int(statement, 3, (int)c_nLevel);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_bind_text16(statement, 4, lpwszBuffer, cbBufferLength * sizeof(wchar_t), SQLITE_STATIC);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_bind_int64(statement, 5, (int64_t)c_kCurrTimestamp);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_step(statement);
		if (ret != SQLITE_DONE)
		{
			std::free(lpwszBuffer);
			return false;
		}
		ret = sqlite3_finalize(statement);
		if (ret != SQLITE_OK)
		{
			std::free(lpwszBuffer);
			return false;
		}

		AppendLogStack(c_wstFinalBuffer);
#endif

		std::free(lpwszBuffer);
		return true;
	}
};
