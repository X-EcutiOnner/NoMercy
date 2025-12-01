#pragma once
#include <mutex>
#include <functional>
#include <sqlite3.h>
#include <xorstr.hpp>
#include "BasicLog.hpp"
#include "../../../Common/AbstractSingleton.hpp"
#include "../../../Common/SimpleTimer.hpp"

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
#define USE_SPDLOG
#endif

#ifdef USE_SPDLOG
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#endif

namespace NoMercyCore
{
	class CLogStack : public std::enable_shared_from_this <CLogStack>
	{
	public:
		CLogStack(const uint8_t nLimit);
		virtual ~CLogStack();

		void Append(const std::wstring& wstMessage);

		auto Get() const;
		auto GetString() const;
		auto GetJson() const;

	private:
		uint8_t m_nLimit;
		std::vector <std::wstring> m_vLogStack;
	};


	class CLogHelper : public CSingleton <CLogHelper>
	{
		using TLogCallbackFunc = std::function<void(uint8_t c_nCategory, const std::wstring& c_wstBuffer)>;

	public:
		CLogHelper(const uint8_t nAppType, const std::wstring& wstrFileName);
		virtual ~CLogHelper();

		bool Initialize();
		void Release();

		void RegisterLogCallback(TLogCallbackFunc pvCallbackFn);
		bool Log(const uint8_t c_nCategory, const std::string& c_stFunction, const uint8_t c_nLevel, const wchar_t* c_wszFormat, ...);

		auto IsInitialized() const	{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_bInitialized; };
		auto IsLogDisabled() const	{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_bLogDisabled; };
		auto GetStack() const		{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_spLogStack; };
#ifdef USE_SPDLOG
		auto GetLogger() const		{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_spLoggerImpl; };
#else
		auto GetDatabase() const	{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_pkDatabase; };
#endif
		auto GetFileName() const	{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); return m_wstrFileName; };

		void ChangeLogDisableState(const bool bDisable)		{ std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); m_bLogDisabled = bDisable; };
		void AppendLogStack(const std::wstring& wstMessage) { std::lock_guard <std::recursive_mutex> __lock(m_rmMutex); m_spLogStack->Append(wstMessage); };
		void EmitLogCallback(const uint8_t c_nCategory, const std::wstring& c_wstBuffer)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

			if (m_pvLogCallbackFn)
				m_pvLogCallbackFn(c_nCategory, c_wstBuffer);
		}

	protected:
		bool __CreateSpamRecordRemoverTriggerForLogDB();
		bool __CreateLogDBFile();

	private:
		mutable std::recursive_mutex m_rmMutex;
		std::shared_ptr <CLogStack> m_spLogStack;
		bool m_bLogDisabled;
		uint8_t m_nAppType;
		std::wstring m_wstrFileName;
		std::wstring m_wstrLoggerName;
		bool m_bInitialized;
		TLogCallbackFunc m_pvLogCallbackFn;
		CStopWatch <std::chrono::milliseconds> m_kSizeCheckTimer;

#ifdef USE_SPDLOG
		std::shared_ptr <spdlog::logger> m_spLoggerImpl;
#else
		sqlite3* m_pkDatabase;
#endif
	};
};
