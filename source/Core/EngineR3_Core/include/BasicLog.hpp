#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <stdarg.h>
#include <iostream>
#include <fstream>
#include <mini-printf/mini-printf.h>

namespace NoMercyCore
{
	static void FileLogA(const std::string &strFileName, const std::string &strLogData)
	{
		auto f = std::ofstream(strFileName.c_str(), std::ofstream::out | std::ofstream::app);
		if (f)
		{
			const auto fn = LI_FN(GetLocalTime).forwarded_safe_cached();
			if (fn)
			{
				SYSTEMTIME sysTime{ 0 };
				fn(&sysTime);

				char szTimeBuf[1024]{ '\0' };
				snprintf(szTimeBuf, sizeof(szTimeBuf), xorstr_("%02d:%02d:%02d - %02d:%02d:%d - %u-%u :: "),
					sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
					sysTime.wDay, sysTime.wMonth, sysTime.wYear,
					HandleToUlong(NtCurrentThreadId()), HandleToUlong(NtCurrentProcessId())
				);

				f << szTimeBuf << strLogData.c_str() << std::endl;
			}
			f.close();
		}
	}
	static void FileLogW(const std::wstring& wstrFileName, const std::wstring& wstrLogData)
	{
		auto f = std::wofstream(wstrFileName.c_str(), std::wofstream::out | std::wofstream::app);
		if (f)
		{
			const auto fn = LI_FN(GetLocalTime).forwarded_safe_cached();
			if (fn)
			{
				SYSTEMTIME sysTime{ 0 };
				fn(&sysTime);

				wchar_t wszTimeBuf[2048]{ L'\0' };
				_snwprintf_s(wszTimeBuf, _countof(wszTimeBuf), xorstr_(L"%02d:%02d:%02d - %02d:%02d:%d - %u-%u :: "),
					sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
					sysTime.wDay, sysTime.wMonth, sysTime.wYear,
					HandleToUlong(NtCurrentThreadId()), HandleToUlong(NtCurrentProcessId())
				);

				f << wszTimeBuf << wstrLogData.c_str() << std::endl;
			}
			f.close();
		}
	}

	static void DebugLogA(const char* c_szLogData)
	{
		const auto fn = LI_FN(OutputDebugStringA).forwarded_safe_cached();
		if (fn)
			fn(c_szLogData);
	}
	static void DebugLogW(const wchar_t* c_wszLogData)
	{
		const auto fn = LI_FN(OutputDebugStringW).forwarded_safe_cached();
		if (fn)
			fn(c_wszLogData);
	}

	static void ConsoleLogA(const char* c_szLogData)
	{
		const auto fnGetStdHandle = LI_FN(GetStdHandle).forwarded_safe_cached();
		const auto fnWriteConsole = LI_FN(WriteConsoleA).forwarded_safe_cached();

		if (fnGetStdHandle && fnWriteConsole)
		{
			const auto hSTDOUT = fnGetStdHandle(STD_OUTPUT_HANDLE);
			if (hSTDOUT && hSTDOUT != INVALID_HANDLE_VALUE)
			{
			    DWORD dwWritten = 0;
			    fnWriteConsole(hSTDOUT, c_szLogData, strlen(c_szLogData), &dwWritten, nullptr);
			}
		}
	}
	static void ConsoleLogW(const wchar_t* c_wszLogData)
	{
		const auto fnGetStdHandle = LI_FN(GetStdHandle).forwarded_safe_cached();
		const auto fnWriteConsole = LI_FN(WriteConsoleW).forwarded_safe_cached();

		if (fnGetStdHandle && fnWriteConsole)
		{
			const auto hSTDOUT = fnGetStdHandle(STD_OUTPUT_HANDLE);
			if (hSTDOUT && hSTDOUT != INVALID_HANDLE_VALUE)
			{
				DWORD dwWritten = 0;
				fnWriteConsole(hSTDOUT, c_wszLogData, wcslen(c_wszLogData), &dwWritten, nullptr);
			}
		}
	}
	
	static void DebugLogf(const char* c_szFormat, ...)
	{
#ifdef _DEBUG
		char szBuffer[8192]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, c_szFormat);
		vsnprintf(szBuffer, sizeof(szBuffer), c_szFormat, vaArgList);
		va_end(vaArgList);

		DebugLogA(szBuffer);
#endif
	}
	static void FileLogfA(const std::string& stFileName, const char* c_szFormat, ...)
	{
		char szBuffer[8192]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, c_szFormat);
		vsprintf_s(szBuffer, c_szFormat, vaArgList);
		va_end(vaArgList);

		FileLogA(stFileName.c_str(), szBuffer);
	}

	static void LogfA(const std::string& strFileName, const char* c_szFormat, ...)
	{
		char szBuffer[8192]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, c_szFormat);
		_vsnprintf_s(szBuffer, sizeof(szBuffer), c_szFormat, vaArgList);
		va_end(vaArgList);

//		const char* newLine = xorstr_("\n");
//		strcat(szBuffer, newLine);

#ifdef _DEBUG
		DebugLogA(szBuffer);
#endif
		ConsoleLogA(szBuffer);
		FileLogA(strFileName.c_str(), szBuffer);
	}
	static void LogfW(const std::wstring& wstrFileName, const wchar_t* c_wszFormat, ...)
	{
		wchar_t wszBuffer[8192]{ L'\0' };

		va_list vaArgList;
		va_start(vaArgList, c_wszFormat);
		_vsnwprintf_s(wszBuffer, _countof(wszBuffer), c_wszFormat, vaArgList);
		va_end(vaArgList);

#ifdef _DEBUG
		DebugLogW(wszBuffer);
#endif
		ConsoleLogW(wszBuffer);
		FileLogW(wstrFileName.c_str(), wszBuffer);
	}
	
	static void LogfA_DEBUG(const std::string& strFileName, const std::string& strMessage)
	{
#ifdef _DEBUG
		DebugLogA(strMessage.c_str());
		ConsoleLogA(strMessage.c_str());
		FileLogA(strFileName.c_str(), strMessage.c_str());
#endif
	}
	static void LogfW_DEBUG(const std::wstring& wstrFileName, const std::wstring& wstrMessage)
	{
#ifdef _DEBUG
		DebugLogW(wstrMessage.c_str());
		ConsoleLogW(wstrMessage.c_str());
		FileLogW(wstrFileName.c_str(), wstrMessage.c_str());
#endif
	}
};
