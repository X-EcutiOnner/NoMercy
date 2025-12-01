#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <stdarg.h>
#include <iostream>
#include <fstream>
#include <mini-printf/mini-printf.h>

#define LOG_FILENAME "PatchUploader.log"

namespace
{
	static void FileLogA(const std::string &strFileName, const std::string &strLogData)
	{
		auto f = std::ofstream(strFileName.c_str(), std::ofstream::out | std::ofstream::app);
		if (f)
		{
			const auto fn = LI_FN(GetLocalTime).forwarded_safe_cached();
			if (fn)
			{
				SYSTEMTIME sysTime = { 0 };
				fn(&sysTime);

				char szTimeBuf[1024];
				snprintf(szTimeBuf, sizeof(szTimeBuf), xorstr("%02d:%02d:%02d - %02d:%02d:%d - %u-%u :: ").crypt_get(),
					sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
					sysTime.wDay, sysTime.wMonth, sysTime.wYear,
					NtCurrentThreadId(), NtCurrentProcessId()
				);

				f << szTimeBuf << strLogData.c_str() << std::endl;
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
	static void ConsoleLogA(const char* c_szLogData)
	{
		std::cout << c_szLogData << std::endl;
	}

	static void DebugLogf(const char* c_szFormat, ...)
	{
#ifdef _DEBUG
		char szTmpString[8192] = { 0 };

		va_list vaArgList;
		va_start(vaArgList, c_szFormat);
		vsnprintf(szTmpString, sizeof(szTmpString), c_szFormat, vaArgList);
		va_end(vaArgList);

		DebugLogA(szTmpString);
#endif
	}
	static void LogfA(const std::string& strFileName, const char* c_szFormat, ...)
	{
		char szTmpString[8192] = { 0 };

		va_list vaArgList;
		va_start(vaArgList, c_szFormat);
		vsnprintf_s(szTmpString, sizeof(szTmpString), c_szFormat, vaArgList);
		va_end(vaArgList);

#ifdef _DEBUG
		DebugLogA(szTmpString);
#endif
		ConsoleLogA(szTmpString);
		FileLogA(strFileName.c_str(), szTmpString);
	}
};
