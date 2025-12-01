#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"

namespace NoMercyTLS
{
#pragma warning(push) 
#pragma warning(disable: 4172)
	const char* TLS_BuildStringA(const char* c_szFunction, char* szFormat, ...)
	{
		char szBuffer[1024]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, szFormat);
		wvsprintfA(szBuffer, szFormat, vaArgList);
		va_end(vaArgList);

		char szRetBuffer[2048]{ '\0' };
		mini_snprintf(szRetBuffer, sizeof(szRetBuffer), xorstr_("%s :: %s\n"), c_szFunction, szBuffer);

		return szRetBuffer;
	}
#pragma warning(pop) 

	void TLS_WriteDebug(const char* c_szMessage)
	{
		OutputDebugStringA(c_szMessage);
	}

	bool TLS_WriteConsole(const char* c_szMessage)
	{
		auto hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (!IS_VALID_HANDLE(hStdOut))
		{
			const auto c_szLogMessage = TLS_BuildStringA(xorstr_(__FUNCTION__), xorstr_("GetStdHandle failed with error: %u"), GetLastError());
			TLS_WriteDebug(c_szLogMessage);
			return false;
		}

		const DWORD dwMessageSize = lstrlenA(c_szMessage);
		if (!dwMessageSize)
			return true;

		DWORD dwWrittenSize = 0;
		if (!WriteConsoleA(hStdOut, c_szMessage, dwMessageSize, &dwWrittenSize, nullptr) || dwWrittenSize != dwMessageSize)
		{
			const auto c_szLogMessage = TLS_BuildStringA(xorstr_(__FUNCTION__), xorstr_("WriteConsoleA failed with error: %u"), GetLastError());
			TLS_WriteDebug(c_szLogMessage);
			return false;
		}

		return true;
	}

	bool TLS_WriteFile(const char* c_szBuffer)
	{
		auto hFile = CreateFileA(CUSTOM_TLS_LOG_FILENAME, FILE_APPEND_DATA, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!IS_VALID_HANDLE(hFile))
		{
			const auto c_szLogMessage = TLS_BuildStringA(xorstr_(__FUNCTION__), xorstr_("CreateFileA failed with error: %u"), GetLastError());
			TLS_WriteDebug(c_szLogMessage);
			return false;
		}

		const DWORD dwSize = lstrlenA(c_szBuffer);

		auto dwWritedBytes = 0UL;
		const auto bWritten = WriteFile(hFile, c_szBuffer, dwSize, &dwWritedBytes, nullptr);
		if (!bWritten || dwWritedBytes != dwSize)
		{
			const auto c_szLogMessage = TLS_BuildStringA(xorstr_(__FUNCTION__), xorstr_("WriteFile failed with error: %u"), GetLastError());
			TLS_WriteDebug(c_szLogMessage);
			CloseHandle(hFile);
			return false;
		}

		FlushFileBuffers(hFile);
		CloseHandle(hFile);
		return true;
	}


	void TLS_Log(const char* c_szMessage)
	{
#ifdef _DEBUG
		TLS_WriteDebug(c_szMessage);
		TLS_WriteConsole(c_szMessage);
#endif
		TLS_WriteFile(c_szMessage);
	}

	void TLS_Logf(const char* c_szFunction, char* szFormat, ...)
	{
		char szBuffer[1024]{ '\0' };

		va_list vaArgList;
		va_start(vaArgList, szFormat);
		wvsprintfA(szBuffer, szFormat, vaArgList);
		va_end(vaArgList);

		char szRetBuffer[2048]{ '\0' };
		mini_snprintf(szRetBuffer, sizeof(szRetBuffer), xorstr_("%s :: %s\n"), c_szFunction, szBuffer);

		TLS_Log(szRetBuffer);
	}
}
