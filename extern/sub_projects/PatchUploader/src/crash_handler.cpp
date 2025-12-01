#include "../include/main.hpp"
#include "../include/BasicLog.hpp"
#include <DbgHelp.h>

BOOL CALLBACK MiniDumpCallback(PVOID pParam, const PMINIDUMP_CALLBACK_INPUT pInput, PMINIDUMP_CALLBACK_OUTPUT pOutput)
{
	BOOL bRet = FALSE;

	if (!pInput || !pOutput)
		return FALSE;

	switch (pInput->CallbackType)
	{
		case IncludeModuleCallback:
		{
			bRet = TRUE;
		} break;

		case IncludeThreadCallback:
		{
			bRet = TRUE;
		} break;

		case ModuleCallback:
		{
			if (!(pOutput->ModuleWriteFlags & ModuleReferencedByMemory)) 
			{
				pOutput->ModuleWriteFlags &= (~ModuleWriteModule);
			}
			bRet = TRUE;
		} break;

		case ThreadCallback:
		{
			bRet = TRUE;
		} break;

		case ThreadExCallback:
		{
			bRet = TRUE;
		} break;

		case MemoryCallback:
		{
			bRet = FALSE;
		} break;

		case CancelCallback:
			break;
	}

	return bRet;
}

bool CreateMiniDump(EXCEPTION_POINTERS* pExceptionInfo)
{
	LogfA(LOG_FILENAME, "Exception handled: %p", pExceptionInfo);
	
	if (IsDebuggerPresent())
		DebugBreak();

	const auto stDumpPath = fmt::format("{0}\\PatchUploader.dmp", std::filesystem::current_path().string());

	auto hFile = CreateFileA(stDumpPath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Exception dump file is not created. Error code: %u Path: %s\n", GetLastError(), stDumpPath.c_str());
		return false;
	}

	// Create the minidump 
	MINIDUMP_EXCEPTION_INFORMATION mdei;
	mdei.ThreadId = GetCurrentThreadId();
	mdei.ExceptionPointers = pExceptionInfo;
	mdei.ClientPointers = FALSE;

	MINIDUMP_CALLBACK_INFORMATION mci;
	mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MiniDumpCallback;
	mci.CallbackParam = 0;

	MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory);

	const auto rv = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, mdt, (pExceptionInfo != 0) ? &mdei : 0, 0, &mci);
	if (!rv)
	{
		LogfA(LOG_FILENAME, "Exception dump can not created. Error code: %u", GetLastError());
	}
	else
	{
		LogfA(LOG_FILENAME, "Exception dump: %s successfully created.", stDumpPath.c_str());
	}

	// Close the file 
	CloseHandle(hFile);
	return true;
}

LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS * pExceptionInfo)
{
	if (pExceptionInfo && pExceptionInfo->ExceptionRecord)
	{
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
		{
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateMiniDump, pExceptionInfo, 0, NULL);
			if (hThread && hThread != INVALID_HANDLE_VALUE)
			{
				WaitForSingleObject(hThread, INFINITE);
				CloseHandle(hThread);
			}
		}
		else
		{
			CreateMiniDump(pExceptionInfo);
		}
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

bool SetupCrashHandler()
{
	if (SetUnhandledExceptionFilter(ExceptionFilter))
	{
		LogfA(LOG_FILENAME, "Mini dump generator succesfully created!");
		return true;
	}

	LogfA(LOG_FILENAME, "Mini dump generator can NOT created! Error code: %u", GetLastError());
	return false;
}
