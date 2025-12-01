#include "../../include/PCH.hpp"
#include "../../include/Defines.hpp"
#include "../../include/MiniDump.hpp"
#include "../../include/WinAPIManager.hpp"
#include "../../include/SafeExecutor.hpp"
#include <DbgHelp.h>

namespace NoMercyCore
{
	static auto gs_bIsMiniDumpHandlerReady = false;
	static auto gs_nMiniDumpReqID = 0;
	static auto gs_wstMiniDumpPath = std::wstring{};
	static TMiniDumpCallback gs_fnMiniDumpCallback = nullptr;

	static decltype(&GetLastError)			gs_fnGetLastError 		 = nullptr;
	static decltype(&CreateFileW)			gs_fnCreateFileW 		 = nullptr;
	static decltype(&CloseHandle)			gs_fnCloseHandle 		 = nullptr;
	static decltype(&MiniDumpWriteDump)		gs_fnMiniDumpWriteDump	 = nullptr;
	static decltype(&CreateThread)			gs_fnCreateThread		 = nullptr;
	static decltype(&WaitForSingleObject)	gs_fnWaitForSingleObject = nullptr;

	// Custom minidump callback 
	BOOL CALLBACK __MyMiniDumpCallback(PVOID /* pParam */, const PMINIDUMP_CALLBACK_INPUT pInput, PMINIDUMP_CALLBACK_OUTPUT pOutput)
	{
		BOOL bRet = FALSE;

		// Check parameters 
		if (!pInput)
			return FALSE;

		if (!pOutput)
			return FALSE;

		// Process the callbacks 
		switch (pInput->CallbackType)
		{
		case IncludeModuleCallback:
		{
			// Include the module into the dump 
			bRet = TRUE;
		}
		break;

		case IncludeThreadCallback:
		{
			// Include the thread into the dump 
			bRet = TRUE;
		}
		break;

		case ModuleCallback:
		{
			// Does the module have ModuleReferencedByMemory flag set ? 
			if (!(pOutput->ModuleWriteFlags & ModuleReferencedByMemory)) {
				// No, it does not - exclude it 
				// wprintf(L"Excluding module: %s \n", pInput->Module.FullPath);
				pOutput->ModuleWriteFlags &= (~ModuleWriteModule);
			}
			bRet = TRUE;
		}
		break;

		case ThreadCallback:
		{
			// Include all thread information into the minidump 
			bRet = TRUE;
		}
		break;

		case ThreadExCallback:
		{
			// Include this information 
			bRet = TRUE;
		}
		break;

		case MemoryCallback:
		{
			// We do not include any information here -> return FALSE 
			bRet = FALSE;
		}
		break;

		case CancelCallback:
			break;
		}

		return bRet;
	}

	static bool __CreateMiniDump(EXCEPTION_POINTERS* pExceptionInfo)
	{
		if (!gs_fnCreateFileW || !gs_fnGetLastError || !gs_fnMiniDumpWriteDump || !gs_fnCloseHandle)
			return false;

		const auto tm = std::time(nullptr);
		std::wostringstream timefmt;
		timefmt << std::put_time(std::localtime(&tm), xorstr_(L"%Y%m%d_%H%M%S"));

		std::error_code ec;
		if (!std::filesystem::exists(gs_wstMiniDumpPath, ec) && !std::filesystem::create_directories(gs_wstMiniDumpPath, ec))
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Dump folder (%s) does not exist and could not created! Error: %d (%hs)"), gs_wstMiniDumpPath.c_str(), ec.value(), ec.message().c_str());

			// Invoke callback
			if (gs_fnMiniDumpCallback)
			{
				auto wstErr = stdext::to_wide(ec.message());
				gs_fnMiniDumpCallback(false, gs_fnGetLastError(), wstErr.c_str());
			}
			return false;
		}

		// const auto app_type = CApplication::Instance().GetAppType();
		const auto filename = fmt::format(xorstr_(L"{0}\\NoMercy_{1}_{2}.dmp"), gs_wstMiniDumpPath, __NOMERCY_VERSION__, timefmt.str());
		if (std::filesystem::exists(filename, ec))
			std::filesystem::remove(filename, ec);

		auto hFile = gs_fnCreateFileW(filename.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (!IS_VALID_HANDLE(hFile))
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Exception dump file is could not created. Error code: %u Path: %s"), gs_fnGetLastError(), filename.c_str());

			// Invoke callback
			if (gs_fnMiniDumpCallback)
				gs_fnMiniDumpCallback(false, gs_fnGetLastError(), filename);

			return false;
		}

		// Create the minidump 
		const auto dwCurrTID = HandleToUlong(NtCurrentThreadId());
		const auto dwCurrPID = HandleToUlong(NtCurrentProcessId());

		MINIDUMP_EXCEPTION_INFORMATION mdei{ 0 };
		mdei.ThreadId = dwCurrTID;
		mdei.ExceptionPointers = pExceptionInfo;
		mdei.ClientPointers = FALSE;

		MINIDUMP_CALLBACK_INFORMATION mci;
		mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)__MyMiniDumpCallback;
		mci.CallbackParam = 0;

		const auto mdt = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory);

		const auto rv = gs_fnMiniDumpWriteDump(NtCurrentProcess(), dwCurrPID, hFile, mdt, (pExceptionInfo != 0) ? &mdei : 0, 0, &mci);
		if (!rv)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"MiniDumpWriteDump failed with error: %u"), gs_fnGetLastError());
		}
		else
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Exception dump: %s successfully created."), filename.c_str());
		}

		// Close the file 
		gs_fnCloseHandle(hFile);

		// Invoke callback
		if (gs_fnMiniDumpCallback)
			gs_fnMiniDumpCallback(!!rv, gs_nMiniDumpReqID, filename);
		
		return true;
	}

	extern uint32_t OnSystemExceptionThrowed(EXCEPTION_POINTERS* pExceptionInfo);
	
	LONG WINAPI __ExceptionFilterSeh(EXCEPTION_POINTERS* pExceptionInfo)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"SEH Exception: %p"), pExceptionInfo && pExceptionInfo->ExceptionRecord ? pExceptionInfo->ExceptionRecord->ExceptionAddress : 0);

		if (IsDebuggerPresent())
			DebugBreak();
//		else
//			OnSystemExceptionThrowed(pExceptionInfo);
#endif

		// Handler should be created
		if (!gs_bIsMiniDumpHandlerReady)
			return EXCEPTION_CONTINUE_SEARCH;

		// Check exception code, if exception occured due than stack overflow, run a new thread
		if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord)
			return EXCEPTION_CONTINUE_SEARCH;

		if (pExceptionInfo->ExceptionRecord->ExceptionAddress == &NoMercyCore::CMiniDump::TriggerSEH)
			return EXCEPTION_CONTINUE_SEARCH;

		if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
		{
			auto hThread = gs_fnCreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(__CreateMiniDump), pExceptionInfo, 0, nullptr);
			if (IS_VALID_HANDLE(hThread))
			{
				gs_fnWaitForSingleObject(hThread, INFINITE);
				gs_fnCloseHandle(hThread);
				return EXCEPTION_EXECUTE_HANDLER;
			}
		}

		// we have a common exception, call directly
		__CreateMiniDump(pExceptionInfo);

		return EXCEPTION_EXECUTE_HANDLER;
	}

	bool CMiniDump::TriggerSEH(int nErrorCode)
	{
		gs_nMiniDumpReqID = nErrorCode;

		if (gs_bIsMiniDumpHandlerReady)
		{
			__try
			{
				*(int*)0 = 0;
			}
			__except (__ExceptionFilterSeh(GetExceptionInformation()))
			{
				return true;
			}
		}
		return false;
	}

	bool CMiniDump::InitMiniDumpHandler()
	{
		auto wstDumpPath = std::filesystem::current_path().wstring();
		const auto wstLowerDumpPath = stdext::to_lower_wide(wstDumpPath);
		if (wstLowerDumpPath.find(xorstr_(L"\\nomercy")) == std::wstring::npos)
			wstDumpPath = fmt::format(xorstr_(L"{0}\\NoMercy\\Dump"), wstDumpPath);
		else
			wstDumpPath = fmt::format(xorstr_(L"{0}\\Dump"), wstDumpPath);

		gs_wstMiniDumpPath = wstDumpPath;

		std::error_code ec{};
		if (!std::filesystem::exists(gs_wstMiniDumpPath, ec) && !std::filesystem::create_directories(gs_wstMiniDumpPath, ec))
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Dump folder (%s) could not created! Error: %d (%hs)"), gs_wstMiniDumpPath.c_str(), ec.value(), ec.message().c_str());
			return false;
		}


		gs_fnGetLastError = LI_FN(GetLastError).forwarded_safe();
		if (!gs_fnGetLastError)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"GetLastError API could not found!"));
			return false;
		}

		gs_fnCreateFileW = LI_FN(CreateFileW).forwarded_safe();
		if (!gs_fnCreateFileW)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"CreateFileW API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		gs_fnCloseHandle = LI_FN(CloseHandle).forwarded_safe();
		if (!gs_fnCloseHandle)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"CloseHandle API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		gs_fnCreateThread = LI_FN(CreateThread).forwarded_safe();
		if (!gs_fnCreateThread)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"CreateThread API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		gs_fnWaitForSingleObject = LI_FN(WaitForSingleObject).forwarded_safe();
		if (!gs_fnWaitForSingleObject)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"WaitForSingleObject API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}


		const auto fnSetUnhandledExceptionFilter = LI_FN(SetUnhandledExceptionFilter).forwarded_safe();
		if (!fnSetUnhandledExceptionFilter)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"SetUnhandledExceptionFilter API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		const auto fnLoadLibrary = LI_FN(LoadLibraryW).forwarded_safe();
		if (!fnLoadLibrary)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"LoadLibraryW API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		const auto fnGetProcAddress = LI_FN(GetProcAddress).forwarded_safe();
		if (!fnGetProcAddress)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"GetProcAddress API could not found! Last error: %u"), gs_fnGetLastError());
			return false;
		}

		const auto hDbgHelp = fnLoadLibrary(xorstr_(L"dbghelp.dll"));
		if (!hDbgHelp)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"LoadLibraryW(dbghelp.dll) failed with error: %u"), gs_fnGetLastError());
			return false;
		}


		gs_fnMiniDumpWriteDump = reinterpret_cast<decltype(&MiniDumpWriteDump)>(fnGetProcAddress(hDbgHelp, xorstr_("MiniDumpWriteDump")));
		if (!gs_fnMiniDumpWriteDump)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"GetProcAddress(MiniDumpWriteDump) failed with error: %u"), gs_fnGetLastError());
			return false;
		}

		if (!fnSetUnhandledExceptionFilter(__ExceptionFilterSeh))
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"SetUnhandledExceptionFilter failed with error: %u"), gs_fnGetLastError());
			return false;
		}

		gs_bIsMiniDumpHandlerReady = true;
#ifdef _DEBUG
		LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Mini dump generator exception handler is succesfully created!\n"));
#endif
		return true;
	}

	void CMiniDump::RegisterMiniDumpCallback(TMiniDumpCallback fn)
	{
		gs_fnMiniDumpCallback = fn;
	}
};
