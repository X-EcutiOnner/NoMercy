#include "../../include/PCH.hpp"
#include "../../include/Index.hpp"
#include "../../include/Application.hpp"
#include "../../include/SafeExecutor.hpp"

namespace NoMercyCore
{
	static constexpr auto MAX_FRAME_COUNT = 32;

	uint32_t OnSystemExceptionThrowed(EXCEPTION_POINTERS* pExceptionInfo)
	{
#ifdef _DEBUG
		if (IsDebuggerPresent())
			__debugbreak();
#endif
		
		if (!g_winAPIs)
			return EXCEPTION_CONTINUE_SEARCH;

		APP_TRACE_LOG(LL_CRI, L"An exception handled! Exception data: %p Current Thread: %u Current process: %u Last error: %u", 
			pExceptionInfo, g_winAPIs->GetCurrentThreadId(), g_winAPIs->GetCurrentProcessId(), g_winAPIs->GetLastError()
		);

		/*
#ifdef _DEBUG
// if 0
		// TODO: Just once than a global func
		if (!SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS))
		{
			APP_TRACE_LOG(LL_CRI, L"SymSetOptions fail! Error: %u",  GetLastError());
	//		return EXCEPTION_CONTINUE_SEARCH;
		}

		if (!SymInitialize(NtCurrentProcess(), nullptr, true))
		{
			APP_TRACE_LOG(LL_CRI, L"SymInitialize fail! Error: %u",  GetLastError());
	//		return EXCEPTION_CONTINUE_SEARCH;
		}
#endif
		*/

		if (pExceptionInfo && pExceptionInfo->ExceptionRecord)
		{
			std::string stExceptionAddrSymbol;
			GetSymbolName((DWORD64)PtrToPtr64(pExceptionInfo->ExceptionRecord->ExceptionAddress), stExceptionAddrSymbol, nullptr);

			APP_TRACE_LOG(LL_CRI, L"Exception Address: 0x%08x Symbol: %s",	pExceptionInfo->ExceptionRecord->ExceptionAddress, stExceptionAddrSymbol.c_str());
			APP_TRACE_LOG(LL_CRI, L"Exception Code: 0x%08x",					pExceptionInfo->ExceptionRecord->ExceptionCode);
			APP_TRACE_LOG(LL_CRI, L"Exception Flags: 0x%08x",				pExceptionInfo->ExceptionRecord->ExceptionFlags);
		}

		if (pExceptionInfo && pExceptionInfo->ContextRecord)
		{
			const auto pContext = *pExceptionInfo->ContextRecord;

#ifndef _M_X64
			APP_TRACE_LOG(LL_CRI, L"Eax: 0x%08x \t Ebx: 0x%08x", pContext.Eax, pContext.Ebx);
			APP_TRACE_LOG(LL_CRI, L"Ecx: 0x%08x \t Edx: 0x%08x", pContext.Ecx, pContext.Edx);
			APP_TRACE_LOG(LL_CRI, L"Esi: 0x%08x \t Edi: 0x%08x", pContext.Esi, pContext.Edi);
			APP_TRACE_LOG(LL_CRI, L"Ebp: 0x%08x \t Esp: 0x%08x", pContext.Ebp, pContext.Esp);
#else
			APP_TRACE_LOG(LL_CRI, L"Rax: 0x%08x \t Rbx: 0x%08x", pContext.Rax, pContext.Rbx);
			APP_TRACE_LOG(LL_CRI, L"Rcx: 0x%08x \t Rdx: 0x%08x", pContext.Rcx, pContext.Rdx);
			APP_TRACE_LOG(LL_CRI, L"Rsi: 0x%08x \t Rdi: 0x%08x", pContext.Rsi, pContext.Rdi);
			APP_TRACE_LOG(LL_CRI, L"Rbp: 0x%08x \t Rsp: 0x%08x", pContext.Rbp, pContext.Rsp);
#endif
		}

		// Check stack

		LPVOID lpFrames[MAX_FRAME_COUNT] = { 0x0 };
		for (auto& lpFrame : lpFrames)
			lpFrame = nullptr;

		auto wCapturedFrames = g_winAPIs->RtlCaptureStackBackTrace(1, MAX_FRAME_COUNT, lpFrames, nullptr);
		if (!wCapturedFrames)
		{
			APP_TRACE_LOG(LL_CRI, L"Any frame can NOT captured! Error: %u",  GetLastError());
			return EXCEPTION_CONTINUE_SEARCH;
		}
		APP_TRACE_LOG(LL_CRI, L"%u Frame captured!", wCapturedFrames);

		for (auto i = 0; i < wCapturedFrames; i++)
		{
#pragma warning(push) 
#pragma warning(disable: 4826)
			auto ullCurrFrame = reinterpret_cast<DWORD64>(lpFrames[i]);
			APP_TRACE_LOG(LL_CRI, L"Current frame index: %d Addr: 0x%lld", i, ullCurrFrame);

			// Get module info
			IMAGEHLP_MODULE64 im64	= { 0 };
			im64.SizeOfStruct		= sizeof(IMAGEHLP_MODULE64);

			auto bGetModuleInfo = g_winAPIs->SymGetModuleInfo64(NtCurrentProcess(), reinterpret_cast<DWORD64>(lpFrames[i]), &im64);
			if (bGetModuleInfo)
			{
				APP_TRACE_LOG(LL_CRI, L"SymGetModuleInfo64: Module: 0x%lld Module Name: %s Image Name: %s Symbol name: %s",
					ullCurrFrame, im64.ModuleName, im64.ImageName, im64.LoadedImageName);
			}
			else
			{
				APP_TRACE_LOG(LL_CRI, L"SymGetModuleInfo64 fail! Error: %u", GetLastError());
			}
#pragma warning(pop) 

			// Get symbol name
			auto dwDisplacement64 = 0ULL;
			std::string stSymbolName;
			if (GetSymbolName(ullCurrFrame, stSymbolName, &dwDisplacement64))
			{
				APP_TRACE_LOG(LL_CRI, L"SymGetSymFromAddr64: Symbol name: %s", stSymbolName.c_str());
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"SymGetSymFromAddr64 fail! Error: %u", GetLastError());
			}

			// Get source filename and line
			auto dwDisplacement		= 0UL;
			IMAGEHLP_LINE64 il64	= { 0 };
			auto bGetLine = g_winAPIs->SymGetLineFromAddr64(NtCurrentProcess(), ullCurrFrame, &dwDisplacement, &il64);
			if (bGetLine)
			{
				APP_TRACE_LOG(LL_CRI, L"File name: %hs File line: %u", il64.FileName, il64.LineNumber);
			}
			else
			{
				APP_TRACE_LOG(LL_CRI, L"SymGetLineFromAddr64 fail! Error: %u", GetLastError());
			}
		}
		
		auto hModule = g_winAPIs->GetModuleHandleW_o(nullptr);
		APP_TRACE_LOG(LL_CRI, L"Base module: %p", hModule);

		wchar_t wszModuleName[MAX_PATH]{ L'\0' };
		g_winAPIs->GetModuleFileNameW(hModule, wszModuleName, MAX_PATH);
		APP_TRACE_LOG(LL_CRI, L"Module name: %s", wszModuleName);

		auto pModuleTime = (time_t)g_winAPIs->GetTimestampForLoadedLibrary(hModule);
		APP_TRACE_LOG(LL_CRI, L"Module time: 0x%08x - %s", pModuleTime, std::ctime(&pModuleTime));

#ifdef _DEBUG
// if 0
		g_winAPIs->SymCleanup(NtCurrentProcess());
#endif
		return EXCEPTION_CONTINUE_SEARCH;
	}
};
