#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ThreadStackWalker.hpp"

static constexpr DWORD MAX_NUMBER_OF_FRAMES = 12;



inline std::shared_ptr <SStackFrame> __GetSymbols(HANDLE hProcess, DWORD64 qwAddress, DWORD64 qwRetAddr, DWORD64 qwStackAddr)
{
	APP_TRACE_LOG(LL_TRACE, L"Getting symbols for: %p / %p / %p", qwAddress, qwRetAddr, qwStackAddr);
	
	if (!qwAddress)
		return {};

	auto newElement = stdext::make_shared_nothrow<SStackFrame>();
	if (!IS_VALID_SMART_PTR(newElement))
	{
		APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for CallStackData");
		return {};
	}

	newElement->qwFrameAddress = qwAddress;
	newElement->qwReturnAddress = qwRetAddr;
	newElement->qwStackAddress = qwStackAddr;
	
	// Get symbol name
	std::string stSymbolName;
	auto qwDisplacement64 = 0ULL;
	auto qwSymbolAddress = 0ULL;
	if (GetSymbolName(qwAddress, stSymbolName, &qwDisplacement64, &qwSymbolAddress, hProcess))
	{
		newElement->stSymbolName = stSymbolName;
		newElement->qwDisplacement = qwDisplacement64;
		newElement->qwSymbolAddress = qwSymbolAddress;
	}
	else
	{
		// APP_TRACE_LOG(LL_WARN, L"SymGetSymFromAddr64 fail! Error: %u", g_winAPIs->GetLastError());
	}

	// Get source filename and line
	auto dwDisplacement = 0UL;
	IMAGEHLP_LINE64 il64 = { 0 };
	const auto bGetLine = g_winAPIs->SymGetLineFromAddr64(hProcess, qwAddress, &dwDisplacement, &il64);
	if (bGetLine)
	{
		APP_TRACE_LOG(LL_SYS, L"File name: %hs File line: %u", il64.FileName, il64.LineNumber);
	}
	else
	{
		const auto dwErrorCode = g_winAPIs->GetLastError();
		APP_TRACE_LOG(
			dwErrorCode == ERROR_INVALID_ADDRESS || dwErrorCode == ERROR_MOD_NOT_FOUND ? LL_TRACE : LL_WARN,
			L"SymGetLineFromAddr64 fail! Error: %u",
			g_winAPIs->GetLastError()
		);
	}

	// Get module name
	IMAGEHLP_MODULE64 moduleInfo{ 0 };
	moduleInfo.SizeOfStruct = sizeof(moduleInfo);
	if (g_winAPIs->SymGetModuleInfo64(hProcess, qwAddress, &moduleInfo))
	{
		newElement->qwImageBaseAddress = moduleInfo.BaseOfImage;
		newElement->dwImageSize = moduleInfo.ImageSize;
		newElement->dwTimestamp = moduleInfo.TimeDateStamp;
		newElement->dwChecksum = moduleInfo.CheckSum;
		newElement->dwSymbolCount = moduleInfo.NumSyms;
		newElement->nSymType = moduleInfo.SymType;
		newElement->stModuleName.assign(moduleInfo.ModuleName);
		newElement->stImageName.assign(moduleInfo.ImageName);
		newElement->stLoadedImageName.assign(moduleInfo.LoadedImageName);
	}
	else
	{
		const auto dwErrorCode = g_winAPIs->GetLastError();
		APP_TRACE_LOG(
			dwErrorCode == ERROR_INVALID_ADDRESS || dwErrorCode == ERROR_MOD_NOT_FOUND ? LL_TRACE : LL_WARN,
			L"SymGetModuleInfo64 failed with error: %u",
			dwErrorCode
		);
	}

	APP_TRACE_LOG(LL_TRACE, L"Symbols handled!");
	return newElement;
}

bool GetThreadCallStack(HANDLE hProcess, HANDLE hThread, std::vector <std::shared_ptr <SStackFrame>>& vecStackData)
{
	vecStackData.clear();
	
	auto bRet = false;

	SYSTEM_INFO sys{ 0 };
	g_winAPIs->GetNativeSystemInfo(&sys);

	if (hProcess && hThread)
	{
		const auto dwThreadID = g_winAPIs->GetThreadId(hThread);
		if (dwThreadID == g_winAPIs->GetCurrentThreadId())
		{
			CONTEXT ctx{ 0 };
			g_winAPIs->RtlCaptureContext(&ctx);

			LPVOID lpFrames[MAX_NUMBER_OF_FRAMES] = { 0x0 };
			for (auto& lpFrame : lpFrames)
				lpFrame = nullptr;

			auto wCapturedFrames = g_winAPIs->RtlCaptureStackBackTrace(1, MAX_NUMBER_OF_FRAMES, lpFrames, nullptr);
			if (!wCapturedFrames)
			{
				APP_TRACE_LOG(LL_CRI, L"Any frame can NOT captured! Error: %u", g_winAPIs->GetLastError());
				return false;
			}
			APP_TRACE_LOG(LL_TRACE, L"%u Frame captured!", wCapturedFrames);

			for (auto i = 0; i < wCapturedFrames; i++)
			{
				const auto qwAddress = reinterpret_cast<DWORD64>(lpFrames[i]);
				APP_TRACE_LOG(LL_TRACE, L"Current frame index: %d Addr: 0x%llu", i, qwAddress);

				if (!qwAddress)
					continue;

				const auto spSymbols = __GetSymbols(hProcess, qwAddress, 0, 0);
				if (!IS_VALID_SMART_PTR(spSymbols))
				{
					APP_TRACE_LOG(LL_ERR, L"[%u] Failed to get symbols for current frame", i);
					continue;
				}
				
#if defined _M_IX86
				spSymbols->qwInstrPtr = ctx.Eip;
#else
				spSymbols->qwInstrPtr = ctx.Rip;
#endif
				spSymbols->bHasDebugRegister = ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
				
				vecStackData.push_back(spSymbols);
			}
			
			bRet = !vecStackData.empty();
		}
		else
		{
			const auto bSuspended = g_winAPIs->SuspendThread(hThread) != (DWORD)-1;

			CONTEXT ctx;
			ZeroMemory(&ctx, sizeof(ctx));
			ctx.ContextFlags = CONTEXT_FULL;

			auto bCtxQueryFailed = false;
			if (!stdext::is_wow64())
			{
				if (!g_winAPIs->GetThreadContext(hThread, &ctx))
				{
					APP_TRACE_LOG(LL_ERR, L"GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
					bCtxQueryFailed = true;
				}
			}
			else
			{
				WOW64_CONTEXT wctx{ 0 };
				wctx.ContextFlags = CONTEXT_FULL;

				if (!g_winAPIs->Wow64GetThreadContext(hThread, &wctx))
				{
					APP_TRACE_LOG(LL_ERR, L"Wow64GetThreadContext failed with error: %u", g_winAPIs->GetLastError());
					bCtxQueryFailed = true;
				}

				memcpy(&ctx, &wctx, sizeof(ctx));
			}

			if (bSuspended)
				g_winAPIs->ResumeThread(hThread);

			if (bCtxQueryFailed)
				return false;

			DWORD dwImageType = IMAGE_FILE_MACHINE_UNKNOWN;

			STACKFRAME64 sf = { 0 };
			sf.AddrPC.Mode = AddrModeFlat;
			sf.AddrStack.Mode = AddrModeFlat;
			sf.AddrFrame.Mode = AddrModeFlat;

#ifdef _M_IX86
			dwImageType = IMAGE_FILE_MACHINE_I386;
			sf.AddrPC.Offset = ctx.Eip;
			sf.AddrStack.Offset = ctx.Esp;
			sf.AddrFrame.Offset = ctx.Ebp;
#elif _M_X64
			dwImageType = IMAGE_FILE_MACHINE_AMD64;
			sf.AddrPC.Offset = ctx.Rip;
			sf.AddrFrame.Offset = ctx.Rbp;
			sf.AddrStack.Offset = ctx.Rsp;
#endif
//			if (sys.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || sys.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
//				dwImageType = IMAGE_FILE_MACHINE_AMD64;

			// sf.AddrReturn.Mode = AddrModeFlat;

			DWORD dwFrame = 0;
			while (true)
			{
				if (dwFrame >= MAX_NUMBER_OF_FRAMES)
				{
					APP_TRACE_LOG(LL_ERR, L"Maximum number of frames reached!");
					break;
				}

				if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
				{
					APP_TRACE_LOG(LL_ERR, L"Process handle is not valid!");
					break;
				}

				if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hThread))
				{
					APP_TRACE_LOG(LL_ERR, L"Thread handle is not valid!");
					break;
				}

				if (!g_winAPIs->StackWalk64(dwImageType, hProcess, hThread, &sf, &ctx, nullptr, g_winAPIs->SymFunctionTableAccess64, g_winAPIs->SymGetModuleBase64, nullptr))
				{
					const auto dwErrorCode = g_winAPIs->GetLastError();
					APP_TRACE_LOG(
						dwErrorCode == ERROR_PARTIAL_COPY ? LL_TRACE : LL_WARN,
						L"StackWalk64 fail! Error: %u",
						g_winAPIs->GetLastError()
					);
					break;
				}

				const auto qwAddress = sf.AddrPC.Offset;
				if (!qwAddress)
				{
					APP_TRACE_LOG(LL_ERR, L"Instruction ptr address is zero!");
					break;
				}

				const auto spSymbols = __GetSymbols(hProcess, qwAddress, sf.AddrReturn.Offset, sf.AddrStack.Offset);
				if (!IS_VALID_SMART_PTR(spSymbols))
				{
					APP_TRACE_LOG(LL_ERR, L"[%u] Failed to get symbols for current frame", dwFrame);
					continue;
				}

#if defined _M_IX86
				spSymbols->qwInstrPtr = ctx.Eip;
#else
				spSymbols->qwInstrPtr = ctx.Rip;
#endif
				spSymbols->bHasDebugRegister = ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;

				vecStackData.push_back(spSymbols);

				dwFrame++;

				// Basic sanity check to make sure the frame is OK
				if (sf.AddrFrame.Offset == 0)
					break;
				//					if (sf.AddrReturn.Offset == 0)
				//						break;
			}

			bRet = !vecStackData.empty();
		}
	}

	return bRet;
}
