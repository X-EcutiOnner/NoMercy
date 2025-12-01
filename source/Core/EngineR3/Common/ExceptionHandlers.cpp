#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ExceptionHandlers.hpp"
#include "../Anti/AntiDebug.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"
#include <crashpad/client/simulate_crash_win.h>

namespace NoMercyCore
{
	extern uint32_t OnSystemExceptionThrowed(EXCEPTION_POINTERS* pExceptionInfo);
}

namespace NoMercy
{
	static const auto gsc_dwTestExceptionCode = 0x1337C0DF;
	
	PVOID pvSingleStepWatcherHandler = nullptr;
	PVOID pvExceptionWatcherHandler = nullptr;
	PVOID pvExceptionWatcherHandler2 = nullptr;

	const auto& get_text_section()
	{
		static const auto text = []() -> std::pair <uint8_t*, size_t>
		{
			const auto hProcessBase = g_winModules->hBaseModule;
			if (hProcessBase)
			{
				const auto pe = Pe::PeNative::fromModule(hProcessBase);
				if (pe.valid())
				{
					for (const auto& section : pe.sections())
					{
						std::string name(reinterpret_cast<const char*>(section.Name), sizeof(section.Name));
						while (!name.empty() && !name.back()) name.pop_back();

						if (name == xorstr_(".text"))
						{
							return { (uint8_t*)((DWORD_PTR)hProcessBase + section.VirtualAddress), section.Misc.VirtualSize};
						}
					}
				}
			}

			return { nullptr, 0 };
		}
		();

		return text;
	}
	bool in_text_range(const DWORD_PTR addr)
	{
		return
			addr >= reinterpret_cast<DWORD_PTR>(get_text_section().first) &&
			addr <= reinterpret_cast<DWORD_PTR>(
				get_text_section().first +
				get_text_section().second
			);
	}

	LONG __OnExceptionThrowed(PEXCEPTION_POINTERS ExceptionInfo)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LL_WARN, L"Exception thrown: 0x%X", ExceptionInfo && ExceptionInfo->ExceptionRecord ? ExceptionInfo->ExceptionRecord->ExceptionCode : 0);
		// OnSystemExceptionThrowed(ExceptionInfo);

		if (!g_winAPIs->IsDebuggerPresent())
#endif
		{
			if (ExceptionInfo && ExceptionInfo->ContextRecord &&
				CApplication::InstancePtr() &&
				IS_VALID_SMART_PTR(CApplication::Instance().HwbpWatcherInstance()) &&
				false == CApplication::Instance().HwbpWatcherInstance()->IsInitialized())
			{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
				APP_TRACE_LOG(LL_WARN, L"VEHWatchdog: Debug registers: %u/%u/%u/%u/%u/%u",
					ExceptionInfo->ContextRecord->Dr0, ExceptionInfo->ContextRecord->Dr1, ExceptionInfo->ContextRecord->Dr2,
					ExceptionInfo->ContextRecord->Dr3, ExceptionInfo->ContextRecord->Dr6, ExceptionInfo->ContextRecord->Dr7
				);
#endif

				if (ExceptionInfo->ContextRecord->Dr0)
					ExceptionInfo->ContextRecord->Dr0 = 0;
				if (ExceptionInfo->ContextRecord->Dr1)
					ExceptionInfo->ContextRecord->Dr1 = 0;
				if (ExceptionInfo->ContextRecord->Dr2)
					ExceptionInfo->ContextRecord->Dr2 = 0;
				if (ExceptionInfo->ContextRecord->Dr3)
					ExceptionInfo->ContextRecord->Dr3 = 0;
				if (ExceptionInfo->ContextRecord->Dr6)
					ExceptionInfo->ContextRecord->Dr6 = 0;
				if (ExceptionInfo->ContextRecord->Dr7)
					ExceptionInfo->ContextRecord->Dr7 = 0;
			}
		}

		if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		{
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == gsc_dwTestExceptionCode)
			{
				APP_TRACE_LOG(LL_SYS, L"Test exception catched!");
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
			APP_TRACE_LOG(LL_WARN, L"VEHWatchdog: Exception: %p", ExceptionInfo->ExceptionRecord->ExceptionCode);
#endif


#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
			const auto vecWhitelistedExceptions = std::vector <uint32_t>{
				(uint32_t)STATUS_INVALID_HANDLE,
				EXCEPTION_CPP_MAGIC // C++ exception
			};
			if (!stdext::in_vector(vecWhitelistedExceptions, ExceptionInfo->ExceptionRecord->ExceptionCode))
			{
				/*
				if (IsDebuggerPresent())
					__debugbreak();
				*/

				if (NoMercyCore::CApplication::InstancePtr())
					NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();
			}
#endif

			// if exception was inside game module and not ud2 or int 0x2d.
			const auto dwExceptionAddress = (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
			if (in_text_range(dwExceptionAddress))
			{
//#ifdef __EXPERIMENTAL__
				// CHECKME should we take care C0000005?
				if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
					ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
				{
					// APP_TRACE_LOG(LL_CRI, L"Exception: %p inside game module: %p", ExceptionInfo->ExceptionRecord->ExceptionCode, dwExceptionAddress);
					// CApplication::Instance().OnCloseRequest(EXIT_ERR_GAME_MODULE_UNKNOWN_EXCEPTION, g_winAPIs->GetLastError());
					// std::abort();
					return EXCEPTION_CONTINUE_EXECUTION;
				}
//#endif

				// if protection PAGE_GUARD or exception code STATUS_GUARD_PAGE_VIOLATION / STATUS_SINGLE_STEP
				MEMORY_BASIC_INFORMATION mbi;
				if (g_winAPIs->VirtualQuery(ExceptionInfo->ExceptionRecord->ExceptionAddress, &mbi, sizeof(mbi)))
				{
					if (mbi.Protect & PAGE_GUARD)
					{
						APP_TRACE_LOG(LL_CRI, L"Exception: %p inside PAGE_GUARD: %p", ExceptionInfo->ExceptionRecord->ExceptionCode, dwExceptionAddress);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_GAME_MODULE_PG_EXCEPTION, g_winAPIs->GetLastError());
					}
					else if (mbi.Protect == PAGE_NOACCESS && mbi.AllocationProtect != PAGE_NOACCESS)
					{
						APP_TRACE_LOG(LL_CRI, L"Exception: %p inside non-accessible: %p Default: %p", ExceptionInfo->ExceptionRecord->ExceptionCode, dwExceptionAddress, mbi.AllocationProtect);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_GAME_MODULE_NO_ACCESS_EXCEPTION, g_winAPIs->GetLastError());
					}
				}
			}
			
			// FIXME: False positive
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				MEMORY_BASIC_INFORMATION mbi;
				g_winAPIs->VirtualQuery(ExceptionInfo->ExceptionRecord->ExceptionAddress, &mbi, sizeof(mbi));

				wchar_t wszMappedName[MAX_PATH]{ L'\0' };
				g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), ExceptionInfo->ExceptionRecord->ExceptionAddress, wszMappedName, MAX_PATH);

				const auto wstLowerModuleName = stdext::to_lower_wide(wszMappedName);
				if (wstLowerModuleName.find(xorstr_(L"nomercy_module")) == std::wstring::npos)
				{
					APP_TRACE_LOG(LL_ERR, L"VEHWatchdog: EXCEPTION_BREAKPOINT detected! Module: %s Address: %p Protect: %p Size: %p Type: %p Allocation: %p (%p)",
						wszMappedName, ExceptionInfo->ExceptionRecord->ExceptionAddress, mbi.Protect, mbi.RegionSize, mbi.Type, mbi.AllocationBase, mbi.AllocationProtect
					);
#ifdef _WIN64
					* (UCHAR*)ExceptionInfo->ContextRecord->Rip = 0x90;
#elif _WIN32
					* (UCHAR*)ExceptionInfo->ContextRecord->Eip = 0x90;
#endif
					// CApplication::Instance().OnCloseRequest(EXIT_ERR_VEH_BREAKPOINT_EXCEPTION, g_winAPIs->GetLastError());
				}
			}

			/*
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
			{
				APP_TRACE_LOG(LL_CRI, L"VEHWatchdog: EXCEPTION_GUARD_PAGE detected!!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_VEH_PAGE_GUARD_EXCEPTION, g_winAPIs->GetLastError());
			}
			*/

//#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_DEBUG_EVENT)
			{
				APP_TRACE_LOG(LL_CRI, L"VEHWatchdog: EXCEPTION_DEBUG_EVENT detected!!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_EXCEPTION_DEBUG_EVENT, g_winAPIs->GetLastError());
			}
//#endif

			if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_WX86_BREAKPOINT)
			{
				APP_TRACE_LOG(LL_CRI, L"VEHWatchdog: STATUS_WX86_BREAKPOINT detected!!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_STATUS_WX86_BREAKPOINT_EXCEPTION, g_winAPIs->GetLastError());
			}

			if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_WX86_SINGLE_STEP)
			{
				APP_TRACE_LOG(LL_CRI, L"VEHWatchdog: STATUS_WX86_SINGLE_STEP detected!!");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_STATUS_WX86_SINGLE_STEP_EXCEPTION, g_winAPIs->GetLastError());
			}

//#ifdef __EXPERIMENTAL__
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION && ExceptionInfo->ContextRecord)
			{
				// Was write?
				if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] != 1)
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				const auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
				if (!addr || !in_text_range(addr))
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				const auto had_single_step = ExceptionInfo->ContextRecord->EFlags & 0x0100;

#ifdef _M_IX86
				const auto pInstrPtr = ExceptionInfo->ContextRecord->Eip;
#else
				const auto pInstrPtr = ExceptionInfo->ContextRecord->Rip;
#endif

				APP_TRACE_LOG(LL_CRI, L"Access violation exception from: %p IP: %p SS: %d", addr, pInstrPtr, had_single_step);

				return EXCEPTION_CONTINUE_SEARCH;
			}
//#endif
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
	LONG WINAPI VEHWatchdog(PEXCEPTION_POINTERS ExceptionInfo)
	{
		return __OnExceptionThrowed(ExceptionInfo);
	}
	LONG WINAPI VCHWatchdog(PEXCEPTION_POINTERS ExceptionInfo)
	{
		return __OnExceptionThrowed(ExceptionInfo);
	}
	LONG WINAPI VEHSSWatchdog(PEXCEPTION_POINTERS ExceptionInfo)
	{
		if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		{
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
			{
				auto bIsTrapAddr = false;
				if (IS_VALID_SMART_PTR(CApplication::Instance().HwbpWatcherInstance()) &&
					CApplication::Instance().HwbpWatcherInstance()->IsInitialized() &&
					CApplication::Instance().HwbpWatcherInstance()->IsTrapAddress(ExceptionInfo->ExceptionRecord->ExceptionAddress))
				{
					bIsTrapAddr = true;
				}

				if (!bIsTrapAddr)
				{
					APP_TRACE_LOG(LL_CRI, L"VehFilter: EXCEPTION_SINGLE_STEP detected!!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_VEH_SINGLE_STEP_EXCEPTION, g_winAPIs->GetLastError());
				}
			}
		}
		
		return EXCEPTION_CONTINUE_SEARCH;
	}

	__forceinline bool InitializeVEH()
	{
		pvExceptionWatcherHandler = g_winAPIs->AddVectoredExceptionHandler(1, VEHWatchdog);
		return (pvExceptionWatcherHandler != nullptr);
	}
	__forceinline bool InitializeVCH()
	{
		pvExceptionWatcherHandler2 = g_winAPIs->AddVectoredContinueHandler(1, VCHWatchdog);
		return (pvExceptionWatcherHandler2 != nullptr);
	}
	__forceinline bool InitializeVEHSS()
	{
		pvSingleStepWatcherHandler = g_winAPIs->AddVectoredExceptionHandler(1, VEHSSWatchdog);
		return (pvSingleStepWatcherHandler != nullptr);
	}

	bool CExceptionHandlers::InitExceptionHandlers()
	{
		APP_TRACE_LOG(LL_SYS, L"Initializing exception handlers...");
		
#if defined(_RELEASE_DEBUG_MODE_)
		return true;
#else
		if (!InitializeVEH())
		{
			APP_TRACE_LOG(LL_ERR, L"VEH exception handler can not created! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Exception handlers part 1 initialized successfully!");

		if (!InitializeVCH())
		{
			APP_TRACE_LOG(LL_ERR, L"VCH exception handler can not created! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Exception handlers part 2 initialized successfully!");

		const auto bSSInitRet = InitSingleStepHandler();
		if (!bSSInitRet)
		{
			APP_TRACE_LOG(LL_ERR, L"VEHSS exception handler can not created! Last error: %u", g_winAPIs->GetLastError());
		}

		APP_TRACE_LOG(LL_SYS, L"Exception handlers part 3 initialized successfully!");

		/*
		// Run test exception
		__try
		{
			g_winAPIs->RaiseException(gsc_dwTestExceptionCode, 0, 0, nullptr);
		}
		__except (VEHWatchdog(GetExceptionInformation()))
		{
		}
		*/
		
		return bSSInitRet;
#endif
	}
	bool CExceptionHandlers::InitSingleStepHandler()
	{
		APP_TRACE_LOG(LL_SYS, L"Initializing single step exception handler...");
		
//#if defined(_RELEASE_DEBUG_MODE_)
//		return true;
//#else
		if (!InitializeVEHSS())
		{
			APP_TRACE_LOG(LL_ERR, L"VEH single step handler can not created! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Single step exception handler initialized successfully!");
		return true;
//#endif
	}

	void CExceptionHandlers::RemoveExceptionHandlers()
	{
		if (pvExceptionWatcherHandler)
			g_winAPIs->RemoveVectoredExceptionHandler(pvExceptionWatcherHandler);
		if (pvExceptionWatcherHandler2)
			g_winAPIs->RemoveVectoredContinueHandler(pvExceptionWatcherHandler2);
		if (pvSingleStepWatcherHandler)
			g_winAPIs->RemoveVectoredExceptionHandler(pvSingleStepWatcherHandler);
	}
	void CExceptionHandlers::RemoveSingleStepHandler()
	{
		g_winAPIs->RemoveVectoredExceptionHandler(pvSingleStepWatcherHandler);
	}
}
