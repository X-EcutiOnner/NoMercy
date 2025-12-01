#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Tls.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"

#define IP_SANITY_CHECK(ip,BaseAddress,ModuleSize) (ip > BaseAddress) && (ip < (BaseAddress + ModuleSize))

namespace NoMercy
{
	static DWORD_PTR g_NtdllBase = 0;
	static DWORD_PTR g_W32UBase = 0;

	static DWORD g_NtdllSize = 0;
	static DWORD g_W32USize = 0;
	
	typedef void(*CallbackFn)();

	void InstrumentationCallbackProxy();

#ifdef _M_X64
	extern "C" void InstrumentationCallback(CONTEXT * context)
	{
		TEB* teb = NtCurrentTeb();

		context->Rip = teb->InstrumentationCallbackPreviousPc;
		context->Rsp = teb->InstrumentationCallbackPreviousSp;
		context->Rcx = context->R10;

		BOOLEAN sanityCheckNt = 0;;
		BOOLEAN sanityCheckWu = 0;
		DWORD_PTR NtdllBase = 0;
		DWORD_PTR W32UBase = 0;
		DWORD NtdllSize = 0;
		DWORD W32USize = 0;

#ifdef _DEBUG
		if (!teb->InstrumentationCallbackDisabled) // Prevent recursion
		{
			teb->InstrumentationCallbackDisabled = TRUE;
			
			PVOID ImageBase = NtCurrentPeb()->ImageBaseAddress;
			PIMAGE_NT_HEADERS NtHeaders = g_winAPIs->RtlImageNtHeader(ImageBase);
			const auto ReturnAddress = context->Rip;
			if (ReturnAddress >= (ULONG_PTR)ImageBase && ReturnAddress < (ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage)
			{
				// ignore if ReturnAddress inside in anticheat module
				APP_TRACE_LOG(LL_CRI, L"Direct syscall detected!");
			}

			// Get pointers to DLL base addresss & sizes
			NtdllBase = (DWORD_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_NtdllBase,
				NULL,
				NULL
			);

			W32UBase = (DWORD_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_W32UBase,
				NULL,
				NULL
			);

			NtdllSize = InterlockedCompareExchange(
				(DWORD*)&g_NtdllSize,
				NULL,
				NULL
			);

			W32USize = InterlockedCompareExchange(
				(DWORD*)&g_W32USize,
				NULL,
				NULL
			);

			// Check to see if the syscall came from within the DLLs
#ifdef _WIN64
			sanityCheckNt = IP_SANITY_CHECK(ctx->Rip, NtdllBase, NtdllSize);
			sanityCheckWu = IP_SANITY_CHECK(ctx->Rip, W32UBase, W32USize);
#else
			sanityCheckNt = IP_SANITY_CHECK(ReturnAddress, NtdllBase, NtdllSize);
			sanityCheckWu = IP_SANITY_CHECK(ReturnAddress, W32UBase, W32USize);
#endif

			uint8_t SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
			const auto SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
			SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
			SymbolInfo->MaxNameLen = MAX_SYM_NAME;

			DWORD64 Displacement = 0;
			const auto bSymRet = g_winAPIs->SymFromAddr(NtCurrentProcess(), context->Rip, &Displacement, SymbolInfo);

			APP_TRACE_LOG(LL_SYS, L"Addr: %p Symbol name: %s Ret: %d (%u)", ReturnAddress, SymbolInfo->Name, bSymRet, g_winAPIs->GetLastError());

			if (!(sanityCheckNt || sanityCheckWu))
			{
				// ignore if ReturnAddress inside in anticheat module
				APP_TRACE_LOG(LL_CRI, L"Manual syscall detected!");
			}
			
			if (SymbolInfo->Address == (ULONG_PTR)g_winAPIs->NtQueryVirtualMemory)
			{
				ULONG_PTR* InstrumentationCallbackPreviousSp = *(ULONG_PTR**)teb->InstrumentationCallbackPreviousSp;
				ULONG_PTR* SysArgs = InstrumentationCallbackPreviousSp + 1; // Skip return address
				**(PSIZE_T*)(SysArgs + 5) = 1337;

				context->Rax = STATUS_ACCESS_DENIED;
			}

			teb->InstrumentationCallbackDisabled = FALSE;
		}
#endif

		RtlRestoreContext(context, NULL);
	}
#else

	NTSTATUS InstrumentationCallback(ULONG_PTR ReturnAddress, ULONG_PTR ReturnVal)
	{
		if (ReturnVal != STATUS_SUCCESS)
			return ReturnVal;

		NTSTATUS Status = ReturnVal;
		
		BOOLEAN sanityCheckNt = 0;;
		BOOLEAN sanityCheckWu = 0;
		DWORD_PTR NtdllBase = 0;
		DWORD_PTR W32UBase = 0;
		DWORD NtdllSize = 0;
		DWORD W32USize = 0;

#ifdef _DEBUG
		TEB* Teb = NtCurrentTeb();
		if (!Teb->InstrumentationCallbackDisabled) // Prevent recursion
		{
			Teb->InstrumentationCallbackDisabled = TRUE;

			PVOID ImageBase = NtCurrentPeb()->ImageBaseAddress;
			PIMAGE_NT_HEADERS NtHeaders = g_winAPIs->RtlImageNtHeader(ImageBase);
			if (ReturnAddress >= (ULONG_PTR)ImageBase && ReturnAddress < (ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage)
			{
				// ignore if ReturnAddress inside in anticheat module
				APP_TRACE_LOG(LL_CRI, L"Direct syscall detected!");
			}

			// Get pointers to DLL base addresss & sizes
			NtdllBase = (DWORD_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_NtdllBase,
				NULL,
				NULL
			);

			W32UBase = (DWORD_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_W32UBase,
				NULL,
				NULL
			);

			NtdllSize = InterlockedCompareExchange(
				(DWORD*)&g_NtdllSize,
				NULL,
				NULL
			);

			W32USize = InterlockedCompareExchange(
				(DWORD*)&g_W32USize,
				NULL,
				NULL
			);

			// Check to see if the syscall came from within the DLLs
#ifdef _WIN64
			sanityCheckNt = IP_SANITY_CHECK(ctx->Rip, NtdllBase, NtdllSize);
			sanityCheckWu = IP_SANITY_CHECK(ctx->Rip, W32UBase, W32USize);
#else
			sanityCheckNt = IP_SANITY_CHECK(ReturnAddress, NtdllBase, NtdllSize);
			sanityCheckWu = IP_SANITY_CHECK(ReturnAddress, W32UBase, W32USize);
#endif

			BYTE SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
			PSYMBOL_INFO SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
			SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
			SymbolInfo->MaxNameLen = MAX_SYM_NAME;

			// An invalid system service was specified in a system service call.
			if (ReturnVal == 0xc000001c)
			{
				APP_TRACE_LOG(LL_CRI, L"Invalid service call!");
				return ReturnVal;
			}

			DWORD64 Displacement = 0;
			const auto bSymRet = g_winAPIs->SymFromAddr(NtCurrentProcess(), ReturnAddress, &Displacement, SymbolInfo);

			APP_TRACE_LOG(LL_SYS, L"Addr: %p Symbol name: %s Ret: %d (%u)", ReturnAddress, SymbolInfo->Name, bSymRet, g_winAPIs->GetLastError());

			if (!(sanityCheckNt || sanityCheckWu))
			{
				// ignore if ReturnAddress inside in anticheat module
				APP_TRACE_LOG(LL_CRI, L"Manual syscall detected!");
				return ReturnVal;
			}
			
			if (SymbolInfo->Address == (ULONG_PTR)g_winAPIs->NtQueryVirtualMemory)
			{
				ULONG_PTR* InstrumentationCallbackPreviousSp = *(ULONG_PTR**)Teb->InstrumentationCallbackPreviousSp;
				ULONG_PTR* SysArgs = InstrumentationCallbackPreviousSp + 1; // Skip return address
				**(PSIZE_T*)(SysArgs + 5) = 1337;

				Status = STATUS_ACCESS_DENIED;
			}

			Teb->InstrumentationCallbackDisabled = FALSE;
		}
#endif

		return Status;
	}
#endif

	bool CSelfApiHooks::__SetInstrumentationCallbackHook(HANDLE ProcessHandle, BOOL Enable)
	{
		if (!IsWindows7OrGreater())
			return true;

		CallbackFn Callback = Enable ? &InstrumentationCallbackProxy : nullptr;

		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo;
#ifdef _WIN64
		CallbackInfo.Version = 0;
#else
		// Native x86 instrumentation callbacks don't work correctly
		BOOL Wow64Process = FALSE;
		if (!g_winAPIs->IsWow64Process(ProcessHandle, &Wow64Process) || !Wow64Process)
		{
			APP_TRACE_LOG(LL_ERR, L"WoW64 processes is not supported!");
			return false;
		}
#endif
		CallbackInfo.Reserved = 0;
		CallbackInfo.Callback = Callback;

		NTSTATUS ntStatus = 0;
		if (IsWindows10OrGreater())
			ntStatus = g_winAPIs->NtSetInformationProcess(ProcessHandle, ProcessInstrumentationCallback, &CallbackInfo, sizeof(CallbackInfo));
		else
			ntStatus = g_winAPIs->NtSetInformationProcess(ProcessHandle, ProcessInstrumentationCallback, (PVOID)&Callback, sizeof(Callback));

		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtSetInformationProcess failed with status: %p", ntStatus);
			return false;
		}

		return true;
	}

	void CSelfApiHooks::InstallInstrumentationCallback(HANDLE hProcess)
	{
		if (!__SetInstrumentationCallbackHook(hProcess, TRUE))
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_INSTALL_INSTR_CALLBACK_HOOK_FAIL, 1);
			return;
		}

		ULONG ReturnLength = 0;
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo;
		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessInstrumentationCallback, &CallbackInfo, sizeof(CallbackInfo), &ReturnLength);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with status: %p", ntStatus);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_INSTALL_INSTR_CALLBACK_HOOK_FAIL, 2);
			return;
		}

		if (CallbackInfo.Callback != &InstrumentationCallbackProxy)
		{
			APP_TRACE_LOG(LL_ERR, L"Callback pointer is not correct: %p/%p", CallbackInfo.Callback, &InstrumentationCallbackProxy);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_INSTALL_INSTR_CALLBACK_HOOK_FAIL, 3);
			return;
		}
	}

	void CSelfApiHooks::RemoveInstrumentationCallback(HANDLE hProcess)
	{
		__SetInstrumentationCallbackHook(hProcess, FALSE);
	}
};
