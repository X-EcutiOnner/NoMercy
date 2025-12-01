#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Monitor/MemoryHookScanner.hpp"
#include "../Network/CloudflareChecker.hpp"
#include "Hooks.hpp"
#include <MinHook.h>
#include <intrin.h>
#include "../../EngineR3_Core/include/PEHelper.hpp"
#pragma intrinsic(_ReturnAddress)

#define ENABLE_HOOK_SCAN_PART_1
// #define ENABLE_HOOK_SCAN_PART_2 
#define ENABLE_HOOK_SCAN_PART_3
#define ENABLE_HOOK_SCAN_PART_4
// #define ENABLE_HOOK_SCAN_PART_5
// #define ENABLE_HOOK_SCAN_PART_6
// #define ENABLE_HOOK_SCAN_PART_7
// #define ENABLE_HOOK_SCAN_PART_8

// RtlUnhandledExceptionFilter2 >> -1
// DbgPrintEx >> 0
// NtDebugContinue, DbgUserBreakPoint >> null fn
// SleepEx(kernelbase) >> alertable always true

namespace NoMercy
{
	static bool s_bImmActive = false;

	extern "C" void __stdcall KiApcStub();

#pragma region HookDeclerations
	static auto NtQueueApcThread_ctx = SHookInfo<decltype(&NtQueueApcThread)>{ nullptr, {} };
	static auto KiUserApcDispatcher_ctx = SHookInfo<WinAPI::TKiUserApcDispatcher>{ nullptr, {} };
	static auto LdrInitializeThunk_ctx = SHookInfo<decltype(&LdrInitializeThunk)>{ nullptr, {} };
	static auto RtlGetFullPathName_U_ctx = SHookInfo<decltype(&RtlGetFullPathName_U)>{ nullptr, {} };
	static auto LdrGetDllHandleEx_ctx = SHookInfo<decltype(&LdrGetDllHandleEx)>{ nullptr, {} };
	static auto NtMapViewOfSection_ctx = SHookInfo<decltype(&NtMapViewOfSection)>{ nullptr, {} };
	static auto SetWindowLongA_ctx = SHookInfo<decltype(&SetWindowLongA)>{ nullptr, {} };
	static auto SetWindowLongW_ctx = SHookInfo<decltype(&SetWindowLongW)>{ nullptr, {} };
	static auto connect_ctx = SHookInfo<decltype(&connect)>{ nullptr, {} };
	static auto WSAConnect_ctx = SHookInfo<decltype(&WSAConnect)>{ nullptr, {} };
	static auto NtDelayExecution_ctx = SHookInfo<decltype(&NtDelayExecution)>{ nullptr, {} };
	static auto ClientThreadSetup_ctx = SHookInfo<WinAPI::TClientThreadSetup>{ nullptr, {} };
	static auto NtCreateSection_ctx = SHookInfo<decltype(&NtCreateSection)>{ nullptr, {} };
	static auto NtAllocateVirtualMemory_ctx = SHookInfo<decltype(&NtAllocateVirtualMemory)>{ nullptr, {} };
	static auto RtlDispatchException_ctx = SHookInfo<decltype(&RtlDispatchException)>{ nullptr, {} };
	static auto NtUserGetAsyncKeyState_ctx = SHookInfo<WinAPI::TNtUserGetAsyncKeyState>{ nullptr, {} };
	static auto NtUserSetWindowLongPtr_ctx = SHookInfo<WinAPI::TNtUserSetWindowLongPtr>{ nullptr, {} };
	static auto NtUserSetWindowLong_ctx = SHookInfo<WinAPI::TNtUserSetWindowLong>{ nullptr, {} };
	static auto NtUserSetTimer_ctx = SHookInfo<WinAPI::TNtUserSetTimer>{ nullptr, {} };
	static auto NtUserCreateWindowEx_ctx = SHookInfo<WinAPI::TNtUserCreateWindowEx>{ nullptr, {} };
	static auto NtGdiHfontCreate_ctx = SHookInfo<WinAPI::TNtGdiHfontCreate>{ nullptr, {} };
	static auto NtContinue_ctx = SHookInfo<decltype(&NtContinue)>{ nullptr, {} };
	static auto NtSetContextThread_ctx = SHookInfo<decltype(&NtSetContextThread)>{ nullptr, {} };
	static auto NtTerminateProcess_ctx = SHookInfo<decltype(&NtTerminateProcess)>{ nullptr, {} };
	// Test
	static auto NtTestAlert_ctx = SHookInfo<decltype(&NtTestAlert)>{ nullptr, {} };
	static auto NtFlushInstructionCache_ctx = SHookInfo<decltype(&NtFlushInstructionCache)>{ nullptr, {} };
	static auto NtUnmapViewOfSection_ctx = SHookInfo<decltype(&NtUnmapViewOfSection)>{ nullptr, {} };
	static auto LdrAccessResource_ctx = SHookInfo<decltype(&LdrAccessResource)>{ nullptr, {} };
	static auto RtlAddVectoredExceptionHandler_ctx = SHookInfo<decltype(&RtlAddVectoredExceptionHandler)>{ nullptr, {} };
	static auto RtlAddVectoredContinueHandler_ctx = SHookInfo<decltype(&RtlAddVectoredContinueHandler)>{ nullptr, {} };
	static auto SetUnhandledExceptionFilter_ctx = SHookInfo<decltype(&SetUnhandledExceptionFilter)>{ nullptr, {} };
	static auto NtCreateFile_ctx = SHookInfo<decltype(&NtCreateFile)>{ nullptr, {} };
	static auto MultiByteToWideChar_ctx = SHookInfo<decltype(&MultiByteToWideChar)>{ nullptr, {} };
	static auto WideCharToMultiByte_ctx = SHookInfo<decltype(&WideCharToMultiByte)>{ nullptr, {} };
	static auto GetAsyncKeyState_ctx = SHookInfo<decltype(&GetAsyncKeyState)>{ nullptr, {} };
	static auto GetKeyState_ctx = SHookInfo<decltype(&GetKeyState)>{ nullptr, {} };
	static auto GetKeyboardState_ctx = SHookInfo<decltype(&GetKeyboardState)>{ nullptr, {} };
	static auto ImmGetHotKey_ctx = SHookInfo<WinAPI::TImmGetHotKey>{ nullptr, {} };
	static auto ImmActivateLayout_ctx = SHookInfo<WinAPI::TImmActivateLayout>{ nullptr, {} };
	static auto RtlInitializeSListHead_ctx = SHookInfo<decltype(&RtlInitializeSListHead)>{ nullptr, {} };
	static auto RtlPcToFileHeader_ctx = SHookInfo<decltype(&RtlPcToFileHeader)>{ nullptr, {} };
	static auto IsNLSDefinedString_ctx = SHookInfo<decltype(&IsNLSDefinedString)>{ nullptr, {} };
	static auto DbgUiSetThreadDebugObject_ctx = SHookInfo<decltype(&DbgUiSetThreadDebugObject)>{ nullptr, {} };
	static auto NtQueryValueKey_ctx = SHookInfo<decltype(&NtQueryValueKey)>{ nullptr, {} };
	static auto NtOpenFile_ctx = SHookInfo<decltype(&NtOpenFile)>{ nullptr, {} };
	static auto LoadAppInitDlls_ctx = SHookInfo<WinAPI::TLoadAppInitDlls>{ nullptr, {} };
	static auto LockResource_ctx = SHookInfo<decltype(&LockResource)>{ nullptr, {} };
	static auto NtCreateWorkerFactory_ctx = SHookInfo<WinAPI::TNtCreateWorkerFactory>{ nullptr, {} };
	static auto RegisterClassExW_ctx = SHookInfo<decltype(&RegisterClassExW)>{ nullptr, {} };
	static auto DbgUiConnectToDbg_ctx = SHookInfo<decltype(&DbgUiConnectToDbg)>{ nullptr, {} };
	static auto DisableThreadLibraryCallsctx = SHookInfo<decltype(&DisableThreadLibraryCalls)>{ nullptr, {} };
	static auto _fsopen_ctx = SHookInfo<decltype(&_fsopen)>{ nullptr, {} };
	static auto NtUserSetWindowsHookEx_ctx = SHookInfo<WinAPI::TNtUserSetWindowsHookEx>{ nullptr, {} };
	static auto NtUserSetClassLongPtr_ctx = SHookInfo<WinAPI::TNtUserSetClassLongPtr>{ nullptr, {} };
	static auto NtProtectVirtualMemory_ctx = SHookInfo<decltype(&NtProtectVirtualMemory)>{ nullptr, {} };
	static auto NtAllocateVirtualMemoryEx_ctx = SHookInfo<WinAPI::TNtAllocateVirtualMemoryEx>{ nullptr, {} };
	static auto NtMapViewOfSectionEx_ctx = SHookInfo<WinAPI::TNtMapViewOfSectionEx>{ nullptr, {} };
	static auto KiUserCallbackDispatcher_ctx = SHookInfo<WinAPI::TKiUserCallbackDispatcher>{ nullptr, {} };
#pragma endregion HookDeclerations
	
	// 
	static void CheckIfReturnIsLegit(const char* function_name, PVOID return_address)
	{
		if (function_name == nullptr || return_address == nullptr)
			return;

		const auto wstFunctionName = stdext::to_wide(function_name);

		DWORD_PTR dwBase = 0;
		if (!CPEFunctions::IsInModule(return_address, 1, dwBase))
		{
			HOOK_LOG(LL_ERR, L"[%s] Return address: %p is not in module ranges", function_name, return_address);
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_OUT_OF_BOUND_MODULE, 1, wstFunctionName);
			return;
		}

		const auto stModuleName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress(dwBase);
		if (stModuleName.empty())
		{
			HOOK_LOG(LL_ERR, L"[%s] Return address: %p module: %p name can not handled!", function_name, return_address, dwBase);
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_OUT_OF_BOUND_MODULE, 2, wstFunctionName);
			return;
		}

		static std::vector <std::wstring> vecAllowedModules = {
		};
		if (!stdext::in_vector(vecAllowedModules, stModuleName))
		{
			HOOK_LOG(LL_ERR, L"[%s] Return address: %p module: %s is not allowed!", function_name, return_address, stModuleName.c_str());
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_OUT_OF_BOUND_MODULE, 3, wstFunctionName);
			return;
		}
	}
	
	// 
	[[noreturn]]
	static inline VOID DiscardApc(PCONTEXT Context)
	{
		NtContinue(Context, FALSE);
	}

	extern "C" void __stdcall HandleApc(PVOID ApcRoutine, PVOID Argument, PCONTEXT Context)
	{
		//__asm nop;

		if (!CApplication::Instance().AnalyserInstance()->IsApcAllowed(ApcRoutine))
		{
			HOOK_LOG(LL_ERR, L"Unknown APC: %p handled!", ApcRoutine);
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_12, 0);
			DiscardApc(Context);
		}

		//__asm nop;
	}

	extern "C"
	{
#ifdef _AMD64_
		// Context passes through a stack! Don't call it directly from a C/C++ code!
		VOID(NTAPI* OriginalApcDispatcher)(CONTEXT Context) = NULL;

		VOID NTAPI ApcHandler(PCONTEXT Context) // Calls from KiApcStub() in ApcStub.asm
		{
			// ApcRoutine = Context->P4Home, Arg = Context->P1Home:
			HandleApc(reinterpret_cast<PVOID>(Context->P4Home), reinterpret_cast<PVOID>(Context->P1Home), Context);
		}
#else
		// All arguments passes through a stack! Don't call it directly from a C/C++ code!
		VOID(NTAPI* OriginalApcDispatcher)(PVOID NormalRoutine, PVOID SystemArgument1, PVOID SystemArgument2, CONTEXT Context) = NULL;

		VOID NTAPI ApcHandler(PVOID ApcRoutine, PVOID Arg, PCONTEXT Context) // Calls from KiApcStub() in ApcStub.asm
		{
			HandleApc(ApcRoutine, Arg, Context);
		}
#endif
	}

	//
	VOID NTAPI RtlInitializeSListHeadDetour(PSLIST_HEADER ListHead)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlInitializeSListHead_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"RtlInitializeSListHead called");

		return RtlInitializeSListHead_ctx.original(ListHead);
	}
	PVOID NTAPI RtlPcToFileHeaderDetour(PVOID PcValue, PVOID* BaseOfImage)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlPcToFileHeader_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"RtlPcToFileHeader called");

		return RtlPcToFileHeader_ctx.original(PcValue, BaseOfImage);
	}
	BOOL WINAPI IsNLSDefinedStringDetour(NLS_FUNCTION Function, DWORD dwFlags, LPNLSVERSIONINFO lpVersionInformation, LPCWSTR lpString, INT cchStr)
	{
		// std::lock_guard <std::recursive_mutex> lock(IsNLSDefinedString_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"IsNLSDefinedString called");

		return IsNLSDefinedString_ctx.original(Function, dwFlags, lpVersionInformation, lpString, cchStr);
	}
	VOID NTAPI DbgUiSetThreadDebugObjectDetour(HANDLE DebugObject)
	{
		// std::lock_guard <std::recursive_mutex> lock(DbgUiSetThreadDebugObject_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"DbgUiSetThreadDebugObject called");

		return DbgUiSetThreadDebugObject_ctx.original(DebugObject);
	}
	NTSTATUS NTAPI NtQueryValueKeyDetour(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation,
		ULONG Length, PULONG ResultLength)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtQueryValueKey_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtQueryValueKey called");

		return NtQueryValueKey_ctx.original(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	}
	NTSTATUS NTAPI NtTestAlertDetour(VOID)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtTestAlert_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtTestAlert called");
		
		//return STATUS_SUCCESS;
		return NtTestAlert_ctx.original();
	}
	NTSTATUS NTAPI NtFlushInstructionCacheDetour(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtFlushInstructionCache_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtFlushInstructionCache called");

		// ...

		return NtFlushInstructionCache_ctx.original(ProcessHandle, BaseAddress, Length);
	}
	NTSTATUS NTAPI NtUnmapViewOfSectionDetour(HANDLE ProcessHandle, PVOID BaseAddress)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUnmapViewOfSection_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		// HOOK_LOG(LL_SYS, L"NtUnmapViewOfSection called");

		// ...

		return NtUnmapViewOfSection_ctx.original(ProcessHandle, BaseAddress);
	}
	NTSTATUS NTAPI LdrAccessResourceDetour(PVOID DllHandle, PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry, PVOID* ResourceBuffer, ULONG* ResourceLength)
	{
		// std::lock_guard <std::recursive_mutex> lock(LdrAccessResource_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"LdrAccessResource called");

		// ...

		return LdrAccessResource_ctx.original(DllHandle, ResourceDataEntry, ResourceBuffer, ResourceLength);
	}
	PVOID NTAPI RtlAddVectoredExceptionHandlerDetour(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlAddVectoredExceptionHandler_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"RtlAddVectoredExceptionHandler called");

		// ...

		return RtlAddVectoredExceptionHandler_ctx.original(First, Handler);
	}

	PVOID NTAPI RtlAddVectoredContinueHandlerDetour(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlAddVectoredContinueHandler_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"RtlAddVectoredContinueHandler called");

		// ...

		return RtlAddVectoredContinueHandler_ctx.original(First, Handler);
	}

	LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilterDetour(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
	{
		// std::lock_guard <std::recursive_mutex> lock(SetUnhandledExceptionFilter_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"SetUnhandledExceptionFilter called");

		// ...

		return SetUnhandledExceptionFilter_ctx.original(lpTopLevelExceptionFilter);
	}

	NTSTATUS NTAPI NtCreateFileDetour(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtCreateFile_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtCreateFile called");

		// ...

		return NtCreateFile_ctx.original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	int WINAPI MultiByteToWideCharDetour(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
	{
		// std::lock_guard <std::recursive_mutex> lock(MultiByteToWideChar_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"MultiByteToWideChar called");

		// ...

		return MultiByteToWideChar_ctx.original(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
	}

	int WINAPI WideCharToMultiByteDetour(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
	{
		// std::lock_guard <std::recursive_mutex> lock(WideCharToMultiByte_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"WideCharToMultiByte called");

		// ...

		return WideCharToMultiByte_ctx.original(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	}

	SHORT WINAPI GetAsyncKeyStateDetour(int vKey)
	{
		// std::lock_guard <std::recursive_mutex> lock(GetAsyncKeyState_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"GetAsyncKeyState called");

#ifdef ENABLE_HOOK_SCAN_PART_1
		PVOID pvBaseAddr = nullptr;
		g_winAPIs->RtlPcToFileHeader(_ReturnAddress(), &pvBaseAddr);
		
		if (*(WORD*)pvBaseAddr != IMAGE_DOS_SIGNATURE)
		{
			HOOK_LOG(LL_CRI, L"GetAsyncKeyState called from unknown module");
		}
#endif
		// ...

		return GetAsyncKeyState_ctx.original(vKey);
	}
	SHORT WINAPI GetKeyStateDetour(int nVirtKey)
	{
		// std::lock_guard <std::recursive_mutex> lock(GetKeyState_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"GetKeyState called");

		// ...

		return GetKeyState_ctx.original(nVirtKey);
	}
	BOOL WINAPI GetKeyboardStateDetour(PBYTE lpKeyState)
	{
		// std::lock_guard <std::recursive_mutex> lock(GetKeyboardState_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"GetKeyboardState called");

		// ...

		return GetKeyboardState_ctx.original(lpKeyState);
	}
	BOOL WINAPI ImmGetHotKeyDetour(DWORD dwHotKeyID, LPUINT lpuModifiers, LPUINT lpuVKey, LPHKL lphKL)
	{
		// std::lock_guard <std::recursive_mutex> lock(ImmGetHotKey_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"ImmGetHotKey called");

#ifdef ENABLE_HOOK_SCAN_PART_1
		s_bImmActive = true;
#endif
		
		return ImmGetHotKey_ctx.original(dwHotKeyID, lpuModifiers, lpuVKey, lphKL);
	}
	int WINAPI ImmActivateLayoutDetour(LPARAM pa)
	{
		// std::lock_guard <std::recursive_mutex> lock(ImmActivateLayout_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"ImmActivateLayout called");

#ifdef ENABLE_HOOK_SCAN_PART_1
		if (s_bImmActive)
		{
			s_bImmActive = false;
		}
		else
		{
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_11, 0);
		}
#endif

		return ImmActivateLayout_ctx.original(pa);
	}

	NTSTATUS NTAPI NtContinueDetour(PCONTEXT ContextRecord, BOOLEAN TestAlert)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtContinue_ctx.mtx);

#ifdef ENABLE_HOOK_SCAN_PART_2
		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtContinue called");

		if (!NoMercy::CApplication::InstancePtr()->ScannerInstance() || NoMercy::CApplication::InstancePtr()->ScannerInstance()->CheckStackTrace())
		{
			HOOK_LOG(LL_SYS, L"NtContinue passed");
			return NtContinue_ctx.original(ContextRecord, TestAlert);
		}
		
		HOOK_LOG(LL_ERR, L"NtContinue failed");
		return STATUS_UNSUCCESSFUL;
#else
		return NtContinue_ctx.original(ContextRecord, TestAlert);
#endif
	}
	NTSTATUS NTAPI NtSetContextThreadDetour(HANDLE ThreadHandle, PCONTEXT ThreadContext)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtSetContextThread_ctx.mtx);

#ifdef ENABLE_HOOK_SCAN_PART_2
		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtSetContextThread called");

		if (!NoMercy::CApplication::InstancePtr()->ScannerInstance() || NoMercy::CApplication::InstancePtr()->ScannerInstance()->CheckStackTrace())
		{
			HOOK_LOG(LL_SYS, L"NtSetContextThread passed");
			return NtSetContextThread_ctx.original(ThreadHandle, ThreadContext);
		}
		
		HOOK_LOG(LL_ERR, L"NtSetContextThread failed");
		return STATUS_UNSUCCESSFUL;
#else
		return NtSetContextThread_ctx.original(ThreadHandle, ThreadContext);
#endif
	}
	
	NTSTATUS NTAPI NtTerminateProcessDetour(HANDLE ProcessHandle, NTSTATUS ExitStatus)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtTerminateProcess_ctx.mtx);

		/*
		if (CApplication::InstancePtr() && NoMercyCore::CApplication::InstancePtr())
		{
			if (!CApplication::Instance().AppIsFinalized())
			{
				NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();
			}
		}
		*/

		return NtTerminateProcess_ctx.original(ProcessHandle, ExitStatus);
	}

	NTSTATUS NTAPI NtQueueApcThreadDetour(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, PVOID ApcReserved)
	{
		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"Internal APC handled: %p", ApcRoutine);
		CApcRoutinesStorage::Instance().AddAllowed(ApcRoutine);

		return NtQueueApcThread_ctx.original(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	}

	void NTAPI LdrInitializeThunkDetour(PCONTEXT NormalContext, PVOID SystemArgument1)
	{
		// std::lock_guard <std::recursive_mutex> lock(LdrInitializeThunk_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		const auto dwThreadID = HandleToUlong(NtCurrentThreadId());
		APP_TRACE_LOG(LL_SYS, L"LdrInitializeThunk called for thread %u", dwThreadID);

#ifdef ENABLE_HOOK_SCAN_PART_3
		// HOOK_LOG(LL_SYS, L"LdrInitializeThunk triggered! Ctx: %p Args: %p-%p TID: %u Original: %p", NormalContext, SystemArgument1, 0, HandleToUlong(NtCurrentThreadId()), LdrInitializeThunk_ctx.original);

		auto bSuspicious = false;
		auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnThreadCreated(HandleToUlong(NtCurrentThreadId()), NtCurrentThread(), NormalContext, bSuspicious);
		HOOK_LOG(LL_SYS, L"Thread: %u analysed, Completed: %d Suspicious: %d", HandleToUlong(NtCurrentThreadId()), bAnalysed, bSuspicious);
#endif

		return LdrInitializeThunk_ctx.original(NormalContext, SystemArgument1);
	}

	ULONG NTAPI RtlGetFullPathName_UDetour(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlGetFullPathName_U_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_4
		// HOOK_LOG(LL_SYS, L"RtlGetFullPathName_U triggered! File: %ls Original: %p", FileName, RtlGetFullPathName_U_ctx.original);

		const auto wstFileName = stdext::to_lower_wide(FileName);
		if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleAddressFromName(wstFileName.c_str(), true))
		{			
			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnModuleLoaded(FileName, NtCurrentThread(), CHECK_TYPE_RtlGetFullPathName_U, bSuspicious);
			if (!bAnalysed || bSuspicious)
			{
				HOOK_LOG(LL_WARN, L"File: %ls analysed, Completed: %d Suspicious: %d", FileName, bAnalysed, bSuspicious);
			}
		}
#endif
		return RtlGetFullPathName_U_ctx.original(FileName, Size, Buffer, ShortName);
	}

	NTSTATUS NTAPI LdrGetDllHandleExDetour(IN ULONG Flags, IN PWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID* DllHandle OPTIONAL)
	{
		// std::lock_guard <std::recursive_mutex> lock(LdrGetDllHandleEx_ctx.mtx);	

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_4
		if (DllName && DllName->Buffer)
		{
			// HOOK_LOG(LL_SYS, L"LdrGetDllHandleEx triggered! Flag: %lu Dll: %ls Original: %p", Flags, DllName->Buffer ? DllName->Buffer : L"", LdrGetDllHandleEx_ctx.original);

			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnModuleRequested(DllName->Buffer, bSuspicious);
			if (!bAnalysed || bSuspicious)
			{
				HOOK_LOG(LL_WARN, L"Module request: %ls analysed, Completed: %d Suspicious: %d", DllName->Buffer ? DllName->Buffer : L"", bAnalysed, bSuspicious);
			}

			if (bSuspicious)
				return LdrGetDllHandleEx_ctx.original(Flags, DllPath, DllCharacteristics, DllName, nullptr);
		}
#endif
		return LdrGetDllHandleEx_ctx.original(Flags, DllPath, DllCharacteristics, DllName, DllHandle);
	}

	NTSTATUS NTAPI NtMapViewOfSectionDetour(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
	{
#ifdef ENABLE_HOOK_SCAN_PART_5
		// Warning: Do NOT enable logs inside this hook
		// std::lock_guard <std::recursive_mutex> lock(NtMapViewOfSection_ctx.mtx);
		// HOOK_LOG(LL_SYS, L"NtMapViewOfSection triggered! Section: %p Base: %p Original: %p", SectionHandle, (BaseAddress && *BaseAddress) ? *BaseAddress : nullptr, NtMapViewOfSection_ctx.original);
	
		if (BaseAddress)
		{
			const auto teb = NtCurrentTeb();
			if (teb)
			{
				auto bSuspicious = false;
				auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnSectionMapped(&BaseAddress, teb->NtTib.ArbitraryUserPointer, bSuspicious);
				// HOOK_LOG(LL_SYS, L"Section: %p Base: %p analysed, Completed: %d Suspicious: %d", SectionHandle, (BaseAddress && *BaseAddress) ? *BaseAddress : nullptr, bAnalysed, bSuspicious);
			}
		}
#endif
		auto ntStatus = NtMapViewOfSection_ctx.original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

		// Home made ASLR test
#ifdef ENABLE_HOOK_SCAN_PART_6
		if (ntStatus == STATUS_SUCCESS || ntStatus == STATUS_IMAGE_NOT_AT_BASE)
		{
			if (BaseAddress && *BaseAddress)
			{
				MEMORY_BASIC_INFORMATION mbi{};
				if (g_winAPIs->VirtualQuery(*BaseAddress, &mbi, sizeof(mbi)))
				{
					if (mbi.Type == MEM_IMAGE)
					{
						const auto pIDH = reinterpret_cast<IMAGE_DOS_HEADER*>(*BaseAddress);
						if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
						{
							const auto pINH = reinterpret_cast<IMAGE_NT_HEADERS*>(((char*)pIDH + pIDH->e_lfanew));
							if (pINH->Signature == IMAGE_NT_SIGNATURE && pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
							{
								if (pINH->OptionalHeader.ImageBase == (ULONG)*BaseAddress)
								{
									if (!(pINH->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
									{
										const auto pRelocDir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(&pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
										if (pRelocDir)
										{
											if (pRelocDir->VirtualAddress)
											{
												// Release original memory
												g_winAPIs->NtUnmapViewOfSection(ProcessHandle, *BaseAddress); 
												
												// Allocate new memory area
												g_winAPIs->VirtualAlloc(*BaseAddress, *ViewSize, MEM_RESERVE, PAGE_NOACCESS);

												// Create new randomized memory
												ntStatus = NtMapViewOfSection_ctx.original(
													SectionHandle,
													ProcessHandle,
													BaseAddress,
													ZeroBits,
													CommitSize,
													SectionOffset,
													ViewSize,
													InheritDisposition,
													AllocationType,
													Protect
												);

												// Continue with new result
												return ntStatus;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
#endif
		return ntStatus;
	}

	LONG WINAPI SetWindowLongADetour(HWND hWnd, int nIndex, LONG dwNewLong)
	{
		// std::lock_guard <std::recursive_mutex> lock(SetWindowLongA_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_7
		HOOK_LOG(LL_SYS, L"SetWindowLongA triggered! Wnd: %p Idx: %d NewTarget: %p Original: %p", hWnd, nIndex, dwNewLong, SetWindowLongA_ctx.original);

		auto bSuspicious = false;
		auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnWndProcHooked(hWnd, nIndex, dwNewLong, bSuspicious);
		HOOK_LOG(LL_SYS, L"A/ Window: %p proc hook analysed, Completed: %d Suspicious: %d", hWnd, bAnalysed, bSuspicious);
#endif

		return SetWindowLongA_ctx.original(hWnd, nIndex, dwNewLong);
	}

	LONG WINAPI SetWindowLongWDetour(HWND hWnd, int nIndex, LONG dwNewLong)
	{
		// std::lock_guard <std::recursive_mutex> lock(SetWindowLongW_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_7
		HOOK_LOG(LL_SYS, L"SetWindowLongW triggered! Wnd: %p Idx: %d NewTarget: %p Original: %p", hWnd, nIndex, dwNewLong, SetWindowLongW_ctx.original);

		auto bSuspicious = false;
		auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnWndProcHooked(hWnd, nIndex, dwNewLong, bSuspicious);
		HOOK_LOG(LL_SYS, L"W/ Window: %p proc hook analysed, Completed: %d Suspicious: %d", hWnd, bAnalysed, bSuspicious);
#endif

		return SetWindowLongW_ctx.original(hWnd, nIndex, dwNewLong);
	}

	int WINAPI connectDetour(UINT_PTR s, const struct sockaddr* name, int namelen)
	{
		// std::lock_guard <std::recursive_mutex> lock(connect_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"connect triggered! Socket: %p Name: %p Length: %d Original: %p", s, name, namelen, connect_ctx.original);

		auto sockInfo = *(sockaddr_in*)name;
		auto stTargetAddress = g_winAPIs->inet_ntoa(sockInfo.sin_addr);
		auto wstTargetAddress = stdext::to_wide(stTargetAddress);
		HOOK_LOG(LL_TRACE, L"Connection target: %s:%u", wstTargetAddress.c_str(), sockInfo.sin_port);

		std::string stErrMsg;
		if (CloudflareChecker::is_cloudflare_ip(stTargetAddress, stErrMsg))
		{
			HOOK_LOG(LL_SYS, L"Cloudflare IP: %s skipped!", wstTargetAddress.c_str());
			return connect_ctx.original(s, name, namelen);
		}
		else if (!stErrMsg.empty())
		{
			HOOK_LOG(LL_WARN, L"Cloudflare IP check failed with error: %hs", stErrMsg.c_str());
		}

		const auto wstLicenseID = NoMercyCore::CApplication::Instance().DataInstance()->GetLicenseCode();
		if (wstLicenseID != xorstr_(L"LITE_PUBLIC_LICENSE") && !stdext::starts_with(wstLicenseID, std::wstring(xorstr_(L"PUBLIC_LICENSE_"))))
		{
			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnConnected(wstTargetAddress, sockInfo.sin_port, bSuspicious);
			HOOK_LOG(LL_SYS, L"Connection %s:%u analysed, Completed: %d Suspicious: %d", wstTargetAddress.c_str(), sockInfo.sin_port, bAnalysed, bSuspicious);

			if (bSuspicious)
			{
				HOOK_LOG(LL_ERR, L"Connection to: %s blocked!", wstTargetAddress.c_str());
				g_winAPIs->WSASetLastError(WSAECONNREFUSED);
				return SOCKET_ERROR;
			}
		}

		return connect_ctx.original(s, name, namelen);
	}
	int WSAAPI WSAConnectDetour(SOCKET s, const struct sockaddr FAR* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
	{
		// std::lock_guard <std::recursive_mutex> lock(WSAConnect_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"WSAConnect triggered! Socket: %p Name: %p Length: %d Original: %p", s, name, namelen, WSAConnect_ctx.original);

		auto sockInfo = *(sockaddr_in*)name;
		auto stTargetAddress = g_winAPIs->inet_ntoa(sockInfo.sin_addr);
		auto wstTargetAddress = stdext::to_wide(stTargetAddress);
		HOOK_LOG(LL_TRACE, L"Connection target: %s:%u", wstTargetAddress.c_str(), sockInfo.sin_port);

		std::string stErrMsg;
		if (CloudflareChecker::is_cloudflare_ip(stTargetAddress, stErrMsg))
		{
			HOOK_LOG(LL_SYS, L"Cloudflare IP: %s skipped!", wstTargetAddress.c_str());
			return WSAConnect_ctx.original(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
		}
		else if (!stErrMsg.empty())
		{
			HOOK_LOG(LL_WARN, L"Cloudflare IP check failed with error: %hs", stErrMsg.c_str());
		}

		const auto wstLicenseID = NoMercyCore::CApplication::Instance().DataInstance()->GetLicenseCode();
		if (wstLicenseID != xorstr_(L"LITE_PUBLIC_LICENSE"))
		{
			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnConnected(wstTargetAddress, sockInfo.sin_port, bSuspicious);
			HOOK_LOG(LL_SYS, L"Connection %s:%u analysed, Completed: %d Suspicious: %d", wstTargetAddress.c_str(), sockInfo.sin_port, bAnalysed, bSuspicious);

			if (bSuspicious)
			{
				HOOK_LOG(LL_ERR, L"Connection to: %s blocked!", wstTargetAddress.c_str());
				g_winAPIs->WSASetLastError(WSAECONNREFUSED);
				return SOCKET_ERROR;
			}
		}

		return WSAConnect_ctx.original(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	}

	NTSTATUS NTAPI NtDelayExecutionDetour(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtDelayExecution_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_7
		// HOOK_LOG(LL_SYS, L"NtDelayExecution triggered! Alert: %d Delay: %p Original: %p", Alertable, DelayInterval->QuadPart, NtDelayExecution_ctx.original);

		auto bSuspicious = false;
		auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnDelayExecution(Alertable, DelayInterval->QuadPart, HandleToUlong(NtCurrentThreadId()), _ReturnAddress(), bSuspicious);
		// HOOK_LOG(LL_SYS, L"NtDelayExecution analysed, Completed: %d Suspicious: %d", bAnalysed, bSuspicious);
#endif

		return NtDelayExecution_ctx.original(Alertable, DelayInterval);
	}

	BOOL WINAPI ClientThreadSetupDetour(VOID)
	{
		// std::lock_guard <std::recursive_mutex> lock(ClientThreadSetup_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_7
		HOOK_LOG(LL_SYS, L"ClientThreadSetup triggered! TID: %u Original: %p", g_winAPIs->GetCurrentThreadId(), ClientThreadSetup_ctx.original);

		CONTEXT ctx{ 0 };
		if (!g_winAPIs->GetThreadContext(NtCurrentThread(), &ctx))
			memset(&ctx, 0, sizeof(ctx));

		auto bSuspicious = false;
		auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnThreadCreated(HandleToUlong(NtCurrentThreadId()), NtCurrentThread(), &ctx, bSuspicious);
		HOOK_LOG(LL_SYS, L"Thread: %u analysed, Completed: %d Suspicious: %d", HandleToUlong(NtCurrentThreadId()), bAnalysed, bSuspicious);
#endif

		return ClientThreadSetup_ctx.original();
	}

	NTSTATUS NTAPI NtCreateSectionDetour(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess,
		ULONG SectionAttributes, HANDLE FileHandle)
	{		
		// std::lock_guard <std::recursive_mutex> lock(NtCreateSection_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

#ifdef ENABLE_HOOK_SCAN_PART_8
		if (FileHandle)
		{
			HOOK_LOG(LL_SYS, L"NtCreateSection triggered! File: %p Original: %p", FileHandle, NtCreateSection_ctx.original);

			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnSectionCreated(FileHandle, SectionAttributes, bSuspicious);
			HOOK_LOG(LL_SYS, L"Section: %p analysed, Completed: %d Suspicious: %d", FileHandle, bAnalysed, bSuspicious);
		}
#endif

		return NtCreateSection_ctx.original(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle);
	}

	NTSTATUS NTAPI NtAllocateVirtualMemoryDetour(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtAllocateVirtualMemory_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		const auto ntStatus = NtAllocateVirtualMemory_ctx.original(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		if (NT_SUCCESS(ntStatus))
		{
			// TODO: patch memory if executable
			/*
			if (memory.Protect & 0xF0) {
				LOG_VERBOSE(3, "Address " << lpAddress << " is executable memory; patching with a return");

				DWORD dwOverwriteSize{};

				// push 0
				// pop rax ; same opcode for pop eax
				// ret
				unsigned char instruction[4]{ 0x6a, 0x00, 0x58, 0xc3 };

				DWORD dwOldProtections{};
				if (!VirtualProtectEx(hProcess, lpAddress, 4, PAGE_READWRITE, &dwOldProtections)) {
					LOG_ERROR("Unable to adjust memory protections at " << lpAddress << " (Error " << GetLastError()
						<< ")");
					return false;
				}
				if (!WriteProcessMemory(hProcess, lpAddress, instruction, 4, nullptr)) {
					LOG_ERROR("Unable to adjust memory protections at " << lpAddress << " (Error " << GetLastError()
						<< ")");
					return false;
				}
				if (!VirtualProtectEx(hProcess, lpAddress, 4, dwOldProtections, &dwOldProtections)) {
					LOG_ERROR("Unable to repair memory protections at " << lpAddress << " (Error " << GetLastError()
						<< ")");
					return false;
				}
			}
			*/

			// TODO: FIX Infinite loop stack overflow
			// https://cdn.koray.services/bOMA9/FAPUBONu43.png
			// CApplication::Instance().MemAllocWatcherInstance()->AppendMemoryRegion(BaseAddress ? *BaseAddress : nullptr, RegionSize ? *RegionSize : 0);
		}
		return ntStatus;
	}

	SHORT NTAPI NtUserGetAsyncKeyStateDetour(INT Key)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserGetAsyncKeyState_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserGetAsyncKeyState called");

		// ...

		return NtUserGetAsyncKeyState_ctx.original(Key);
	}
	LONG NTAPI NtUserSetWindowLongDetour(HWND hWnd, DWORD Index, LONG NewValue, BOOL Ansi)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserSetWindowLong_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserSetWindowLong called");

		// ...

		return NtUserSetWindowLong_ctx.original(hWnd, Index, NewValue, Ansi);
	}
	LONG_PTR NTAPI NtUserSetWindowLongPtrDetour(HWND hWnd, DWORD Index, LONG_PTR NewValue, BOOL Ansi)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserSetWindowLongPtr_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserSetWindowLongPtr called");

		// ...

		return NtUserSetWindowLongPtr_ctx.original(hWnd, Index, NewValue, Ansi);
	}
	UINT_PTR NTAPI NtUserSetTimerDetour(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserSetTimer_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserSetTimer called");

		// ...

		return NtUserSetTimer_ctx.original(hWnd, nIDEvent, uElapse, lpTimerFunc);
	}
	HWND NTAPI NtUserCreateWindowExDetour(DWORD dwExStyle, WinAPI::PLARGE_STRING plstrClassName, WinAPI::PLARGE_STRING plstrClsVersion, WinAPI::PLARGE_STRING plstrWindowName,
		DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam, DWORD dwFlags, PVOID acbiBuffer)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserCreateWindowEx_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserCreateWindowEx called");

		// ...

		return NtUserCreateWindowEx_ctx.original(dwExStyle, plstrClassName, plstrClsVersion, plstrWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam, dwFlags, acbiBuffer);
	}
	HFONT NTAPI NtGdiHfontCreateDetour(PENUMLOGFONTEXDVW pelfw, ULONG cjElfw, WinAPI::LFTYPE lft, FLONG fl, PVOID pvCliData)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtGdiHfontCreate_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtGdiHfontCreate called");

		// ...

		return NtGdiHfontCreate_ctx.original(pelfw, cjElfw, lft, fl, pvCliData);
	}
	NTSTATUS NTAPI NtOpenFileDetour(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtOpenFile_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtOpenFile called");

		if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer)
		{
			// TODO: Check if this is a file inside the windows directory or signed file
			HOOK_LOG(LL_WARN, L"File: %ls", ObjectAttributes->ObjectName->Buffer);
		}

		return NtOpenFile_ctx.original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	}
	VOID WINAPI LoadAppInitDllsDetour(VOID)
	{
		// std::lock_guard <std::recursive_mutex> lock(LoadAppInitDlls_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"LoadAppInitDlls called");
		
		// ...
		
		return LoadAppInitDlls_ctx.original();
	}
	LPVOID WINAPI LockResourceDetour(HGLOBAL hResData)
	{
		// std::lock_guard <std::recursive_mutex> lock(LockResource_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"LockResource called");
		
		// ...
		
		return LockResource_ctx.original(hResData);
	}
	NTSTATUS NTAPI NtCreateWorkerFactoryDetour(PHANDLE WorkerFactoryHandleReturn, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE CompletionPortHandle, HANDLE WorkerProcessHandle, PVOID StartRoutine, PVOID StartParameter, ULONG MaxThreadCount, SIZE_T StackReserve, SIZE_T StackCommit)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtCreateWorkerFactory_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"NtCreateWorkerFactory called");
		
		// ...
		
		return NtCreateWorkerFactory_ctx.original(WorkerFactoryHandleReturn, DesiredAccess, ObjectAttributes, CompletionPortHandle, WorkerProcessHandle, StartRoutine, StartParameter, MaxThreadCount, StackReserve, StackCommit);
	}
	ATOM WINAPI RegisterClassExWDetour(const WNDCLASSEXW* lpwcx)
	{
		// std::lock_guard <std::recursive_mutex> lock(RegisterClassExW_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"RegisterClassExW called");
		
		// ...
		
		return RegisterClassExW_ctx.original(lpwcx);
	}
	NTSTATUS NTAPI DbgUiConnectToDbgDetour(VOID)
	{
		// std::lock_guard <std::recursive_mutex> lock(DbgUiConnectToDbg_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"DbgUiConnectToDbg called");
		
		// ...
		
		return DbgUiConnectToDbg_ctx.original();
	}
	BOOL WINAPI DisableThreadLibraryCallsDetour(HMODULE hModule)
	{
		// std::lock_guard <std::recursive_mutex> lock(DisableThreadLibraryCallsctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"DisableThreadLibraryCalls called");
		
		// ...
		
		return DisableThreadLibraryCallsctx.original(hModule);
	}
	FILE* __cdecl _fsopenDetour(char const* _FileName, char const* _Mode, int _ShFlag)
	{
		// std::lock_guard <std::recursive_mutex> lock(_fsopen_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
		
		HOOK_LOG(LL_SYS, L"_fsopen called");
		
		// ...
		
		return _fsopen_ctx.original(_FileName, _Mode, _ShFlag);
	}
	HHOOK NTAPI NtUserSetWindowsHookExDetour(HINSTANCE Mod, PUNICODE_STRING ModuleName, DWORD ThreadId, int HookId, HOOKPROC HookProc, BOOL Ansi)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserSetWindowsHookEx_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserSetWindowsHookEx called");

		// ...

		return NtUserSetWindowsHookEx_ctx.original(Mod, ModuleName, ThreadId, HookId, HookProc, Ansi);
	}
	ULONG_PTR NTAPI NtUserSetClassLongPtrDetour(HWND hwnd, INT offset, LONG_PTR newval, BOOL ansi)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtUserSetClassLongPtr_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtUserSetClassLongPtr called");
		
		// ...

		return NtUserSetClassLongPtr_ctx.original(hwnd, offset, newval, ansi);
	}
	NTSTATUS NTAPI NtProtectVirtualMemoryDetour(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtProtectVirtualMemory_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtProtectVirtualMemory called");

		// ...

		return NtProtectVirtualMemory_ctx.original(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}
	NTSTATUS NTAPI NtAllocateVirtualMemoryExDetour(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtAllocateVirtualMemoryEx_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtAllocateVirtualMemoryEx called");

		// ...

		return NtAllocateVirtualMemoryEx_ctx.original(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
	}
	NTSTATUS NTAPI NtMapViewOfSectionExDetour(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType, ULONG Win32Protect, WinAPI::PEXT_PARAMS ExtParameters, ULONG ExtParametersCount)
	{
		// std::lock_guard <std::recursive_mutex> lock(NtMapViewOfSectionEx_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"NtMapViewOfSectionEx called");

		// ...

		return NtMapViewOfSectionEx_ctx.original(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize, AllocationType, Win32Protect, ExtParameters, ExtParametersCount);
	}
	VOID NTAPI KiUserCallbackDispatcherDetour(ULONG Index, PVOID Argument, ULONG ArgumentLength)
	{
		// std::lock_guard <std::recursive_mutex> lock(KiUserCallbackDispatcher_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_SYS, L"KiUserCallbackDispatcher called");

		// ...

		return KiUserCallbackDispatcher_ctx.original(Index, Argument, ArgumentLength);
	}
	
	extern BOOL RtlDispatchExceptionMemAccessDetect(PEXCEPTION_RECORD pExcptRec, CONTEXT* pContext);

	ULONG WINAPI RtlDispatchExceptionDetour(PEXCEPTION_RECORD ExceptionInfo, CONTEXT* pContext)
	{
		// std::lock_guard <std::recursive_mutex> lock(RtlDispatchException_ctx.mtx);

		// CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());

		HOOK_LOG(LL_CRI, L"RtlDispatchException triggered! Exception data: %p Context: %p Original: %p", ExceptionInfo, pContext, RtlDispatchException_ctx.original);

		if (ExceptionInfo)
		{
			if (RtlDispatchExceptionMemAccessDetect(ExceptionInfo, pContext))
				return 1;

#ifdef ENABLE_HOOK_SCAN_PART_9
			auto bSuspicious = false;
			auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnExceptionThrowed(ExceptionInfo, bSuspicious);
			HOOK_LOG(LL_SYS, L"Exception: %p analysed, Completed: %d Suspicious: %d", ExceptionInfo, bAnalysed, bSuspicious);

			if (bSuspicious)
				return 1;
#endif
		}

		return RtlDispatchException_ctx.original(ExceptionInfo, pContext);
	}

	static bool InitRtlDispatchExceptionHook()
	{
		auto pAddr = (BYTE*)g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("KiUserExceptionDispatcher"));
		if (!pAddr)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_FOUND_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"KiUserExceptionDispatcher at: %p - %0x%X", pAddr, *pAddr);

		while (*pAddr != 0xE8)
			pAddr++;
		APP_TRACE_LOG(LL_SYS, L"KiUserExceptionDispatcher call: %p - %0x%X", pAddr, *pAddr);

		RtlDispatchException_ctx.original = (decltype(&RtlDispatchException))((*(DWORD*)(pAddr + 1)) + 5 + (DWORD_PTR)pAddr);
		if (!RtlDispatchException_ctx.original)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_BASE_FOUND_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"RtlDispatchException: %p", RtlDispatchException_ctx.original);

		// Add exception
		CHookScanner::ExceptionRule exc;
		exc.bFindByAddr = TRUE;
		exc.pvProcedureAddr = RtlDispatchException_ctx.original;
		CApplication::Instance().HookScannerInstance()->AddExceptionRule(exc);

		// Hook
		auto dwNewAddr = (DWORD_PTR)RtlDispatchExceptionDetour - (DWORD_PTR)pAddr - 5;
		if (!dwNewAddr)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_PATCH_ADDR_FOUND_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"KiUserExceptionDispatcher patch addr: %p", dwNewAddr);

		DWORD dwOldProtection;
		if (!g_winAPIs->VirtualProtect((LPVOID)pAddr, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtection))
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_PRE_PROTECT_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		SIZE_T cbWrittenSize = 0;
		if (!g_winAPIs->WriteProcessMemory(NtCurrentProcess(), (PVOID)((DWORD_PTR)pAddr + 1), &dwNewAddr, 4, &cbWrittenSize))
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_WRITE_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		return true;
	}


	bool CSelfApiHooks::__InitializePatchs()
	{
		HOOK_LOG(LL_SYS, L"API Patch Initilization has been started!");

		auto bRet = true;

		std::vector <std::tuple <std::wstring, std::string, uint8_t>> vecPatchList = {
#ifndef _DEBUG
#if (BLOCK_CONSOLE_WINDOW == TRUE)
			{ xorstr_(L"kernelbase.dll"), xorstr_("AllocConsole"), NOP_HOOK },
			{ xorstr_(L"kernelbase.dll"), xorstr_("AttachConsole"), NOP_HOOK },

			{ xorstr_(L"kernel32.dll"), xorstr_("AllocConsole"), NOP_HOOK },
			{ xorstr_(L"kernel32.dll"), xorstr_("GetConsoleWindow"), NOP_HOOK },
			{ xorstr_(L"kernel32.dll"), xorstr_("AttachConsole"), NOP_HOOK },
#endif

			{ xorstr_(L"ntdll.dll"), xorstr_("DbgBreakPoint"), NOP_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUserBreakPoint"), NOP_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiConnectToDbg"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiContinue"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiConvertStateChangeStructure"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiDebugActiveProcess"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiGetThreadDebugObject"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiIssueRemoteBreakin"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiRemoteBreakin"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiSetThreadDebugObject"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiStopDebugging"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgUiWaitStateChange"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgPrintReturnControlC"), RET_HOOK },
			{ xorstr_(L"ntdll.dll"), xorstr_("DbgPrompt"), RET_HOOK },

			// TODO: NtWaitForDebugEvent
#endif

			{ xorstr_(L"ntdll.dll"), xorstr_("RtlRemoteCall"), NOP_HOOK },

			{ xorstr_(L"python"), xorstr_("PyRun_SimpleString"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyRun_SimpleStringFlags"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyRun_SimpleFile"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyRun_SimpleFileFlags"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyRun_SimpleFileEx"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyRun_SimpleFileExFlags"), RET_HOOK },
			{ xorstr_(L"python"), xorstr_("PyFile_FromString"), RET_HOOK },
		};

		std::vector <CHookScanner::ExceptionRule> vecExceptionRules;

		for (const auto& [stModuleName, stFuncName, nHookType] : vecPatchList)
		{
			HMODULE hModule = nullptr;

			const std::wstring python = xorstr_(L"python");
			if (stModuleName == python)
				hModule = g_winModules->hPython;
			else
				hModule = g_winAPIs->GetModuleHandleW_o(stModuleName.c_str());

			if (!hModule)
				continue;

			const auto fpAddr = g_winAPIs->GetProcAddress_o(hModule, stFuncName.c_str());
			if (!fpAddr)
				continue;

			CHookScanner::ExceptionRule exc;
			exc.pvProcedureAddr = fpAddr;
			exc.bFindByAddr = TRUE;

			vecExceptionRules.emplace_back(exc);
		}

		CApplication::Instance().HookScannerInstance()->AddExceptionRules(vecExceptionRules);

		for (const auto& [stModuleName, stFuncName, nHookType] : vecPatchList)
		{
			__BlockAPI(stModuleName, stFuncName, nHookType);
		}

		HOOK_LOG(LL_SYS, L"API Patch Initilization completed!");
		return bRet;
	}

	bool CSelfApiHooks::IsHookedAPI(const std::wstring& stFunction)
	{
		for (auto& ctx : m_vHooks)
		{
			if (ctx.func == stFunction)
				return true;
		}
		return false;
	}

	SHookContext CSelfApiHooks::GetHook(const std::wstring& stFunction)
	{
		for (auto& ctx : m_vHooks)
		{
			if (ctx.func == stFunction)
				return ctx;
		}
		return {};
	}

	bool CSelfApiHooks::IsHookIntegrityCorrupted()
	{
		if (!m_bHooksIsInitialized)
			return false;
		if (!CApplication::Instance().AppIsInitiliazed())
			return false;
		if (!IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			return false;
		if (!CApplication::Instance().AppIsInitializedThreadCompleted())
			return false;

		static const uint8_t pNullBuffer[] = { 0x0 };
		for (auto [func, addr, detour, backup, original] : m_vHooks)
		{
			if (!memcmp(&backup, &pNullBuffer, sizeof(backup)))
				return false;

			HOOK_LOG(LL_TRACE, L"Target func: %s (%p)", func.c_str(), addr);

			BYTE current_mem[sizeof(backup)]{ 0 };
			memcpy(&current_mem, addr, sizeof(backup));

			if (memcmp(current_mem, backup, sizeof(backup)))
			{
				HOOK_LOG(LL_CRI, L"Function: %s (%p) hook is corrupted. Current: %s Backup: %s", func.c_str(), addr,
					stdext::dump_hex(current_mem, sizeof(current_mem)).c_str(), stdext::dump_hex(backup, sizeof(backup)).c_str()
				);
				return true;
			}
			HOOK_LOG(LL_TRACE, L"Function: %s (%p) is succesfully validated.", func.c_str(), addr);
		};
		return false;
	}

	void CSelfApiHooks::ReleaseSelfAPIHooks()
	{
		MH_STATUS status = MH_UNKNOWN;

		for (auto [func, addr, detour, backup, original] : m_vHooks)
		{
			HOOK_LOG(LL_SYS, L"Target func: %s (%p)", func.c_str(), addr);

			status = MH_DisableHook(addr);
			HOOK_LOG(LL_SYS, L"Hook disabled. Status: %d (%s)", status, MH_StatusToString(status));

			status = MH_RemoveHook(addr);
			HOOK_LOG(LL_SYS, L"Hook removed. Status: %d (%s)", status, MH_StatusToString(status));
		}

		status = MH_Uninitialize();
		HOOK_LOG(LL_SYS, L"MinHook released. Status: %d (%s)", status, MH_StatusToString(status));
	}

	bool CSelfApiHooks::__InitializeDetours()
	{
		HOOK_LOG(LL_SYS, L"Detours Initilization has been started!");

		// APC filter
		std::vector <const char*> vForbiddenListK = {
			xorstr_("LoadLibraryA"), xorstr_("LoadLibraryW"), xorstr_("LoadLibraryExA"), xorstr_("LoadLibraryExW")
		};
		std::vector <const char*> vForbiddenListNT = {
			xorstr_("LdrLoadDll"),
			xorstr_("RtlFillMemory"), // https://www.x86matthew.com/view_post?id=writeprocessmemory_apc
			xorstr_("RtlCopyMappedMemory") // https://gist.github.com/mq1n/af3ce68cd1a6e74d880b6a5981000878
		};

		std::map <std::string, LPVOID> mapForbiddenPtrs;
		if (mapForbiddenPtrs.empty())
		{
			for (const auto& it : vForbiddenListK)
			{
				if (g_winModules->hKernelbase)
				{
					const auto ptr = g_winAPIs->GetProcAddress_o(g_winModules->hKernelbase, it);
					if (ptr)
						mapForbiddenPtrs.emplace(fmt::format(xorstr_("{0}_kernelbase"), it), ptr);
				}
				const auto ptr = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, it);
				if (ptr)
					mapForbiddenPtrs.emplace(fmt::format(xorstr_("{0}_kernel32"), it), ptr);
			}
			for (const auto& it : vForbiddenListNT)
			{
				const auto ptr = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll_o, it);
				if (ptr)
					mapForbiddenPtrs.emplace(it, ptr);
			}
		}
		for (const auto& [api, ptr] : mapForbiddenPtrs)
		{
			HOOK_LOG(LL_SYS, L"Forbidden API: %hs (%p) added to APC check list!", api.c_str(), ptr);
			CApcRoutinesStorage::Instance().AddDenied(ptr);
		}
#ifdef _M_IX86
		using ApcDispatcherPtr = void(__stdcall*)(PVOID NormalRoutine, PVOID SysArg1, PVOID SysArg2, CONTEXT Context);
#else
		using ApcDispatcherPtr = void(__stdcall*)(CONTEXT Context);
#endif
		OriginalApcDispatcher = (ApcDispatcherPtr)g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("KiUserApcDispatcher"));


		// Hook engine
		auto status = MH_Initialize();
		if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED)
		{
			HOOK_LOG(LL_ERR, L"MinHook initilization failed. Status: %d (%hs)", status, MH_StatusToString(status));
			return false;
		}
		HOOK_LOG(LL_SYS, L"MinHook initialized.");

		// Setup hook informations
		m_vHooks.push_back({
			xorstr_(L"connect"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWs2_32, xorstr_("connect")),
			connectDetour
		});
		m_vHooks.push_back({
			xorstr_(L"WSAConnect"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWs2_32, xorstr_("WSAConnect")),
			WSAConnectDetour
		});
		/*
		m_vHooks.push_back({
			xorstr_(L"NtMapViewOfSection"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtMapViewOfSection")),
			NtMapViewOfSectionDetour
		});

		m_vHooks.push_back({
			xorstr_(L"NtDelayExecution"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtDelayExecution")),
			NtDelayExecutionDetour
		});
		m_vHooks.push_back({
			xorstr_(L"SetWindowLongA"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("SetWindowLongA")),
			SetWindowLongADetour
		});
		m_vHooks.push_back({
			xorstr_(L"SetWindowLongW"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("SetWindowLongW")),
			SetWindowLongWDetour
		});
		*/
		/*
		* DISABLED
		m_vHooks.push_back({
			xorstr_(L"ClientThreadSetup"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("ClientThreadSetup")),
			ClientThreadSetupDetour
		});
		*/
		m_vHooks.push_back({
			xorstr_(L"NtCreateSection"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtCreateSection")),
			NtCreateSectionDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtAllocateVirtualMemory"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtAllocateVirtualMemory")),
			NtAllocateVirtualMemoryDetour
		});

// DONMA_TEST
//#if 0
		if (IsWindowsVistaOrGreater())
		{
			m_vHooks.push_back({
				xorstr_(L"KiUserApcDispatcher"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("KiUserApcDispatcher")),
				KiApcStub
			});
			
			m_vHooks.push_back({
				xorstr_(L"NtQueueApcThread"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueueApcThread")),
				NtQueueApcThreadDetour
			});
			
			/*
			m_vHooks.push_back({
				xorstr_(L"LdrInitializeThunk"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrInitializeThunk")),
				LdrInitializeThunkDetour
			});
			*/
			
			m_vHooks.push_back({
				xorstr_(L"RtlGetFullPathName_U"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlGetFullPathName_U")),
				RtlGetFullPathName_UDetour
			});

			m_vHooks.push_back({
				xorstr_(L"NtContinue"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtContinue")),
				NtContinueDetour
			});

			m_vHooks.push_back({
				xorstr_(L"NtSetContextThread"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtSetContextThread")),
				NtSetContextThreadDetour
			});
			
			/*
			m_vHooks.push_back({
				xorstr_(L"NtTerminateProcess"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtTerminateProcess")),
				NtTerminateProcessDetour
			});
			*/
		}
		if (IsWindows7OrGreater())
		{
			m_vHooks.push_back({
				xorstr_(L"LdrGetDllHandleEx"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrGetDllHandleEx")),
				LdrGetDllHandleExDetour
			});
		}
//#endif

		if (g_winModules->hWin32u)
		{
			/*
			m_vHooks.push_back({
				xorstr_(L"NtUserGetAsyncKeyState"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtUserGetAsyncKeyState")),
				NtUserGetAsyncKeyStateDetour
			});
			m_vHooks.push_back({
				xorstr_(L"NtUserSetWindowLong"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtUserSetWindowLong")),
				NtUserSetWindowLongDetour
			});
			*/
			
#if (NM_PLATFORM == 64)
			m_vHooks.push_back({
				xorstr_(L"NtUserSetWindowLongPtr"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtUserSetWindowLongPtr")),
				NtUserSetWindowLongPtrDetour
			});
#endif	
			
			// FIXME: RTC failure 
			/*
			m_vHooks.push_back({
				xorstr_(L"NtUserSetTimer"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtUserSetTimer")),
				NtUserSetTimerDetour
			});
			*/
			// FIXME: RTC failure 
			/*
			m_vHooks.push_back({
			xorstr_(L"NtUserCreateWindowEx"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtUserCreateWindowEx")),
				NtUserCreateWindowExDetour
			});
			*/
			/*
			m_vHooks.push_back({
				xorstr_(L"NtGdiHfontCreate"),
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hWin32u, xorstr_("NtGdiHfontCreate")),
				NtGdiHfontCreateDetour
			});   
			*/
		}
		/*
		// Test hooks
		m_vHooks.push_back({
			xorstr_(L"RtlInitializeSListHead"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlInitializeSListHead")),
			RtlInitializeSListHeadDetour
		});
		m_vHooks.push_back({
			xorstr_(L"RtlPcToFileHeader"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlPcToFileHeader")),
			RtlPcToFileHeaderDetour
		});
		m_vHooks.push_back({
			xorstr_(L"IsNLSDefinedString"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("IsNLSDefinedString")),
			IsNLSDefinedStringDetour
		});
		m_vHooks.push_back({
			xorstr_(L"DbgUiSetThreadDebugObject"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("DbgUiSetThreadDebugObject")),
			DbgUiSetThreadDebugObjectDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtQueryValueKey"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueryValueKey")),
			NtQueryValueKeyDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtTestAlert"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtTestAlert")),
			NtTestAlertDetour
		});
		*/
		/*
		* BROKEN
		m_vHooks.push_back({
			xorstr_(L"NtFlushInstructionCache"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtFlushInstructionCache")),
			NtFlushInstructionCacheDetour
		});
		*/
		/*
		m_vHooks.push_back({
			xorstr_(L"NtUnmapViewOfSection"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtUnmapViewOfSection")),
			NtUnmapViewOfSectionDetour
		});
		m_vHooks.push_back({
			xorstr_(L"LdrAccessResource"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrAccessResource")),
			LdrAccessResourceDetour
		});
		m_vHooks.push_back({
			xorstr_(L"RtlAddVectoredExceptionHandler"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlAddVectoredExceptionHandler")),
			RtlAddVectoredExceptionHandlerDetour
		});
		m_vHooks.push_back({
			xorstr_(L"RtlAddVectoredContinueHandler"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlAddVectoredContinueHandler")),
			RtlAddVectoredContinueHandlerDetour
		});
		m_vHooks.push_back({
			xorstr_(L"SetUnhandledExceptionFilter"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("SetUnhandledExceptionFilter")),
			SetUnhandledExceptionFilterDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtCreateFile"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtCreateFile")),
			NtCreateFileDetour
		});
		*/
		/*
		* BROKEN
		m_vHooks.push_back({
			xorstr_(L"MultiByteToWideChar"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("MultiByteToWideChar")),
			MultiByteToWideCharDetour
		});
		m_vHooks.push_back({
			xorstr_(L"WideCharToMultiByte"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("WideCharToMultiByte")),
			WideCharToMultiByteDetour
		});
		*/
		/*
		m_vHooks.push_back({
			xorstr_(L"GetAsyncKeyState"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("GetAsyncKeyState")),
			GetAsyncKeyStateDetour
		});
		m_vHooks.push_back({
			xorstr_(L"GetKeyState"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("GetKeyState")),
			GetKeyStateDetour
		});
		m_vHooks.push_back({
			xorstr_(L"GetKeyboardState"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("GetKeyboardState")),
			GetKeyboardStateDetour
		});
		m_vHooks.push_back({
			xorstr_(L"ImmGetHotKey"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hImm32, xorstr_("ImmGetHotKey")),
			ImmGetHotKeyDetour
		});
		m_vHooks.push_back({
			xorstr_(L"ImmActivateLayout"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hImm32, xorstr_("ImmActivateLayout")),
			ImmActivateLayoutDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtOpenFile"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtOpenFile")),
			NtOpenFileDetour
		});
		*/
		/*
		m_vHooks.push_back({
			xorstr_(L"LoadAppInitDlls"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("LoadAppInitDlls")),
			LoadAppInitDllsDetour
		});
		m_vHooks.push_back({
			xorstr_(L"LockResource"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("LockResource")),
			LockResourceDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtCreateWorkerFactory"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtCreateWorkerFactory")),
			NtCreateWorkerFactoryDetour
		});
		m_vHooks.push_back({
			xorstr_(L"RegisterClassExW"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hUser32, xorstr_("RegisterClassExW")),
			RegisterClassExWDetour
		});
		m_vHooks.push_back({
			xorstr_(L"DbgUiConnectToDbg"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("DbgUiConnectToDbg")),
			DbgUiConnectToDbgDetour
		});
		m_vHooks.push_back({
			xorstr_(L"DisableThreadLibraryCalls"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hKernel32, xorstr_("DisableThreadLibraryCalls")),
			DisableThreadLibraryCallsDetour
		});
		m_vHooks.push_back({
			xorstr_(L"_fsopen"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hMsvcrt, xorstr_("_fsopen")),
			_fsopenDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtUserSetWindowsHookEx"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtUserSetWindowsHookEx")),
			NtUserSetWindowsHookExDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtUserSetClassLongPtr"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtUserSetClassLongPtr")),
			NtUserSetClassLongPtrDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtProtectVirtualMemory"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtProtectVirtualMemory")),
			NtProtectVirtualMemoryDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtAllocateVirtualMemoryEx"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtAllocateVirtualMemoryEx")),
			NtAllocateVirtualMemoryExDetour
		});
		m_vHooks.push_back({
			xorstr_(L"NtMapViewOfSectionEx"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("NtMapViewOfSectionEx")),
			NtMapViewOfSectionExDetour
		});
		m_vHooks.push_back({
			xorstr_(L"KiUserCallbackDispatcher"),
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(g_winModules->hNtdll, xorstr_("KiUserCallbackDispatcher")),
			KiUserCallbackDispatcherDetour
		});
		*/

		// Initialize hooks
		std::vector <CHookScanner::ExceptionRule> vecExceptionRules;

		for (auto& [func, addr, detour, backup, original] : m_vHooks)
		{
			HOOK_LOG(LL_SYS, L"Adding hook to scanner's exception list... Function: %s Address: %p", func.c_str(), addr);
			
			CHookScanner::ExceptionRule exc;
			exc.pvProcedureAddr = addr;
			exc.bFindByAddr = TRUE;

			vecExceptionRules.emplace_back(exc);
		}

		CApplication::Instance().HookScannerInstance()->AddExceptionRules(vecExceptionRules);

		HOOK_LOG(LL_SYS, L"Hook scan exception list created!");

		for (auto& [func, addr, detour, backup, original] : m_vHooks)
		{
			HOOK_LOG(LL_SYS, L"MinHook processing... Function: %s Address: %p Detour: %p Backup %s",
				func.c_str(), addr, detour, stdext::dump_hex(backup, sizeof(backup)).c_str()
			);

			if (!addr || !detour)
			{
				HOOK_LOG(LL_ERR, L"Hook: %s params are corrupted!", func.c_str());
				continue;
			}

			const auto dwRealAddr = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetRealAddress(addr);
			if (dwRealAddr && dwRealAddr != addr)
			{
				HOOK_LOG(LL_WARN, L"Func: %s is already hooked! Real address: %p", func.c_str(), dwRealAddr);
				addr = dwRealAddr;
				// return false;
			}
			HOOK_LOG(LL_SYS, L"Hooking function: %s Address: %p Detour: %p", func.c_str(), addr, detour);

			status = MH_CreateHook(addr, detour, &original);
			if (status != MH_OK)
			{
				HOOK_LOG(LL_ERR, L"MinHook create hook failed. Target: %s (%p) Status: %d (%hs)", func.c_str(), addr, status, MH_StatusToString(status));
				return false;
			}
			HOOK_LOG(LL_SYS, L"MinHook create hook success.");

			if (func == xorstr_(L"connect"))
				connect_ctx.original = (decltype(&connect))original;
			else if (func == xorstr_(L"NtMapViewOfSection"))
				NtMapViewOfSection_ctx.original = (decltype(&NtMapViewOfSection))original;
			else if (func == xorstr_(L"NtDelayExecution"))
				NtDelayExecution_ctx.original = (decltype(&NtDelayExecution))original;
			else if (func == xorstr_(L"SetWindowLongA"))
				SetWindowLongA_ctx.original = (decltype(&SetWindowLongA))original;
			else if (func == xorstr_(L"SetWindowLongW"))
				SetWindowLongW_ctx.original = (decltype(&SetWindowLongW))original;
			else if (func == xorstr_(L"ClientThreadSetup"))
				ClientThreadSetup_ctx.original = (WinAPI::TClientThreadSetup)original;
			else if (func == xorstr_(L"NtCreateSection"))
				NtCreateSection_ctx.original = (decltype(&NtCreateSection))original;
			else if (func == xorstr_(L"NtAllocateVirtualMemory"))
				NtAllocateVirtualMemory_ctx.original = (decltype(&NtAllocateVirtualMemory))original;
			else if (func == xorstr_(L"NtQueueApcThread"))
				NtQueueApcThread_ctx.original = (decltype(&NtQueueApcThread))original;
			else if (func == xorstr_(L"LdrInitializeThunk"))
				LdrInitializeThunk_ctx.original = (decltype(&LdrInitializeThunk))original;
			else if (func == xorstr_(L"RtlGetFullPathName_U"))
				RtlGetFullPathName_U_ctx.original = (decltype(&RtlGetFullPathName_U))original;
			else if (func == xorstr_(L"LdrGetDllHandleEx"))
				LdrGetDllHandleEx_ctx.original = (decltype(&LdrGetDllHandleEx))original;
			else if (func == xorstr_(L"NtUserGetAsyncKeyState"))
				NtUserGetAsyncKeyState_ctx.original = (WinAPI::TNtUserGetAsyncKeyState)original;
			else if (func == xorstr_(L"NtUserSetWindowLong"))
				NtUserSetWindowLong_ctx.original = (WinAPI::TNtUserSetWindowLong)original;
			else if (func == xorstr_(L"NtUserSetWindowLongPtr"))
				NtUserSetWindowLongPtr_ctx.original = (WinAPI::TNtUserSetWindowLongPtr)original;
			else if (func == xorstr_(L"NtUserSetTimer"))
				NtUserSetTimer_ctx.original = (WinAPI::TNtUserSetTimer)original;
			else if (func == xorstr_(L"NtUserCreateWindowEx"))
				NtUserCreateWindowEx_ctx.original = (WinAPI::TNtUserCreateWindowEx)original;
			else if (func == xorstr_(L"NtGdiHfontCreate"))
				NtGdiHfontCreate_ctx.original = (WinAPI::TNtGdiHfontCreate)original;
			else if (func == xorstr_(L"NtContinue"))
				NtContinue_ctx.original = (decltype(&NtContinue))original;
			else if (func == xorstr_(L"NtSetContextThread"))
				NtSetContextThread_ctx.original = (decltype(&NtSetContextThread))original;
			else if (func == xorstr_(L"NtTerminateProcess"))
				NtTerminateProcess_ctx.original = (decltype(&NtTerminateProcess))original;
			else if (func == xorstr_(L"RtlInitializeSListHead"))
				RtlInitializeSListHead_ctx.original = (decltype(&RtlInitializeSListHead))original;
			else if (func == xorstr_(L"RtlPcToFileHeader"))
				RtlPcToFileHeader_ctx.original = (decltype(&RtlPcToFileHeader))original;
			else if (func == xorstr_(L"IsNLSDefinedString"))
				IsNLSDefinedString_ctx.original = (decltype(&IsNLSDefinedString))original;
			else if (func == xorstr_(L"DbgUiSetThreadDebugObject"))
				DbgUiSetThreadDebugObject_ctx.original = (decltype(&DbgUiSetThreadDebugObject))original;
			else if (func == xorstr_(L"NtQueryValueKey"))
				NtQueryValueKey_ctx.original = (decltype(&NtQueryValueKey))original;
			else if (func == xorstr_(L"NtTestAlert"))
				NtTestAlert_ctx.original = (decltype(&NtTestAlert))original;
			else if (func == xorstr_(L"WSAConnect"))
				WSAConnect_ctx.original = (decltype(&WSAConnect))original;
			else if (func == xorstr_(L"KiUserApcDispatcher"))
				KiUserApcDispatcher_ctx.original = (WinAPI::TKiUserApcDispatcher)original;
			else if (func == xorstr_(L"NtFlushInstructionCache"))
				NtFlushInstructionCache_ctx.original = (decltype(&NtFlushInstructionCache))original;
			else if (func == xorstr_(L"NtUnmapViewOfSection"))
				NtUnmapViewOfSection_ctx.original = (decltype(&NtUnmapViewOfSection))original;
			else if (func == xorstr_(L"LdrAccessResource"))
				LdrAccessResource_ctx.original = (decltype(&LdrAccessResource))original;
			else if (func == xorstr_(L"RtlAddVectoredExceptionHandler"))
				RtlAddVectoredExceptionHandler_ctx.original = (decltype(&RtlAddVectoredExceptionHandler))original;
			else if (func == xorstr_(L"RtlAddVectoredContinueHandler"))
				RtlAddVectoredContinueHandler_ctx.original = (decltype(&RtlAddVectoredContinueHandler))original;
			else if (func == xorstr_(L"SetUnhandledExceptionFilter"))
				SetUnhandledExceptionFilter_ctx.original = (decltype(&SetUnhandledExceptionFilter))original;
			else if (func == xorstr_(L"NtCreateFile"))
				NtCreateFile_ctx.original = (decltype(&NtCreateFile))original;
			else if (func == xorstr_(L"MultiByteToWideChar"))
				MultiByteToWideChar_ctx.original = (decltype(&MultiByteToWideChar))original;
			else if (func == xorstr_(L"WideCharToMultiByte"))
				WideCharToMultiByte_ctx.original = (decltype(&WideCharToMultiByte))original;
			else if (func == xorstr_(L"GetAsyncKeyState"))
				GetAsyncKeyState_ctx.original = (decltype(&GetAsyncKeyState))original;
			else if (func == xorstr_(L"GetKeyState"))
				GetKeyState_ctx.original = (decltype(&GetKeyState))original;
			else if (func == xorstr_(L"GetKeyboardState"))
				GetKeyboardState_ctx.original = (decltype(&GetKeyboardState))original;
			else if (func == xorstr_(L"ImmGetHotKey"))
				ImmGetHotKey_ctx.original = (WinAPI::TImmGetHotKey)original;
			else if (func == xorstr_(L"ImmActivateLayout"))
				ImmActivateLayout_ctx.original = (WinAPI::TImmActivateLayout)original;
			else if (func == xorstr_(L"NtOpenFile"))
				NtOpenFile_ctx.original = (decltype(&NtOpenFile))original;
			else if (func == xorstr_(L"LoadAppInitDlls"))
				LoadAppInitDlls_ctx.original = (WinAPI::TLoadAppInitDlls)original;
			else if (func == xorstr_(L"LockResource"))
				LockResource_ctx.original = (decltype(&LockResource))original;
			else if (func == xorstr_(L"NtCreateWorkerFactory"))
				NtCreateWorkerFactory_ctx.original = (WinAPI::TNtCreateWorkerFactory)original;
			else if (func == xorstr_(L"RegisterClassExW"))
				RegisterClassExW_ctx.original = (decltype(&RegisterClassExW))original;
			else if (func == xorstr_(L"DbgUiConnectToDbg"))
				DbgUiConnectToDbg_ctx.original = (decltype(&DbgUiConnectToDbg))original;
			else if (func == xorstr_(L"DisableThreadLibraryCalls"))
				DisableThreadLibraryCallsctx.original = (decltype(&DisableThreadLibraryCalls))original;
			else if (func == xorstr_(L"_fsopen"))
				_fsopen_ctx.original = (decltype(&_fsopen))original;
			else if (func == xorstr_(L"NtUserSetWindowsHookEx"))
				NtUserSetWindowsHookEx_ctx.original = (WinAPI::TNtUserSetWindowsHookEx)original;
			else if (func == xorstr_(L"NtUserSetClassLongPtr"))
				NtUserSetClassLongPtr_ctx.original = (WinAPI::TNtUserSetClassLongPtr)original;
			else if (func == xorstr_(L"NtProtectVirtualMemory"))
				NtProtectVirtualMemory_ctx.original = (decltype(&NtProtectVirtualMemory))original;
			else if (func == xorstr_(L"NtAllocateVirtualMemoryEx"))
				NtAllocateVirtualMemoryEx_ctx.original = (WinAPI::TNtAllocateVirtualMemoryEx)original;
			else if (func == xorstr_(L"NtMapViewOfSectionEx"))
				NtMapViewOfSectionEx_ctx.original = (WinAPI::TNtMapViewOfSectionEx)original;
			else if (func == xorstr_(L"KiUserCallbackDispatcher"))
				KiUserCallbackDispatcher_ctx.original = (WinAPI::TKiUserCallbackDispatcher)original;
			else
			{
				HOOK_LOG(LL_ERR, L"Unknown function: %s", func.c_str());
				return false;
			}

			// Get memory copy
			BYTE byMemCopy[5]{ 0x0 };
			memcpy(&byMemCopy, addr, sizeof(byMemCopy));

			auto stCopyMem = stdext::dump_hex(byMemCopy, sizeof(byMemCopy));
			HOOK_LOG(LL_SYS, L"Original function: %s", stCopyMem.c_str());
			
			status = MH_EnableHook(addr);
			if (status != MH_OK)
			{
				HOOK_LOG(LL_ERR, L"MinHook enable hook failed. Target: %s (%p) Status: %d (%hs)", func.c_str(), addr, status, MH_StatusToString(status));
				return false;
			}

			memcpy(&backup, addr, sizeof(backup));
			stCopyMem = stdext::dump_hex(backup, sizeof(backup));
			HOOK_LOG(LL_SYS, L"Hook enabled! Backup function: %s", stCopyMem.c_str());

			// Check hook is applied successfully
			if (memcmp(addr, &backup, sizeof(backup)) != 0)
			{
				HOOK_LOG(LL_ERR, L"Hook enable failed. Target: %s (%p)", func.c_str(), addr);
				return false;
			}

			HOOK_LOG(LL_SYS, L"Hook enabled successfully. Target: %s (%p)", func.c_str(), addr);
		}

		HOOK_LOG(LL_SYS, L"All hooks enabled successfully.");

		// FIXME: Crash after than "UserExceptionDispatcher patch add"
#ifdef ENABLE_HOOK_SCAN_PART_8
		// Exception dispatcher
		if (InitRtlDispatchExceptionHook() == false)
		{
			HOOK_LOG(LL_ERR, L"Exception patcher can not initialized! Error: %u", g_winAPIs->GetLastError());
			return false;
		}
#endif

		HOOK_LOG(LL_SYS, L"Detours Initilization completed!");
		return true;
	}
};
