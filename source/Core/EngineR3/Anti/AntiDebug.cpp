#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiDebug.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../../Common/StdExtended.hpp"
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)





namespace NoMercy
{
#ifndef _M_X64

#pragma data_seg(".ngX1")
	auto dwVehintoAddr = 0UL;
#pragma data_seg()
#pragma comment(linker, "/section:.ngX1,RWS")

	LONG NTAPI VehIntoExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
	{
		ExceptionInfo->ContextRecord->Eip = dwVehintoAddr;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	inline void VehIntoBreak()
	{
		return; // FIXME: Crash with manualmap

		auto pVEHHandle = g_winAPIs->AddVectoredExceptionHandler(1, &VehIntoExceptionFilter);

		_asm
		{
			mov dwVehintoAddr, offset __Intosafe;
			mov ecx, 1;
		}
__here:
		_asm
		{
			rol ecx, 1;
			into;
			jmp __here;
		}
__Intosafe:

		if (pVEHHandle)
			g_winAPIs->RemoveVectoredExceptionHandler(pVEHHandle);
	}

#endif

	inline bool SetFakeImageBase()
	{
		const auto pCurrModule = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		if (!pCurrModule)
			return false;

		const auto dwCurrBase = reinterpret_cast<DWORD_PTR>(pCurrModule->DllBase);
		if (!dwCurrBase)
			return false;

		const auto pLdrData = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetLdrModule(dwCurrBase));
		if (!pLdrData)
			return false;

		const auto pNewBase = reinterpret_cast<DWORD_PTR>(pLdrData->DllBase) + 0x100000;
		APP_TRACE_LOG(LL_SYS, L"Old image base: %p redirected to: %p", pLdrData->DllBase, pNewBase);

		pLdrData->DllBase = reinterpret_cast<LPVOID>(pNewBase);
		return true;
	}

	inline bool SetFakeImageSize()
	{
		const auto pCurrModule = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		if (!pCurrModule)
			return false;

		const auto dwCurrBase = reinterpret_cast<DWORD_PTR>(pCurrModule->DllBase);
		if (!dwCurrBase)
			return false;

		const auto pLdrData = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetLdrModule(dwCurrBase));
		if (!pLdrData)
			return false;

		const auto dwNewSize = 0x1000000;
		APP_TRACE_LOG(LL_SYS, L"Old image size: %p converted to: %p", pLdrData->SizeOfImage, dwNewSize);

		pLdrData->SizeOfImage = dwNewSize;
		return true;
	}

	inline bool CrashDebuggerViaFormatText()
	{
		/*
		DWORD Val = 6969;
		g_winAPIs->SetLastError(Val);
		*/
		
		wchar_t wszCrashTextBuffer[] = { L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', L'%', L's', 0x0 }; //%s%s%s%s%s%s%s%s%s%s%s
		g_winAPIs->OutputDebugStringW(wszCrashTextBuffer);

		/*
		const auto dwLastError = g_winAPIs->GetLastError();
		const auto dwAppType = NoMercyCore::CApplication::Instance().GetAppType();
		return dwLastError == Val;
		*/
		return false;
	}

	inline bool BasicDebugTriggered()
	{
		if (g_winAPIs->IsDebuggerPresent()) 
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: g_winAPIs->IsDebuggerPresent");
			return true;
		}

		auto pPEB = NtCurrentPeb();
		if (pPEB && pPEB->BeingDebugged)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: pPEB->BeingDebugged");
			return true;
		}

		if (pPEB && pPEB->NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: pPEB->NtGlobalFlag");
			return true;
		}

		auto dwFlags = 0UL;
		auto dwReturnSize = 0UL;
		if (NT_SUCCESS(g_winAPIs->NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugFlags, &dwFlags, sizeof(dwFlags), &dwReturnSize)))
		{
			if (dwReturnSize != sizeof(dwFlags) || dwFlags == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: NtQueryInformationProcess.ProcessDebugFlags");
				return true;
			}
		}

		return false;
	}

	inline bool RemoteDebugTriggered()
	{
		auto bDebugged = BOOL(FALSE);
		const auto bApiRet = g_winAPIs->CheckRemoteDebuggerPresent(NtCurrentProcess(), &bDebugged);
		if (bApiRet && bDebugged)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckRemoteDebuggerPresent");
			return true;
		}

		return false;
	}

#pragma warning(push) 
#pragma warning(disable: 4731)
	inline bool PEBWow64Triggered()
	{
#ifndef _M_X64
		if (stdext::is_wow64())
		{
			auto bDebugged = BYTE(0x0);
			__asm
			{
				pushad
					mov eax, dword ptr fs : [0x18]
					sub eax, 0x2000
					mov eax, dword ptr[eax + 0x60];
					mov al, byte ptr[eax + 0x2]
					mov bDebugged, al
					popad
			}

			if (bDebugged)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: PEBWow64Triggered");
				return true;
			}
		}
#endif
		return false;
	}
#pragma warning(push) 

	bool DebugPortTriggered()
	{
		DWORD dwReturned = 0;
		HANDLE hPort = nullptr;

		if (NT_SUCCESS(g_winAPIs->NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &hPort, sizeof(hPort), &dwReturned)))
		{
			if (hPort == (HANDLE)-1)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: ProcessDebugPort");
				return true;
			}
		}

		return false;
	}

	inline bool CheckCloseHandle()
	{
		__try 
		{
			g_winAPIs->CloseHandle((HANDLE)0xDEADBEEF);
		}
		__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
		{
			return true;
		}
		return false;
	}

	bool CloseHandleViaInvalidHandleTriggered()
	{
		if (CheckCloseHandle())
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CloseHandleViaInvalidHandleTriggered");
			return true;
		}
		return false;
	}

	inline bool CheckCloseHandle2()
	{
		auto hMutex = g_winAPIs->CreateMutexW(NULL, FALSE, xorstr_(L"ntdil.dli"));
		if (IS_VALID_HANDLE(hMutex))
		{
			if (g_winAPIs->SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
			{
				__try 
				{
					g_winAPIs->CloseHandle(hMutex);
				}
				__except (HANDLE_FLAG_PROTECT_FROM_CLOSE)
				{
					return true;
				}
			}
		}

		return false;
	}

	bool CloseHandleViaProtectedHandleTriggered()
	{
		if (CheckCloseHandle2())
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CloseHandleViaProtectedHandleTriggered");
			return true;
		}

		return false;
	}

	bool DetachFromDebuggerProcessTriggered()
	{
		auto hDebugObject = HANDLE(INVALID_HANDLE_VALUE);
		auto dwFlags = 0UL;

		auto ntStatus = g_winAPIs->NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), NULL);
		if (!NT_SUCCESS(ntStatus))
			return false;

		ntStatus = g_winAPIs->NtSetInformationDebugObject(hDebugObject, (DEBUGOBJECTINFOCLASS)1, &dwFlags, sizeof(dwFlags), NULL);
		if (!NT_SUCCESS(ntStatus))
			return false;

		ntStatus = g_winAPIs->NtRemoveProcessDebug(NtCurrentProcess(), hDebugObject);
		if (!NT_SUCCESS(ntStatus)) 
			return false;

		ntStatus = g_winAPIs->NtClose(hDebugObject);
		if (!NT_SUCCESS(ntStatus)) 
			return false;

		APP_TRACE_LOG(LL_ERR, L"Debugger detected via: NtQuerySystemInformation.DetachFromDebuggerProcessTriggered");
		return true;
	}

	bool SofticeSymbolTriggered()
	{
		const auto lstSymbols = {
			xorstr_(L"////.//SICE"),xorstr_(L"////.//SIWVID"),xorstr_(L"////.//SIWVIDSTART"),
			xorstr_(L"////.//NTICE"),xorstr_(L"////.//ICEEXT"),xorstr_(L"////.//TRW"),
			xorstr_(L"////.//TRWDEBUG")
		};

		for (const auto& szSymbol : lstSymbols)
		{
			auto hDevice = g_winAPIs->CreateFileW(szSymbol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (IS_VALID_HANDLE(hDevice))
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: SofticeSymbolTriggered.%s", szSymbol);
				return true;
			}
		}

		return false;
	}

	bool SyserSymbolTriggered()
	{
		const auto lstSymbols = {
			xorstr_(L"////.//Syser"),xorstr_(L"////.//SyserBoot"),xorstr_(L"////.//SyserDbgMsg")
		};

		for (const auto& szSymbol : lstSymbols)
		{
			auto hDevice = g_winAPIs->CreateFileW(szSymbol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (IS_VALID_HANDLE(hDevice))
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: SyserSymbolTriggered.%s", szSymbol);
				return true;
			}
		}

		return false;
	}

	bool GlobalFlagsClearInProcessTriggered()
	{
		if (NoMercyCore::CApplication::Instance().DataInstance()->IsPackedProcess())
			return false;
		
		const auto pImageBase = (PBYTE)g_winModules->hBaseModule;
		if (!pImageBase)
			return false;

		const auto pIDH = (PIMAGE_DOS_HEADER)pImageBase;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)((LPBYTE)pImageBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		if (pImageLoadConfigDirectory->GlobalFlagsClear)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: GlobalFlagsClearInProcessTriggered");
			return true;
		}

		return false;
	}

	bool CheckDebugObjectsTriggered()
	{		
		auto __GetDebugObjectCount = []() -> DWORD {
			DWORD dwCount = 0;
			
			ULONG ulSize = 0x1000;
			auto pTypesInfo = (OBJECT_TYPES_INFORMATION*)CMemHelper::Allocate(ulSize);

			auto ntStatus = g_winAPIs->NtQueryObject(nullptr, ObjectTypesInformation, pTypesInfo, ulSize, &ulSize);
			if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
			{
				pTypesInfo = (OBJECT_TYPES_INFORMATION*)CMemHelper::ReAlloc(pTypesInfo, ulSize);
				if (!pTypesInfo)
					return dwCount;

				ntStatus = g_winAPIs->NtQueryObject(nullptr, ObjectTypesInformation, pTypesInfo, ulSize, &ulSize);
				if (!NT_SUCCESS(ntStatus))
				{
					CMemHelper::Free(pTypesInfo);
					pTypesInfo = nullptr;
				}
			}

			if (ntStatus == STATUS_SUCCESS && pTypesInfo)
			{
				POBJECT_TYPE_INFORMATION objectType = (POBJECT_TYPE_INFORMATION)PH_FIRST_OBJECT_TYPE(pTypesInfo);

				for (ULONG i = 0; i < pTypesInfo->NumberOfTypes; i++)
				{
					if (objectType->TypeName.Length && objectType->TypeName.Buffer)
					{
						const auto wstTypeName = std::wstring(objectType->TypeName.Buffer, objectType->TypeName.Length);
						if (!wcscmp(wstTypeName.c_str(), xorstr_(L"DebugObject")))
						{
							if (objectType->TotalNumberOfObjects > 0)
							{
								dwCount += objectType->TotalNumberOfObjects;
							}
						}
					}

					objectType = (POBJECT_TYPE_INFORMATION)PH_NEXT_OBJECT_TYPE(objectType);
				}
			}
			
			if (pTypesInfo)
			{
				CMemHelper::Free(pTypesInfo);
				pTypesInfo = nullptr;
			}
			return dwCount;
		};
		
		auto dwFirstDebugObjCount = __GetDebugObjectCount();
		if (dwFirstDebugObjCount > 0)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckDebugObjectsTriggered(pre) - %d", dwFirstDebugObjCount);
			// return true;
		}
		
		OBJECT_ATTRIBUTES object_attrib;
		InitializeObjectAttributes(&object_attrib, 0, 0, 0, 0);
		
		HANDLE debugObject = NULL;
		const auto ntCreateObjRet = g_winAPIs->NtCreateDebugObject(&debugObject, DEBUG_ALL_ACCESS, &object_attrib, 0);
		if (NT_SUCCESS(ntCreateObjRet))
		{
			auto dwSecondDebugObjCount = __GetDebugObjectCount();	
			g_winAPIs->NtClose(debugObject);

			if (dwSecondDebugObjCount == dwFirstDebugObjCount)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckDebugObjectsTriggered(post) - %d", dwSecondDebugObjCount);
				return true;
			}
		}
		
		return false;
	}

	bool ThreadBreakOnTerminationTriggered()
	{
		auto dwResult = 0UL;
		if (NT_SUCCESS(g_winAPIs->NtSetInformationThread(NtCurrentThread(), ThreadBreakOnTermination, &dwResult, sizeof(dwResult))))
		{
			if (dwResult)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: ThreadBreakOnTerminationTriggered");
				return true;
			}
		}
	
		return false;
	}

	bool CAntiDebug::SeDebugPrivTriggered()
	{
		const auto dwCsrssPid = g_winAPIs->CsrGetProcessId();
		if (!dwCsrssPid)
			return false;

		auto hProcess = g_winAPIs->OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwCsrssPid);
		if (IS_VALID_HANDLE(hProcess)) 
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: SeDebugPrivTriggered");
			return true;
		}

		return false;
	}

	bool CheckDebugObjectSize()
	{
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, 0, 0, 0, 0);

		BYTE pMemory[0x1000] = { 0 };

		auto hDebugObject = HANDLE(INVALID_HANDLE_VALUE);
		if (NT_SUCCESS(g_winAPIs->NtCreateDebugObject(&hDebugObject, DEBUG_ALL_ACCESS, &oa, 0)))
		{
			const auto pObjectType = reinterpret_cast<POBJECT_TYPE_INFORMATION>(pMemory);
			if (NT_SUCCESS(g_winAPIs->NtQueryObject(hDebugObject, ObjectTypeInformation, pObjectType, sizeof(pMemory), 0)))
			{
				if (pObjectType->TotalNumberOfObjects == 0)
				{
					APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckDebugObjectHandles");
					return true;
				}
			}
			g_winAPIs->NtClose(hDebugObject);
		}

		return false;
	}

	inline bool CheckSystemDebugControl()
	{
		if (!IsWindows10OrGreater())
			return false;
		
		auto bufferFake			= NULL;
		auto bufferFake2		= NULL;
		auto dwRetLenght		= 0UL;
		auto dwReturnLength		= 0UL;
		auto ntStatus			= g_winAPIs->NtSystemDebugControl(SysDbgQueryModuleInformation, 0, 0, 0, 0, 0);
		// auto ntStatus		= g_winAPIs->NtSystemDebugControl(SysDbgGetLiveKernelDump, &bufferFake, 0x10, &bufferFake2, 0x10, &dwRetLenght);

		APP_TRACE_LOG(LL_SYS, L"NtSystemDebugControl completed! Status: %p Return length: %u", ntStatus, dwReturnLength);

		return ntStatus != STATUS_DEBUGGER_INACTIVE;
	}

	bool CheckHeapSetInformation()
	{
#undef HeapCompatibilityInformation

		ULONG uHeapInfo = 2; /* HEAP_LFH */
		if (!g_winAPIs->HeapSetInformation(g_winAPIs->GetProcessHeap(), HeapCompatibilityInformation, &uHeapInfo, sizeof(uHeapInfo)))
			return true;

		return false;
	}

	bool CheckDebugFilterState()
	{
		const auto ntStatus = g_winAPIs->NtSetDebugFilterState(0, 0, TRUE);
		if (!NT_SUCCESS(ntStatus))
			return true;

		return false;
	}

	bool CheckEmulationWithTime()
	{
		const auto tStart = std::chrono::high_resolution_clock::now();

		g_winAPIs->GetCurrentProcessId();
		g_winAPIs->GetCurrentProcessId();
		g_winAPIs->GetCurrentProcessId();
		g_winAPIs->GetCurrentProcessId();

		const auto tDiff = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - tStart).count();
		if (tDiff > 100)
			return true;

		return false;
	}

	bool CheckHeapFlags()
	{
		auto bRet = false;

		auto pDebugBuffer = g_winAPIs->RtlCreateQueryDebugBuffer(0, FALSE);
		if (pDebugBuffer)
		{
			const auto ntStatus = g_winAPIs->RtlQueryProcessDebugInformation((HANDLE)g_winAPIs->GetCurrentProcessId(), WinAPI::PDI_HEAPS | WinAPI::PDI_HEAP_BLOCKS, pDebugBuffer);
			if (NT_SUCCESS(ntStatus))
			{
				const auto pHeapInfo = WinAPI::PDEBUG_HEAP_INFORMATION(PULONG(pDebugBuffer->Heaps) + 1);

				if (pHeapInfo->Flags == 0x50000062)
					bRet = true;
			}
			g_winAPIs->RtlDestroyQueryDebugBuffer(pDebugBuffer);
		}
		return bRet;
	}

	bool CheckCloseWindow()
	{
		const auto bRet = g_winAPIs->CloseWindow((HWND)0xDEADBEEF);
		if (bRet || g_winAPIs->GetLastError() != ERROR_INVALID_WINDOW_HANDLE)
			return true;
		return false;
	}

	bool CheckSystemTime()
	{
		auto bRet = false;

		BOOLEAN bAdjustPrivRet = FALSE;
		if (NT_SUCCESS(g_winAPIs->RtlAdjustPrivilege(SE_SYSTEMTIME_PRIVILEGE, TRUE, FALSE, &bAdjustPrivRet)))
		{
			auto hEvent = g_winAPIs->CreateEventW(NULL, FALSE, FALSE, NULL);
			if (IS_VALID_HANDLE(hEvent))
			{
				if (NT_SUCCESS(g_winAPIs->NtSetSystemInformation(SystemTimeSlipNotification, &hEvent, sizeof(hEvent))))
				{
					if (g_winAPIs->WaitForSingleObject(hEvent, 1) == WAIT_OBJECT_0)
						bRet = true;
				}
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hEvent);
			}
		}
		return bRet;
	}

	bool CheckDebugObjectHandle()
	{
		auto hDebugObject = HANDLE(0);
		DWORD dwReturned = 0;

		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), &dwReturned);
		if (!NT_SUCCESS(ntStatus))
			return false;

		if (ntStatus != STATUS_PORT_NOT_SET) 
			return true;

		if (ntStatus == STATUS_PORT_NOT_SET && hDebugObject)
			return true;

		return false;
	}

	bool CheckBugCheck()
	{
		auto dwBugCheck = 0UL;

		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, (PVOID)&dwBugCheck, sizeof(dwBugCheck), &dwBugCheck);
		if (ntStatus == STATUS_PORT_NOT_SET && dwBugCheck != 4)
			return true;

		return false;
	}

	bool CheckWow64Context()
	{
		WOW64_CONTEXT context = { 0 };
		context.ContextFlags = WOW64_CONTEXT_ALL;

		if (NT_SUCCESS(g_winAPIs->NtQueryInformationThread(NtCurrentThread(), ThreadWow64Context, &context, sizeof(context), NULL)))
		{
			if (context.Dr6 && context.Dr7)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: ThreadWow64Context");
				return true;
			}
		}
		return false;
	}

	bool CheckNtYieldExecutionQuerySingleStep()
	{
		uint8_t Debugged = 0;
		
		for (DWORD dwX = 0; dwX < 0x20; dwX++)
		{
			g_winAPIs->Sleep(0xf);

			if (g_winAPIs->NtYieldExecution() != STATUS_NO_YIELD_PERFORMED)
				Debugged++;
		}

		return Debugged > 3;
	}

	bool CheckAntiStepOver()
	{
		auto pRetAddress = _ReturnAddress();
		
		auto bBpFound = *(PBYTE)pRetAddress == 0xCC;
		if (bBpFound)
		{
			DWORD dwOldProtect = 0;
			if (g_winAPIs->VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				*(PBYTE)pRetAddress = 0x90;
				g_winAPIs->VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
			}
		}
		return bBpFound;
	}

	void DummyFunc()
	{
		__nop();
	}

	bool CheckIsBadHideContext()
	{
		const auto memAddress = reinterpret_cast<uint64_t>(&DummyFunc);
		
		CONTEXT ctx = { 0 };
		ctx.Dr0 = memAddress;
		ctx.Dr7 = 1;
		ctx.ContextFlags = 0x10;
		
		CONTEXT ctx2 = { 0 };
		ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (NT_SUCCESS(g_winAPIs->NtSetContextThread(NtCurrentThread(), (PCONTEXT)1)))
			return TRUE;
		if (NT_SUCCESS(g_winAPIs->NtGetContextThread(NtCurrentThread(), (PCONTEXT)1)))
			return TRUE;

		if (!NT_SUCCESS(g_winAPIs->NtSetContextThread(NtCurrentThread(), &ctx)))
			return FALSE;
		if (!NT_SUCCESS(g_winAPIs->NtGetContextThread(NtCurrentThread(), &ctx2)))
			return FALSE;
		
		if (ctx2.Dr0 != ctx.Dr0 ||
			ctx2.Dr0 != memAddress ||
			ctx2.Dr1 ||
			ctx2.Dr2 ||
			ctx2.Dr3 ||
			!ctx2.Dr7)
		{
			return TRUE;
		}
		
		ctx2.Dr0 = 0;
		ctx2.Dr7 = 0;
		ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		g_winAPIs->NtGetContextThread(NtCurrentThread(), &ctx);
		return FALSE;
	}

	bool CheckWriteWatch()
	{

		
		auto addresses = static_cast<PVOID*>(g_winAPIs->VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!addresses)
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualAlloc(addresses) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto buffer = static_cast<int*>(g_winAPIs->VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
		if (!buffer)
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualAlloc(buffer) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->VirtualFree(addresses, 0, MEM_RELEASE);
			return false;
		}
	
		bool result = false, error = false;

		// make some calls where a buffer *can* be written to, but isn't actually edited because we pass invalid parameters	
		if (g_winAPIs->GlobalGetAtomNameW(INVALID_ATOM, (LPWSTR)buffer, 1) != FALSE ||
			g_winAPIs->GetEnvironmentVariableW(xorstr_(L"%random_environment_var_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%"), (LPWSTR)buffer, 4096 * 4096) != FALSE ||
			g_winAPIs->GetBinaryTypeW(xorstr_(L"%random_file_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%"), (LPDWORD)buffer) != FALSE ||
			g_winAPIs->HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE ||
			g_winAPIs->ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE ||
			g_winAPIs->GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE ||
			g_winAPIs->GetWriteWatch(0, &CheckWriteWatch, 0, NULL, NULL, (PULONG)buffer) == 0)
		{
			result = false;
			error = true;
		}

		if (error == false)
		{
			//all calls failed as they're supposed to
			ULONG_PTR hits = 4096;
			DWORD granularity = 0;

			if (g_winAPIs->GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0)
			{
				result = FALSE;
			}
			else
			{
				//should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
				//if there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
				result = hits != 0;
			}
		}

		g_winAPIs->VirtualFree(addresses, 0, MEM_RELEASE);
		g_winAPIs->VirtualFree(buffer, 0, MEM_RELEASE);
		return result;
	}

	bool CheckDebugBreak()
	{		
		__try
		{
			g_winAPIs->DebugBreak();
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

#ifdef _M_IX86
	bool Int3Check()
	{
		__try
		{
			__asm int 3;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	bool Int2dCheck()
	{
		__try
		{
			__asm xor eax, eax;
			__asm int 0x2d;
			__asm nop;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}
#endif

	bool CheckDebugRegisters()
	{
		SIZE_T drX = 0;
		ULONG_PTR val;
		CONTEXT* ctx;

		__try
		{
			__writeeflags(__readeflags() | 0x100);
			val = __rdtsc();
			__nop();
			return TRUE;
		}
		__except (ctx = (GetExceptionInformation())->ContextRecord,
			drX = (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) ?
			ctx->Dr0 | ctx->Dr1 | ctx->Dr2 | ctx->Dr3 : 0,
			EXCEPTION_EXECUTE_HANDLER)
		{
			if (drX)
				return true;
		}
		return false;
	}

#ifdef _M_IX86
	bool IceInstructionCheck()
	{
		__try
		{
			__asm __emit 0xF1;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}
#endif

	bool MutexCheck()
	{
		const auto lstBadMutexList = {
			xorstr_(L"$ IDA trusted_idbs"),
			xorstr_(L"$ IDA registry mutex $")
		};

		for (const auto& c_szMutex : lstBadMutexList)
		{
			auto hMutex = g_winAPIs->OpenMutexW(MUTEX_ALL_ACCESS, FALSE, c_szMutex);
			if (IS_VALID_HANDLE(hMutex))
			{
				g_winAPIs->CloseHandle(hMutex);
				return true;
			}
		}

		return false;
	}

	DWORD CheckSignatures()
	{
		MODULEINFO mi{ 0 };
		if (g_winAPIs->GetModuleInformation(NtCurrentProcess(), g_winModules->hUser32, &mi, sizeof(mi)))
		{
			// TODO: Scan section by section with protection check, currently it's causing crash

			auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
			if (IS_VALID_SMART_PTR(upPatternScanner))
			{
				const auto lstPatterns = {
					xorstr_(L"4C 8B D1 B8 ? ? ? ? 0F 05 C3 FF 15 9F 85 0A 00 E9"),
					xorstr_(L"4C 8B D1 B8 ? ? ? ? 0F 05 C3 90 90 90 90 90 90 FF 25 00 00 00 00"),
					xorstr_(L"EB 01 CC 90 FF 25 00 00 00 00 9C 1F")
				};
				std::size_t i = 0;
				for (const auto& curr : lstPatterns)
				{
					i++;

					const auto pattern = Pattern(curr, PatternType::Address);
					if (upPatternScanner->findPatternSafe((LPVOID)mi.lpBaseOfDll, mi.SizeOfImage, pattern))
					{
						APP_TRACE_LOG(LL_ERR, L"Pattern: %d found!", i);
						return i;
					}
				}
			}
		}
		
		return 0;
	}
	
	DWORD CheckOtherSymbols()
	{
		const auto lstSymbols = {
			xorstr_(L"\\\\.\\pipe\\cuckoo"), xorstr_(L"\\\\.\\OsiData"), xorstr_(L"\\\\.\\DbgMsg"),
			xorstr_(L"\\\\.\\LiveKd"), xorstr_(L"\\\\.\\W32Dasm"), xorstr_(L"\\\\.\\ICEDUMP"),
			xorstr_(L"\\\\.\\EXTREM"), xorstr_(L"\\\\.\\RING0")
		};

		uint8_t idx = 0;
		for (const auto& szSymbol : lstSymbols)
		{
			idx++;

			auto hDevice = g_winAPIs->CreateFileW(szSymbol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (IS_VALID_HANDLE(hDevice))
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckOtherSymbols.%s", szSymbol);
				return idx;
			}
		}

		return 0;
	}

	bool CAntiDebug::InitAntiDebug(LPDWORD pdwErrorStep)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti debug initialization has been started!");

//		SetFakeImageBase();
//		SetFakeImageSize();

		std::vector <std::tuple <uint32_t, std::function <bool()>, EFlags, uint32_t>> vecInfoHelpers = {
			{1, std::bind(&CrashDebuggerViaFormatText), EFlags::NONE, 0},
			{2, std::bind(&BasicDebugTriggered), EFlags::NONE, 0},
			{3, std::bind(&RemoteDebugTriggered), EFlags::NONE, 0},
			{4, std::bind(&DetachFromDebuggerProcessTriggered), EFlags::NONE, 0},
			{5, std::bind(&PEBWow64Triggered), EFlags::NONE, 0},
			{6, std::bind(&DebugPortTriggered), EFlags::NONE, 0},
			{7, std::bind(&CloseHandleViaInvalidHandleTriggered), EFlags::NONE, 0},
			{8, std::bind(&CloseHandleViaProtectedHandleTriggered), EFlags::NONE, 0},
			{9, std::bind(&SofticeSymbolTriggered), EFlags::NONE, 0},
			{10, std::bind(&SyserSymbolTriggered), EFlags::NONE, 0},
			{11, std::bind(&CheckDebugObjectsTriggered), EFlags::DISABLED, 0}, // CHECKME
			{12, std::bind(&ThreadBreakOnTerminationTriggered), EFlags::NONE, 0},
			{13, std::bind(&GlobalFlagsClearInProcessTriggered), EFlags::NONE, 0},
			{14, std::bind(&CheckHeapSetInformation), EFlags::NONE, 0},
			{16, std::bind(&CheckSystemDebugControl), EFlags::DISABLED, 0}, // CHECKME
			{17, std::bind(&CheckDebugFilterState), EFlags::OPTIONAL, 0},
			{18, std::bind(&CheckEmulationWithTime), EFlags::OPTIONAL, 0},
			{19, std::bind(&CheckHeapFlags), EFlags::OPTIONAL, 0},
			{20, std::bind(&CheckCloseWindow), EFlags::OPTIONAL, 0},
			{21, std::bind(&CheckSystemTime), EFlags::OPTIONAL, 0},
			{22, std::bind(&CheckDebugObjectHandle), EFlags::OPTIONAL, 0},
			{23, std::bind(&CheckBugCheck), EFlags::TEST, 0},
			{24, std::bind(&CheckWow64Context), EFlags::OPTIONAL, 0},
			{25, std::bind(&CheckWriteWatch), EFlags::DISABLED, 0}, // CHECKME
			{26, std::bind(&CheckNtYieldExecutionQuerySingleStep), EFlags::DISABLED, 0}, // CHECKME
			{27, std::bind(&CheckAntiStepOver), EFlags::OPTIONAL, 0},
			{28, std::bind(&CheckIsBadHideContext), EFlags::TEST, 0}, // cause to incompatible with hwbp check (200)
			{29, std::bind(&CheckDebugBreak), EFlags::TEST, 0},
#ifdef _M_IX86
			{30, std::bind(&Int3Check), EFlags::TEST, 0},
			{31, std::bind(&Int2dCheck), EFlags::TEST, 0},
			{32, std::bind(&IceInstructionCheck), EFlags::TEST, 0},
#endif
			{33, std::bind(&CheckDebugRegisters), EFlags::TEST, 0}, // todo: move after ss exc handler
			{34, std::bind(&MutexCheck), EFlags::TEST, 0},
			{0, std::bind(&CheckOtherSymbols), EFlags::NONE, 100},
//			{0, std::bind(&CheckSignatures), EFlags::NONE, 200}, // todo: refactor with section scanner
		};
		
		auto dwDetectIdx = 0UL;

		for (const auto& [idx, fn, flags, base] : vecInfoHelpers)
		{			
			APP_TRACE_LOG(LL_SYS, L"Anti debug step %u+%u checking... Flags: %d", base, idx, flags);

			if (flags == EFlags::DISABLED)
			{
				APP_TRACE_LOG(LL_SYS, L"Anti debug step %u is disabled!", idx);
				continue;
			}
			else if (flags == EFlags::TEST && !stdext::is_debug_env())
			{
				APP_TRACE_LOG(LL_SYS, L"Anti debug step %u is disabled in release mode!", idx);
				continue;
			}

			const auto bRet = fn();
			if (bRet)
			{
				APP_TRACE_LOG(LL_CRI, L"Debugger %u detected!", idx);
				
				if (flags != EFlags::OPTIONAL)
				{
					dwDetectIdx = base + idx;
#ifndef _DEBUG
					break;
#endif
				}				
			}

			APP_TRACE_LOG(LL_SYS, L"Anti debug step %u completed!", idx);
		}
			
#ifndef _M_X64
		VehIntoBreak();
#endif

		APP_TRACE_LOG(dwDetectIdx == 0 ? LL_SYS : LL_CRI, L"Debug check routine completed! Result: %u", dwDetectIdx);

		if (pdwErrorStep) *pdwErrorStep = dwDetectIdx;
		return dwDetectIdx == 0;
	}

	extern bool KernelDebugInformationCheckTriggered();
	bool CAntiDebug::CheckRuntimeAntiDebug(LPDWORD pdwDetectType)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (g_winAPIs->IsDebuggerPresent()) // pass it for debug build and if have a attached debugger
			return false;
#endif

		if (DetachFromDebuggerProcessTriggered())
		{
			if (pdwDetectType) *pdwDetectType = 1;
			return true;
		}

		if (KernelDebugInformationCheckTriggered())
		{
			if (pdwDetectType) *pdwDetectType = 2;
			return true;
		}

		return false;
	}

	bool CAntiDebug::CheckPreAntiDebug()
	{
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		CrashDebuggerViaFormatText();

		const auto pPEB = NtCurrentPeb();
		if (pPEB && pPEB->BeingDebugged)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: pPEB->BeingDebugged");
			return false;
		}

		if (pPEB && pPEB->NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: pPEB->NtGlobalFlag");
			return false;
		}
#endif
		return true;
	}

	bool CAntiDebug::IsImageSumCorrupted(LPVOID pvBaseImage, uint64_t unCorrectSum)
	{
		const auto pIDH = static_cast<IMAGE_DOS_HEADER*>(pvBaseImage);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(pIDH) + pIDH->e_lfanew));
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pISH = reinterpret_cast<PIMAGE_SECTION_HEADER>((reinterpret_cast<DWORD_PTR>(pINH) + sizeof(pINH->Signature) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader));
		if (!pISH)
			return false;

		const auto unTargetAddr = reinterpret_cast<DWORD_PTR>(pvBaseImage) + pISH->VirtualAddress;
		const auto dwCurrentSum = CPEFunctions::CalculateMemChecksumFast(reinterpret_cast<LPCVOID>(unTargetAddr), pISH->SizeOfRawData);
		return (dwCurrentSum != unCorrectSum);
	}

	bool CAntiDebug::CheckStartupTime()
	{
		auto SystemTimeDiff = [](LPSYSTEMTIME stA, LPSYSTEMTIME stB, LPSYSTEMTIME stC) {
			FILETIME ftA, ftB, ftC;
			ULARGE_INTEGER uiA, uiB, uiC;

			g_winAPIs->SystemTimeToFileTime(stA, &ftA);
			g_winAPIs->SystemTimeToFileTime(stB, &ftB);
			uiA.HighPart = ftA.dwHighDateTime;
			uiA.LowPart = ftA.dwLowDateTime;
			uiB.HighPart = ftB.dwHighDateTime;
			uiB.LowPart = ftB.dwLowDateTime;

			uiC.QuadPart = uiA.QuadPart - uiB.QuadPart;

			ftC.dwHighDateTime = uiC.HighPart;
			ftC.dwLowDateTime = uiC.LowPart;
			g_winAPIs->FileTimeToSystemTime(&ftC, stC);
		};

		FILETIME creation, exit, kernel, user;
		SYSTEMTIME current, creationSt, diffSt;

		g_winAPIs->GetSystemTime(&current);

		if (!g_winAPIs->GetProcessTimes(NtCurrentProcess(), &creation, &exit, &kernel, &user))
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcessTimes failed with error: %u", g_winAPIs->GetLastError());
			return true;
		}
		if (!g_winAPIs->FileTimeToSystemTime(&creation, &creationSt))
		{
			APP_TRACE_LOG(LL_ERR, L"FileTimeToSystemTime failed with error: %u", g_winAPIs->GetLastError());
			return true;
		}

		SystemTimeDiff(&current, &creationSt, &diffSt);

		APP_TRACE_LOG(LL_SYS, L"Creation time(GetProcessTimes): %d:%d:%d:%d", creationSt.wHour, creationSt.wMinute, creationSt.wSecond, creationSt.wMilliseconds);
		APP_TRACE_LOG(LL_SYS, L"Current time(GetSystemTime): %d:%d:%d:%d", current.wHour, current.wMinute, current.wSecond, current.wMilliseconds);
		APP_TRACE_LOG(LL_SYS, L"Time diff: %d:%d:%d:%d", diffSt.wHour, diffSt.wMinute, diffSt.wSecond, diffSt.wMilliseconds);

		// if they are using process suspension to inject dlls during startup (aka before we got to here)
		const auto time = diffSt.wMilliseconds + (diffSt.wSecond * 1000) + (diffSt.wMinute * 1000 * 60);
		APP_TRACE_LOG(LL_SYS, L"Diff: %d", time);

		if (time > 10000)
			return false;
		return true;
	}
};
