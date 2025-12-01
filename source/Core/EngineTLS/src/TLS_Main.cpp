#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Cleancall.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"

namespace NoMercyTLS
{
	static constexpr auto	gs_bTlsActive		= true;
	static auto				gs_bTlsCompleted	= false;
	static HMODULE			gs_hModule			= nullptr;

	bool HasEntrypointBreakpoint(LPVOID lpBase)
	{
		static constexpr auto sc_nCheckSize = 10;

		if (!lpBase)
			return false;

		const auto pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBase);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(pIDH) + pIDH->e_lfanew));
		if (pINH->Signature != IMAGE_NT_SIGNATURE || pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return false;

		const auto pEntryPoint = reinterpret_cast<PBYTE>((pINH->OptionalHeader.AddressOfEntryPoint + reinterpret_cast<DWORD_PTR>(pIDH)));
		if (!pEntryPoint)
			return false;

		uint8_t pBuffer[sc_nCheckSize]{ 0x0 };
		__try
		{
			stdext::CRT::mem::__memcpy(pBuffer, pEntryPoint, sc_nCheckSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		for (auto i = 0u; i < sizeof(pBuffer); ++i)
		{
			if (pBuffer[i] == 0xCC)
				return true;
		}

		return false;
	}

	bool HasTLSBreakpoint(LPVOID lpBase)
	{
		if (!lpBase)
			return false;

		const auto pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBase);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(pIDH) + pIDH->e_lfanew));
		if (pINH->Signature != IMAGE_NT_SIGNATURE || pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return false;

		const auto pIFH = reinterpret_cast<PIMAGE_FILE_HEADER>(&pINH->FileHeader);
		if (!pIFH)
			return false;

		const auto pIOH = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pINH->OptionalHeader);
		if (!pIOH)
			return false;

		const auto pISH = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pINH) + sizeof(IMAGE_NT_HEADERS) + (pIFH->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));
		if (!pISH)
			return false;

		const auto pIDD = &(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
		if (!pIDD || !pIDD->VirtualAddress)
			return false;

		const auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((DWORD_PTR)pIDD->VirtualAddress + (DWORD_PTR)pIDH);
		if (!pTLS)
			return false;

		auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		if (callback)
		{
			while (*callback)
			{
				const auto pCallbackPtr = *callback;

				uint8_t pOpcode{ 0x0 };
				__try
				{
					stdext::CRT::mem::__memcpy(&pOpcode, pCallbackPtr, sizeof(pOpcode));
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					return false;
				}

				if (pOpcode == 0xCC)
					return true;

				callback++;
			}
		}

		return false;
	}

	bool DetachFromDebugger()
	{
		auto hDebugObject = HANDLE(INVALID_HANDLE_VALUE);
		auto dwFlags = 0UL;

		auto ntStatus = NT::NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), nullptr);
		if (!NT_SUCCESS(ntStatus))
			return false;

		ntStatus = NT::NtSetInformationDebugObject(hDebugObject, (DEBUGOBJECTINFOCLASS)1, &dwFlags, sizeof(dwFlags), nullptr);
		if (!NT_SUCCESS(ntStatus))
			return false;

		ntStatus = NT::NtRemoveProcessDebug(NtCurrentProcess(), hDebugObject);
		if (!NT_SUCCESS(ntStatus))
			return false;

		ntStatus = NT::NtClose(hDebugObject);
		if (!NT_SUCCESS(ntStatus))
			return false;

		return true;
	}

	bool IsTlsCompleted()
	{
		return !gs_bTlsActive || gs_bTlsCompleted;
	}

	void TLS_EnumerateModules(LPVOID lpParam, void(*cb)(LDR_DATA_TABLE_ENTRY*, LPVOID))
	{
		const auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (Current)
				cb(Current, lpParam);

			CurrentEntry = CurrentEntry->Flink;
		}
	}
	void TLS_EnumerateThreads(LPVOID lpParam, void(*cb)(DWORD, LPVOID))
	{
		ULONG ulRequiredSize = 0;
		const auto dwProcessId = HandleToULong(NtCurrentProcessId());
		BYTE* pBuffer = nullptr;
		do
		{
			uint8_t byDummy[1];
			auto ntStatus = NT::NtQuerySystemInformation(SystemProcessInformation, &byDummy, 1, &ulRequiredSize);
			if (ntStatus != STATUS_INFO_LENGTH_MISMATCH || !ulRequiredSize)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("NtQuerySystemInformation (1) failed with unknown status: %p", ntStatus);
#endif
				break;
			}

			pBuffer = (BYTE*)TLS_AllocateMemory(ulRequiredSize);
			if (!pBuffer)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("malloc failed with size: %p", ulRequiredSize);
#endif
				break;
			}

			ULONG ulDummy = 0;
			ntStatus = NT::NtQuerySystemInformation(SystemProcessInformation, pBuffer, ulRequiredSize, &ulDummy);
			if (!NT_SUCCESS(ntStatus))
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("NtQuerySystemInformation (2) failed with unknown status: %p", ntStatus);
#endif
				break;
			}

			auto bBreakLoop = false;
			SYSTEM_PROCESS_INFORMATION* pkCurrProcInfo = nullptr;
			auto pkProcInfo = (SYSTEM_PROCESS_INFORMATION*)pBuffer;
			while (!pkCurrProcInfo && !bBreakLoop)
			{
				if (reinterpret_cast<DWORD_PTR>(pkProcInfo->UniqueProcessId) == dwProcessId)
				{
					pkCurrProcInfo = pkProcInfo;
				}

				if (!pkProcInfo->NextEntryOffset)
				{
					bBreakLoop = true;
				}
				else
				{
					pkProcInfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pkProcInfo + pkProcInfo->NextEntryOffset);
				}
			}

			if (!pkCurrProcInfo && bBreakLoop)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("Process: %u info not found!", dwProcessId);
#endif
				break;
			}

			auto pkThread = pkCurrProcInfo->Threads;
			if (!pkThread)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("Process: %u threads info not found!", dwProcessId);
#endif
				break;
			}

			const auto dwThreadCount = pkCurrProcInfo->NumberOfThreads;
			for (DWORD i = 0; i < dwThreadCount; i++)
			{
				cb(HandleToULong(pkThread->ClientId.UniqueThread), lpParam);
				pkThread++;
			}
		} while (FALSE);

		if (pBuffer)
		{
			TLS_FreeMemory(pBuffer, ulRequiredSize);
			pBuffer = nullptr;
		}
	}
	void TLS_EnumerateMemorys(LPVOID lpParam, void(*cb)(PVOID, MEMORY_BASIC_INFORMATION, LPVOID))
	{
		PVOID baseAddress = nullptr;
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		while (NT_SUCCESS(NT::NtQueryVirtualMemory(NtCurrentProcess(), baseAddress, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
		{
			if ((mbi.Protect & PAGE_EXECUTE) ||
				(mbi.Protect & PAGE_EXECUTE_READ) ||
				(mbi.Protect & PAGE_EXECUTE_READWRITE) ||
				(mbi.Protect & PAGE_EXECUTE_WRITECOPY))
			{
				cb(baseAddress, mbi, lpParam);
			}

			baseAddress = RtlOffsetToPointer(baseAddress, mbi.RegionSize);
		}
	}

	bool TLS_IsMainModule(HMODULE hModule)
	{
		if (gs_hModule && hModule == gs_hModule)
			return true;

		const auto pIDH = (IMAGE_DOS_HEADER*)gs_hModule;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			// TLS_LOG("Invalid DOS header.");
			return false;
		}
		const auto pINH = (IMAGE_NT_HEADERS*)((LPBYTE)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			// TLS_LOG("Invalid NT header.");
			return false;
		}
		const auto pEntryPoint = pINH->OptionalHeader.AddressOfEntryPoint + pINH->OptionalHeader.ImageBase;
		if (!pEntryPoint)
		{
			// TLS_LOG("Invalid entry point.");
			return false;
		}

		// TLS_LOG("Main module entry point: %p/%p", pEntryPoint, hModule);
		return hModule == (HMODULE)pEntryPoint;
	}

	bool TLS_IsIninModule(DWORD_PTR dwAddress)
	{
		if (gs_hModule && (HMODULE)dwAddress == gs_hModule)
			return true;

		const auto pIDH = (IMAGE_DOS_HEADER*)gs_hModule;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			// TLS_LOG("Invalid DOS header.");
			return false;
		}
		const auto pINH = (IMAGE_NT_HEADERS*)((LPBYTE)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			// TLS_LOG("Invalid NT header.");
			return false;
		}
		const auto pEntryPoint = pINH->OptionalHeader.AddressOfEntryPoint + pINH->OptionalHeader.ImageBase;
		if (!pEntryPoint)
		{
			// TLS_LOG("Invalid entry point.");
			return false;
		}

		char szBuffer[MAX_PATH]{ '\0' };
		const auto nRet = GetModuleFileNameA((HMODULE)dwAddress, szBuffer, sizeof(szBuffer));
		TLS_LOG("Main module entry point=%p, address=%p, size=%p, range=%p, file=%s(%u)",
			pEntryPoint, dwAddress, pINH->OptionalHeader.SizeOfImage, (DWORD_PTR)pEntryPoint + pINH->OptionalHeader.SizeOfImage, szBuffer, nRet
		);
		
		return dwAddress >= pEntryPoint && dwAddress < ((DWORD_PTR)pEntryPoint + pINH->OptionalHeader.SizeOfImage);
	}

	void TLS_Worker(HMODULE hModule)
	{
		gs_hModule = hModule;

		char szBuffer[MAX_PATH]{ '\0' };
		const auto nRet = GetModuleFileNameA(nullptr, szBuffer, sizeof(szBuffer));
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("Process base module file name: %s(%u)", szBuffer, nRet);
#endif

		if (nRet && szBuffer[0] != '\0')
		{
			if (strstr(szBuffer, xorstr_("rundll")))
			{
				gs_bTlsCompleted = true;
				return;
			}
		}

#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS process name check step completed!");
#endif

		// Pre validation
#if USE_THEMIDA_SDK != 1
#ifndef _DEBUG
		if (HasTLSBreakpoint(hModule))
		{
			TLS_LOG("[1] System validation corrupted.");
			std::abort();
			return;
		}

		if (HasEntrypointBreakpoint(hModule))
		{
			TLS_LOG("[2] System validation corrupted.");
			std::abort();
			return;
		}
#endif
#endif
		
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS entrypoint check step completed!");
#endif

		// Initialize WinAPIs
		if (!InitializeWinAPIs())
		{
			TLS_LOG("TLS WinAPI initilization failed.");
			std::abort();
			return;
		}
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS WinAPIs successfully initialized!");
#endif

#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		// Post-initilization validation
		if (DetachFromDebugger())
		{
			TLS_LOG("System integrity corrupted.");
			std::abort();
			return;
		}
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS detach from debugger completed.");
#endif

		const auto ntStatus = NT::NtSetInformationThread(NtCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
		if (!NT_SUCCESS(ntStatus))
		{
			TLS_LOG("TLS thread hiding failed with status: %p", ntStatus);
			std::abort();
			return;
		}
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS main thread anti debug completed.");
#endif
#endif

		// TODO: activate
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
//		if (!stdext::is_debug_env()) // FIXME: under APC load incompatible (3 worker thread spawn from ntdll)
//			TLS_ScanThreads();
		TLS_ScanModules();
		TLS_ScanMemory();
#endif

#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS scan methods completed!");
#endif

		// TODO: activate
#if 0
		// Remap
		auto pPEB = NtCurrentPeb();
		if (pPEB && !pPEB->BeingDebugged)
		{
			TLS_EnumerateModules(nullptr, [](LDR_DATA_TABLE_ENTRY* Current, LPVOID) {
				static auto counter = 0;
				if (counter++ < 4)
				{
#ifdef _DEBUG
					TLS_LOG("Remapping module: %p -> %ls", Current->DllBase, Current->FullDllName.Buffer);
#endif

					if (!TLS_RemapImage((ULONG_PTR)Current->DllBase))
					{
						TLS_LOG("RemapImage: %ls failed.", Current->FullDllName.Buffer);
						return;
					}

#ifdef _DEBUG
					TLS_LOG("Module: %p -> %ls succesfully remapped!", Current->DllBase, Current->FullDllName.Buffer);
#endif
				}
			});
		}
#endif

		if (!stdext::is_debug_env() && !TLS_RemapImage((ULONG_PTR)GetModuleHandleA(0)))
		{
			TLS_LOG("RemapImage failed.");
			std::abort();
			return;
		}
	}

	void TLS_Routine(PVOID hModule, DWORD dwReason, PVOID pContext)
	{
		if (gs_bTlsCompleted)
			return; // run once

		if (!gs_bTlsActive)
		{
#ifdef ENABLE_TLS_LOGS
			TLS_LOG("TLS is not active.");
#endif
			return;
		}

#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS started.");
#endif

		__try
		{
			TLS_Worker((HMODULE)hModule);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
#ifdef ENABLE_TLS_LOGS
			TLS_LOG("TLS worker failed.");
#endif
		}

#ifdef ENABLE_TLS_LOGS
		TLS_LOG("TLS initilization completed.");
#endif
		gs_bTlsCompleted = true;
		return;
	}
}
