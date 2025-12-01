#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"

#define LDRP_MAX_MODULE_LOOP 10240
#define IN_REGION(x, Base, Size) (((ULONG_PTR)x >= (ULONG_PTR)Base) && ((ULONG_PTR)x <= (ULONG_PTR)Base + (ULONG_PTR)Size))

namespace NoMercyTLS
{
	PVOID supLdrFindImageByAddressEx(
		_In_ BOOL LockLoader,
		_In_opt_ PVOID AddressValue,
		_Out_ PVOID* ImageBase
	)
	{
		ULONG_PTR imageBounds;

		PLDR_DATA_TABLE_ENTRY ldrTableEntry;
		PLIST_ENTRY listHead;
		PLIST_ENTRY nextEntry;

		PIMAGE_NT_HEADERS NtHeaders;

		PVOID foundBase = NULL, pvImageBase = NULL;

		PPEB currentPeb = NtCurrentPeb();

		MEMORY_BASIC_INFORMATION mi;

		ULONG lockDisposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
		PVOID lockCookie = NULL;

		NTSTATUS ntStatus;

		*ImageBase = NULL;

		if (LockLoader) {
			ntStatus = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY,
				&lockDisposition, &lockCookie);

			if (!NT_SUCCESS(ntStatus))
				return NULL;

			//
			// Loader lock failed. Query virtual memory.
			//

			if (lockDisposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED) {

				ntStatus = NtQueryVirtualMemory(
					NtCurrentProcess(),
					AddressValue,
					MemoryBasicInformation,
					&mi,
					sizeof(MEMORY_BASIC_INFORMATION),
					NULL);

				if (!NT_SUCCESS(ntStatus)) {
					mi.AllocationBase = NULL;
				}
				else {
					if (mi.Type == MEM_IMAGE) {
						*ImageBase = mi.AllocationBase;
					}
					else {
						mi.AllocationBase = NULL;;
					}
				}
				return mi.AllocationBase;
			}

		}

		//
		// Walk PEB.
		//

		__try {

			ULONG cLoops = 0;

			if (currentPeb->Ldr != NULL) {
				listHead = &currentPeb->Ldr->InLoadOrderModuleList;
				nextEntry = listHead->Flink;
				if (nextEntry != NULL) {
					while (nextEntry != listHead && cLoops < LDRP_MAX_MODULE_LOOP) {

						ldrTableEntry = CONTAINING_RECORD(nextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						pvImageBase = ldrTableEntry->DllBase;

						NtHeaders = RtlImageNtHeader(pvImageBase);
						if (NtHeaders) {
							imageBounds = (ULONG_PTR)RtlOffsetToPointer(pvImageBase, NtHeaders->OptionalHeader.SizeOfImage);
							if (IN_REGION(AddressValue, pvImageBase, NtHeaders->OptionalHeader.SizeOfImage)) {
								foundBase = pvImageBase;
								break;
							}
						}

						nextEntry = nextEntry->Flink;
						cLoops += 1;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			foundBase = NULL;
		}

		if (LockLoader) {
			LdrUnlockLoaderLock(0, lockCookie);
		}

		*ImageBase = foundBase;
		return foundBase;
	}

	void TLS_ScanMemory()
	{
		TLS_EnumerateMemorys(nullptr, [](PVOID pvBaseAddress, MEMORY_BASIC_INFORMATION mbi, LPVOID lpParam) {
			auto fnPrintPageInfo = [](MEMORY_BASIC_INFORMATION mbi) {
				TLS_LOG("Base: %p Size: %p State: %p Protect: %p Type: %p Allocation: %p w/ %p",
					mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type, mbi.AllocationBase, mbi.AllocationProtect
				);
			};
			auto fnGetAddressOwnerName = [](LPVOID lpAddress) -> UNICODE_STRING* {
				// const auto mappedFilenameLength = sizeof(UNICODE_STRING) + MAX_PATH * 2;
				const auto mappedFilenameLength = 0x1000;

				auto pusMappedFilename = (UNICODE_STRING*)TLS_AllocateMemory(mappedFilenameLength);
				if (!pusMappedFilename)
					return nullptr;

				const auto ntStatus = NT::NtQueryVirtualMemory(NtCurrentProcess(), lpAddress, MemoryMappedFilenameInformation, pusMappedFilename, mappedFilenameLength, 0);
				if (!NT_SUCCESS(ntStatus))
				{
					TLS_FreeMemory(pusMappedFilename, mappedFilenameLength);
					return nullptr;
				}

				return pusMappedFilename;
			};
			auto fnIsWow64Module = [&fnGetAddressOwnerName](LPVOID lpAddress) {
				if (!stdext::is_wow64())
					return false;

				auto pusMappedFilename = fnGetAddressOwnerName(lpAddress);
				if (!pusMappedFilename)
					return false;

				auto bRet = false;
				const auto lstWhitelistedModules = {
					xorstr_(L"\\Windows\\System32\\wow64cpu.dll"),
					xorstr_(L"\\Windows\\System32\\wow64.dll"),
					xorstr_(L"\\Windows\\System32\\wow64win.dll")
				};
				for (const auto& wszModule : lstWhitelistedModules)
				{
					if (wcsstr(pusMappedFilename->Buffer, wszModule))
					{
						bRet = true;
						break;
					}
				}

				if (!bRet)
				{
					TLS_LOG("Unknown image owner: %ls", pusMappedFilename->Buffer);
				}
				TLS_FreeMemory(pusMappedFilename, 0x1000);
				return bRet;
			};
			auto fnIsWhitelistedModule = [&fnGetAddressOwnerName](LPVOID lpAddress) {
				if (!stdext::is_wow64())
					return false;

				auto pusMappedFilename = fnGetAddressOwnerName(lpAddress);
				if (!pusMappedFilename)
					return false;

				auto bRet = false;
				const auto lstWhitelistedModules = {
					xorstr_(L"\\Kaspersky Lab\\"), // https://i.imgur.com/arS0APR.png
				};
				for (const auto& wszModule : lstWhitelistedModules)
				{
					if (wcsstr(pusMappedFilename->Buffer, wszModule))
					{
						bRet = true;
						break;
					}
				}

				if (!bRet)
				{
					TLS_LOG("Unknown image owner: %ls", pusMappedFilename->Buffer);
				}
				TLS_FreeMemory(pusMappedFilename, 0x1000);
				return bRet;
			};

			if (mbi.State != MEM_COMMIT)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("Non-commit section!");
				fnPrintPageInfo(mbi);
#endif
				return;
			}
			if (mbi.Protect == PAGE_NOACCESS)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("No-access protected section!");
				fnPrintPageInfo(mbi);
#endif
				return;
			}
			if (mbi.Protect & PAGE_GUARD)
			{
#ifdef ENABLE_TLS_LOGS
				TLS_LOG("Guard protected section!");
				fnPrintPageInfo(mbi);
#endif
				return;
			}

			if (mbi.Type == MEM_IMAGE)
			{
				PVOID pvImageBase = nullptr;
				if (!supLdrFindImageByAddressEx(TRUE, pvBaseAddress, &pvImageBase))
				{
					if (!fnIsWow64Module(pvBaseAddress) && !fnIsWhitelistedModule(pvBaseAddress))
					{
#ifdef ENABLE_TLS_LOGS
						TLS_LOG("Suspect image section!");
						fnPrintPageInfo(mbi);
#endif

						const auto pusMappedFilename = fnGetAddressOwnerName(pvBaseAddress);

						wchar_t wszBuffer[0x1000]{ L'\0' };
						wsprintfW(wszBuffer, xorstr_(L"Memory: %p backed by unknown module: (%ls)"),
							pvBaseAddress, pusMappedFilename ? pusMappedFilename->Buffer : xorstr_(L"<unknown>")
						);

						TLS_MessageBox(xorstr_(L"NoMercy core protector"), wszBuffer);

						LdrShutdownProcess();
						std::abort();
						return;
					}
				}
			}
			else if (mbi.Type == MEM_MAPPED || mbi.Type == MEM_PRIVATE)
			{
#ifdef ENABLE_TLS_LOGS
				fnPrintPageInfo(mbi);
#endif
				// TODO: scan with IManualmapperScanner methods
			}
		});
	}
}
