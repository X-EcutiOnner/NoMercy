#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ScannerInterface.hpp"
#include "../Common/Quarentine.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"



namespace NoMercy
{
	extern bool ScanModuleLinks(HANDLE hProcess, ptr_t c_pvModuleBase);

	bool CopySectionMemory(HANDLE hProcess, ptr_t dwBaseAddress, DWORD64 dwRegionSize, LPVOID& lprefMemCopy)
	{
		bool bRet = false;
		LPVOID lpMemCopy = nullptr;
		DWORD dwOldProtect = 0;

		do
		{
			lpMemCopy = CMemHelper::Allocate(dwRegionSize);
			if (!lpMemCopy)
			{
				SCANNER_LOG(LL_ERR, L"Allocate %llu bytes memory failed with error: %u", dwRegionSize, g_winAPIs->GetLastError());
				break;
			}

			if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ProtectVirtualMemory(
					hProcess, (PVOID64)dwBaseAddress, dwRegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect
				) == false)
			{
				SCANNER_LOG(LL_ERR, L"ProtectVirtualMemory failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			SIZE_T cbReadSize = 0;
			const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
				hProcess, (PVOID64)dwBaseAddress, lpMemCopy, dwRegionSize, &cbReadSize
			);

			if (ntStatus != STATUS_SUCCESS || cbReadSize != dwRegionSize)
			{
				SCANNER_LOG(LL_ERR, L"ReadVirtualMemory failed with error: %p", ntStatus);
				break;
			}

			lprefMemCopy = lpMemCopy;
			bRet = true;
		} while (FALSE);

		if (dwOldProtect)
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ProtectVirtualMemory(
				hProcess, (PVOID64)dwBaseAddress, dwRegionSize, dwOldProtect, &dwOldProtect
			);
		}

		return bRet;
	}

	bool ScanSectionBase(HANDLE hProcess, LPVOID lpRegionMem, DWORD64 dwRegionSize)
	{
		static const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->GetBlacklist();
		if (vecBlacklist.empty())
			return true;

		for (const auto& [obj, opts] : vecBlacklist)
		{
				/*
						uint32_t id{ 0 };
		// Mapped file scanner
		std::wstring file_name{ "" };
		uint64_t mapped_file_checksum{ 0 };
		// Mapped file PE section scanner
		std::wstring region_name{ "" };
		uint64_t region_base{ 0 };
		uint32_t region_size{ 0 };
		uint32_t region_checksum{ 0 };
		uint32_t region_charecteristics{ 0 };
		float region_entropy{ 0.0f };
		// Mapped file PE hash scanner
		std::wstring region_hash{ "" };
		// Mapped file PE EAT scanner
		uint32_t eat_base{ 0 };
		uint32_t eat_ordinal{ 0 };
		std::wstring export_name{ "" };
		// Mapped file pattern scanner
		std::wstring pattern{ "" };
		std::wstring mask{ "" };
		uint32_t pattern_type{ 0 };
		// Mapped file memory dump scanner
		std::wstring memory_base{ "" };
		std::wstring memory_copy{ "" };
				*/

				/*
				if (!obj.data.empty() && obj.data == stBuffer)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_DEBUG_STRING, obj.id, obj.data);
					break;
				}
				*/
		}

		return true;
	}

	bool ScanSectionPeHeader(HANDLE hProcess, LPVOID lpRegionMem, ptr_t dwBaseAddress, DWORD64 dwRegionSize)
	{
		if (dwRegionSize != PE_HEADER_SIZE)
			return true;

		const auto pIDH = (PIMAGE_DOS_HEADER)lpRegionMem;
		if (pIDH && pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		{
			const auto pINH = (PIMAGE_NT_HEADERS)((LPBYTE)lpRegionMem + pIDH->e_lfanew);
			if (pINH && pINH->Signature == IMAGE_NT_SIGNATURE)
			{
				wchar_t wszFileName[2048]{ L'\0' };
				g_winAPIs->GetMappedFileNameW(hProcess, (LPVOID)dwBaseAddress, wszFileName, 2048);

				auto dwTimestamp = pINH->FileHeader.TimeDateStamp;
				auto dwModuleSize = pINH->OptionalHeader.SizeOfCode;
				auto dwDataSize = pINH->OptionalHeader.SizeOfInitializedData;

				APP_TRACE_LOG(LL_ERR, L"PE Header found! Base: %p Size: %p Owner: %s | Timestamp: %u Module size: %p Data size: %p",
					dwBaseAddress, dwRegionSize, wszFileName, dwTimestamp, dwModuleSize, dwDataSize
				);

				//TODO: check
			}
		}

		return true;
	}

	bool ScanSectionHash(HANDLE hProcess, LPVOID lpRegionMem, DWORD64 dwRegionSize)
	{
		/*
		const auto stHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA1(vSectionCopy.data(), vSectionCopy.size());
		TODO: check

		todo tlsh
			*/
		return true;
	}

	bool ScanSharedPage(HANDLE hProcess, ptr_t dwBaseAddress, DWORD64 dwRegionSize)
	{
		const auto bWow64 = stdext::is_wow64();
		auto bRet = false;
		auto bLockRet = false;
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		SYSTEM_INFO	si{ 0 };
		PSAPI_WORKING_SET_INFORMATION* ppwsi = nullptr;

		if (!g_winAPIs->VirtualQueryEx(hProcess, (LPCVOID)dwBaseAddress, &mbi, sizeof(mbi)))
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualQueryEx failed with error: %u", g_winAPIs->GetLastError());
			goto _complete;
		}

		if (~mbi.Protect & PAGE_READONLY && ~mbi.Protect & PAGE_READWRITE)
			goto _complete;

		PVOID pvBaseAddr = (PVOID)dwBaseAddress;
		SIZE_T cbRegionSize = (SIZE_T)dwRegionSize;
		const auto ntStatus = g_winAPIs->NtLockVirtualMemory(hProcess, &pvBaseAddr, &cbRegionSize, VM_LOCK_1);
		if (!NT_SUCCESS(ntStatus))
			goto _complete;
		bLockRet = true;

		ppwsi = (PSAPI_WORKING_SET_INFORMATION*)malloc(sizeof(*ppwsi));
		if (!ppwsi)
			goto _complete;

		auto counter = 0;
		while (!g_winAPIs->QueryWorkingSet(hProcess, ppwsi, sizeof(*ppwsi)))
		{
			if (counter++ > 10)
				goto _complete;

			const auto dwErr = g_winAPIs->GetLastError();
			if (dwErr == ERROR_BAD_LENGTH)
			{
				ppwsi = (PSAPI_WORKING_SET_INFORMATION*)realloc(ppwsi, (ppwsi->NumberOfEntries * 1.25) * sizeof(PSAPI_WORKING_SET_INFORMATION));
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"QueryWorkingSet failed with error: %u", dwErr);
				goto _complete;
			}
		}

		if (bWow64)
			g_winAPIs->GetNativeSystemInfo(&si);
		else
			g_winAPIs->GetSystemInfo(&si);

		auto dwVirtualPage = (ULONGLONG)dwBaseAddress / si.dwPageSize;

		unsigned int ecx = 0;
		for (ecx = ppwsi->NumberOfEntries; ecx; --ecx)
		{
			if ((DWORD_PTR)ppwsi->WorkingSetInfo[ecx].VirtualPage == dwVirtualPage)
				break;
		}

		bRet = ppwsi->WorkingSetInfo[ecx].Shared;

		if (bRet)
		{
//			todo: throw
		}

_complete:
		if (bLockRet)
			g_winAPIs->NtUnlockVirtualMemory(hProcess, &pvBaseAddr, &cbRegionSize, VM_LOCK_1);
		if (ppwsi)
			free(ppwsi);

		return bRet;
	}

	bool ScanPattern(HANDLE hProcess, LPVOID lpRegionMem, DWORD64 dwRegionSize)
	{
		const auto pattern_scanner = stdext::make_unique_nothrow<CPatternScanner>();
		if (!IS_VALID_SMART_PTR(pattern_scanner))
			return false;

		static const auto lstPatterns = {
			// Borland pattern
			Pattern(xorstr_(L"45 6D 62 61 72 63 61 72 63 61 64 65 72 6F 20 52 41 44"), PatternType::Address),
			// DLLmain patterns
			Pattern(xorstr_(L"55 8B EC 83 7D 0C 01 75 ?"), PatternType::Address),
			Pattern(xorstr_(L"4D 65 73 73 61 67 65 42 6F 78 41 00 4D 65 73 73 61 67 65 42 6F 78 57"), PatternType::Address),
			// x64 prologue
			Pattern(xorstr_(L"48 89 4C ?"), PatternType::Address),
			Pattern(xorstr_(L"48 83 EC ?"), PatternType::Address)
		};
		
		uint32_t idx = 0;
		for (const auto& pkPattern : lstPatterns)
		{
			idx++;

			if (pattern_scanner->findPatternSafe(lpRegionMem, dwRegionSize, pkPattern))
			{
				SCANNER_LOG(LL_ERR, L"Pattern: %u matched!", idx);
	//			TODO: throw
			}
		}

		return true;
	}

	bool ScanProtectViolation(HANDLE hProcess, DWORD dwBaseProtect, DWORD dwProtect)
	{
		if (dwProtect != dwBaseProtect)
		{
//			todo: check
		}

		if (dwProtect == PAGE_EXECUTE_READWRITE || dwBaseProtect == PAGE_EXECUTE_READWRITE)
		{
//			todo: check
		}

		return true;
	}

	void ScanPageGuardProtection(void* current_address, MEMORY_BASIC_INFORMATION memory_information)
	{
		/*
		if (memory_information.Protect != PAGE_NOACCESS)
		{
			auto bad_ptr = IsBadReadPtr(current_address, sizeof(temporary_buffer));
			auto ntStatus = NtReadVirtualMemory(
				GetCurrentProcess(), 
				current_address, 
				temporary_buffer, sizeof(temporary_buffer), 
				0
			);

			if (read < 0 || bad_ptr)
			{
				ntStatus = NtQueryVirtualMemory(
					GetCurrentProcess(), 
					current_address, 
					0, 
					&new_memory_information, sizeof(new_memory_information), 
					&return_length);

				const auto bShouldReport = 
						new_memory_information.state != memory_information.state || 
						new_memory_information.protect != memory_information.protect;

				if (bShouldReport)
				{

				}
			}
		}
		*/
	}

	std::vector <std::shared_ptr <SSectionEnumContext>> GetSectionList(HANDLE hProcess, bool bRwxOnly)
	{
		auto vOutput = std::vector <std::shared_ptr <SSectionEnumContext>>();

		const auto spAnticheatModule = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		const auto dwProcessId = g_winAPIs->GetProcessId(hProcess);

		MEMORY_BASIC_INFORMATION64 basicInfo = { 0 };

		auto dwSectionCount = 0UL;
		auto dwPassedSectionCount = 0UL;
		auto ntStatus = 0UL;

		ptr_t lastBase = 0;
		for (uint64_t memptr = MEMORY_START_ADDRESS; memptr < MEMORY_END_ADDRESS_X64; memptr = (uint64_t)basicInfo.BaseAddress + basicInfo.RegionSize)
		{
			ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryVirtualMemory(
				hProcess, (PVOID64)memptr, MemoryBasicInformation, &basicInfo, sizeof(basicInfo)
			);
			if (ntStatus == STATUS_INVALID_PARAMETER || ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_PROCESS_IS_TERMINATING)
				break;
			else if (ntStatus != STATUS_SUCCESS)
			{
				dwPassedSectionCount++;
				continue;
			}

			dwSectionCount++;

			auto spCurrSectionCtx = std::shared_ptr<SSectionEnumContext>();

#if 0
			// Filter non-section regions
			if ((basicInfo.State != MEM_COMMIT/* && basicInfo.State != MEM_RESERVE */) /* || basicInfo.Type != SEC_IMAGE */ || lastBase == (ptr_t)basicInfo.AllocationBase)
			{
				dwPassedSectionCount++;
				continue;
			}
#endif

			if (basicInfo.Protect == PAGE_NOACCESS)
			{
				dwPassedSectionCount++;
				continue;
			}

			if (IS_VALID_SMART_PTR(spAnticheatModule) && spAnticheatModule->DllBase && spAnticheatModule->SizeOfImage)
			{
				if (dwProcessId == g_winAPIs->GetCurrentProcessId() &&
					(DWORD_PTR)basicInfo.BaseAddress >= (DWORD_PTR)spAnticheatModule->DllBase && ((DWORD_PTR)spAnticheatModule->DllBase + spAnticheatModule->SizeOfImage) <= (DWORD_PTR)basicInfo.BaseAddress)
				{
					dwPassedSectionCount++;
					continue;
				}
			}

			// Ignore protected process memory watchdogs
			if (CApplication::Instance().ScannerInstance()->IsProtectedMemoryRegions(hProcess, (LPVOID)basicInfo.BaseAddress))
			{
				dwPassedSectionCount++;
				continue;
			}

			if (bRwxOnly)
			{
				if (!(basicInfo.Protect & PAGE_EXECUTE && basicInfo.Protect & PAGE_EXECUTE_READ ||
					basicInfo.Protect & PAGE_EXECUTE_READWRITE && basicInfo.Protect & PAGE_EXECUTE_WRITECOPY))
				{
					dwPassedSectionCount++;
					continue;
				}
			}

			try
			{
				spCurrSectionCtx = stdext::make_shared_nothrow<SSectionEnumContext>();
				if (IS_VALID_SMART_PTR(spCurrSectionCtx))
				{
					spCurrSectionCtx->AllocationBase = (ptr_t)basicInfo.AllocationBase;
					spCurrSectionCtx->BaseAddress = (ptr_t)basicInfo.BaseAddress;
					spCurrSectionCtx->Protect = basicInfo.Protect;
					spCurrSectionCtx->RegionSize = basicInfo.RegionSize;
					spCurrSectionCtx->State = basicInfo.State;
					spCurrSectionCtx->BaseProtect = basicInfo.AllocationProtect;
					spCurrSectionCtx->Type = basicInfo.Type;

					vOutput.emplace_back(spCurrSectionCtx);
				}
			}
			catch (const std::bad_alloc& e)
			{
				SCANNER_LOG(LL_ERR, L"Failed to allocate memory for section context!, error: %hs", e.what());
				break;
			}
			
			lastBase = (ptr_t)basicInfo.AllocationBase;
		}

		APP_TRACE_LOG(LL_TRACE, L"Section count: %u passed count: %u Scannable count: %u", dwSectionCount, dwPassedSectionCount, vOutput.size());
		return vOutput;
	}


	ISectionScanner::ISectionScanner()
	{
	}
	ISectionScanner::~ISectionScanner()
	{
	}

	bool ISectionScanner::IsScanned(std::shared_ptr <SSectionScanContext> pkSectionCtx)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(
			SCAN_CACHE_SECTION, 
			fmt::format(
				xorstr_(L"p:{0}|a:{1}"),
				pkSectionCtx->dwProcessId, fmt::ptr(pkSectionCtx->dwBase)
			)
		);
	}
	void ISectionScanner::AddScanned(std::shared_ptr <SSectionScanContext> pkSectionCtx)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(
			SCAN_CACHE_SECTION,
			fmt::format(
				xorstr_(L"p:{0}|a:{1}"),
				pkSectionCtx->dwProcessId, fmt::ptr(pkSectionCtx->dwBase)
			)
		);
	}

	void ISectionScanner::OnScan(HANDLE hProcess, ptr_t dwBaseAddress, ptr_t dwAllocationBase, ULONG64 dwRegionSize, DWORD dwState, DWORD dwProtect, DWORD dwBaseProtect, DWORD dwType)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		auto bRet = false;
		auto dwProcessId = g_winAPIs->GetProcessId(hProcess);
		auto wstSectionOwner = L""s;
		wchar_t wszModuleName[MAX_PATH]{ L'\0' };

		SCANNER_LOG(LL_TRACE,
			L"Section scanner has been started! Target section: %llx(%llx) - %llu Own process: %p(%u)",
			dwBaseAddress, dwAllocationBase, dwRegionSize, hProcess, dwProcessId
		);

		const auto ctx = stdext::make_shared_nothrow<SSectionScanContext>();
		if (!IS_VALID_SMART_PTR(ctx))
		{
			SCANNER_LOG(LL_ERR, L"Memory allocation for SSectionScanContext failed with error: %d", errno);
			return;
		}
		ctx->dwBase = dwBaseAddress;
		ctx->dwProcessId = dwProcessId;
		ctx->dwSize = dwRegionSize;
		ctx->hProcess = nullptr;

		if (IsScanned(ctx))
		{
			// SCANNER_LOG(LL_SYS, L"Section already scanned!");
			goto _Complete;
		}

		// Add to checked list
		AddScanned(ctx);

		// Should be committed
		if (dwState != MEM_COMMIT)
			goto _Complete;

		// Code sections
		const auto bIsExecutableMemory =
			dwProtect == PAGE_EXECUTE || dwProtect == PAGE_EXECUTE_READ || dwProtect == PAGE_EXECUTE_READWRITE || dwProtect == PAGE_EXECUTE_WRITECOPY;

		// Data sections
		const auto bIsStorageMemory = 
			dwProtect == PAGE_READONLY || dwProtect == PAGE_READWRITE;

		// Skip pages that aren't executable and aren't read/write
		if (!bIsExecutableMemory && !bIsStorageMemory)
			goto _Complete;

		// Check page accesible
		if (dwProtect & PAGE_GUARD || dwProtect == PAGE_NOACCESS)
			goto _Complete;

		// Query owner name
		wstSectionOwner = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(hProcess, (HMODULE)dwAllocationBase);

		if (stdext::is_wow64())
		{
			if (!wstSectionOwner.empty() && g_winAPIs->GetModuleFileNameExW(hProcess, (HMODULE)dwAllocationBase, wszModuleName, MAX_PATH))
			{
				auto wstModuleOwner = stdext::to_lower_wide(wszModuleName);
				if (wstModuleOwner != wstSectionOwner)
				{
					wstSectionOwner = stdext::replace<std::wstring>(wstSectionOwner, xorstr_(L"\\syswow64\\"), xorstr_(L"\\system32\\"));
					wstModuleOwner = stdext::replace<std::wstring>(wstModuleOwner, xorstr_(L"\\syswow64\\"), xorstr_(L"\\system32\\"));

					if (wstModuleOwner.find(wstSectionOwner) == std::wstring::npos)
					{
						SCANNER_LOG(LL_ERR, L"Memory mismatch, Memory owner name: %s Module owner name: %s", wstSectionOwner.c_str(), wstModuleOwner.c_str());
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SECTION_SCAN, 2, wstSectionOwner); // todo idleri enuma al
					}
				}
			}
		}

		// Scan routine

		// Check manually mapped module
		HMODULE hOwner = nullptr;
		g_winAPIs->GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)dwAllocationBase, &hOwner);
		if (!hOwner)
		{
			SCANNER_LOG(LL_ERR, L"Manually mapped module: %p at process: %u", dwAllocationBase, dwProcessId);
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SECTION_SCAN, 3, wstSectionOwner);
		}

		// Check for code cave
		const auto pCurrentSecHdr = reinterpret_cast<IMAGE_SECTION_HEADER*>((ULONGLONG)dwAllocationBase);
		if (pCurrentSecHdr)
		{
			const auto IsMonitored =
				(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
				(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

			//if (IsMonitored || (!pCurrentSecHdr->Misc.PhysicalAddress && !pCurrentSecHdr->Misc.VirtualSize) /* not touched, allocated section */)
			if (IsMonitored)
			{
				SCANNER_LOG(LL_ERR, L"Code cave section: %p at process: %u", dwAllocationBase, dwProcessId);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SECTION_SCAN, 4, wstSectionOwner);
			}
		}

		// Check for allocated executable pages outside of mapped modules
		if ((dwType == MEM_PRIVATE || dwType == MEM_MAPPED) && bIsExecutableMemory)
		{
			if (((ULONGLONG)dwBaseAddress & 0xFF0000000000) != 0x7F0000000000 &&
				((ULONGLONG)dwBaseAddress & 0xFFF000000000) != 0x7F000000000 &&
				((ULONGLONG)dwBaseAddress & 0xFFFFF0000000) != 0x70000000 &&
				(ULONGLONG)dwBaseAddress != 0x3E0000
				&& dwBaseAddress != dwAllocationBase)
			{
				SCANNER_LOG(LL_ERR, L"Executable memory outside of a mapped module at %p process: %u", dwBaseAddress, dwProcessId);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SECTION_SCAN, 5, wstSectionOwner);
			}
		}

		CApplication::Instance().ScannerInstance()->FileScanner()->Scan(wstSectionOwner, FILE_SCAN_TYPE_SECTION);

		LPVOID lpMemCopy = nullptr;
		bRet = CopySectionMemory(hProcess, dwBaseAddress, dwRegionSize, lpMemCopy);
		SCANNER_LOG(bRet ? LL_SYS : LL_ERR, L"Section memory copy completed! Result: %d", bRet);
		if (!bRet)
			goto _Complete;

		bRet = ScanSectionBase(hProcess, lpMemCopy, dwRegionSize);
		//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section base scan routine completed! Result: %d", bRet);

		bRet = ScanSectionPeHeader(hProcess, lpMemCopy, dwBaseAddress, dwRegionSize);
		//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section pe header scan routine completed! Result: %d", bRet);

		bRet = ScanSectionHash(hProcess, lpMemCopy, dwRegionSize);
		//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section hash scan routine completed! Result: %d", bRet);

		bRet = ScanSharedPage(hProcess, dwBaseAddress, dwRegionSize);
		//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section shared page scan routine completed! Result: %d", bRet);

		if (dwAllocationBase == dwBaseAddress)
		{
			bRet = ScanPattern(hProcess, lpMemCopy, dwRegionSize);
			//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section pattern scan routine completed! Result: %d", bRet);
		}

		bRet = ScanProtectViolation(hProcess, dwBaseProtect, dwProtect);
		//SCANNER_LOG(bRet ? LL_SYS : LL_ERR, "Section protect violation scan routine completed! Result: %d", bRet);

		// Scan module links
		if (dwType == MEM_IMAGE)
		{
			if (dwAllocationBase != dwBaseAddress)
			{
				SCANNER_LOG(LL_ERR, L"Section: %s base: %p different than allocation base: %p", wstSectionOwner.c_str(), dwBaseAddress, dwAllocationBase);
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SECTION_SCAN, 6, wstSectionOwner);
			}

			bRet = ScanModuleLinks(hProcess, dwBaseAddress);
			SCANNER_LOG(bRet ? LL_SYS : LL_ERR, L"Section file scan routine completed! Result: %d", bRet);
		}

		bRet = true;
_Complete:
		if (lpMemCopy)
			CMemHelper::Free(lpMemCopy);

		SCANNER_LOG(bRet ? LL_SYS : LL_ERR, L"Section scan routine completed! Result: %d", bRet);
		return;
	}

	void ISectionScanner::ScanSync(std::shared_ptr <SSectionScanContext> pkSectionCtx)
	{
		return;
	}
	bool ISectionScanner::ScanAll()
	{
		return true;
	}

	bool ISectionScanner::ScanProcessSections(HANDLE hProcess)
	{
		SCANNER_LOG(LL_SYS, L"Section scanner has been started! Target process: %u(%p)", g_winAPIs->GetProcessId(hProcess), hProcess);

		if (!hProcess)
		{
			SCANNER_LOG(LL_ERR, L"Target handle is NOT valid!");
			return true;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Target process is NOT active!");
			return true;
		}

		const auto stProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (stProcessName.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}
		SCANNER_LOG(LL_SYS, L"Process image name: %s", stProcessName.c_str());

		auto timer = CStopWatch<std::chrono::microseconds>();

		const auto bRet = CApplication::Instance().ScannerInstance()->EnumerateSections(hProcess, true, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
			OnScan(
				hProcess, pCurrSection->BaseAddress, pCurrSection->AllocationBase, pCurrSection->RegionSize,
				pCurrSection->State, pCurrSection->Protect, pCurrSection->BaseProtect, pCurrSection->Type
			);
		});

		APP_TRACE_LOG(LL_TRACE, L"Section scan completed on: %lu ms", timer.diff());
		return bRet;
	}

	bool IScanner::EnumerateSections(HANDLE hProcess, bool bRwxOnly, std::function<void(std::shared_ptr <SSectionEnumContext>)> cb)
	{		
		if (!this || !cb)
			return false;

		SCANNER_LOG(LL_TRACE, L"Section enumerator has been started!");

		auto vSectionList = GetSectionList(hProcess, bRwxOnly);
		if (vSectionList.empty())
		{
			// SCANNER_LOG(LL_WARN, L"Section list is NULL!");
			return false;
		}

		for (const auto& spCurrSection : vSectionList)
		{
			if (IS_VALID_SMART_PTR(spCurrSection))
			{
				cb(spCurrSection);
			}
		}

		vSectionList.clear();
		return true;
	}
};
