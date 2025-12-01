#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"

namespace NoMercy
{
#pragma optimize("", off)
	bool CheckHiddenVAD(const ptr_t* ptr)
	{
		auto ret = true;

		__try
		{
			ptr_t x = *ptr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ret = false;
		}

		return ret;
	}
#pragma optimize("", on) 

	inline bool IsAddedRegion(LPVOID lpBase)
	{
		const auto vecScanCache = CApplication::Instance().ScannerInstance()->GetManualMapScanCache();
		for (const auto& pCurrRegion : vecScanCache)
		{
			if (pCurrRegion.AllocationBase == lpBase)
				return true;
		}
		return false;
	}

	inline bool ValidateHeaders(LPVOID lpData)
	{
		if (!lpData)
			return false;

		if (IsBadReadPtr(lpData, 2))
			return true; // ignore

		uint8_t byMemCopy[2]{ 0x0 };
		memcpy(&byMemCopy, lpData, 2);
		if (byMemCopy[0] != 'M' || byMemCopy[1] != 'Z')
			return false;

		auto pIDH = (PIMAGE_DOS_HEADER)lpData;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pIDH + pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		if (pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return false;

		return true;
	}

	inline uint8_t CorruptedImage(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi)
	{
		auto pMemCopy = CMemHelper::Allocate(mbi.RegionSize);
		if (!pMemCopy)
			return 0; // allocation failed, ignore

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsLoadedModuleBase((DWORD_PTR)mbi.AllocationBase))
		{
			APP_TRACE_LOG(LL_ERR, L"%p is not loaded module base", mbi.AllocationBase);
			CMemHelper::Free(pMemCopy);
			return 1;
		}

		SIZE_T pBytesRead = 0;
		if (!g_winAPIs->ReadProcessMemory(hProcess, (LPCVOID)mbi.AllocationBase, pMemCopy, mbi.RegionSize, &pBytesRead) || pBytesRead != mbi.RegionSize)
		{
			APP_TRACE_LOG(LL_WARN, L"ReadProcessMemory failed with error: %u Target: %p", g_winAPIs->GetLastError(), mbi.AllocationBase);
			CMemHelper::Free(pMemCopy);
			return 0; // ignore
		}

		if (!ValidateHeaders(pMemCopy))
		{
			APP_TRACE_LOG(LL_ERR, L"Module %p headers could not validated", mbi.AllocationBase);
			CMemHelper::Free(pMemCopy);
			return 3;
		}

		const auto validAllocationFlags = mbi.AllocationProtect == PAGE_EXECUTE_WRITECOPY || mbi.AllocationProtect == PAGE_READONLY;
		if (mbi.Type != MEM_IMAGE || !validAllocationFlags)
		{
			APP_TRACE_LOG(LL_ERR, L"Module %p not valid image! Allocated protection: %p Type: %u", mbi.AllocationBase, mbi.AllocationProtect, mbi.Type);
			CMemHelper::Free(pMemCopy);
			return 4;
		}

		CMemHelper::Free(pMemCopy);
		return 0;
	}

	inline DWORD_PTR GetInstructionPointer(HANDLE hThread)
	{
		auto pThread = stdext::make_unique_nothrow<CThread>(hThread);
		if (!pThread || !pThread.get() || !pThread->IsValid())
			return 0;

		auto pContext = pThread->GetContext();
		if (!pContext || !pContext.get())
			return 0;

#ifdef _WIN64
		return pContext->Rip;
#else
		return pContext->Eip;
#endif
	}

	void IScanner::CheckManualMappedModules(bool bFatal)
	{
		// Clear previous scan cache
		m_vThreadRegionScanList.clear();

		// Query anti-cheat module informations
		const auto spAnticheatData = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		if (!IS_VALID_SMART_PTR(spAnticheatData))
		{
			APP_TRACE_LOG(LL_ERR, L"spAnticheatData get failed! Last error: %u", g_winAPIs->GetLastError());
			return;
		}

		// Iterate threads, handle start addresses and instruction pointers
		auto threadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT);
		if (!IS_VALID_SMART_PTR(threadEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"threadEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return;
		}

		const auto vThreads = threadEnumerator->EnumerateThreads(NtCurrentProcess());
		if (vThreads.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Thread list is null!");
			return;
		}

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		for (const auto& hThread : vThreads)
		{
			auto upThread = stdext::make_unique_nothrow<CThread>(hThread);
			if (!IS_VALID_SMART_PTR(upThread) || !upThread->IsValid())
				continue;

			const auto c_lpStartAddress = (LPCVOID)upThread->GetStartAddress();
			if (c_lpStartAddress)
			{
				if (g_winAPIs->VirtualQuery(c_lpStartAddress, &mbi, sizeof(mbi)))
				{
					if (mbi.AllocationBase > 0 && !IsAddedRegion(mbi.AllocationBase))
						m_vThreadRegionScanList.emplace_back(mbi);
				}
			}

			const auto c_lpInstructionPtr = (LPCVOID)GetInstructionPointer(hThread);
			if (c_lpInstructionPtr)
			{
				if (g_winAPIs->VirtualQuery(c_lpInstructionPtr, &mbi, sizeof(mbi)))
				{
					if (mbi.AllocationBase > 0 && !IsAddedRegion(mbi.AllocationBase))
						m_vThreadRegionScanList.emplace_back(mbi);
				}
			}
		}

		APP_TRACE_LOG(LL_TRACE, L"Finished iterating threads - Scanning %u address(es)", m_vThreadRegionScanList.size());

		// Get system directory
		wchar_t wszSystemPath[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->GetSystemDirectoryW(wszSystemPath, sizeof(wszSystemPath)))
		{
			APP_TRACE_LOG(LL_ERR, L"GetSystemDirectoryW failed with error: %u", g_winAPIs->GetLastError());
			return;
		}
		const auto wstLowerSystemPath = stdext::to_lower_wide(wszSystemPath);

		// Get host executable
		const auto stExecutable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
		const auto wstExecutable = stdext::to_lower_wide(stExecutable);

		// Declare whitelisted modules
		const auto lstWhitelistedModules = {
			fmt::format(xorstr_(L"{0}\\wow64cpu.dll"), wstLowerSystemPath),
			fmt::format(xorstr_(L"{0}\\wow64.dll"), wstLowerSystemPath),
			fmt::format(xorstr_(L"{0}\\wow64win.dll"), wstLowerSystemPath)
		};

		// Iterate thread addresses and compare by memory's allocation owner name
		for (const auto& pCurrRegion : m_vThreadRegionScanList)
		{
			// Ignore anti-cheat module from scan
			if (spAnticheatData->DllBase == pCurrRegion.AllocationBase)
				continue;

			// Query for memory's owner name
			HMODULE hModule_peb = nullptr, hModule = nullptr;
			auto stPath = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(NtCurrentProcess(), (HMODULE)pCurrRegion.AllocationBase);
			if (stPath.length() > 2)
			{
				hModule_peb = (HMODULE)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleAddressFromName(stPath.c_str());
				hModule = g_winAPIs->GetModuleHandleW_o(stPath.c_str());
			}
			const auto wstLowerPath = stdext::to_lower_wide(stPath);

			// Validate memory region part 1
			if (!hModule_peb && !hModule && // undetermined module
				pCurrRegion.AllocationBase != g_winModules->hNtdll && // memory is not allocated by ntdll
				g_winAPIs->VirtualQuery(pCurrRegion.AllocationBase, &mbi, sizeof(mbi)) && // is it still valid region(can be freed at the scan time, to get through this)
				// wstLowerPath != wstExecutable && // is it created my main executable
				std::find(lstWhitelistedModules.begin(), lstWhitelistedModules.end(), wstLowerPath) == lstWhitelistedModules.end()) // is it created by wow64 component module
			{
				APP_TRACE_LOG(LL_ERR, L"Manual mapped module detected: '%ls' (%p/%p) by check 1", wstLowerPath.c_str(), pCurrRegion.AllocationBase, pCurrRegion.BaseAddress);

				if (bFatal)
					CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_UNVALIDATED_MODULE);
				else
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_UNVALIDATED_MODULE, stPath);
				continue;
			}

			// Validate memory region part 2
			const auto ret = CorruptedImage(NtCurrentProcess(), pCurrRegion);
			if (ret)
			{
				stPath = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(NtCurrentProcess(), (HMODULE)pCurrRegion.AllocationBase);
				if (!stPath.empty() && wstLowerPath != wstExecutable)
				{
					APP_TRACE_LOG(LL_ERR, L"Manual mapped module detected: %s by check 2 ret: %u", stPath.c_str(), ret);
					const auto stSubId = fmt::format(xorstr_(L"{0}000{1}"), MANUAL_MAP_SCAN_CORRUPTED_IMAGE, ret);
					const auto nSubId = _wtoi(stSubId.c_str());

					if (bFatal)
						CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, nSubId);
					else
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, nSubId, stPath);
				}
			}
		}

		// Iterate host process modules
		std::vector <std::shared_ptr <SModuleEnumContext>> vModules;
		auto ret = EnumerateModules(NtCurrentProcess(), [&](std::shared_ptr <SModuleEnumContext> ctx) {
			vModules.emplace_back(ctx);
			return true;
		});
		if (!ret || vModules.size() < 2)
		{
			APP_TRACE_LOG(LL_ERR, L"Module list is null!");
			
			if (bFatal)
				CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_MODULE_LIST_NULL);
			else
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_MODULE_LIST_NULL);
			return;
		}

		// Iterate host process memory sections
		APP_TRACE_LOG(LL_TRACE, L"Iterating virtual pages");

		DWORD dwSectionCount = 0;
		ret = EnumerateSections(NtCurrentProcess(), false, [&](std::shared_ptr <SSectionEnumContext> spCurrentSectionInfos) {
			dwSectionCount++;

			auto stPathBaseOwner = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(
				NtCurrentProcess(), (HMODULE)spCurrentSectionInfos->BaseAddress
			);
			if (stPathBaseOwner.empty() && (!stdext::is_x64_build() || stdext::is_wow64()))
			{
				stPathBaseOwner = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(
					NtCurrentProcess(), (HMODULE)Ptr64ToPtr(spCurrentSectionInfos->BaseAddress)
				);
			}

			if (!spCurrentSectionInfos->AllocationBase || !spCurrentSectionInfos->BaseAddress)
			{
				APP_TRACE_LOG(LL_ERR, L"[1] Suspected memory region found, Base: 0x%llx (%s)", spCurrentSectionInfos->BaseAddress, stPathBaseOwner.c_str());

				if (bFatal)
					CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_UNKNOWN_REGION_BASE);
				else
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_UNKNOWN_REGION_BASE, stPathBaseOwner.c_str());
			}

			if (spAnticheatData->DllBase == (PVOID)spCurrentSectionInfos->AllocationBase)
				return;

			// Linked module
			if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsLoadedModuleBase((DWORD_PTR)Ptr64ToPtr(spCurrentSectionInfos->AllocationBase)))
				return;

			const auto stPathRealOwner = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetMappedNameNative(
				NtCurrentProcess(), (HMODULE)spCurrentSectionInfos->AllocationBase
			);
			/*
			if (stPathRealOwner.empty() &&
				(spCurrentSectionInfos->Protect == PAGE_EXECUTE_READWRITE || spCurrentSectionInfos->Protect == PAGE_EXECUTE_WRITECOPY))
			{
				APP_TRACE_LOG(LL_ERR, L"[2] Suspected memory region found, Base: 0x%llx (%s) Protect: %u",
					spCurrentSectionInfos->BaseAddress, stPathBaseOwner.c_str(), spCurrentSectionInfos->Protect
				);

				if (bFatal)
					CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_UNKNOWN_OWNER_NAME, wstPath);
				else
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_UNKNOWN_OWNER_NAME, wstPath);
			}
			*/

			APP_TRACE_LOG(LL_TRACE, L"[%u] Current region: 0x%llx-0x%llx Size: %llu State: %p Protect: %p Owner: %s / %s",
				dwSectionCount, spCurrentSectionInfos->AllocationBase, spCurrentSectionInfos->BaseAddress,
				spCurrentSectionInfos->RegionSize, spCurrentSectionInfos->State, spCurrentSectionInfos->Protect,
				stPathRealOwner.c_str(), stPathBaseOwner.c_str()
			);

#if 0
			// CoW (copy-on-write) check
			if (spCurrentSectionInfos->Type == MEM_MAPPED || spCurrentSectionInfos->Type == MEM_IMAGE)
			{
				if (g_winAPIs->VirtualLock(Ptr64ToPtr(spCurrentSectionInfos->BaseAddress), spCurrentSectionInfos->RegionSize))
				{
					PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { 0 };
					pworkingSetExInformation.VirtualAddress = Ptr64ToPtr(spCurrentSectionInfos->BaseAddress);

					if (g_winAPIs->QueryWorkingSetEx(NtCurrentProcess(), &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
					{
						if (!pworkingSetExInformation.VirtualAttributes.Shared)
						{
							APP_TRACE_LOG(LL_ERR, L"CoW memory: 0x%llx Protect: %p(Base: %p) Type: %p State: %p Owner: %s",
								spCurrentSectionInfos->BaseAddress, spCurrentSectionInfos->Protect, spCurrentSectionInfos->BaseProtect,
								spCurrentSectionInfos->Type, spCurrentSectionInfos->State,
								stPathRealOwner.c_str()
							);

							/*
							if (bFatal)
								CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_COW_DETECT);
							else
								CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_COW_DETECT, stPathRealOwner);
							return;
							*/
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"QueryWorkingSetEx failed with error: %u", g_winAPIs->GetLastError());
					}

					g_winAPIs->VirtualUnlock(Ptr64ToPtr(spCurrentSectionInfos->BaseAddress), spCurrentSectionInfos->RegionSize);
				}
			}
#endif

			if (spCurrentSectionInfos->State == MEM_FREE)
			{
				if (CheckHiddenVAD((ptr_t*)&spCurrentSectionInfos->BaseAddress))
				{
					APP_TRACE_LOG(LL_ERR, L"VAD hidden memory block detected! Owner: %s", stPathRealOwner.c_str());

					if (bFatal)
						CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_HIDDEN_VAD);
					else
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_HIDDEN_VAD, stPathRealOwner);
				}
				return;
			}

			if (spCurrentSectionInfos->RegionSize < 0x1000)
				return;

			if (spCurrentSectionInfos->State != MEM_COMMIT && spCurrentSectionInfos->State != (MEM_RESERVE | MEM_COMMIT))
				return;

			if (spCurrentSectionInfos->Type != MEM_PRIVATE && spCurrentSectionInfos->Type != MEM_IMAGE)
				return;

			/*
			if (spCurrentSectionInfos->Type == MEM_PRIVATE && spCurrentSectionInfos->RegionSize > 20480) // 20 KB
			{
				APP_TRACE_LOG(LL_ERR, L"Higher size memory block detected! Size: %llu Owner: %s", spCurrentSectionInfos->RegionSize, stPathRealOwner.c_str());

				if (bFatal)
					CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_HIGH_SIZE_BLOCK);
				else
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_HIGH_SIZE_BLOCK, stPathRealOwner);

				return;
			}
			*/

			if (spCurrentSectionInfos->Type != MEM_IMAGE && spCurrentSectionInfos->BaseProtect == PAGE_EXECUTE_READWRITE && spCurrentSectionInfos->RegionSize == 0x1000)
			{
				if (spCurrentSectionInfos->Protect & PAGE_GUARD)
				{
					return;
				}

				// Unaccessible
				else if (IsBadReadPtr((void*)spCurrentSectionInfos->BaseAddress, 0x1000))
				{
					APP_TRACE_LOG(LL_ERR, L"Unaccessible memory: 0x%llx Protect: %p(Base: %p) Owner: %s",
						spCurrentSectionInfos->BaseAddress, spCurrentSectionInfos->Protect, spCurrentSectionInfos->BaseProtect, stPathRealOwner.c_str()
					);

					if (bFatal)
						CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_UNACCESSIBLE_PE_HEADER);
					else
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_UNACCESSIBLE_PE_HEADER, stPathRealOwner);

					return;
				}
				else
				{
					// Read PE header
					uint8_t pBuffer[2]{ 0x0 };
					memcpy(&pBuffer, spCurrentSectionInfos->BaseAddress, sizeof(pBuffer));

					// Cleared header
					if (pBuffer[0] == 0x0 && pBuffer[1] == 0x0)
					{
						/*
						APP_TRACE_LOG(LL_ERR, L"Clearared possible PE header base: 0x%llx Protect: %p(Base: %p) Owner: %s",
							spCurrentSectionInfos->BaseAddress, spCurrentSectionInfos->Protect, spCurrentSectionInfos->BaseProtect, stPathRealOwner.c_str()
						);

						if (bFatal)
							CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_CLEARED_PE_HEADER);
						else
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_CLEARED_PE_HEADER, stPathRealOwner);

						*/
						return;
					}
					// exist header
					else if (pBuffer[0] == 'M' && pBuffer[1] == 'Z')
					{
						// TODO: Scan PE header
						//	Validate with file compare
						//	Compare header fields with blacklist
						//	Validate field is correct(e.g timestamp is not abnormal or size is valid value etc)
						__nop();
					}
				}
			}

			auto bInside = false;
			for (const auto& pCurrModule : vModules)
			{
				const auto dwCurrentBase = (DWORD_PTR)spCurrentSectionInfos->BaseAddress;

				if ((ptr_t)pCurrModule->pvBaseAddress == spCurrentSectionInfos->AllocationBase)
				{
					bInside = true;
					break;
				}

				if (dwCurrentBase >= (DWORD_PTR)pCurrModule->pvBaseAddress && dwCurrentBase <= ((DWORD_PTR)pCurrModule->pvBaseAddress + pCurrModule->cbModuleSize))
				{
					bInside = true;
					break;
				}
			}

			// DLL not found in PEB
			if (!bInside)
			{
				/*
				APP_TRACE_LOG(LL_WARN, L"Mapped memory detected! Base: 0x%llx(0x%llx) - Size: %llu Type: %p - Owner: %s / %s",
					spCurrentSectionInfos->BaseAddress, spCurrentSectionInfos->AllocationBase, spCurrentSectionInfos->RegionSize,
					spCurrentSectionInfos->Type, stPathRealOwner.c_str(), stPathBaseOwner.c_str()
				);
				*/

				if (spCurrentSectionInfos->AllocationBase != spCurrentSectionInfos->BaseAddress || spCurrentSectionInfos->Type == MEM_IMAGE)
				{
					/*
					APP_TRACE_LOG(LL_WARN, 
						"Current base: 0x%llx(%s) different than Allocated base: 0x%llx(%s) or Type: %p is not image",
						spCurrentSectionInfos->BaseAddress, stPathBaseOwner.c_str(), spCurrentSectionInfos->AllocationBase, stPathRealOwner.c_str(), spCurrentSectionInfos->Type
					);
					*/
					
					/*
					if (stPathRealOwner.empty())
					{
						
						if (bFatal)
							CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_UNLINKED_MODULE);
						else
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_UNLINKED_MODULE);
					}
					else
					{
						if (CApplication::Instance().AnalyserInstance())
						{
							const auto wstPath = stdext::to_wide(stPathRealOwner);

							auto bSuspicious = false;
							auto bAnalyse = CApplication::Instance().AnalyserInstance()->OnModuleLoaded(wstPath, NtCurrentThread(), CHECK_TYPE_MANUAL_MAP_SCAN, bSuspicious);
							APP_TRACE_LOG(LL_TRACE, L"Analyse completed. Ret: %d Susp: %d", bAnalyse ? 1 : 0, bSuspicious ? 1 : 0);

							if (bSuspicious)
							{
								if (bFatal)
									CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_SUSPICIOUS_MODULE, wstPath);
								else
									CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_SUSPICIOUS_MODULE, wstPath);
							}
						}
					}
					*/
				}
				else
				{
					if (spCurrentSectionInfos->Type == MEM_PRIVATE)
					{
						APP_TRACE_LOG(LL_TRACE, L"Pattern scan started in mapped memory");

						if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsBadReadPtr(
								(void*)spCurrentSectionInfos->AllocationBase, spCurrentSectionInfos->RegionSize)
							)
						{
							const auto pattern_scanner = stdext::make_unique_nothrow<CPatternScanner>();
							if (!IS_VALID_SMART_PTR(pattern_scanner))
							{
								APP_TRACE_LOG(LL_ERR, L"Memory allocation for pattern scanner failed with error: %u", g_winAPIs->GetLastError());
								return;
							}

							const auto lstPatterns = {
								Pattern(xorstr_(L"73 6E 78 68 6B 36 34 2E 64 6C 6C"), PatternType::Address),
								Pattern(xorstr_(L"55 8B EC 83 7D 0C 01 75 ?"), PatternType::Address),
								Pattern(xorstr_(L"4D 65 73 73 61 67 65 42 6F 78 41 00 4D 65 73 73 61 67 65 42 6F 78 57"), PatternType::Address)
							};

							uint8_t idx = 0;
							for (const auto& pattern : lstPatterns)
							{
								idx++;
								if (pattern_scanner->findPatternSafe((LPVOID)spCurrentSectionInfos->AllocationBase, spCurrentSectionInfos->RegionSize, pattern))
								{
									APP_TRACE_LOG(LL_ERR,
										L"Pattern: %u matched in memory: %p (%u) (%s)",
										idx, spCurrentSectionInfos->AllocationBase, spCurrentSectionInfos->RegionSize, stPathRealOwner.c_str()
									);

									const auto stSubId = fmt::format(xorstr_(L"{0}000{1}"), MANUAL_MAP_SCAN_BLACKLISTED_PATTERN, idx);
									const auto nSubId = _wtoi(stSubId.c_str());

									if (bFatal)
										CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, nSubId);
									else
										CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, nSubId, stPathRealOwner);
								}
							}
						}
					}
				}
			}
		});

		if (!ret || dwSectionCount < 2)
		{
			APP_TRACE_LOG(LL_ERR, L"Section list is null!");

			if (bFatal)
				CApplication::Instance().OnCloseRequest(EXIT_ERR_MANUAL_MAP_DETECT, MANUAL_MAP_SCAN_SECTION_LIST_NULL);
			else
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MANUAL_MAPPED_MODULE, MANUAL_MAP_SCAN_SECTION_LIST_NULL);
			return;
		}
	}
};
