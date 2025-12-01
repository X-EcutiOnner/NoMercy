#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ScannerInterface.hpp"
#include "../Common/Quarentine.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../Helper/SessionHelper.hpp"
#include "../../EngineR3_Core/include/WindowEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../EngineR3_Core/include/FileVersion.hpp"

namespace NoMercy
{
	bool IScanner::CDB_IsProcessExistByName(const SCDBBaseContext& kContext, const std::wstring& stTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Process(name) scan started! Index: %u Target: %s", kContext.dwListIndex, stTargetName.c_str());
	
		auto bFound = false;

		// Instant search for the process name
		if (CProcessFunctions::FindProcess(stTargetName.c_str()))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted process found: %s", stTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, stTargetName);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SProcessCheckObjects procObj{};
			procObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			procObj.process_name = stTargetName;

			CApplication::Instance().QuarentineInstance()->ProcessQuarentine()->SetBlacklisted(procObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsProcessExistByChecksum(const SCDBBaseContext& kContext, const std::wstring& stSum)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Process(sum) scan started! Index: %u Sum: %s", kContext.dwListIndex, stSum.c_str());

		// Instant search for the process checksum
		auto bFound = false;
		const auto stLowerSum = stdext::to_lower_ansi(stSum);

		auto spProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(spProcEnumerator))
		{
			auto vProcs = spProcEnumerator->EnumerateProcesses();
			for (auto hProc : vProcs)
			{
				if (IS_VALID_HANDLE(hProc))
				{
					const auto szProcName = CProcessFunctions::GetProcessName(hProc);
					if (!szProcName.empty() && NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(szProcName))
					{
						auto stProcSum = CApplication::Instance().CacheManagerInstance()->GetCachedFileSHA1(szProcName);
						if (stProcSum.empty())
							stProcSum = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(szProcName);
						const auto stLowerProcSum = stdext::to_lower_ansi(stProcSum);

						// APP_TRACE_LOG(LL_SYS, L"Current process: %s Hash: %s Target: %s IsTarget: %d", szProcName.c_str(), stLowerProcSum.c_str(), stLowerSum.c_str(), stLowerProcSum == stLowerSum);
						if (!stLowerProcSum.empty() && stLowerProcSum == stLowerSum)
						{
							bFound = true;
							APP_TRACE_LOG(LL_WARN, L"Blacklisted process found: %s (%s)", szProcName.c_str(), stLowerSum.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, szProcName);
							spProcEnumerator.reset();
							break;
						}
					}
				}
				g_winAPIs->Sleep(20);
			}

			spProcEnumerator.reset();
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SProcessCheckObjects procObj{};
			procObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			procObj.process_file_hash = stdext::to_wide(stLowerSum);

			CApplication::Instance().QuarentineInstance()->ProcessQuarentine()->SetBlacklisted(procObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsProcessExistByFileDesc(const SCDBBaseContext& kContext, const std::wstring& stDesc, const std::wstring& wstVer)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Process(desc) scan started! Index: %u Sum: %s", kContext.dwListIndex, stDesc.c_str());

		// Instant search for the process checksum
		auto bFound = false;
		const auto stLowerDesc = stdext::to_lower_ansi(stDesc);
		const auto stLowerVer = stdext::to_lower_ansi(wstVer);

		auto spProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(spProcEnumerator))
		{
			auto vProcs = spProcEnumerator->EnumerateProcesses();
			for (auto hProc : vProcs)
			{
				if (IS_VALID_HANDLE(hProc))
				{
					const auto wstProcName = CProcessFunctions::GetProcessName(hProc);

					if (!wstProcName.empty() &&
						NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(wstProcName))
					{
						CFileVersion verInfo{};
						if (verInfo.QueryFile(wstProcName))
						{
							const auto stLowerCurrFileDesc = stdext::to_lower_ansi(verInfo.GetFileDescription());
							const auto stLowerCurrFileVer = stdext::to_lower_ansi(verInfo.GetFixedFileVersion());

							const auto bCond1 = !stLowerCurrFileDesc.empty() && stLowerCurrFileDesc == stLowerDesc;
							const auto bCond2 = !wstVer.empty() && !stLowerCurrFileVer.empty() && stLowerCurrFileVer == stLowerVer;
							if (bCond1 && (wstVer.empty() || bCond2))
							{
								bFound = true;
								APP_TRACE_LOG(LL_WARN, L"Blacklisted process found: %s (%s/%s)", wstProcName.c_str(), stLowerCurrFileDesc.c_str(), stLowerCurrFileVer.c_str());
								CApplication::Instance().ScannerInstance()->SendViolationNotification(
									kContext.dwListIndex, kContext.stID, kContext.bStreamed,
									stdext::to_wide(fmt::format(xorstr_("{} ({}/{})"), stdext::to_ansi(wstProcName), stLowerCurrFileDesc, stLowerCurrFileVer))
								);
								spProcEnumerator.reset();
								break;
							}
						}
					}
				}
				g_winAPIs->Sleep(20);
			}

			spProcEnumerator.reset();
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SProcessCheckObjects procObj{};
			procObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			procObj.process_file_desc = stdext::to_wide(stLowerDesc);

			CApplication::Instance().QuarentineInstance()->ProcessQuarentine()->SetBlacklisted(procObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsModuleExistByNameInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Module(name) scan started! Index: %u Target: %s", kContext.dwListIndex, stTargetName.c_str());

		// Instant search for the module name
		auto bFound = false;
		const auto wstTargetModuleName = std::wstring(stTargetName.begin(), stTargetName.end());

		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			auto vProcs = upProcEnumerator->EnumerateProcesses();
			for (auto hProc : vProcs)
			{
				if (IS_VALID_HANDLE(hProc))
				{
					if (!bFound && !kContext.bIsListed)
					{
						CApplication::Instance().ScannerInstance()->EnumerateModules(hProc, [&](std::shared_ptr <SModuleEnumContext> module) {
							if (IS_VALID_SMART_PTR(module))
							{
								if (module->pvBaseAddress && module->cbModuleSize)
								{
									const auto wstCurrentModuleName = stdext::to_lower_wide(module->wszModuleName);

									if (wstCurrentModuleName.find(wstTargetModuleName) != std::wstring::npos)
									{
										bFound = true;
										APP_TRACE_LOG(LL_WARN, L"Blacklisted module found by name: %s", stTargetName.c_str());
										CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, wstCurrentModuleName);
										return false;
									}
								}
							}
							return true;
						});
					}
				}
			}
			upProcEnumerator.reset();
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SModuleCheckObjects moduleObj{};
			moduleObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			moduleObj.name = stTargetName;

			CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted(moduleObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsModuleExistByNameInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Module(name) scan started! Index: %u Target: %s", kContext.dwListIndex, stTargetName.c_str());

		// Instant search for the module name
		auto bFound = false;
		const auto wstTargetModuleName = std::wstring(stTargetName.begin(), stTargetName.end());

		{
			if (!bFound && !kContext.bIsListed)
			{
				{
					CApplication::Instance().ScannerInstance()->EnumerateModules(NtCurrentProcess(), [&](std::shared_ptr <SModuleEnumContext> module) {
						if (IS_VALID_SMART_PTR(module))
						{
							if (module->pvBaseAddress && module->cbModuleSize)
							{
								const auto wstCurrentModuleName = stdext::to_lower_wide(module->wszModuleName);

								if (wstCurrentModuleName.find(wstTargetModuleName) != std::wstring::npos)
								{
									bFound = true;
									APP_TRACE_LOG(LL_WARN, L"Blacklisted module found by name: %s", stTargetName.c_str());
									CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, wstCurrentModuleName);
									return false;
								}
							}
						}
						return true;
					});
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SModuleCheckObjects moduleObj{};
			moduleObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			moduleObj.name = stTargetName;

			CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted(moduleObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsModuleExistByChecksum(const SCDBBaseContext& kContext, const std::wstring& stSum)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Module(sum) scan started! Index: %u Sum: %s", kContext.dwListIndex, stSum.c_str());
	
		// Instant search for the module checksum
		auto bFound = false;
		const auto llTargetSum = stdext::str_to_u64(stSum.c_str());

		{
			{
				CApplication::Instance().ScannerInstance()->EnumerateModules(NtCurrentProcess(), [&](std::shared_ptr <SModuleEnumContext> module) {
					if (IS_VALID_SMART_PTR(module))
					{
						if (module->pvBaseAddress && module->cbModuleSize)
						{
							// just get pe header
							module->cbModuleSize = 4096;

							auto lpBuffer = CMemHelper::Allocate(module->cbModuleSize);
							if (lpBuffer)
							{
								SIZE_T cbReadBytes = 0;
								const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
									NtCurrentProcess(), (PVOID64)module->pvBaseAddress, lpBuffer, module->cbModuleSize, &cbReadBytes
								);

								if (NT_SUCCESS(ntStatus) && module->cbModuleSize == cbReadBytes)
								{
									const auto qwCurrSum = CPEFunctions::CalculateMemChecksumFast(lpBuffer, module->cbModuleSize);
									if (qwCurrSum == llTargetSum)
									{
										bFound = true;
										APP_TRACE_LOG(LL_WARN, L"Blacklisted module found by hash: %ls (0x%X)", module->wszModuleName, qwCurrSum);
										CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, module->wszModuleName);
										return false;
									}
								}

								CMemHelper::Free(lpBuffer);
							}
						}
					}
					return true;
				});
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SModuleCheckObjects moduleObj{};
			moduleObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			moduleObj.hash = stSum;

			CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted(moduleObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsWindowsExistByTitleClass(const SCDBBaseContext& kContext, const std::wstring& stTitle, const std::wstring& stClass)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Window(title-class) scan started! Index: %u Title: '%s' Class: '%s'", kContext.dwListIndex, stTitle.c_str(), stClass.c_str());
		
		auto bFound = false;
		auto nReqFieldCount = 0;
		if (!stTitle.empty()) nReqFieldCount++;
		if (!stClass.empty()) nReqFieldCount++;

		if (!nReqFieldCount)
			return false;

		const auto wstLowerTitle = stdext::to_lower_wide(stTitle);
		const auto wstLowerClass = stdext::to_lower_wide(stClass);

		auto spWindowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		if (!IS_VALID_SMART_PTR(spWindowEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"spWindowEnumerator allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}
		auto vecWindows = spWindowEnumerator->EnumerateWindows();
		if (vecWindows.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Windows enumerator failed! Any window can not handled!");

			vecWindows = spWindowEnumerator->EnumerateWindowsNative();
			if (vecWindows.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Windows enumerator second attempt failed! Any window can not handled!");
				// return false;
			}
		}
		APP_TRACE_LOG(LL_SYS, L"%u window found for scan!", vecWindows.size());

		std::size_t i = 0;
		for (auto& hWnd : vecWindows)
		{
			if (!hWnd || !g_winAPIs->IsWindow(hWnd))
			{
				ADMIN_DEBUG_LOG(LL_SYS, L"[%u] Window: %p is corrupted!", i++, hWnd);
				continue;
			}

			wchar_t wszTitle[MAX_PATH * 2]{ L'\0' };
			g_winAPIs->GetWindowTextW(hWnd, wszTitle, MAX_PATH);
			const auto wstLowerCurrTitle = stdext::to_lower_wide(wszTitle);

			wchar_t wszClass[MAX_PATH * 2]{ L'\0' };
			g_winAPIs->GetClassNameW(hWnd, wszClass, MAX_PATH);
			const auto wstLowerCurrClass = stdext::to_lower_wide(wszClass);

			ADMIN_DEBUG_LOG(LL_SYS, L"[%u] Window: %p Title: %s Class: %s", i++, hWnd, wstLowerCurrTitle.c_str(), wstLowerCurrClass.c_str());

			auto nFoundFieldCount = 0;
			if (!wstLowerTitle.empty() && wstLowerCurrTitle.find(wstLowerTitle) != std::wstring::npos)
			{
				APP_TRACE_LOG(LL_WARN, L"Found scanner title text: '%s' in '%s'", wstLowerTitle.c_str(), wstLowerCurrTitle.c_str());
				nFoundFieldCount++;
			}

			if (!wstLowerClass.empty() && wstLowerCurrClass.find(wstLowerClass) != std::wstring::npos)
			{
				APP_TRACE_LOG(LL_WARN, L"Found scanner class text: '%s' in '%s'", wstLowerClass.c_str(), wstLowerCurrClass.c_str());
				nFoundFieldCount++;
			}

			if (nFoundFieldCount == nReqFieldCount)
			{
				DWORD dwProcessId = 0;
				auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessId);
				auto szProcessName = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);

				wchar_t wszFileName[MAX_PATH]{ L'\0' };
				g_winAPIs->GetWindowModuleFileNameW(hWnd, wszFileName, MAX_PATH);

				APP_TRACE_LOG(LL_WARN, L"Blacklisted window found: %p Owner: %u (%u) by %s", hWnd, dwProcessId, dwThreadId, szProcessName.c_str());
				CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, szProcessName);
				bFound = true;
				break;
			}
		}

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SWindowCheckObjects windowObj{};
			windowObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			windowObj.window_name = stTitle;
			windowObj.class_name = stClass;
			
			CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetBlacklisted(windowObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsWindowsExistByStyleExstyle(const SCDBBaseContext& kContext, const std::wstring& stStyle, const std::wstring& stExstyle)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Window(style-exstyle) scan started! Index: %u Style: %s Exstyle: %s", kContext.dwListIndex, stStyle.c_str(), stExstyle.c_str());

		// Instant search for the window style-exstyle
		auto bFound = false;
		
		const auto nStyle = stdext::str_to_u32(stStyle.c_str());
		const auto nExStyle = stdext::str_to_u32(stExstyle.c_str());

		auto spWindowEnumerator = stdext::make_unique_nothrow<CWindowEnumerator>();
		for (const auto& hWnd : spWindowEnumerator->EnumerateWindows())
		{
			if (!g_winAPIs->IsWindow(hWnd) || !g_winAPIs->IsWindowVisible(hWnd))
				continue;

			WINDOWINFO wndfo{};
			GetWindowInfoSafe(hWnd, &wndfo);

			if ((nStyle && nStyle == wndfo.dwStyle) && (nExStyle && nExStyle == wndfo.dwExStyle))
			{
				DWORD dwProcessId = 0;
				auto dwThreadId = g_winAPIs->GetWindowThreadProcessId(hWnd, &dwProcessId);
				auto szProcessName = CProcessFunctions::GetProcessNameFromProcessId(dwProcessId);

				wchar_t wszFileName[MAX_PATH]{ L'\0' };
				g_winAPIs->GetWindowModuleFileNameW(hWnd, wszFileName, MAX_PATH);

				bFound = true;
				APP_TRACE_LOG(LL_WARN, L"Blacklisted window found: %p Owner: %u (%u) by %s", hWnd, dwProcessId, dwThreadId, szProcessName.c_str());
				CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, szProcessName);
				break;
			}
		}
		
		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SWindowCheckObjects windowObj{};
			windowObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			windowObj.window_style = nStyle;
			windowObj.window_ex_style = nExStyle;

			CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetBlacklisted(windowObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsFileExistByName(const SCDBBaseContext& kContext, const std::wstring& stTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB File(path) scan started! Index: %u Target:", kContext.dwListIndex, stTargetName.c_str());

		auto bFound = false;

		// Instant search for the file path
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stTargetName))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted file found: %s", stTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, stTargetName);
		}
		else
		{
			// Add to quarentine
			SFileCheckObjects fileObj{};
			fileObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			fileObj.name = stTargetName;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(fileObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_CheckFileSum(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stSum, const std::wstring& stShouldEqual)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB File(sum) scan started! Index: %u Sum: %s", kContext.dwListIndex, stSum.c_str());

		auto bFound = false;
		const auto nShouldEqual = stdext::str_to_s8(stShouldEqual.c_str());

		// Instant search for the file checksum
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stTargetName))
		{
			const auto stCurrentSum = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileMd5(stTargetName);
			if (!stCurrentSum.empty())
			{
				if ((nShouldEqual && stCurrentSum != stSum) || (!nShouldEqual && stCurrentSum == stSum))
				{
					bFound = true;
					APP_TRACE_LOG(LL_WARN, L"Blacklisted file found: %s", stTargetName.c_str());
					CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, stTargetName);
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SFileCheckObjects fileObj{};
			fileObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			fileObj.name = stTargetName;
			fileObj.md5 = stSum;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(fileObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_CheckFilePattern(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType, const std::wstring& wstAddress)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB File(pattern) scan started! Index: %u Sum: %s", kContext.dwListIndex, stPattern.c_str());

		auto bFound = false;

		const auto nPatternType = stdext::str_to_s32(stPatternType.c_str());
		Pattern pattern(stPattern, nPatternType);

		auto pTargetAddr = !wstAddress.empty() ? (void*)stdext::string_to_pointer(wstAddress) : nullptr;

		// Instant search for the file checksum
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stTargetName))
		{
			auto stFileBuffer = stdext::to_ansi(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ReadFileContent(stTargetName));
			if (!stFileBuffer.empty())
			{
				auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
				if (IS_VALID_SMART_PTR(upPatternScanner))
				{
					auto lpFileBuffer = stFileBuffer.data();

					auto pIDH = (IMAGE_DOS_HEADER*)lpFileBuffer;
					if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
						return false;

					auto pINH = (IMAGE_NT_HEADERS*)(&lpFileBuffer[pIDH->e_lfanew]);
					if (pINH->Signature != IMAGE_NT_SIGNATURE)
						return false;

					std::vector <IMAGE_SECTION_HEADER*> sections;
					sections.reserve(pINH->FileHeader.NumberOfSections);

					auto pSection = (IMAGE_SECTION_HEADER*)(&lpFileBuffer[pIDH->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(uint32_t) + pINH->FileHeader.SizeOfOptionalHeader]);
					for (uint16_t i = 0; i < pINH->FileHeader.NumberOfSections; ++i, ++pSection)
					{
						if ((pSection->Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE)) == 0 && pSection->NumberOfRelocations == 0)
						{
							sections.push_back(pSection);
						}
					}

					uint32_t BytesPerBlock = 1024 * 512;
					for (auto iter : sections)
					{
						uint32_t offset = 0;
						while (offset < iter->SizeOfRawData)
						{
							uint32_t len = BytesPerBlock;
							if (offset + len > iter->SizeOfRawData)
								len = iter->SizeOfRawData - offset;

#ifdef _DEBUG
							wchar_t wszMappedFileName[2048]{ L'\0' };
							g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)&lpFileBuffer[iter->PointerToRawData + offset], wszMappedFileName, 2048);

							const auto stBuffer = std::string((const char*)&lpFileBuffer[iter->PointerToRawData + offset], len);

							SCANNER_LOG(LL_SYS, L"Current region base: %p Size: %u Characteristics: %p",
								iter->PointerToRawData + offset, len, iter->Characteristics
							);
#endif

							const auto pSectionAddr = &lpFileBuffer[iter->PointerToRawData + offset];
							if (pTargetAddr && pTargetAddr != pSectionAddr)
							{
								offset += len;
								continue;
							}

							if (upPatternScanner->findPatternSafe(pSectionAddr, len, pattern))
							{
								APP_TRACE_LOG(LL_WARN, L"Blacklisted pattern found: %s at %p(%u)", stPattern.c_str(), pSectionAddr, len);
								CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);

								bFound = true;
								return bFound;
							}

							offset += len;
						}
					}
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SFileCheckObjects fileObj{};
			fileObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			fileObj.name = stTargetName;
			fileObj.blacklisted_pattern = stPattern;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(fileObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_CheckFileSectionHash(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stSectionHash)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB File(section hash) scan started! Index: %u Target: %s Sum: %s", kContext.dwListIndex, stTargetName.c_str(), stSectionHash.c_str());

		auto bFound = false;

		const auto wstTargetSectionLowerHash = stdext::to_lower_wide(stSectionHash);

		// Instant search for the file checksum
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stTargetName))
		{
			auto stFileBuffer = stdext::to_ansi(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ReadFileContent(stTargetName));
			if (!stFileBuffer.empty())
			{
				auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
				if (IS_VALID_SMART_PTR(upPatternScanner))
				{
					auto lpFileBuffer = stFileBuffer.data();

					auto pIDH = (IMAGE_DOS_HEADER*)lpFileBuffer;
					if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
						return false;

					auto pINH = (IMAGE_NT_HEADERS*)(&lpFileBuffer[pIDH->e_lfanew]);
					if (pINH->Signature != IMAGE_NT_SIGNATURE)
						return false;

					std::vector <IMAGE_SECTION_HEADER*> sections;
					sections.reserve(pINH->FileHeader.NumberOfSections);

					auto pSection = (IMAGE_SECTION_HEADER*)(&lpFileBuffer[pIDH->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(uint32_t) + pINH->FileHeader.SizeOfOptionalHeader]);
					for (uint16_t i = 0; i < pINH->FileHeader.NumberOfSections; ++i, ++pSection)
					{
						if ((pSection->Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE)) == 0 && pSection->NumberOfRelocations == 0)
						{
							sections.push_back(pSection);
						}
					}

					uint32_t BytesPerBlock = 1024 * 512;
					for (auto iter : sections)
					{
						uint32_t offset = 0;
						while (offset < iter->SizeOfRawData)
						{
							uint32_t len = BytesPerBlock;
							if (offset + len > iter->SizeOfRawData)
								len = iter->SizeOfRawData - offset;

#ifdef _DEBUG
							wchar_t wszMappedFileName[2048]{ L'\0' };
							g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)&lpFileBuffer[iter->PointerToRawData + offset], wszMappedFileName, 2048);

							const auto stBuffer = std::string((const char*)&lpFileBuffer[iter->PointerToRawData + offset], len);

							SCANNER_LOG(LL_SYS, L"Current region base: %p Size: %u Characteristics: %p",
								iter->PointerToRawData + offset, len, iter->Characteristics
							);
#endif

							const auto stCurrSectionHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256((std::uint8_t*)&lpFileBuffer[iter->PointerToRawData + offset], len);

							if (!stCurrSectionHash.empty() && stCurrSectionHash == wstTargetSectionLowerHash)
							{
								APP_TRACE_LOG(LL_WARN, L"Blacklisted hash found: %s", stCurrSectionHash.c_str());
								CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);

								bFound = true;
								return bFound;
							}

							offset += len;
						}
					}
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SFileCheckObjects fileObj{};
			fileObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			fileObj.name = stTargetName;
			fileObj.section_sha256 = wstTargetSectionLowerHash;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(fileObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsRegionExistInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stLength, const std::wstring& stSum)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Region scan started! Index: %u Addr: %s Length: %s Sum: %s", kContext.dwListIndex, stAddress.c_str(), stLength.c_str(), stSum.c_str());

		auto bFound = false;
		const auto nAddress = stdext::str_to_u64(stAddress.c_str());
		const auto nLength = stdext::str_to_u64(stLength.c_str());
		const auto nSum = stdext::str_to_u64(stSum.c_str());

		// Instant search for the region
		{
			if (!bFound && !kContext.bIsListed)
			{
				{
					CApplication::Instance().ScannerInstance()->EnumerateSections(NtCurrentProcess(), false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
						if ((uint64_t)pCurrSection->BaseAddress == nAddress && pCurrSection->RegionSize == nLength)
						{
							const auto nCurrSum = CPEFunctions::CalculateMemChecksumFast((LPCVOID)pCurrSection->BaseAddress, pCurrSection->RegionSize);
							if (nCurrSum && nCurrSum == nSum)
							{
								bFound = true;
								APP_TRACE_LOG(LL_WARN, L"Blacklisted section found: %s(%s) -> %s", stAddress.c_str(), stLength.c_str(), stSum.c_str());
								CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
								return;
							}
						}
					});
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SMemoryCheckObjects sectionObj{};
			sectionObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			sectionObj.id = kContext.stID;
			sectionObj.region_base = nAddress;
			sectionObj.region_size = nLength;
			sectionObj.region_checksum = nSum;

			CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->SetBlacklisted(sectionObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsRegionExistInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stLength, const std::wstring& stSum)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Region scan started! Index: %u Addr: %s Length: %s Sum: %s", kContext.dwListIndex, stAddress.c_str(), stLength.c_str(), stSum.c_str());

		auto bFound = false;
		const auto nAddress = stdext::str_to_u64(stAddress.c_str());
		const auto nLength = stdext::str_to_u64(stLength.c_str());
		const auto wstLowerTargetSum = stdext::to_lower_wide(stSum.c_str());
		const auto bHasTargetParam = nAddress && nLength;

		// Instant search for the region
		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			for (auto hProcess : upProcEnumerator->EnumerateProcesses())
			{
				if (IS_VALID_HANDLE(hProcess))
				{
					if (!bFound && !kContext.bIsListed)
					{
						if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
						{
							const auto wstLowerProcessName = stdext::to_lower_wide(CProcessFunctions::GetProcessName(hProcess));

							CApplication::Instance().ScannerInstance()->EnumerateSections(hProcess, false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
								if (!bHasTargetParam ||
									(bHasTargetParam && (uint64_t)pCurrSection->BaseAddress == nAddress && pCurrSection->RegionSize == nLength))
								{
									const auto mask = (PAGE_READONLY | PAGE_READWRITE | /* PAGE_WRITECOPY | */ PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
									if (pCurrSection->Protect & mask)
									{
										const auto wstCurrSum = CPEFunctions::CalculateRemoteMemChecksumSHA256(hProcess, pCurrSection->BaseAddress, pCurrSection->RegionSize);
										if (!wstLowerTargetSum.empty() && wstLowerTargetSum == wstCurrSum)
										{
											bFound = true;
											APP_TRACE_LOG(LL_WARN, L"Blacklisted section found: %s(%s) -> %s", stAddress.c_str(), stLength.c_str(), stSum.c_str());
											CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, wstLowerProcessName);
											return;
										}
									}
								}
							});
						}
					}
				}
			}
			upProcEnumerator.reset();
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SMemoryCheckObjects sectionObj{};
			sectionObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			sectionObj.id = kContext.stID;
			sectionObj.region_base = nAddress;
			sectionObj.region_size = nLength;
			sectionObj.region_checksum_sha256 = wstLowerTargetSum;

			CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->SetBlacklisted(sectionObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsPatternExistInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Game Pattern scan started! Index: %u Pattern: %s Mask: %s Type: %s", kContext.dwListIndex, stPattern.c_str(), stMask.c_str(), stPatternType.c_str());

		auto bFound = false;
		const auto nPatternType = stdext::str_to_s32(stPatternType.c_str());

		// Instant search for the pattern
		auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
		if (IS_VALID_SMART_PTR(upPatternScanner))
		{
			Pattern pattern(stPattern, nPatternType);
			{
				if (!bFound && !kContext.bIsListed)
				{
					{
						CApplication::Instance().ScannerInstance()->EnumerateSections(NtCurrentProcess(), false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
							if (pCurrSection->RegionSize < 0x1000000)
							{
								if (!CMemHelper::IsBadReadPtr(pCurrSection->BaseAddress))
								{
									auto lpMemCopy = CMemHelper::Allocate(pCurrSection->RegionSize);
									if (!lpMemCopy)
									{
										APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory with size: %llu for pattern scan!", pCurrSection->RegionSize);
									}
									else
									{
										const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
											NtCurrentProcess(), PtrToPtr64(pCurrSection->BaseAddress), lpMemCopy, pCurrSection->RegionSize, nullptr
										);
										if (!NT_SUCCESS(ntStatus))
										{
											APP_TRACE_LOG(LL_TRACE, L"Failed to read memory: %p with size: %llu for pattern scan! Status: %p", pCurrSection->BaseAddress, pCurrSection->RegionSize, ntStatus);
										}
										else
										{
											if (upPatternScanner->findPatternSafe(lpMemCopy, static_cast<uint32_t>(pCurrSection->RegionSize), pattern))
											{
												APP_TRACE_LOG(LL_WARN, L"Blacklisted pattern found: %s at %p(%u)", stPattern.c_str(), pCurrSection->BaseAddress, pCurrSection->RegionSize);
												CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);

												bFound = true;
												CMemHelper::Free(lpMemCopy);
												return;
											}
										}

										CMemHelper::Free(lpMemCopy);
									}
								}
							}
							});
					}
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SMemoryCheckObjects patternObj{};
			patternObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			patternObj.id = kContext.stID;
			patternObj.pattern = stPattern;
			patternObj.mask = stMask;
			patternObj.pattern_type = nPatternType;

			CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->SetBlacklisted(patternObj, {});
		}

		APP_TRACE_LOG(LL_SYS, L"Pattern scan completed with result: %d", bFound ? 1 : 0);
		return bFound;
	}
	bool IScanner::CDB_IsPatternExistInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType, const DWORD dwTargetPID)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB General Pattern scan started! Index: %u Pattern: %s Mask: %s Type: %s Target: %u", kContext.dwListIndex, stPattern.c_str(), stMask.c_str(), stPatternType.c_str(), dwTargetPID);

		auto bFound = false;
		const auto nPatternType = stdext::str_to_s32(stPatternType.c_str());

		// Instant search for the pattern
		auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
		if (IS_VALID_SMART_PTR(upPatternScanner))
		{
			Pattern pattern(stPattern, nPatternType);

			auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION);
			if (IS_VALID_SMART_PTR(upProcEnumerator))
			{
				const auto dwCurrSID = CApplication::Instance().GetCurrentProcessSID();
				const auto stCurrProcessName = CProcessFunctions::GetProcessName(NtCurrentProcess());

				for (auto hProcess : upProcEnumerator->EnumerateProcesses())
				{
					if (IS_VALID_HANDLE(hProcess))
					{
						if (!bFound && !kContext.bIsListed)
						{
							if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
							{
								const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
								if (dwTargetPID && dwTargetPID != dwProcessID)
									continue;

								// Check pid is not current process id
								if (dwProcessID == g_winAPIs->GetCurrentProcessId())
								{
									// APP_TRACE_LOG(LL_SYS, L"Current process id: %u is same with process: %u", dwProcessID, g_winAPIs->GetCurrentProcessId());
									continue;
								}

								// Check process session id, if it is different from current session id, skip it
								DWORD dwSessionID = 0;
								if (!g_winAPIs->ProcessIdToSessionId(dwProcessID, &dwSessionID) || dwSessionID != dwCurrSID)
								{
									// APP_TRACE_LOG(LL_SYS, L"Current process session id: %u is different from process: %u session id: %u", dwCurrSID, dwProcessID, dwSessionID);
									continue;
								}

								// Check process launch time for speed up scanning
								static constexpr auto dwMaxProcessLaunchTime = 60 * 30; // 30 minutes
								const auto dwCurrentTime = stdext::get_current_epoch_time();
								const auto dwProcessStartTime = CProcessFunctions::GetProcessCreationTime(hProcess);
								const auto uliProcessStartTime = dwCurrentTime - dwProcessStartTime;
								if (uliProcessStartTime > dwMaxProcessLaunchTime)
								{
									// APP_TRACE_LOG(LL_SYS, L"Current process launch time: %u is greater than: %u", uliProcessStartTime, dwMaxProcessLaunchTime);
									continue;
								}

								// Check the executable name
								const auto stProcessName = CProcessFunctions::GetProcessName(hProcess);
								if (stProcessName == stCurrProcessName)
								{
									// APP_TRACE_LOG(LL_SYS, L"Current process name: %s is same with process: %s", stCurrProcessName.c_str(), stProcessName.c_str());
									continue;
								}

								CApplication::Instance().ScannerInstance()->EnumerateSections(hProcess, false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
									if (pCurrSection->RegionSize < 0x1000000)
									{
										if (!CMemHelper::IsBadReadPtr(pCurrSection->BaseAddress))
										{
											auto lpMemCopy = CMemHelper::Allocate(pCurrSection->RegionSize);
											if (!lpMemCopy)
											{
												APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory with size: %llu for pattern scan!", pCurrSection->RegionSize);
											}
											else
											{
												const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
													hProcess, PtrToPtr64(pCurrSection->BaseAddress), lpMemCopy, pCurrSection->RegionSize, nullptr
												);
												if (!NT_SUCCESS(ntStatus))
												{
													APP_TRACE_LOG(LL_TRACE, L"Failed to read memory: %p with size: %llu for pattern scan! Status: %p", pCurrSection->BaseAddress, pCurrSection->RegionSize, ntStatus);
												}
												else
												{
													if (upPatternScanner->findPatternSafe(lpMemCopy, static_cast<uint32_t>(pCurrSection->RegionSize), pattern))
													{
														APP_TRACE_LOG(LL_WARN, L"Blacklisted pattern found: %s at %p(%u)", stPattern.c_str(), pCurrSection->BaseAddress, pCurrSection->RegionSize);
														CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);

														bFound = true;
														CMemHelper::Free(lpMemCopy);
														upProcEnumerator.reset(); 
														return;
													}
												}

												CMemHelper::Free(lpMemCopy);
											}
										}
									}
								});
							}
						}
					}
				}
				upProcEnumerator.reset();
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SMemoryCheckObjects patternObj{};
			patternObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			patternObj.id = kContext.stID;
			patternObj.pattern = stPattern;
			patternObj.mask = stMask;
			patternObj.pattern_type = nPatternType;

			CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->SetBlacklisted(patternObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsMemDumpExist(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stMemCopy)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Mem dump scan started! Index: %u Address: %s Mem-copy: %s", kContext.dwListIndex, stAddress.c_str(), stMemCopy.c_str());

		auto bFound = false;

		// Instant search for the memory dump
		if (!stAddress.empty() && !stMemCopy.empty())
		{
			const auto pAddress = stdext::string_to_pointer64(stAddress);
			const auto vMemCopy = stdext::string_to_byte_array(stMemCopy);
			if (!vMemCopy.empty())
			{
				auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
				if (IS_VALID_SMART_PTR(upProcEnumerator))
				{
					for (auto hProcess : upProcEnumerator->EnumerateProcesses())
					{
						if (IS_VALID_HANDLE(hProcess))
						{
							const auto dwProcessId = g_winAPIs->GetProcessId(hProcess);
							const auto stProcessName = CProcessFunctions::GetProcessName(hProcess);

							BYTE	pBytes[32]{ 0x0 };
							SIZE_T	cbBytesRead = 0;

							if (NT_SUCCESS(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
								hProcess, (PVOID64)pAddress, (PVOID)pBytes, vMemCopy.size(), &cbBytesRead)) && cbBytesRead == vMemCopy.size()
							)
							{
								if (!memcmp(pBytes, vMemCopy.data(), vMemCopy.size()))
								{
									bFound = true;
									APP_TRACE_LOG(LL_WARN, L"Blacklisted mem dump found: %s(%s) at %u(%s)", stAddress.c_str(), stMemCopy.c_str(), dwProcessId, stProcessName.c_str());
									CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, stProcessName);
									break;
								}
							}
						}
					}
					upProcEnumerator.reset();
				}
			}
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SMemoryCheckObjects memDumpObj{};
			memDumpObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			memDumpObj.id = kContext.stID;
			memDumpObj.memory_base = stAddress;
			memDumpObj.memory_copy = stMemCopy;

			CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->SetBlacklisted(memDumpObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsFileMappingExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB File mapping scan started! Target: %s", szTargetName.c_str());
	
		auto bFound = false;

		// Instant search for the file mapping
		auto hMapFile = g_winAPIs->OpenFileMappingW(SYNCHRONIZE, FALSE, szTargetName.c_str());
		if (IS_VALID_HANDLE(hMapFile))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted file mapping found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hMapFile);
			bFound = true;
		}

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;

			CApplication::Instance().QuarentineInstance()->FileMappingNameQuarentine()->SetBlacklisted({ idx, szTargetName }, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsMutexExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Mutex scan started! Target: %s", szTargetName.c_str());

		auto bFound = false;

		// Instant search for the mutex
		auto hMutex = g_winAPIs->OpenMutexW(SYNCHRONIZE, FALSE, szTargetName.c_str());
		if (IS_VALID_HANDLE(hMutex))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted mutex found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hMutex);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			
			CApplication::Instance().QuarentineInstance()->MutantNameQuarentine()->SetBlacklisted({idx, szTargetName}, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsEventExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Event name scan started! Target: %s", szTargetName.c_str());

		auto bFound = false;

		// Instant search for the event
		auto hEvent = g_winAPIs->OpenEventW(SYNCHRONIZE, FALSE, szTargetName.c_str());
		if (IS_VALID_HANDLE(hEvent))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted event found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hEvent);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;

			CApplication::Instance().QuarentineInstance()->EventNameQuarentine()->SetBlacklisted({ idx, szTargetName }, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsSemaphoreExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Semaphore scan started! Target: %s", szTargetName.c_str());

		auto bFound = false;

		// Instant search for the semaphore
		auto hSemaphore = g_winAPIs->OpenSemaphoreW(SYNCHRONIZE, FALSE, szTargetName.c_str());
		if (IS_VALID_HANDLE(hSemaphore))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted semaphore found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hSemaphore);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;

			CApplication::Instance().QuarentineInstance()->SemaphoreNameQuarentine()->SetBlacklisted({ idx, szTargetName }, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsJobObjectExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Job object scan started! Target: %s", szTargetName.c_str());

		auto bFound = false;

		// Instant search for the job object
		auto hJobObject = g_winAPIs->OpenJobObjectW(SYNCHRONIZE, FALSE, szTargetName.c_str());
		if (IS_VALID_HANDLE(hJobObject))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted job object found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hJobObject);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;

			CApplication::Instance().QuarentineInstance()->JobNameQuarentine()->SetBlacklisted({ idx, szTargetName }, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsSymLinkExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB symlink scan started! Target: %s", szTargetName.c_str());
	
		auto bFound = false;

		// Instant search for the symlink
		const auto stDeviceName = fmt::format(xorstr_(L"\\\\.\\{0}"), szTargetName);
		auto hDevice = g_winAPIs->CreateFileW(stDeviceName.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (IS_VALID_HANDLE(hDevice))
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted symlink found: %s", szTargetName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			g_winAPIs->CloseHandle(hDevice);
			bFound = true;
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			const auto idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;

			CApplication::Instance().QuarentineInstance()->SymLinkQuarentine()->SetBlacklisted({ idx, szTargetName }, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsMemChecksumCorrupted(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stSize, const std::wstring& szCorrectHash, const std::wstring& stShouldEqual)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Mem checksum scan started! Target addr: %s size: %s", stAddress.c_str(), stSize.c_str());
		
		auto bFound = false;

		if (!stAddress.empty() && !stSize.empty() && !stShouldEqual.empty())
		{
			const auto lpAddress = stdext::string_to_pointer(stAddress);
			const auto cbSize = stdext::str_to_u64(stSize.c_str());
			const auto nShouldEqual = stdext::str_to_s8(stShouldEqual.c_str());

			if (lpAddress && cbSize)
			{
				{
					{
						CApplication::Instance().ScannerInstance()->EnumerateSections(NtCurrentProcess(), false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
							auto pBuffer = CMemHelper::Allocate(cbSize);
							if (pBuffer)
							{
								SIZE_T dwReadByteCount = 0UL;
								if (NT_SUCCESS(g_winAPIs->NtReadVirtualMemory(NtCurrentProcess(), (LPVOID)lpAddress, &pBuffer, cbSize, &dwReadByteCount)) && cbSize == dwReadByteCount)
								{
									const auto stBuffer = std::string((const char*)pBuffer, cbSize);
									auto szCurrentHash = stdext::to_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256(stBuffer));
									if (szCurrentHash.empty() == false && ((nShouldEqual && szCurrentHash != szCorrectHash) || !nShouldEqual && szCurrentHash == szCorrectHash))
									{
										APP_TRACE_LOG(LL_WARN, L"Blacklisted mem sum found: %p (%u)", lpAddress, cbSize);
										CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
										bFound = true;
									}
								}

								CMemHelper::Free(pBuffer);
							}
						});
					}
				}
			}
		}

		return bFound;
	}
	bool IScanner::CDB_IsMemCorrupted(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stOffsetList, const std::wstring& stSize, const std::wstring& stCorrectChecksum, const std::wstring& stShouldEqual)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Mem checksum(ex) scan started! Target addr: %s", stAddress.c_str());

		auto bFound = false;

		if (!stAddress.empty() && !stOffsetList.empty() && !stSize.empty() && !stCorrectChecksum.empty())
		{
			const auto lpAddress = stdext::string_to_pointer(stAddress);
			const auto vOffsetList = stdext::string_to_byte_array(stOffsetList);
			const auto nSize = stdext::str_to_s32(stSize.c_str());
			const auto nShouldEqual = stdext::str_to_s32(stShouldEqual.c_str());

			{
				{
					auto lpBuffer = CMemHelper::Allocate(nSize);
					if (lpBuffer)
					{
						SIZE_T cbSize = 0;
						auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
							NtCurrentProcess(), (PVOID64)lpAddress, lpBuffer, nSize, &cbSize
						);

						if (NT_SUCCESS(ntStatus))
						{
							for (const auto& offset : vOffsetList)
							{
								ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
									NtCurrentProcess(), (PVOID64)(lpAddress + (DWORD_PTR)offset), lpBuffer, nSize, &cbSize
								);

								if (!NT_SUCCESS(ntStatus))
									break;
							}
							if (lpBuffer)
							{
								const auto stBuffer = std::string((const char*)lpBuffer, cbSize);
								auto szCurrentHash = stdext::to_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256(stBuffer));
								if (szCurrentHash.empty() == false &&
									((nShouldEqual && szCurrentHash != stCorrectChecksum) ||
									 !nShouldEqual && szCurrentHash == stCorrectChecksum))
								{
									APP_TRACE_LOG(LL_WARN, L"Blacklisted mem sum found: %p (%u)", lpAddress, cbSize);
									CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
									bFound = true;
								}
							}
							
						}
						CMemHelper::Free(lpBuffer);
					}
				}
			}
		}
		return bFound;
	}
	bool IScanner::CDB_IsEbpContextCorrupted(const SCDBBaseContext& kContext, const std::wstring& stOffset, const std::wstring& stRangeSize, const std::wstring& stPattern, const std::wstring& stPatternType)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB thread context scan started! Target offset: %s", stOffset.c_str());

		auto bFound = false;

		// Instant search for the thread context
		if (!stOffset.empty() && !stPattern.empty() && !stPatternType.empty() && !stRangeSize.empty())
		{
			const auto nOffset = stdext::str_to_u32(stOffset.c_str());
			const auto nRangeSize = stdext::str_to_u32(stRangeSize.c_str());
			const auto nPatternType = stdext::str_to_u32(stPatternType.c_str());
			
			if (nOffset)
			{
				const auto pattern_scanner = stdext::make_unique_nothrow<CPatternScanner>();
				const auto enumerator = stdext::make_unique_nothrow<CThreadEnumerator>(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT);
				if (IS_VALID_SMART_PTR(pattern_scanner) && IS_VALID_SMART_PTR(enumerator))
				{
					{
						{
							const auto threads = enumerator->EnumerateThreads(NtCurrentProcess());
							for (const auto& hThread : threads)
							{
								if (IS_VALID_HANDLE(hThread))
								{
									uintptr_t ebp = 0;

#if (NM_PLATFORM == 86)
									if (stdext::is_wow64())
									{
										auto ctx = WOW64_CONTEXT{ 0 };
										ctx.ContextFlags = CONTEXT_FULL;
										if (!g_winAPIs->Wow64GetThreadContext(hThread, &ctx))
											continue;
										ebp = ctx.Ebp;
									}
									else
#endif
									{
										auto ctx = CONTEXT{ 0 };
										ctx.ContextFlags = CONTEXT_FULL;
										if (!g_winAPIs->GetThreadContext(hThread, &ctx))
											continue;
#if (NM_PLATFORM == 64)
										ebp = ctx.Rbp;
#else
										ebp = ctx.Ebp;
#endif
									}

									if (ebp)
									{
										SIZE_T cbReadSize = 0;
										PVOID lpStackPtr = nullptr;

										auto ntStatus = g_winAPIs->NtReadVirtualMemory(NtCurrentProcess(), reinterpret_cast<LPVOID>(ebp + nOffset), &lpStackPtr, sizeof(lpStackPtr), &cbReadSize);
										if (NT_SUCCESS(ntStatus) && cbReadSize == sizeof(lpStackPtr))
										{
											if (IS_VALID_SMART_PTR(pattern_scanner))
											{
												Pattern pattern(stPattern, nPatternType);
												if (pattern_scanner->findPatternSafe(lpStackPtr, nRangeSize, pattern))
												{
													bFound = true;
													APP_TRACE_LOG(LL_WARN, L"Blacklisted ebp context found");
													CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
													break;
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
		}

		// Add to quarentine
		if (!bFound && !kContext.bIsListed)
		{
			SThreadCheckObject threadObj{};
			threadObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			threadObj.context_offset = stdext::str_to_u32(stOffset.c_str());
			threadObj.context_range_size = stdext::str_to_u32(stRangeSize.c_str());
			threadObj.context_pattern_type = stdext::str_to_u32(stPatternType.c_str());
			threadObj.context_pattern = stPattern;

			CApplication::Instance().QuarentineInstance()->ThreadQuarentine()->SetBlacklisted(threadObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_CheckAPIModuleBound(const SCDBBaseContext& kContext, const std::wstring& stModuleName, const std::wstring& wstAPIName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB api module bound scan started! Target offset: %s!%s", stModuleName.c_str(), wstAPIName.c_str());

		auto bFound = false;

		auto InModuleRange = [](HANDLE hProcess, HMODULE hModule, DWORD64 dwAddress) {
			auto obRet = std::optional<bool>();

			MODULEINFO mi = { 0 };
			if (g_winAPIs->GetModuleInformation(hProcess, hModule, &mi, sizeof(mi)))
			{
				const auto dwBase = reinterpret_cast<DWORD64>(mi.lpBaseOfDll);
				const auto dwHi = reinterpret_cast<DWORD64>(mi.lpBaseOfDll) + mi.SizeOfImage;

				obRet = (dwAddress >= dwBase && dwAddress <= dwHi);
			}
			return obRet;
		};

		const auto stAPIName = stdext::to_ansi(wstAPIName);
		if (!stModuleName.empty() && !stAPIName.empty())
		{
			{
				{
					CApplication::Instance().ScannerInstance()->EnumerateModules(NtCurrentProcess(), [&](std::shared_ptr <SModuleEnumContext> module) {
						if (IS_VALID_SMART_PTR(module))
						{
							const auto stCurrModule = stdext::to_lower_wide(module->wszModuleName);
							if (stCurrModule == stModuleName)
							{
								if (module->pvBaseAddress && module->cbModuleSize)
								{
									auto lpBuffer = CMemHelper::Allocate(module->cbModuleSize);
									if (lpBuffer)
									{
										SIZE_T cbReadSize = 0;
										const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
											NtCurrentProcess(), (PVOID64)module->pvBaseAddress, lpBuffer, module->cbModuleSize, &cbReadSize
										);
										if (NT_SUCCESS(ntStatus))
										{
											const auto address = (DWORD64)CPEFunctions::GetExportEntry((HMODULE)lpBuffer, stAPIName.c_str());
											if (address)
											{
												const auto obRet = InModuleRange(NtCurrentProcess(), (HMODULE)module->pvBaseAddress, address);
												if (obRet.has_value() && obRet.value())
												{
													APP_TRACE_LOG(LL_WARN, L"WinAPI outbound detected");
													CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
													bFound = true;
													return false;
												}
											}
										}

										CMemHelper::Free(lpBuffer);
									}
								}
							}
						}
						return true;
					});
				}
			}
		}
		return bFound;
	}
	bool IScanner::CDB_CheckYaraFile(const SCDBBaseContext& kContext, std::vector<std::uint8_t> stFileContext)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB yara scan started!");

		auto bFound = false;

		if (m_upYaraDetector->analyze(stFileContext))
		{
			if (!m_upYaraDetector->getDetectedRules().empty())
			{
				APP_TRACE_LOG(LL_WARN, L"Blacklisted yara entry detected");
				CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
				bFound = true;
			}
		}

		return bFound;
	}
	bool IScanner::CDB_CheckRegistryKeyExist(const SCDBBaseContext& kContext, const std::wstring& stKey, const std::wstring& stPath)
	{
		auto bFound = false;

		HKEY key = 0;
		if (stKey == xorstr_(L"HKEY_CLASSES_ROOT"))
			key = HKEY_CLASSES_ROOT;
		else if (stKey == xorstr_(L"HKEY_CURRENT_USER"))
			key = HKEY_CURRENT_USER;
		else if (stKey == xorstr_(L"HKEY_LOCAL_MACHINE"))
			key = HKEY_LOCAL_MACHINE;
		else if (stKey == xorstr_(L"HKEY_USERS"))
			key = HKEY_USERS;
		else if (stKey == xorstr_(L"HKEY_PERFORMANCE_DATA"))
			key = HKEY_PERFORMANCE_DATA;

		if (key)
		{
			HKEY hKey{ 0 };
			if (g_winAPIs->RegOpenKeyW(key, stPath.c_str(), &hKey) == ERROR_SUCCESS)
			{
				APP_TRACE_LOG(LL_WARN, L"Blacklisted registry key: %s detected", stPath.c_str());
				CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
				bFound = true;

				g_winAPIs->RegCloseKey(hKey);
			}
		}

		return bFound;
	}
	bool IScanner::CDB_IsWindowsStationExist(const SCDBBaseContext& kContext, const std::wstring& stStationID)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Windows Station scan started! Index: %u Target: %s", kContext.dwListIndex, stStationID.c_str());

		const auto stLowerStationID = stdext::to_lower_ansi(stStationID);

		auto sm = stdext::make_unique_nothrow<CSessionHelper>();
		if (!sm)
		{
			APP_TRACE_LOG(LL_WARN, L"Failed to create session helper!");
			return false;
		}

		std::vector <SWtsSessionInfo> vecSessions;
		if (!sm->GetSessions(vecSessions))
		{
			APP_TRACE_LOG(LL_WARN, L"Failed to get sessions!");
			return false;
		}
		
		auto bFound = false;
		for (const auto& session : vecSessions)
		{
			if (session.winstation_name[0] != '\0')
			{
				const auto stStationName = stdext::to_lower_ansi(session.winstation_name);
				if (stStationName == stLowerStationID)
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted windows station found: %s", stStationID.c_str());
					CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
					bFound = true;
					break;
				}
			}
		}

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SCommonQuarentineHandler winStationObj{};
			winStationObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			winStationObj.data = stStationID;

			CApplication::Instance().QuarentineInstance()->WindowsStationQuarentine()->SetBlacklisted(winStationObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsWaitableTimerExist(const SCDBBaseContext& kContext, const std::wstring& wstTimerName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Waitable Timer scan started! Index: %u Target: %s", kContext.dwListIndex, wstTimerName.c_str());
		
		auto bFound = false;

		UNICODE_STRING usTimerName{};
		g_winAPIs->RtlInitUnicodeString(&usTimerName, wstTimerName.c_str());

		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, &usTimerName, OBJ_CASE_INSENSITIVE, 0, 0);

		HANDLE hTimer{ nullptr };
		auto ntStatus = g_winAPIs->NtOpenTimer(&hTimer, TIMER_ALL_ACCESS, &oa);
		if (ntStatus == STATUS_SUCCESS)
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted waitable timer found: %s", wstTimerName.c_str());
	
			ULONG ulReturnLength = 0;
			TIMER_BASIC_INFORMATION TimerInformation{ 0 };
			ntStatus = g_winAPIs->NtQueryTimer(hTimer, TimerBasicInformation, &TimerInformation, sizeof(TimerInformation), &ulReturnLength);
			if (ntStatus == STATUS_SUCCESS) {
				APP_TRACE_LOG(LL_SYS, L"Timer: %s query completed! State: %d Remaining time: %lld", wstTimerName.c_str(), TimerInformation.TimerState, TimerInformation.RemainingTime.QuadPart);
			} else  {
				APP_TRACE_LOG(LL_WARN, L"Timer: %s query failed! Error: %p", wstTimerName.c_str(), ntStatus);
			}	
			
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
			bFound = true;

			g_winAPIs->NtClose(hTimer);
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			APP_TRACE_LOG(LL_WARN, L"Open waitable timer: %s failed with status: %p", wstTimerName.c_str(), ntStatus);
			
			// Add to quarentine
			SCommonQuarentineHandler winTimerObj{};
			winTimerObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			winTimerObj.data = wstTimerName;

			CApplication::Instance().QuarentineInstance()->WaitableTimerQuarentine()->SetBlacklisted(winTimerObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsHandleObjectExist(const SCDBBaseContext& kContext, const std::wstring& stHandleObjectName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB Handle object scan started! Index: %u Target: %s", kContext.dwListIndex, stHandleObjectName.c_str());

		const auto stLowerHandleObjectName = stdext::to_lower_wide(stHandleObjectName);

		auto bFound = false;
		CApplication::Instance().ScannerInstance()->EnumerateHandles([this, &kContext, &stLowerHandleObjectName, &bFound](const SHandleScanContext* ctx) {
			if (bFound)
				return false;
			
#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Checking handle: %p, from: %u", ctx->hHandle, ctx->hSourcePid);
#endif

			// Open source process
			SafeHandle hSourceProcess = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(
				PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, ctx->hSourcePid
			);
			if (!hSourceProcess.IsValid())
			{
#ifdef _DEBUG
				APP_TRACE_LOG(LL_ERR, L"Failed to open source process: %u", ctx->hSourcePid);
#endif
				return true;
			}

			// Duplicate handle
			HANDLE hDupHandle = nullptr;
			const auto ntStatus = g_winAPIs->NtDuplicateObject(
				hSourceProcess.get(), ctx->hHandle, NtCurrentProcess(), &hDupHandle, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES
			);
			if (!NT_SUCCESS(ntStatus))
			{
#ifdef _DEBUG
				if (ntStatus != STATUS_NOT_SUPPORTED)
				{
					APP_TRACE_LOG(LL_ERR, L"NtDuplicateObject failed with status: %p", ntStatus);
				}
#endif
				return true;
			}

			// Query handle type
			const auto stObjectType = CApplication::Instance().ScannerInstance()->GetHandleObjectType(hDupHandle);
			if (stObjectType.empty())
			{
#ifdef _DEBUG
				APP_TRACE_LOG(LL_ERR, L"GetHandleObjectType for: %p failed", hDupHandle);
#endif
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return true;
			}

			// Query object name
			const auto stObjectName = CApplication::Instance().ScannerInstance()->GetHandleObjectName(hSourceProcess, hDupHandle);
			if (stObjectName.empty())
			{
#ifdef _DEBUG
				APP_TRACE_LOG(LL_ERR, L"GetHandleObjectName for: %p failed", hDupHandle);
#endif
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return true;
			}
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Process: %u Handle: %p (%p) Object type: %s Name: %s", ctx->hSourcePid, ctx->hHandle, hDupHandle, stObjectType.c_str(), stObjectName.c_str());
#endif

			if (stObjectName == stLowerHandleObjectName)
			{
				bFound = true;
				return false;
			}

			return true;
		});

		if (bFound)
		{
			APP_TRACE_LOG(LL_WARN, L"Blacklisted handle object found: %s", stLowerHandleObjectName.c_str());
			CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, stHandleObjectName);
		}
		
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SCommonQuarentineHandler winStationObj{};
			winStationObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			winStationObj.data = stHandleObjectName;

			CApplication::Instance().QuarentineInstance()->HandleObjectNameQuarentine()->SetBlacklisted(winStationObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsServiceExist(const SCDBBaseContext& kContext, const std::wstring& szTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB service scan started! Target: %s", szTargetName.c_str());

		auto bFound = false;

		const auto stCorrectLowerName = stdext::to_lower_wide(szTargetName);
		
		CApplication::Instance().ScannerInstance()->EnumerateServices([&](std::shared_ptr <SServiceScanContext> ctx) {
			if (IS_VALID_SMART_PTR(ctx))
			{
				if (ctx->dwServiceState == SERVICE_RUNNING)
				{
					const auto wstCurrLowerName = stdext::to_lower_wide(ctx->stServiceName);
					if (stCorrectLowerName == wstCurrLowerName)
					{
						APP_TRACE_LOG(LL_WARN, L"Blacklisted service found: %s", szTargetName.c_str());
						CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
						bFound = true;
						return false;
					}
				}
			}
			return true;
		}); 

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SCommonQuarentineHandler svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.data = szTargetName;

			CApplication::Instance().QuarentineInstance()->ServiceNameQuarentine()->SetBlacklisted(svcObj, {});
		}

		return bFound;
	}
	bool IScanner::CDB_IsServiceExistByHash(const SCDBBaseContext& kContext, const std::wstring& stServiceHash)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB service hash scan started! Target: %s", stServiceHash.c_str());

		auto bFound = false;

		const auto stCorrectLowerHash = stdext::to_lower_wide(stServiceHash);

		CApplication::Instance().ScannerInstance()->EnumerateServices([&](std::shared_ptr <SServiceScanContext> ctx) {
			if (IS_VALID_SMART_PTR(ctx))
			{
				if (ctx->dwServiceState == SERVICE_RUNNING && !ctx->stServiceExecutable.empty())
				{
					if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(ctx->stServiceExecutable))
					{
						const auto stServiceCurrentHash = stdext::to_lower_wide(
							NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(ctx->stServiceExecutable)
						);
						
						if (stServiceCurrentHash == stCorrectLowerHash)
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted service hash found: %s", stCorrectLowerHash.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
							bFound = true;
							return false;
						}
					}
				}
			}
			return true;
		});

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SFileCheckObjects svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.sha1 = stServiceHash;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(svcObj, {});
		}

		return bFound;
	}

	bool IScanner::CDB_IsDriverExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB driver scan started! Target: %s", stTargetName.c_str());

		auto bFound = false;

		const auto stCorrectLowerName = stdext::to_lower_wide(stTargetName);

		CApplication::Instance().ScannerInstance()->EnumerateDrivers([&](std::shared_ptr <SDriverScanContext> ctx) {
			if (IS_VALID_SMART_PTR(ctx))
			{
				const auto wstCurrLowerName = stdext::to_lower_wide(ctx->wstExecutable);
				if (wstCurrLowerName.find(stCorrectLowerName) != std::wstring::npos)
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted driver found: %s", ctx->wstExecutable.c_str());
					CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, ctx->wstExecutable);
					bFound = true;
					return false;
				}
			}
			return true;
		});

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SCommonQuarentineHandler svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.data = stTargetName;

			CApplication::Instance().QuarentineInstance()->DriverFileNameQuarentine()->SetBlacklisted(svcObj, {});
		}

		return bFound;
	}

	bool IScanner::CDB_IsDriverExistByHash(const SCDBBaseContext& kContext, const std::wstring& stTargetHash)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB driver hash scan started! Target: %s", stTargetHash.c_str());

		auto bFound = false;

		const auto stCorrectLowerHash = stdext::to_lower_wide(stTargetHash);

		CApplication::Instance().ScannerInstance()->EnumerateDrivers([&](std::shared_ptr <SDriverScanContext> ctx) {
			if (IS_VALID_SMART_PTR(ctx))
			{
				if (!ctx->wstExecutable.empty())
				{
					if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(ctx->wstExecutable))
					{
						const auto stServiceCurrentHash = stdext::to_lower_wide(
							NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(ctx->wstExecutable)
						);
						
						if (stServiceCurrentHash == stCorrectLowerHash)
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted driver hash found: %s", stCorrectLowerHash.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
							bFound = true;
							return false;
						}
					}
				}
			}
			return true;
		});

		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SFileCheckObjects svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.sha1 = stTargetHash;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(svcObj, {});
		}

		return bFound;
	}

	bool IScanner::CDB_IsCertContextExist(const SCDBBaseContext& kContext, const std::wstring& stProvider, const std::wstring& stSerial)
	{
		auto fnIsCertPresent = [](const std::wstring& stFilename, const std::wstring& stProvider, const std::wstring& stSerial) {
			// TODO: CACHE

			const auto dwSignCheckRet = PeSignatureVerifier::CheckFileSignature(stFilename, false); // TODO: convertSignInfo(lRetVal)
			if (dwSignCheckRet == ERROR_SUCCESS)
			{
				CryptoApiWrapper::SignerInfoPtr si;
				const auto dwCertQueryRet = PeSignatureVerifier::GetCertificateInfo(stFilename, si);
				
				const auto dwErrorCode = g_winAPIs->GetLastError();
				if (dwCertQueryRet != ERROR_SUCCESS)
				{
					APP_TRACE_LOG(LL_ERR, L"Signature provider query failed in step1! Error: %u/%p", dwCertQueryRet, dwCertQueryRet);
				}
				else if (!IS_VALID_SMART_PTR(si))
				{
					APP_TRACE_LOG(LL_ERR, L"Signature provider query failed in step2! Error: %u/%p", dwErrorCode, dwErrorCode);
				}
				else
				{
					const auto wstCurrProvider = stdext::to_lower_wide(si->subjectName);
					const auto wstCurrSerial = stdext::to_lower_wide(si->serialNumber);

					const auto bProviderMatched = !stProvider.empty() && stProvider == wstCurrProvider;
					const auto bSerialMatched = !stSerial.empty() && stSerial == wstCurrSerial;

					if (bProviderMatched || bSerialMatched)
					{
						APP_TRACE_LOG(LL_WARN, L"Matched cert ctx! Provider: %s(%d) Serial: %s(%d)",
							wstCurrProvider.c_str(), bProviderMatched ? 1 : 0, wstCurrSerial.c_str(), bSerialMatched ? 1 : 0
						);
						return true;
					}
				}
			}
			else
			{
				const auto dwErrorLevel = dwSignCheckRet == ERROR_NOT_FOUND ? LL_WARN : LL_ERR;
				APP_TRACE_LOG(dwErrorLevel, L"CheckFileSignature failed with error: %u", dwSignCheckRet);
			}
			return false;
		};

		APP_TRACE_LOG(LL_SYS, L"Cheat DB cert ctx scan started! Target: '%s'/'%s'", stProvider.c_str(), stSerial.c_str());

		auto bFound = false;

		const auto stTargetLowerProvider = stdext::to_lower_wide(stProvider);
		const auto stTargetLowerSerial = stdext::to_lower_wide(stSerial);
		
		// Process
		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			auto vProcs = upProcEnumerator->EnumerateProcesses();
			for (auto hProc : vProcs)
			{
				if (IS_VALID_HANDLE(hProc))
				{
					const auto szProcName = CProcessFunctions::GetProcessName(hProc);
					if (!szProcName.empty() && NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(szProcName))
					{
						if (fnIsCertPresent(szProcName, stTargetLowerProvider, stTargetLowerSerial))
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted cert found in a process: %s", szProcName.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, fmt::format(xorstr_(L"{}-{}\\{}"), szProcName, stProvider, stSerial));
							upProcEnumerator.reset();
							bFound = true;
							return false;
						}
					}
				}
			}
			upProcEnumerator.reset();
		}

		// Service
		if (!bFound && !kContext.bIsListed)
		{
			CApplication::Instance().ScannerInstance()->EnumerateServices([&](std::shared_ptr <SServiceScanContext> ctx) {
				if (IS_VALID_SMART_PTR(ctx))
				{
					if (ctx->dwServiceState == SERVICE_RUNNING)
					{
						if (!ctx->stServiceExecutable.empty() &&
							NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(ctx->stServiceExecutable))
						{
							if (fnIsCertPresent(ctx->stServiceExecutable, stTargetLowerProvider, stTargetLowerSerial))
							{
								APP_TRACE_LOG(LL_WARN, L"Blacklisted cert found in a service: %s", ctx->stServiceExecutable.c_str());
								CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, fmt::format(xorstr_(L"{}-{}\\{}"), ctx->stServiceExecutable, stProvider, stSerial));
								bFound = true;
								return false;
							}
						}
					}
				}
				return true;
			});
		}

		// Driver
		if (!bFound && !kContext.bIsListed)
		{
			CApplication::Instance().ScannerInstance()->EnumerateDrivers([&](std::shared_ptr <SDriverScanContext> ctx) {
				if (IS_VALID_SMART_PTR(ctx))
				{
					if (!ctx->wstExecutable.empty() &&
						NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(ctx->wstExecutable))
					{
						if (fnIsCertPresent(ctx->wstExecutable, stTargetLowerProvider, stTargetLowerSerial))
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted cert found in a driver: %s", ctx->wstExecutable.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, fmt::format(xorstr_(L"{}-{}\\{}"), ctx->wstExecutable, stProvider, stSerial));
							bFound = true;
							return false;
						}
					}
				}
				return true;
			});
		}

#if 0
		// Root certs
		if (!bFound && !kContext.bIsListed)
		{
			std::vector <CERT_SEARCH_DATA> searchData;
			std::vector <FindData> found;
			std::vector <FailInfo> fails;
			PeSignatureVerifier::checkCertificates(searchData, &found, &fails);

			for (const auto& [id, data] : found)
			{
				for (const auto& ctx : data)
				{
					/*
					if (fnIsCertPresent(szProcName, stTargetLowerProvider, stTargetLowerSerial))
					{
						APP_TRACE_LOG(LL_WARN, L"Blacklisted cert found in a root: %s", ctx->wstExecutable.c_str());
						CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed);
							bFound = true;
							return false;
					}
					*/
				}
			}

			__nop();
		}
#endif

		// Quarentine
		if (!bFound && !kContext.bIsListed)
		{
			// Add to quarentine
			SFileCheckObjects svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.cert_provider = stProvider;
			svcObj.cert_serial = stSerial;

			CApplication::Instance().QuarentineInstance()->FileQuarentine()->SetBlacklisted(svcObj, {});
		}

		return bFound;
	}

	bool IScanner::CDB_CheckWindowTextHeuristic(const SCDBBaseContext& kContext, const std::wstring& stLookedText)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB window heuristic scan started! Target: %s", stLookedText.c_str());

		const auto stLookedLowerStr = stdext::to_lower_wide(stLookedText);

		for (int qy = 0; qy < 100; qy++)
		{
			for (int qx = 0; qx < 100; qx++)
			{
				POINT p{ 0 };
				p.x = qx * 20;
				p.y = qy * 20;

				const auto hWnd = g_winAPIs->WindowFromPoint(p);
				if (!hWnd)
					continue;

				wchar_t wszWndTitle[MAX_PATH]{ '\0' };
				if (g_winAPIs->GetWindowTextW(hWnd, wszWndTitle, MAX_PATH) && wszWndTitle[0] != L'\0')
				{
					const auto wstWndTitle = stdext::to_lower_wide(wszWndTitle);
					if (!wstWndTitle.empty())
					{
						if (wstWndTitle.find(stLookedLowerStr) != std::wstring::npos)
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted window heuristic found: %s(%s)", wstWndTitle.c_str(), stLookedLowerStr.c_str());
							CApplication::Instance().ScannerInstance()->SendViolationNotification(kContext.dwListIndex, kContext.stID, kContext.bStreamed, wstWndTitle);
							return true;
						}
					}
				}
			}
		}

		if (!kContext.bIsListed)
		{
			// Add to quarentine
			SWindowCheckObjects svcObj{};
			svcObj.idx = sc_nCheatDBBlacklistIDBase + kContext.dwListIndex;
			svcObj.window_heuristic = stLookedText;

			CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetBlacklisted(svcObj, {});
		}

		return false;
	}

};
