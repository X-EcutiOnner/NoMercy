#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include <wow64pp.hpp>

#define ENUM_PROCESS_MODULES_LIMIT 0x800




namespace NoMercy
{
	std::vector <std::shared_ptr <SModuleEnumContext>> GetModuleList(HANDLE hProcess)
	{
		auto vOutput = std::vector <std::shared_ptr <SModuleEnumContext>>();
		const auto is_wow64 = stdext::is_wow64();

		auto iterate_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				SCANNER_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return;
			}

			NTSTATUS ntStat = 0;
			ULONG64 ul64ReadBytes = 0;

			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pPBI = { 0 };
			ntStat = g_winAPIs->NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_TRACE, L"NtWow64QueryInformationProcess64(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			wow64pp::defs::PEB_64 pPEB = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_TRACE, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			if (!pPEB.Ldr)
			{
				SCANNER_LOG(LL_ERR, L"Peb Loader data is null!");
				return;
			}

			wow64pp::defs::PEB_LDR_DATA_64 pPebLdrData = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pPEB.Ldr, &pPebLdrData, sizeof(pPebLdrData), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(2) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			auto iModuleCount = 0;
			auto iRetryCount = 0;

			auto Head = pPebLdrData.InLoadOrderModuleList.Flink;
			auto Node = Head;

			// CHECKME: Infinite loop
			//Head -= sizeof(wow64pp::defs::LIST_ENTRY_64);

			do
			{
				wow64pp::defs::LDR_DATA_TABLE_ENTRY_64 pCurrModule = { 0 };
				ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)Node, &pCurrModule, sizeof(pCurrModule), &ul64ReadBytes);

				if (NT_SUCCESS(ntStat))
				{
					if (pCurrModule.DllBase)
					{
						++iModuleCount;

						WCHAR wstrModuleName[MAX_PATH] = { L'\0' };

						ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pCurrModule.FullDllName.Buffer, &wstrModuleName, pCurrModule.FullDllName.Length, &ul64ReadBytes);
						if (!NT_SUCCESS(ntStat))
						{
							SCANNER_LOG(LL_ERR, L"ReadProcessMemory(4) fail! Target process: %p Status: %p", hProcess, ntStat);
							continue;
						}

						auto pCurrModuleCtx = stdext::make_shared_nothrow<SModuleEnumContext>();
						if (!IS_VALID_SMART_PTR(pCurrModuleCtx))
						{
							SCANNER_LOG(LL_ERR, L"Module enum context container can NOT allocated! Error: %u", g_winAPIs->GetLastError());
							return;
						}

						pCurrModuleCtx->pvBaseAddress = pCurrModule.DllBase;
						pCurrModuleCtx->cbModuleSize = pCurrModule.SizeOfImage;
						wcscpy(pCurrModuleCtx->wszModuleName, wstrModuleName);

						vOutput.push_back(pCurrModuleCtx);
					}
				}
				else
				{
					SCANNER_LOG(LL_ERR, L"ReadProcessMemory(3) fail! Target process: %p Status: %p", hProcess, ntStat);
					if (++iRetryCount == 3)
					{
						break;
					}
				}

				Node = pCurrModule.InLoadOrderLinks.Flink;

			} while (Head != Node && iModuleCount < ENUM_PROCESS_MODULES_LIMIT);
		};

		auto iterate_native = [&] {
			NTSTATUS ntStat = 0;
			SIZE_T cbReadBytes = 0;

			PROCESS_BASIC_INFORMATION pPBI = { 0 };
			ntStat = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_TRACE, L"NtQueryInformationProcess(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			PEB pPEB = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_TRACE, L"NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			if (!pPEB.Ldr)
			{
				SCANNER_LOG(LL_ERR, L"Peb Loader data is null!");
				return;
			}

			PEB_LDR_DATA pPebLdrData = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, pPEB.Ldr, &pPebLdrData, sizeof(pPebLdrData), &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"ReadProcessMemory(2) fail! Target process: %p Status: %p", hProcess, ntStat);
				return;
			}

			auto iModuleCount = 0;
			auto iRetryCount = 0;

			auto Head = pPebLdrData.InLoadOrderModuleList.Flink;
			auto Node = Head;

			// CHECKME: Infinite loop
			//Head -= sizeof(LIST_ENTRY);

			do
			{
				LDR_DATA_TABLE_ENTRY pCurrModule = { 0 };
				ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, Node, &pCurrModule, sizeof(pCurrModule), &cbReadBytes);

				if (NT_SUCCESS(ntStat))
				{
					if (pCurrModule.DllBase)
					{
						++iModuleCount;

						WCHAR wstrModuleName[MAX_PATH] = { L'\0' };
						ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, pCurrModule.FullDllName.Buffer, &wstrModuleName, pCurrModule.FullDllName.Length, &cbReadBytes);
						if (!NT_SUCCESS(ntStat))
						{
							SCANNER_LOG(LL_ERR, L"ReadProcessMemory(4) fail! Target process: %p Status: %p", hProcess, ntStat);
							continue;
						}

						auto pCurrModuleCtx = stdext::make_shared_nothrow<SModuleEnumContext>();
						if (!IS_VALID_SMART_PTR(pCurrModuleCtx))
						{
							SCANNER_LOG(LL_ERR, L"Module enum context container can NOT allocated! Error: %u", g_winAPIs->GetLastError());
							return;
						}

						pCurrModuleCtx->pvBaseAddress = (DWORD_PTR)pCurrModule.DllBase;
						pCurrModuleCtx->cbModuleSize = pCurrModule.SizeOfImage;
						wcscpy(pCurrModuleCtx->wszModuleName, wstrModuleName);

						vOutput.push_back(pCurrModuleCtx);
					}
				}
				else
				{
					SCANNER_LOG(LL_ERR, L"ReadProcessMemory(3) fail! Target process: %p Status: %p", hProcess, ntStat);
					if (++iRetryCount == 3)
					{
						break;
					}
				}

				Node = pCurrModule.InLoadOrderLinks.Flink;

			} while (Head != Node && iModuleCount < ENUM_PROCESS_MODULES_LIMIT);
		};

		if (is_wow64)
			iterate_wow64();
		
		iterate_native();
		return vOutput;
	}


	bool CheckModulePEHeaderHash(HANDLE hProcess, const std::wstring& szModuleName, PVOID pModuleDump, std::size_t cbHeaderSize)
	{
		APP_TRACE_LOG(LL_SYS, L"PE header check step started");

		const auto stBuffer = std::string((const char*)pModuleDump, cbHeaderSize);
		auto szCurrHash = stdext::to_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256(stBuffer));
		if (szCurrHash.empty())
		{
			// ...
		}

		APP_TRACE_LOG(LL_SYS, L"PE header hash check step completed");
		
		//	CApplication::Instance().QuarentineInstance()->CheckModulePeHeaderHash(szCurrHash);
		return true;
	}
	bool CheckModulePEHeaderWipe(HANDLE hProcess, const std::wstring& szModuleName, PVOID pModuleDump, std::size_t cbHeaderSize)
	{
		APP_TRACE_LOG(LL_SYS, L"PE header wipe check step started");
		
		BYTE pNullBuf[] = { 0x0 };
		if (!memcmp(pModuleDump, pNullBuf, cbHeaderSize))
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		APP_TRACE_LOG(LL_SYS, L"PE header wipe check step completed");
		return true;
	}
	bool CheckModulePEHeaderFill(HANDLE hProcess, const std::wstring& szModuleName, PVOID pModuleDump, std::size_t cbHeaderSize)
	{
		APP_TRACE_LOG(LL_SYS, L"PE header fake fill check step started");

		auto hFile = g_winAPIs->CreateFileW(szModuleName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		auto dwLastError = g_winAPIs->GetLastError();

		if (!IS_VALID_HANDLE(hFile))
		{
			SCANNER_LOG(LL_ERR, L"CreateFileA fail! File: '%s' Error: %u", szModuleName.c_str(), dwLastError);

			if (dwLastError != ERROR_ACCESS_DENIED && dwLastError != ERROR_SHARING_VIOLATION)
				return false;
			return true;
		}

		LARGE_INTEGER liFileSize;
		if (!g_winAPIs->GetFileSizeEx(hFile, &liFileSize))
		{
			SCANNER_LOG(LL_ERR, L"GetFileSizeEx fail! Error: %u", g_winAPIs->GetLastError());

			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pFileBuffer = CMemHelper::Allocate(liFileSize.LowPart);
		if (!pFileBuffer)
		{
			SCANNER_LOG(LL_ERR, L"Memory can NOT allocated! Error: %u", g_winAPIs->GetLastError());

			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		DWORD dwBytesRead;
		if (!g_winAPIs->ReadFile(hFile, pFileBuffer, liFileSize.LowPart, &dwBytesRead, NULL) || dwBytesRead != liFileSize.LowPart)
		{
			SCANNER_LOG(LL_ERR, L"ReadFile fail! Error: %u", g_winAPIs->GetLastError());

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pFileIDH = (IMAGE_DOS_HEADER*)pFileBuffer;
		if (pFileIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SCANNER_LOG(LL_ERR, L"File dos signature check fail!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pFileINH = (IMAGE_NT_HEADERS*)((BYTE*)pFileIDH + pFileIDH->e_lfanew);
		if (pFileINH->Signature != IMAGE_NT_SIGNATURE)
		{
			SCANNER_LOG(LL_ERR, L"File nt signature check fail!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pFileHeader = (IMAGE_OPTIONAL_HEADER32*)&pFileINH->OptionalHeader;
		if (!pFileHeader)
		{
			SCANNER_LOG(LL_ERR, L"File optional header not found!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pMemIDH = (IMAGE_DOS_HEADER*)pModuleDump;
		if (pMemIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SCANNER_LOG(LL_ERR, L"Mem dos signature check fail!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pMemINH = (IMAGE_NT_HEADERS*)((BYTE*)pMemIDH + pMemIDH->e_lfanew);
		if (pMemINH->Signature != IMAGE_NT_SIGNATURE)
		{
			SCANNER_LOG(LL_ERR, L"Mem nt signature check fail!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		auto pMemHeader = (IMAGE_OPTIONAL_HEADER32*)&pMemINH->OptionalHeader;
		if (!pMemHeader)
		{
			SCANNER_LOG(LL_ERR, L"File optional header not found!");

			CMemHelper::Free(pFileBuffer);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		if (pFileINH->FileHeader.TimeDateStamp != pMemINH->FileHeader.TimeDateStamp)
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		if (pFileHeader->SizeOfImage != pMemHeader->SizeOfImage)
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		if (pFileHeader->ImageBase != pMemHeader->ImageBase)
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		if (pFileHeader->SizeOfInitializedData != pMemHeader->SizeOfInitializedData)
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		CMemHelper::Free(pFileBuffer);
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hFile);
		APP_TRACE_LOG(LL_SYS, L"PE header fake fill check step completed");
		return true;
	}
	bool CheckModulePEHeaderDestroy(HANDLE hProcess, const std::wstring& szModuleName, LPCVOID pModuleBase, std::size_t cbHeaderSize)
	{
		APP_TRACE_LOG(LL_SYS, L"PE header destroy check step started");

		auto ntStat = NTSTATUS(0x0);

		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (!g_winAPIs->VirtualQueryEx(hProcess, pModuleBase, &mbi, sizeof(mbi)))
		{
			SCANNER_LOG(LL_ERR, L"NtQueryVirtualMemory fail! Target process: %p Status: %p", hProcess, ntStat);
			return false;
		}

		if (mbi.State == MEM_FREE)
		{
			//		CApplication::Instance().ScannerInstance()->SendViolationMessageToMasterServer();
		}

		APP_TRACE_LOG(LL_SYS, L"PE header destroy check step completed");
		return true;
	}
	bool IsUnlinkedModule(DWORD dwBase)
	{
		APP_TRACE_LOG(LL_SYS, L"Module unlink check step started");
		const auto bHasLoaded = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsLoadedModuleBase(dwBase);
		APP_TRACE_LOG(LL_SYS, L"Module unlink check step completed");
		return !bHasLoaded;
	}

	bool ScanModuleHeader(HANDLE hProcess, const std::wstring& szModuleName, LPCVOID pModuleBase, std::size_t cbModuleSize)
	{
		SCANNER_LOG(LL_SYS, L"Module header scan started! Target process: %p(%u) Module name: %s Module data: %p-%u",
			hProcess, g_winAPIs->GetProcessId(hProcess), szModuleName.c_str(), pModuleBase, cbModuleSize);

		auto bRet = false;

		auto dwReadSize = 0x1000;
		auto pModuleDump = CMemHelper::Allocate(dwReadSize);
		if (!pModuleDump)
		{
			SCANNER_LOG(LL_ERR, L"Memory can NOT allocated! Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		
		auto read_header_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				SCANNER_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return false;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return false;
			}

			ULONG64 ul64ReadBytes = 0;
			auto ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, PtrToPtr64(pModuleBase), pModuleDump, dwReadSize, &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			return true;
		};
		auto read_header_native = [&] {
			SIZE_T cbReadBytes = 0;
			auto ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)pModuleBase, pModuleDump, dwReadSize, &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtReadVirtualMemory fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			return true;
		};

		DWORD dwOldProtect = 0;
		if (!g_winAPIs->VirtualProtectEx(hProcess, (LPVOID)pModuleBase, dwReadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			SCANNER_LOG(LL_ERR, L"VirtualProtectEx failed with error: %u", g_winAPIs->GetLastError());
			CMemHelper::Free(pModuleDump);
			return false;
		}

		auto bReadRet = false;
		const auto is_wow64 = CApplication::Instance().FunctionsInstance()->IsWow64Process(NtCurrentProcess());
		if (is_wow64)
			bReadRet = read_header_wow64();
		else
			bReadRet = read_header_native();

		g_winAPIs->VirtualProtectEx(hProcess, (LPVOID)pModuleBase, dwReadSize, dwOldProtect, &dwOldProtect);

		if (!bReadRet)
			goto _Complete;

		size_t dwPEHeaderSize = 0;

		dwPEHeaderSize = CPEFunctions::GetPEHeaderSize(pModuleDump);
		if (!dwPEHeaderSize)
		{
			SCANNER_LOG(LL_ERR, L"PE Header size find fail!");
			goto _Complete;
		}

		SCANNER_LOG(LL_SYS, L"Module dump succesfully created! Base: %p Size: %u", pModuleDump, dwPEHeaderSize);

		if (!CheckModulePEHeaderDestroy(hProcess, szModuleName, pModuleBase, cbModuleSize))
		{
			SCANNER_LOG(LL_ERR, L"PE Header was destroyed!");
			goto _Complete;
		}
		if (!CheckModulePEHeaderWipe(hProcess, szModuleName, pModuleDump, dwPEHeaderSize))
		{
			SCANNER_LOG(LL_ERR, L"PE Header was wiped!");
			goto _Complete;
		}
		if (!CheckModulePEHeaderFill(hProcess, szModuleName, pModuleDump, dwPEHeaderSize))
		{
			SCANNER_LOG(LL_ERR, L"PE Header was fill'd with fake data!");
			goto _Complete;
		}
		if (!CheckModulePEHeaderHash(hProcess, szModuleName, pModuleDump, dwPEHeaderSize))
		{
			SCANNER_LOG(LL_ERR, L"PE Header hash blacklisted!");
			goto _Complete;
		}

		APP_TRACE_LOG(LL_SYS, L"Module header scan completed");
		bRet = true;

_Complete:
		if (pModuleDump)
			CMemHelper::Free(pModuleDump);
		return bRet;
	}

	bool ScanModuleInformations(HANDLE hProcess, const std::wstring& szModuleName, LPCVOID dwModuleBase, DWORD dwModuleSize)
	{
		APP_TRACE_LOG(LL_SYS, L"Module info scan started");

		auto pModuleDump = CMemHelper::Allocate(dwModuleSize);
		if (!pModuleDump)
		{
			SCANNER_LOG(LL_ERR, L"Memory can NOT allocated! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto read_module_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				SCANNER_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return false;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return false;
			}

			ULONG64 ul64ReadBytes = 0;
			auto ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, PtrToPtr64(dwModuleBase), pModuleDump, dwModuleSize, &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			return true;
		};
		auto read_module_native = [&] {
			SIZE_T cbReadBytes = 0;
			auto ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)dwModuleBase, pModuleDump, dwModuleSize, &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtReadVirtualMemory fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			return true;
		};

		auto bRet = false;
		auto szMemoryHash = std::wstring(L"");
		auto stBuffer = std::string("");

		// Dump module
		auto bReadRet = false;
		const auto is_wow64 = CApplication::Instance().FunctionsInstance()->IsWow64Process(NtCurrentProcess());
		if (is_wow64)
			bReadRet = read_module_wow64();
		else
			bReadRet = read_module_native();

		if (!bReadRet)
			goto _Complete;

		// Get module's memory hash
		stBuffer = std::string((const char*)pModuleDump, dwModuleSize);
		szMemoryHash = stdext::to_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256(stBuffer));
		if (szMemoryHash.empty())
		{
			SCANNER_LOG(LL_ERR, L"Memory hash can NOT generated! Error: %u", g_winAPIs->GetLastError());
			goto _Complete;
		}

		// TODO: check hash
		// TODO: check first 12 byte 

		APP_TRACE_LOG(LL_SYS, L"Module info scan completed");

		bRet = true;
_Complete:
		if (pModuleDump)
			CMemHelper::Free(pModuleDump);
		return bRet;
	}

	bool ScanModuleLinks(HANDLE hProcess, ptr_t c_pvModuleBase)
	{
		auto bFound = false;

		if (!IS_VALID_HANDLE(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Target handle is NOT valid!");
			return true;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Target process is NOT active!");
			return true;
		}

		const auto vModuleList = GetModuleList(hProcess);
		if (vModuleList.empty())
		{
			SCANNER_LOG(LL_ERR, L"Module list is NULL!");
			return false;
		}

		for (const auto& pCurrModule : vModuleList)
		{
			if (IS_VALID_SMART_PTR(pCurrModule))
			{
				if (pCurrModule->pvBaseAddress == (DWORD_PTR)c_pvModuleBase)
				{
					bFound = true;
				}
			}
		}

		if (bFound == false) // check alloc base and base is it equal 
		{
			// manually mapped or unlinked module found
			// todo throw
		}

		return true;
	}

	IModuleScanner::IModuleScanner()
	{
	}
	IModuleScanner::~IModuleScanner()
	{
	}

	bool IModuleScanner::IsScanned(std::wstring stModuleName)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_MODULE, stModuleName);
	}
	void IModuleScanner::AddScanned(std::wstring stModuleName)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_MODULE, stModuleName);
	}

	void IModuleScanner::OnScan(HANDLE hProcess, const std::wstring& szModuleName, LPCVOID dwModuleBase, DWORD dwModuleSize)
	{
		SCANNER_LOG(LL_TRACE, L"Module scanner has been started! Target module: %s(%p-%p) Target proc: %p(%u)",
			szModuleName.c_str(), dwModuleBase, dwModuleSize, hProcess, g_winAPIs->GetProcessId(hProcess)
		);

		if (IsScanned(szModuleName))
			return;

		// Add to checked list
		AddScanned(szModuleName);

		// Enable FS redirection
		PVOID OldValue = nullptr;
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			SCANNER_LOG(LL_ERR, L"FS redirection enable failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		// Check file exist in disk
		if (!std::filesystem::exists(szModuleName))
		{
			SCANNER_LOG(LL_ERR, L"Module file: %s does not exist!", szModuleName.c_str());
			return;			// TODO: throw
		}

		// Scan module header
		ScanModuleHeader(hProcess, szModuleName, dwModuleBase, dwModuleSize);

		// Scan module memory hash
		ScanModuleInformations(hProcess, szModuleName, dwModuleBase, dwModuleSize);

		// Disable FS redirection
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);

		// Redirect to file scan
		CApplication::Instance().ScannerInstance()->FileScanner()->Scan(szModuleName, FILE_SCAN_TYPE_MODULE);
	}

	bool IScanner::EnumerateModules(HANDLE hProcess, std::function<bool(std::shared_ptr <SModuleEnumContext>)> cb)
	{
		SCANNER_LOG(LL_TRACE, L"Module enumerator has been started!");

		if (!cb)
			return false;

		const auto vModuleList = GetModuleList(hProcess);
		if (vModuleList.empty())
		{
			SCANNER_LOG(LL_TRACE, L"Module list is NULL!");
			return false;
		}

		for (const auto& pCurrModule : vModuleList)
		{
			if (IS_VALID_SMART_PTR(pCurrModule))
			{
				if (!cb(pCurrModule))
					break;
			}
		}

		return true;
	}

	void IModuleScanner::ScanSync(std::wstring stModulePath)
	{
		return;
	}
	bool IModuleScanner::ScanAll()
	{
		return true;
	}

	bool IModuleScanner::ScanProcessModules(HANDLE hProcess)
	{
		SCANNER_LOG(LL_SYS, L"Module scanner has been started! Target process: %u(%p)", g_winAPIs->GetProcessId(hProcess), hProcess);

		if (!IS_VALID_HANDLE(hProcess))
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

		return CApplication::Instance().ScannerInstance()->EnumerateModules(hProcess, [&](std::shared_ptr <SModuleEnumContext> pCurrModule) {
			OnScan(hProcess, stdext::to_lower_wide(pCurrModule->wszModuleName), (LPCVOID)pCurrModule->pvBaseAddress, pCurrModule->cbModuleSize);
			return true;
		});
	}
};
