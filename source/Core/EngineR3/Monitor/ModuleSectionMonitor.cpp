#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ModuleSectionMonitor.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	CModuleSectionMonitor::CModuleSectionMonitor() :
		m_bIsInitialized(false)
	{
	}
	CModuleSectionMonitor::~CModuleSectionMonitor()
	{
	}

	bool CModuleSectionMonitor::IsAddedRegion(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize)
	{
		for (const auto& pCurrRegion : m_vRegions)
		{
			if (pCurrRegion->process == hProcess && pCurrRegion->base == lpSectionBase && pCurrRegion->size == cbSize)
				return true;
		}
		return false;
	}
	bool CModuleSectionMonitor::IsSkippedRegion(HANDLE hProcess, LPVOID lpSectionBase)
	{
		for (const auto& [hCurrProcess, pvCurMemBase] : m_mapSkippedList)
		{
			if (hCurrProcess == hProcess && pvCurMemBase == lpSectionBase)
				return true;
		}
		return false;
	}
	bool CModuleSectionMonitor::ValidateRegions()
	{
		if (m_vRegions.empty())
			return true;

		for (const auto& pCurrRegion : m_vRegions)
		{
			if (IsSkippedRegion(pCurrRegion->process, pCurrRegion->base))
				continue;

			const auto qwCurrChecksum = CPEFunctions::CalculateRemoteMemChecksumFast(pCurrRegion->process, pCurrRegion->base, pCurrRegion->size);
			if (!qwCurrChecksum)
			{
				APP_TRACE_LOG(LL_TRACE, L"Hash calculate failed for: %p / %p (%u)", pCurrRegion->process, pCurrRegion->base, pCurrRegion->size);
				m_mapSkippedList.emplace(pCurrRegion->process, pCurrRegion->base);
				continue;
			}

			const auto bCorrupted = pCurrRegion->checksum != qwCurrChecksum;
			if (bCorrupted)
			{
				MEMORY_BASIC_INFORMATION mbi{};
				const auto nVirtQueryRet = g_winAPIs->VirtualQueryEx(NtCurrentProcess(), pCurrRegion->base, &mbi, sizeof(mbi));

				std::wstring wstSymbolName;
				const auto bSymbolRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetFunctionNameFromAddress(NtCurrentProcess(), mbi.AllocationBase, pCurrRegion->base, wstSymbolName);

				const auto stOwner = CApplication::Instance().FunctionsInstance()->GetModuleOwnerName(NtCurrentProcess(), pCurrRegion->base);
				const auto bIsIgnored = mbi.Protect == PAGE_READWRITE && !bSymbolRet && stOwner.empty();
				APP_TRACE_LOG(mbi.Protect == PAGE_READWRITE ? LL_TRACE : LL_CRI,
					L"Corrupted memory! Current base: %p Size: %u Current sum: %llu Corrent sum: %llu Eq: %d Owner: '%s' VQ: %u Protect: %u Func: '%s' (%d)",
					pCurrRegion->base, pCurrRegion->size, qwCurrChecksum, pCurrRegion->checksum, bCorrupted ? 0 : 1, stOwner.c_str(),
					nVirtQueryRet, mbi.Protect, wstSymbolName.c_str(), bSymbolRet
				);

				if (bIsIgnored)
				{
					// Add to skipped list
					m_mapSkippedList.emplace(pCurrRegion->process, pCurrRegion->base);
				}
				else
				{
					return false;
				}
			}
		}
		
		return true;
	}
	void CModuleSectionMonitor::AddToCheckList(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize)
	{
		if (IsAddedRegion(hProcess, lpSectionBase, cbSize))
			return;

		const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
		APP_TRACE_LOG(LL_SYS, L"Target process: %p (%u) Section: %p (%p)", hProcess, dwProcessID, lpSectionBase, cbSize);

		const auto qwChecksum = CPEFunctions::CalculateRemoteMemChecksumFast(hProcess, lpSectionBase, cbSize);
		if (!qwChecksum)
		{
			APP_TRACE_LOG(LL_WARN, L"Hash calculation for: %p (%u) failed in process: %p (%u)", lpSectionBase, cbSize, hProcess, dwProcessID);
			return;
		}

		APP_TRACE_LOG(LL_TRACE, L"Section added to check list! Base: %p Size: %p Sum: %p", lpSectionBase, cbSize, qwChecksum);

		auto softBPInfos = stdext::make_shared_nothrow<SModuleSectionData>();
		if (softBPInfos)
		{
			softBPInfos->process = hProcess;
			softBPInfos->base = lpSectionBase;
			softBPInfos->size = cbSize;
			softBPInfos->checksum = qwChecksum;
			
			m_vRegions.emplace_back(softBPInfos);
		}
	}
	bool CModuleSectionMonitor::ScanModuleFileSections(HANDLE hProcess, LPVOID lpModuleBase, const std::wstring& wstBaseName)
	{
		const auto lpBuffer = CMemHelper::Allocate(0x1000);
		if (!lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"Memory allocation failed with error code: %u", g_winAPIs->GetLastError());
			return false;
		}

		SIZE_T cbReadSize = 0;
		const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
			hProcess, lpModuleBase, lpBuffer, 0x1000, &cbReadSize
		);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(ntStatus == STATUS_PARTIAL_COPY ? LL_WARN : LL_ERR, L"Memory: %p read failed with status: %p", lpModuleBase, ntStatus);
			CMemHelper::Free(lpBuffer);
			return false;
		}

		APP_TRACE_LOG(LL_TRACE, L"Routine started for: %p (%u) / %p -> %ls", hProcess, g_winAPIs->GetProcessId(hProcess), lpModuleBase, wstBaseName.c_str());

		const auto PIDH = (PIMAGE_DOS_HEADER)lpBuffer;
		if (!PIDH || PIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return true;
//			CApplication::Instance().OnCloseRequest(EXIT_ERR_SECTION_SCAN_MEM_NOT_VALID, 1);
//			return false;
		}

		const auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)lpBuffer + PIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SECTION_SCAN_MEM_NOT_VALID, 2);
			return false;
		}

		const auto pIFH = (PIMAGE_FILE_HEADER)&pINH->FileHeader;
		if (!pIFH)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SECTION_SCAN_MEM_NOT_VALID, 3);
			return false;
		}

		const auto pISH = IMAGE_FIRST_SECTION(pINH);
		if (!pISH)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_SECTION_SCAN_MEM_NOT_VALID, 4);
			return false;
		}

		const auto nSectionNumber = pIFH->NumberOfSections;
#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"%u section found!", nSectionNumber);
#endif

		for (std::size_t i = 0; i < nSectionNumber; ++i)
		{
			auto pCurrSection = pISH[i];
#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Current section: %hs Base: %p Size: %u", (char*)pCurrSection.Name, (DWORD_PTR)lpModuleBase + pCurrSection.VirtualAddress, pCurrSection.Misc.VirtualSize);
#endif

			const auto IsMonitored =
				(pCurrSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrSection.Characteristics & IMAGE_SCN_MEM_READ) &&
				(pCurrSection.Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrSection.Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

			if (IsMonitored)
			{
#ifdef _DEBUG
				APP_TRACE_LOG(LL_SYS, L"Section: %s suitable for check!", (char*)pCurrSection.Name);
#endif
				AddToCheckList(hProcess, (VOID*)((ULONG_PTR)lpBuffer + pCurrSection.VirtualAddress), pCurrSection.Misc.VirtualSize);
			}
		}

		CMemHelper::Free(lpBuffer);
		return true;
	}
	void CModuleSectionMonitor::AddProcessToCheckList(HANDLE hProcess)
	{
		std::vector <HMODULE> vModules;

		auto __AppendModule = [&](const DWORD dwProcessID, const std::wstring& stModuleName, const bool bOptional = false) {
			auto bFound = false;

			if (stModuleName.empty())
			{
				const auto pkBaseData = CProcessFunctions::GetProcessBaseData(dwProcessID);
				if (pkBaseData.pBaseAddress)
				{
					vModules.emplace_back((HMODULE)pkBaseData.pBaseAddress);
					return true;
				}
			}

//			/*
			CApplication::Instance().ScannerInstance()->EnumerateModules(hProcess, [&](std::shared_ptr <SModuleEnumContext> module) {
				if (IS_VALID_SMART_PTR(module))
				{
					if (module->pvBaseAddress && module->cbModuleSize)
					{
						const auto wstCurrentModuleName = stdext::to_lower_wide(module->wszModuleName);

						if (wstCurrentModuleName.find(stModuleName) != std::wstring::npos)
						{
							vModules.emplace_back((HMODULE)module->pvBaseAddress);
							bFound = true;
							return false;
						}
					}
				}
				return true;
			});
//			*/
			/*
			const auto hModule = CProcessFunctions::GetModuleHandle(dwProcessID, stModuleName);
			if (hModule)
			{
				vModules.emplace_back(hModule);
			}
			else if (!bOptional)
			*/
			if (!bOptional && !bFound)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s could not found in process: %u", stModuleName.c_str(), dwProcessID);
				return false;
			}

			return true;
		};

		const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
		APP_TRACE_LOG(LL_SYS, L"Module section monitor will start process: %p (%u)", hProcess, dwProcessID);

		const auto stExecutable = CProcessFunctions::GetProcessName(hProcess);
		if (stExecutable.empty())
			CApplication::Instance().OnCloseRequest(EXIT_ERR_GET_PROCESS_NAME_FAIL, g_winAPIs->GetLastError());

		// Host executable
		if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsPackedExecutable(stExecutable))
			__AppendModule(dwProcessID, L"");

		// Default system modules
		__AppendModule(dwProcessID, xorstr_(L"kernel32.dll"));
		__AppendModule(dwProcessID, xorstr_(L"ntdll.dll"));

		// Optional system modules
		if (g_winModules->hKernelbase)
			__AppendModule(dwProcessID, xorstr_(L"kernelbase.dll"));
		if (g_winModules->hWin32u)
			__AppendModule(dwProcessID, xorstr_(L"win32u.dll"));

		// Game modules
		__AppendModule(dwProcessID, xorstr_(L"python27.dll"), true);

		APP_TRACE_LOG(LL_SYS, L"Module section monitored list initialized. Size: %u for process: %u", vModules.size(), dwProcessID);

		if (!vModules.empty())
			m_mapCheckList.emplace(hProcess, vModules);
	}

	DWORD CModuleSectionMonitor::ModuleSectionMonitorRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Module section monitor check event has been started");

//		if (m_mapCheckList.empty())
//			return 0;

		// Scan 
		for (auto it = this->m_mapCheckList.begin(); it != this->m_mapCheckList.end(); ++it)
		{
			const auto hProcess = it->first;
			const auto vModules = it->second;

			CApplication::Instance().ScannerInstance()->EnumerateModules(hProcess, [&](std::shared_ptr <SModuleEnumContext> ctx) {
				if (IS_VALID_SMART_PTR(ctx))
				{
					if (stdext::in_vector(vModules, (HMODULE)ctx->pvBaseAddress))
					{
						APP_TRACE_LOG(LL_TRACE, L"Current module: %p (%s)", ctx->pvBaseAddress, ctx->wszModuleName);
						const auto module_name = stdext::to_lower_wide(ctx->wszModuleName);

						if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsPackedExecutable(module_name))
						{
							const auto bIsPython = module_name.find(xorstr_(L"python")) != std::wstring::npos;
							/*
							const auto bIsPython = g_winModules->hPython && g_winModules->hPython == (HMODULE)ctx->pvBaseAddress;
							if (!bIsPython)
							{
								const auto stExecutable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
								const auto stLowerExecutable = stdext::to_lower_wide(stExecutable);

								if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(module_name) &&
									stLowerExecutable != module_name)
								{
									APP_TRACE_LOG(LL_CRI, L"Module: %s is packed executable.", module_name.c_str());
									CApplication::Instance().OnCloseRequest(EXIT_ERR_UNVALIDATED_MEMORY_OWNER, 1, (void*)module_name.c_str());
								}
								return false;
							}
							*/
						}

						if (ctx->pvBaseAddress &&
							!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(module_name) &&
							(g_winModules->hBaseModule && g_winModules->hBaseModule != (HMODULE)ctx->pvBaseAddress) &&
							(g_winModules->hPython && g_winModules->hPython != (HMODULE)ctx->pvBaseAddress))
						{
							APP_TRACE_LOG(LL_CRI, L"Module: %s path corrupted.", module_name.c_str());
							CApplication::Instance().OnCloseRequest(EXIT_ERR_UNVALIDATED_MEMORY_OWNER, 2, (void*)module_name.c_str());
							return false;
						}

						// File sections
						ScanModuleFileSections(hProcess, (LPVOID)ctx->pvBaseAddress, ctx->wszModuleName);
						g_winAPIs->Sleep(10);
					}
				}
				return true;
			});
		}

		// Validate
		if (this->ValidateRegions() == false)
		{
			// TODO: Enable
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_MEMORY_REGION_2, g_winAPIs->GetLastError());
			return 0;
		}

		return 0;
	}

	DWORD WINAPI CModuleSectionMonitor::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CModuleSectionMonitor*>(lpParam);
		return This->ModuleSectionMonitorRoutine();
	}

	bool CModuleSectionMonitor::InitializeMonitorThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_MODULE_SECTION_MONITOR, StartThreadRoutine, (void*)this, 12000, false);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
	void CModuleSectionMonitor::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_MODULE_SECTION_MONITOR);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
