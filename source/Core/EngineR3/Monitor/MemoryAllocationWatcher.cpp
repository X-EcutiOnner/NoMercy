#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "MemoryAllocationWatcher.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"

#ifdef _WIN64
	#define START_ADDRESS (PVOID)0x00000000010000
	#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
	#define START_ADDRESS (PVOID)0x10000
	#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif

namespace NoMercy
{
	bool SearchForMapMatch(const std::map <PVOID, DWORD>& mapMemoryContainer, const PVOID pvBase, const DWORD dwSize)
	{
		for (const auto& it : mapMemoryContainer)
		{
			if (it.first == pvBase && it.second == dwSize)
				return true;
		}
		return false;
	}

	bool WatchMemoryAllocations(SMemWatcherCtx* pWatcher, const void* pMemBase, size_t cbLength, MEMORY_BASIC_INFORMATION* pMBI, int nSize)
	{
		if (!pWatcher || !pMemBase || !pMBI)
			return false;
			
		DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
		
		const void* end = (const void*)((const char*)pMemBase + cbLength);
		while (pMemBase < end && g_winAPIs->VirtualQuery(pMemBase, &pMBI[0], sizeof(*pMBI)) == sizeof(*pMBI))
		{
			MEMORY_BASIC_INFORMATION* i = &pMBI[0];
			if ((i->State != MEM_FREE || i->State != MEM_RELEASE) && i->Type & (MEM_IMAGE | MEM_PRIVATE) && i->Protect & mask)
			{
				if (!pWatcher->WasFilled)
				{
					if (!SearchForMapMatch(pWatcher->RegionInfo, i->BaseAddress, i->RegionSize))
						pWatcher->RegionInfo.insert(pWatcher->RegionInfo.begin(), std::pair<PVOID, DWORD>(i->BaseAddress, i->RegionSize));
				}
				else
				{
					if (!SearchForMapMatch(pWatcher->RegionInfo, i->BaseAddress, i->RegionSize))
						return true;
				}
			}
			
			pMemBase = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
		}

		return false;
	}
	
	bool DestroyThreadsAndFreeMemory(MEMORY_BASIC_INFORMATION* pMBI, const std::wstring& wstOwner)
	{
		static std::vector <PVOID> s_vecIgnoredPtrs;

		if (!pMBI)
			return false;
		if (stdext::in_vector(s_vecIgnoredPtrs, pMBI->BaseAddress))
			return true;

		auto wstLauncherExe = NoMercyCore::CApplication::Instance().DataInstance()->GetLauncherExecutable();
		wstLauncherExe = stdext::to_lower_wide(wstLauncherExe);
		const auto bIsEAC = wstLauncherExe.find(xorstr_(L"_eac.exe")) != std::wstring::npos;
		if (bIsEAC)
		{
			// Specific case for EAC

			if (wstOwner.empty() && pMBI->Protect == PAGE_EXECUTE_READWRITE && pMBI->RegionSize == 0x1000 && pMBI->State == MEM_COMMIT && pMBI->Type == MEM_PRIVATE)
			{
				APP_TRACE_LOG(LL_WARN, L"Skipping EAC memory region %p", pMBI->BaseAddress);

				s_vecIgnoredPtrs.emplace_back(pMBI->BaseAddress);
				return true;
			}
		}

		auto upThreadEnumerator = stdext::make_unique_nothrow<CThreadEnumerator>();
		if (IS_VALID_SMART_PTR(upThreadEnumerator))
		{
			auto vecThreads = upThreadEnumerator->EnumerateThreads(NtCurrentProcess());
			ADMIN_DEBUG_LOG(LL_SYS, L"%u thread found!", vecThreads.size());

			for (auto& hThread : vecThreads)
			{
				const auto dwThreadID = g_winAPIs->GetThreadId(hThread);
				if (dwThreadID && dwThreadID != g_winAPIs->GetCurrentThreadId())
				{
					g_winAPIs->SuspendThread(hThread);

					DWORD_PTR dwStartAddress = 0x0;
					auto ntStatus = g_winAPIs->NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(dwStartAddress), nullptr);

					g_winAPIs->ResumeThread(hThread);

					ADMIN_DEBUG_LOG(LL_WARN, L"Current thread: %u Start address: %p Query ret: %p", dwThreadID, dwStartAddress, ntStatus);

					if (NT_SUCCESS(ntStatus))
					{
						if (dwStartAddress >= (DWORD_PTR)pMBI->BaseAddress && dwStartAddress <= ((DWORD_PTR)pMBI->BaseAddress + pMBI->RegionSize))
						{
							APP_TRACE_LOG(LL_CRI, L"Remote thread %u (%s) is in the memory region, it's will be terminated!", dwThreadID, wstOwner.c_str());
							ntStatus = g_winAPIs->NtTerminateThread(hThread, 0);
							APP_TRACE_LOG(LL_WARN, L"Thread: %u terminate completed with status: %p", dwThreadID, ntStatus);
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread failed with error: %u", g_winAPIs->GetLastError());
					}
				}
			}
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"upThreadEnumerator allocation failed with error: %u", g_winAPIs->GetLastError());
		}

		wchar_t wszBaseMappedName[512 * 2]{ L'\0' };
		const auto dwBaseMappedNameSize = g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), pMBI->AllocationBase, wszBaseMappedName, 512);
		
		APP_TRACE_LOG(
			wstOwner.size() ? LL_CRI : LL_WARN,
			L"'%s'/'%s' owned memory region %p is going to be unmapped! Protect: %p Size: %p State: %p Type: %p Allocated area: %p Allocated protection: %p",
			wstOwner.c_str(), wszBaseMappedName, pMBI->BaseAddress, pMBI->Protect, pMBI->RegionSize, pMBI->State, pMBI->Type,
			pMBI->AllocationBase, pMBI->AllocationProtect
		);

		const auto ntStatus = g_winAPIs->NtUnmapViewOfSection(NtCurrentProcess(), pMBI->BaseAddress);
		APP_TRACE_LOG(LL_WARN, L"Memory region %p (%s) is unmap completed with status: %p", pMBI->BaseAddress, wstOwner.c_str(), ntStatus);

		if (!NT_SUCCESS(ntStatus))
		{
//			const auto bFreeRet = g_winAPIs->VirtualFree(pMBI->BaseAddress, 0, MEM_FREE);
//			APP_TRACE_LOG(LL_WARN, L"Memory region %p (%s) is free completed with status: %d", pMBI->BaseAddress, wstOwner.c_str(), bFreeRet);

			s_vecIgnoredPtrs.emplace_back(pMBI->BaseAddress);
		}

		return true;
	}
	
	bool ReportToCallback(MEMORY_BASIC_INFORMATION* pMBI, SMemWatcherCtx* pWatcher, EMemAllocDetectionType nDetectCode)
	{
		static std::vector <std::wstring> s_vecWhitelist;

		if (!pMBI || !pWatcher)
			return false;
		
		SMemGuardCtx guard{};
		guard.detectBy = nDetectCode;
		guard.mbi = *pMBI;
		
		wchar_t wszMappedName[512 * 2]{ L'\0' };
		const auto dwMappedNameSize = g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), pMBI->BaseAddress, wszMappedName, 512);
		APP_TRACE_LOG(LL_WARN, L"Memory region %p is mapped to %s(%u) Error: %u", pMBI->BaseAddress, wszMappedName, dwMappedNameSize, g_winAPIs->GetLastError());

		auto bWhitelisted = false;
		const auto wstFixedMappedName = stdext::to_lower_wide(CProcessFunctions::DosDevicePath2LogicalPath(wszMappedName));
		APP_TRACE_LOG(LL_SYS, L"Fixed name: %s", wstFixedMappedName.c_str());
	
		if (!wstFixedMappedName.empty())
		{
			if (stdext::in_vector(s_vecWhitelist, wstFixedMappedName))
				return false;

			if (CApplication::Instance().HookScannerInstance()->IsKnownTempModuleName(wstFixedMappedName))
			{
				APP_TRACE_LOG(LL_WARN, L"Module already loaded by hook scanner, skipped!");
				bWhitelisted = true;
			}
			else if (CApplication::Instance().MemAllocWatcherInstance()->IsWhitelistedObject(wstFixedMappedName))
			{
				APP_TRACE_LOG(LL_WARN, L"Module is whitelisted, skipped!");
				bWhitelisted = true;
			}
			else
			{
				const auto wstSysPath = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->SystemPath());
				const auto wstSysPath2 = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->SystemPath2());

				if (!wstSysPath.empty() && (stdext::starts_with(wstFixedMappedName, wstSysPath) || stdext::starts_with(wstFixedMappedName, wstSysPath2)))
				{
					const auto dwCheckSignRet = PeSignatureVerifier::CheckFileSignature(wstFixedMappedName, true);
					const auto dwSignStatus = TrustVerifyWrapper::convertSignInfo(dwCheckSignRet);

					APP_TRACE_LOG(LL_SYS, L"Module incoming from system path and trusted source, Sign ret: %u status: %u", dwCheckSignRet, dwSignStatus);
					if (dwSignStatus == SignStatus::Valid)
						bWhitelisted = true;
				}
			}
		}

		if (bWhitelisted)
		{
			s_vecWhitelist.push_back(wstFixedMappedName);
			return false;
		}

		auto action = pWatcher->callback ? pWatcher->callback(&guard) : false;
		APP_TRACE_LOG(LL_WARN, L"Module (%s) is not loaded from known sources, ACT: %d", wstFixedMappedName.c_str(), action);

		if (!action)
			DestroyThreadsAndFreeMemory(pMBI, wstFixedMappedName);
		
		return true;
	}

	CMemAllocWatcher::CMemAllocWatcher()
	{
	}
	CMemAllocWatcher::~CMemAllocWatcher()
	{
	}

	std::vector <std::wstring> CMemAllocWatcher::GetWhitelist()
	{
		std::lock_guard <std::mutex> __lock(m_mtxLock);

		return m_vecWhitelist;
	}

	bool CMemAllocWatcher::IsWhitelistedObject(const std::wstring& wstFilename, bool bShouldBeSigned)
	{
		if (wstFilename.empty())
			return true;

		auto wstLowerFilename = stdext::to_lower_wide(wstFilename);
		if (stdext::starts_with(wstLowerFilename, std::wstring(xorstr_(L"\\")))) // dos path style
			wstLowerFilename = CProcessFunctions::DosDevicePath2LogicalPath(wstLowerFilename.c_str());

		std::error_code ec{};
		if (!std::filesystem::exists(wstLowerFilename, ec))
		{
			APP_TRACE_LOG(LL_WARN, L"File: %s does not exist!", wstLowerFilename.c_str());
			return true; // ignore
		}

		APP_TRACE_LOG(LL_SYS, L"File: %s", wstLowerFilename.c_str());

		auto vecWhitelist = GetWhitelist();
		for (const auto& wstCurrFile : vecWhitelist)
		{
			const auto wstCurrLowerFile = stdext::to_lower_wide(wstCurrFile);
			if (wstLowerFilename.find(wstCurrLowerFile) != std::wstring::npos)
			{
				if (bShouldBeSigned)
				{
					const auto dwCheckSignRet = PeSignatureVerifier::CheckFileSignature(wstLowerFilename, true);
					const auto dwSignStatus = TrustVerifyWrapper::convertSignInfo(dwCheckSignRet);

					APP_TRACE_LOG(LL_SYS, L"File: %s Sign ret: %u status: %u", wstLowerFilename.c_str(), dwCheckSignRet, dwSignStatus);
					return dwSignStatus == SignStatus::Valid;
				}
				else
				{
					return true;
				}
			}
		}

		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(wstLowerFilename))
		{
			const auto vecwhitelist = std::vector <std::wstring>{
				xorstr_(L"python27.dll")
			};

			for (const auto& wstCurrFile : vecwhitelist)
			{
				const auto wstCurrLowerFile = stdext::to_lower_wide(wstCurrFile);
				if (wstLowerFilename.find(wstCurrLowerFile) != std::wstring::npos)
				{
					APP_TRACE_LOG(LL_WARN, L"#1 File: %s is whitelisted!", wstLowerFilename.c_str());
					return true;
				}
				if (wstLowerFilename.find(xorstr_(L"\\lib\\")) != std::wstring::npos)
				{
					const auto veclibwhitelist = std::vector <std::wstring>{
						xorstr_(L"unicodedata.pyd"),
						xorstr_(L"select.pyd"),
						xorstr_(L"socket.pyd"),
						xorstr_(L"pyexpat.pyd"),
					};

					for (const auto& wstCurrLibFile : veclibwhitelist)
					{
						const auto wstCurrLowerLibFile = stdext::to_lower_wide(wstCurrLibFile);
						if (wstLowerFilename.find(wstCurrLowerLibFile) != std::wstring::npos)
						{
							APP_TRACE_LOG(LL_WARN, L"#2 File: %s is whitelisted!", wstLowerFilename.c_str());
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	void CMemAllocWatcher::AppendMemoryRegion(PVOID pvBaseAddress, ULONG ulRegionSize)
	{
		// std::lock_guard <std::mutex> __lock(m_mtxLock);

		if (!SearchForMapMatch(m_pWatcherCtx.RegionInfo, pvBaseAddress, ulRegionSize))
			m_pWatcherCtx.RegionInfo.insert(m_pWatcherCtx.RegionInfo.begin(), std::pair <PVOID, DWORD>(pvBaseAddress, ulRegionSize));
	}

	void CMemAllocWatcher::SetCallback(MemoryGuardCallback kNotificationCallback)
	{
		// std::lock_guard <std::mutex> __lock(m_mtxLock);

		m_pWatcherCtx.callback = kNotificationCallback;
	}

	DWORD CMemAllocWatcher::MemAllocWatcherThreadProcessor(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Memory allocation watcher event has been started!");

		SMemWatcherCtx watcher;
		watcher.WasFilled = false;
		watcher.callback = nullptr;

		while (true)
		{
			MEMORY_BASIC_INFORMATION mbi{ 0 };
			auto IllegalAlloc = WatchMemoryAllocations(&watcher, START_ADDRESS, END_ADDRESS, &mbi, sizeof(mbi));

			watcher.WasFilled = true;

			if (IllegalAlloc)
				ReportToCallback(&mbi, &watcher, ByExternalAllocation);

			g_winAPIs->Sleep(3000);
		}

		return 0;
	}

	DWORD WINAPI CMemAllocWatcher::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CMemAllocWatcher*>(lpParam);
		return This->MemAllocWatcherThreadProcessor();
	}

	bool CMemAllocWatcher::InitializeThread()
	{
		m_vecWhitelist.emplace_back(xorstr_(L"NvCameraWhitelisting32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"NvCameraAllowlisting32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"nvapi.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"igdinfo32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"igc32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"intelcontrollib32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"igdumdim32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"igd9dxva32.dll"));
		m_vecWhitelist.emplace_back(xorstr_(L"bdcap32.dll"));

		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_MEM_ALLOC_WATCHER, StartThreadRoutine, (void*)this, 0, true);
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
	void CMemAllocWatcher::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_MEM_ALLOC_WATCHER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
