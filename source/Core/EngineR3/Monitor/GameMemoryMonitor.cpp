#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "GameMemoryMonitor.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	CGameMemoryMonitor::CGameMemoryMonitor() :
		m_bIsInitialized(false)
	{
	}
	CGameMemoryMonitor::~CGameMemoryMonitor()
	{
	}

	bool CGameMemoryMonitor::IsAddedRegion(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize)
	{
		for (const auto& pCurrRegion : m_vRegions)
		{
			if (pCurrRegion->process == hProcess && pCurrRegion->base == lpSectionBase && pCurrRegion->size == cbSize)
				return true;
		}
		return false;
	}
	bool CGameMemoryMonitor::ValidateRegions()
	{
		if (m_vRegions.empty())
			return true;

		for (const auto& pCurrRegion : m_vRegions)
		{
			const auto qwCurrChecksum = CPEFunctions::CalculateRemoteMemChecksumFast(pCurrRegion->process, pCurrRegion->base, pCurrRegion->size);
			if (!qwCurrChecksum)
			{
				APP_TRACE_LOG(LL_TRACE, L"Hash calculate failed for: %p / %p (%u)", pCurrRegion->process, pCurrRegion->base, pCurrRegion->size);
				continue;
			}

			const auto stLog = fmt::format(xorstr_(L"Current base: {} Size: {} Current sum: {} Corrent sum: {} Eq: {}"),
				fmt::ptr(pCurrRegion->base), pCurrRegion->size, fmt::ptr((PVOID64)qwCurrChecksum), fmt::ptr((PVOID64)pCurrRegion->checksum), qwCurrChecksum == pCurrRegion->checksum
			);
			if (pCurrRegion->checksum != qwCurrChecksum) // spam prevention
			{
				APP_TRACE_LOG(
					pCurrRegion->checksum == qwCurrChecksum ? LL_SYS : LL_CRI,
					L"%s",
					stLog.c_str()
				);
			}

			if (pCurrRegion->checksum != qwCurrChecksum)
			{
				const auto stOwner = CApplication::Instance().FunctionsInstance()->GetModuleOwnerName(NtCurrentProcess(), pCurrRegion->base);
				APP_TRACE_LOG(LL_ERR, L"Corrupted memory! Owner: %s", stOwner.c_str());
				return false;
			}
		}

		return true;
	}
	void CGameMemoryMonitor::AddToCheckList(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize)
	{
		if (IsAddedRegion(hProcess, lpSectionBase, cbSize))
			return;

		const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
		APP_TRACE_LOG(LL_SYS, L"Target section: %p (%u) - %p (%p)", hProcess, dwProcessID, lpSectionBase, cbSize);

		const auto qwChecksum = CPEFunctions::CalculateRemoteMemChecksumFast(hProcess, lpSectionBase, cbSize);
		if (!qwChecksum)
		{
			APP_TRACE_LOG(LL_WARN, L"Hash calculation for: %p (%u) failed in process: %p (%u)", lpSectionBase, cbSize, hProcess, dwProcessID);
			return;
		}

		APP_TRACE_LOG(LL_SYS, L"Section added to check list! Base: %p Size: %p Sum: %p", lpSectionBase, cbSize, qwChecksum);

		auto softBPInfos = stdext::make_shared_nothrow<SGameRegionData>();
		if (softBPInfos)
		{
			softBPInfos->process = hProcess;
			softBPInfos->base = lpSectionBase;
			softBPInfos->size = cbSize;
			softBPInfos->checksum = qwChecksum;
			
			m_vRegions.emplace_back(softBPInfos);
		}
	}

	void CGameMemoryMonitor::AddProcessToCheckList(HANDLE hProcess)
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
		APP_TRACE_LOG(LL_SYS, L"Region monitor will start process: %p (%u)", hProcess, dwProcessID);

		const auto stExecutable = CProcessFunctions::GetProcessName(hProcess);
		if (stExecutable.empty())
			CApplication::Instance().OnCloseRequest(EXIT_ERR_GET_PROCESS_NAME_FAIL, g_winAPIs->GetLastError());

		// Host executable
		if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsPackedExecutable(stExecutable))
			__AppendModule(dwProcessID, L"");

		// Default system modules
		__AppendModule(dwProcessID, xorstr_(L"kernel32.dll"));
		__AppendModule(dwProcessID, xorstr_(L"ntdll.dll"));
		__AppendModule(dwProcessID, xorstr_(L"user32.dll"));

		// Optional system modules
		if (g_winModules->hKernelbase)
			__AppendModule(dwProcessID, xorstr_(L"kernelbase.dll"));
		if (g_winModules->hWin32u)
			__AppendModule(dwProcessID, xorstr_(L"win32u.dll"));

		// Game modules
//		__AppendModule(dwProcessID, xorstr_(L"python27.dll"), true);

		APP_TRACE_LOG(LL_SYS, L"Region monitored module list initialized. Size: %u for process: %u", vModules.size(), dwProcessID);

		if (!vModules.empty())
			m_mapCheckList.emplace(hProcess, vModules);
	}

	DWORD CGameMemoryMonitor::RegionMonitorRoutine(void)
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		constexpr auto LOG_LEVEL = LL_SYS;
		static CStopWatch <std::chrono::milliseconds> s_sw;
#else
		constexpr auto LOG_LEVEL = LL_TRACE;
#endif
		APP_TRACE_LOG(LOG_LEVEL, L"Region monitor check event has been started");

//		if (m_mapCheckList.empty())
//			return 0;

		// Scan 
		for (const auto& [hProcess, vModules] : m_mapCheckList)
		{
			const BYTE* baseAddress = 0;
			MEMORY_BASIC_INFORMATION basicInfo = { 0 };

			SIZE_T bufferSize = 0;
			while ((bufferSize = g_winAPIs->VirtualQueryEx(hProcess, baseAddress, &basicInfo, sizeof(basicInfo))) != 0)
			{
				if (std::find(vModules.begin(), vModules.end(), (HMODULE)basicInfo.AllocationBase) != vModules.end())
				{
					if (basicInfo.State == MEM_COMMIT && basicInfo.Protect != PAGE_NOACCESS && !(basicInfo.Protect & PAGE_GUARD))
					{
						if (basicInfo.Protect & PAGE_EXECUTE_READ || basicInfo.Protect & PAGE_EXECUTE_READWRITE || basicInfo.Protect & PAGE_EXECUTE_WRITECOPY)
						{
							// TODO: Check is backed by and image range, else terminate

							if (!(basicInfo.RegionSize > bufferSize && basicInfo.RegionSize > 16 * 1024 * 1024)) // should be less than 16 MB
							{
								this->AddToCheckList(hProcess, basicInfo.BaseAddress, basicInfo.RegionSize);
							}
						}
					}
				}

				baseAddress += basicInfo.RegionSize;
				g_winAPIs->Sleep(10);
			}
		}

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LOG_LEVEL, L"Region monitor check enumberation completed in %u ms", s_sw.diff());
#endif

		// Validate
		if (this->ValidateRegions() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_MEMORY_REGION, g_winAPIs->GetLastError());
			return 0;
		}

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		APP_TRACE_LOG(LOG_LEVEL, L"Region monitor check validation completed in %u ms", s_sw.diff());
		s_sw.reset();
#endif

		return 0;
	}

	DWORD WINAPI CGameMemoryMonitor::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CGameMemoryMonitor*>(lpParam);
		return This->RegionMonitorRoutine();
	}

	bool CGameMemoryMonitor::InitializeMonitorThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_MEMORY_MONITOR, StartThreadRoutine, (void*)this, 30000, false);
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
	void CGameMemoryMonitor::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_MEMORY_MONITOR);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
