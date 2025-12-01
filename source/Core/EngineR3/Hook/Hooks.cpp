#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Hooks.hpp"

namespace NoMercy
{
	CSelfApiHooks::CSelfApiHooks() :
		m_bHooksIsInitialized(false), m_lpDllNotificationCookie(nullptr), m_pvSingleStepWatcher(nullptr), m_bHooksIsInitializing(false)
	{
		m_upFilterData = std::make_unique<SFilterData>();
		m_spPageGuardHookHelper = std::make_shared<CPageGuardHook>();
	}

	bool CSelfApiHooks::PatchFunction(const std::string& stName, DWORD_PTR lpFunc, uint8_t type)
	{
		HOOK_LOG(LL_SYS, L"%hs (%p) func patch has been started! Type: %u", stName.c_str(), lpFunc, type);

		if (!lpFunc)
		{
			HOOK_LOG(LL_ERR, L"Invalid function address!");
			return false;
		}

		auto pOrigMem = CMemHelper::Allocate(10 * sizeof(BYTE));
		if (!pOrigMem)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_PATCH_API_ALLOCATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		auto nBackupSize = 0;

		if (type == RET_HOOK)
		{
			BYTE ret[6] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

			auto dwOldProtection = 0UL;
			if (!g_winAPIs->VirtualProtect(reinterpret_cast<LPVOID>(lpFunc), sizeof(ret), PAGE_EXECUTE_READWRITE, &dwOldProtection))
			{
				HOOK_LOG(LL_SYS, L"VirtualProtect (pre) failed with error: %u", g_winAPIs->GetLastError());
				CMemHelper::Free(pOrigMem);
				return false;
			}

			memcpy(pOrigMem, reinterpret_cast<LPVOID>(lpFunc), sizeof(ret));
			nBackupSize = sizeof(ret);
			memcpy((void*)(lpFunc), &ret, sizeof(ret));

			if (!g_winAPIs->VirtualProtect(reinterpret_cast<LPVOID>(lpFunc), sizeof(ret), dwOldProtection, &dwOldProtection))
			{
				HOOK_LOG(LL_SYS, L"VirtualProtect (post) failed with error: %u", g_winAPIs->GetLastError());
				CMemHelper::Free(pOrigMem);
				return false;
			}
		}
		else if (type == NOP_HOOK)
		{
			BYTE ret[1] = { 0x90 };

			auto dwOldProtection = 0UL;
			if (!g_winAPIs->VirtualProtect(reinterpret_cast<LPVOID>(lpFunc), sizeof(ret), PAGE_EXECUTE_READWRITE, &dwOldProtection))
			{
				HOOK_LOG(LL_SYS, L"VirtualProtect (pre) failed with error: %u", g_winAPIs->GetLastError());
				CMemHelper::Free(pOrigMem);
				return false;
			}

			memcpy(pOrigMem, reinterpret_cast<LPVOID>(lpFunc), sizeof(ret));
			nBackupSize = sizeof(ret);
			memcpy((void*)(lpFunc), &ret, sizeof(ret));

			if (!g_winAPIs->VirtualProtect(reinterpret_cast<LPVOID>(lpFunc), sizeof(ret), dwOldProtection, &dwOldProtection))
			{
				HOOK_LOG(LL_SYS, L"VirtualProtect (post) failed with error: %u", g_winAPIs->GetLastError());
				CMemHelper::Free(pOrigMem);
				return false;
			}
		}

		auto spBackupData = stdext::make_shared_nothrow<SPatchBackup>();
		if (!spBackupData)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_PATCH_API_ALLOCATE_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		spBackupData->FuncName = stdext::to_wide(stName);
		spBackupData->Address = lpFunc;
		spBackupData->Backup = pOrigMem;
		spBackupData->BackupSize = nBackupSize;

		m_vecPatchs.emplace_back(spBackupData);

		HOOK_LOG(LL_SYS, L"%hs succesfuly banned! Type: %d", stName.c_str(), type);
		return true;
	}

	bool CSelfApiHooks::__BlockAPI(const std::wstring& module, const std::string& func, uint8_t type)
	{
		HOOK_LOG(LL_SYS, L"%s!%hs api block initilization has been start!", module.c_str(), func.c_str());

#ifdef _M_X64
		auto dwAddr = 0ULL;
#else
		auto dwAddr = 0UL;
#endif

		const std::wstring python = xorstr_(L"python");
		if (python == module)
			dwAddr = (DWORD_PTR)g_winAPIs->GetProcAddress_o(g_winModules->hPython, func.c_str());
		else
			dwAddr = (DWORD_PTR)g_winAPIs->GetProcAddress_o(g_winAPIs->GetModuleHandleW_o(module.c_str()), func.c_str());

		if (python != module && !dwAddr)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_PATCH_API_NOT_FOUND, g_winAPIs->GetLastError());
			return false;
		}
		
		return PatchFunction(func, dwAddr, type);
	}

	bool CSelfApiHooks::IsPatchedFunction(const std::wstring& stName)
	{
		for (auto& patch : m_vecPatchs)
		{
			if (patch->FuncName == stName)
				return true;
		}
		return false;
	}

	bool CSelfApiHooks::IsInitialized()
	{
		return m_bHooksIsInitialized;
	}

	bool CSelfApiHooks::InitializeSelfAPIHooks()
	{
		m_bHooksIsInitializing = true;

		m_upApcStorages = stdext::make_unique_nothrow<CApcRoutinesStorage>();
		if (!IS_VALID_SMART_PTR(m_upApcStorages))
		{
			APP_TRACE_LOG(LL_CRI, L"APC routines storage could not allocated with error: %u", g_winAPIs->GetLastError());
			return false;
		}

#ifndef _RELEASE_DEBUG_MODE_
		if (__InitializePatchs() == false)
		{
			//CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_PATCH_INIT_FAIL, g_winAPIs->GetLastError());
			//return false;
		}
#endif

		if (__InitializeDetours() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_DETOUR_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		if (InitDllNotificationCallback() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HOOK_DLL_NOTIFICATION_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		if (CApplication::Instance().MemAllocWatcherInstance()->InitializeThread() == false)
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_MEM_ALLOC_WATCHER_THREAD_INIT_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		// TODO:
		// InitializeSingleStepWatcher
		// InstallInstrumentationCallback
		
		APP_TRACE_LOG(LL_SYS, L"Self API hooks initialized successfully!");
		m_bHooksIsInitializing = false;
		m_bHooksIsInitialized = true;
		return true;
	}

	void CSelfApiHooks::ReleasePatchs()
	{
		for (const auto& spPatch : m_vecPatchs)
		{
			if (IS_VALID_SMART_PTR(spPatch))
			{
				auto pBackup = spPatch->Backup;
				if (spPatch->Address && pBackup)
				{
					__try
					{
						memcpy((void*)spPatch->Address, pBackup, spPatch->BackupSize);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
					}
					CMemHelper::Free(pBackup);
				}
			}
		}
		m_vecPatchs.clear();
	}

	void CSelfApiHooks::CleanupHooks()
	{
		if (!m_bHooksIsInitialized)
			return;
		m_bHooksIsInitialized = false;
		
		// FIXME
		// RtlpCallQueryRegistryRoutine / STATUS_THREADPOOL_HANDLE_EXCEPTION
		// ReleasePatchs();
		// ReleaseSelfAPIHooks();
		ReleaseDllNotificationCallback();
		CApplication::Instance().MemAllocWatcherInstance()->ReleaseThread();
		RemoveSyscallHooks();

		APP_TRACE_LOG(LL_SYS, L"Self API hooks cleaned up successfully!");
	}
};
