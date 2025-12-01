#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Hooks.hpp"
#include "PageGuardHook.hpp"

#define INITIAL_HOOK_CAPACITY   32
#define INVALID_HOOK_POS UINT_MAX

namespace NoMercy
{
	struct
	{
		SHookEntry* pkItems{ nullptr };
		UINT        nCapacity{ 0 };
		UINT        nSize{ 0 };
	} g_hooks;

	static LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
	{
		if (!CApplication::InstancePtr() ||
			!IS_VALID_SMART_PTR(CApplication::Instance().SelfHooksInstance()) ||
#ifndef _DEBUG
			!CApplication::Instance().AppIsInitiliazed() ||
			!CApplication::Instance().SelfHooksInstance()->IsInitialized() ||
#endif
			!IS_VALID_SMART_PTR(CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper())
			)
		{
			return EXCEPTION_CONTINUE_SEARCH; // Process is not initialized yet
		}
		
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			const auto lpDetour = CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper()->HandlePageGuard(ExceptionInfo->ExceptionRecord->ExceptionAddress);
			if (lpDetour)
			{
#if defined(_M_X64) || defined(__x86_64__)
				ExceptionInfo->ContextRecord->Rip = (DWORD64)lpDetour;
#else
				ExceptionInfo->ContextRecord->Eip = (DWORD)lpDetour;
#endif
			}

			// Set single step flag
			ExceptionInfo->ContextRecord->EFlags |= 0x100; 

			// Continue execution
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		{
			CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper()->RefreshALLHooks();

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	
	CPageGuardHook::CPageGuardHook() :
		m_hExceptionHandler(nullptr), m_hHeap(nullptr)
	{
	}
	CPageGuardHook::~CPageGuardHook()
	{
	}
	
	bool CPageGuardHook::Initialize()
	{
		if (!m_hHeap)
		{
			m_hHeap = g_winAPIs->HeapCreate(0, 0, 0);
			if (!m_hHeap)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to create heap with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}
		
		if (!m_hExceptionHandler)
		{
			m_hExceptionHandler = g_winAPIs->AddVectoredExceptionHandler(true, &ExceptionHandler);
			if (!m_hExceptionHandler)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to add vectored exception handler with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}
		
		return true;
	}
	bool CPageGuardHook::Uninitialize()
	{
		bool status = true;

		if (m_hExceptionHandler)
		{
			status = g_winAPIs->RemoveVectoredExceptionHandler(m_hExceptionHandler);
			m_hExceptionHandler = nullptr;
		}

		if (m_hHeap)
		{
			status = this->EnableALLHooks(false) && status;

			g_winAPIs->HeapFree(m_hHeap, 0, g_hooks.pkItems);
			g_winAPIs->HeapDestroy(m_hHeap);

			m_hHeap = nullptr;

			g_hooks.pkItems = nullptr;
			g_hooks.nCapacity = 0;
			g_hooks.nSize = 0;
		}

		return status;
	}
	
	bool CPageGuardHook::CreateHook(LPVOID pTarget, LPVOID pDetour)
	{
		if (!pTarget || !pDetour)
			return false;

		const auto pos = FindHookEntry(pTarget);
		if (pos == INVALID_HOOK_POS)
		{
			auto pHook = AddHookEntry();
			pHook->bActive = false;
			pHook->pTarget = pTarget;
			pHook->pDetour = pDetour;
		}
		return true;
	}
	bool CPageGuardHook::EnableHook(LPVOID pTarget)
	{
		if (!pTarget)
			return EnableALLHooks(true);

		return EnableHookEx(pTarget, true);
	}
	bool CPageGuardHook::DisableHook(LPVOID pTarget)
	{
		return EnableHookEx(pTarget, false);
	}
	void CPageGuardHook::RefreshHook(LPVOID pTarget)
	{
		UINT pos = FindHookEntry(pTarget);

		if (pos != INVALID_HOOK_POS)
			RefreshHookEx(pos);
	}

	LPVOID CPageGuardHook::HandlePageGuard(LPVOID pAddress)
	{
		for (auto i = 0u; i < g_hooks.nSize; ++i)
		{
			auto pHook = &g_hooks.pkItems[i];
			if (pHook->bActive && pHook->pTarget == pAddress)
				return pHook->pDetour;
		}

		return nullptr;
	}

	bool CPageGuardHook::EnableALLHooks(bool enable)
	{
		bool status = true;
		UINT first = INVALID_HOOK_POS;

		for (auto i = 0u; i < g_hooks.nSize; ++i)
		{
			if (g_hooks.pkItems[i].bActive != enable)
			{
				first = i;
				break;
			}
		}

		if (first != INVALID_HOOK_POS)
		{
			for (auto i = 0u; i < g_hooks.nSize; ++i)
			{
				if (g_hooks.pkItems[i].bActive != enable)
				{
					status = EnableHookEx(i, enable);
					if (!status)
						break;
				}
			}
		}

		return status;
	}
	void CPageGuardHook::RefreshALLHooks()
	{
		for (auto i = 0u; i < g_hooks.nSize; ++i)
		{
			if (g_hooks.pkItems[i].bActive)
			{
				RefreshHookEx(i);
			}
		}
	}

	bool CPageGuardHook::EnableHookEx(LPVOID pTarget, bool bEnable)
	{
		auto pos = FindHookEntry(pTarget);
		if (pos != INVALID_HOOK_POS)
			return EnableHookEx(pos, bEnable);

		return false;
	}
	void CPageGuardHook::RefreshHookEx(UINT pos)
	{
		auto pHook = &g_hooks.pkItems[pos];
		if (pHook->bActive)
			GuardEntry(pHook);
	}
	bool CPageGuardHook::EnableHookEx(UINT pos, bool enable)
	{
		auto pHook = &g_hooks.pkItems[pos];
		
		if (pHook->bActive != enable)
			pHook->bActive = enable;

		if (enable)
		{
			GuardEntry(pHook);

			if (!IsPageGuarded(pHook->pTarget))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to guard page at address: 0x%p", pHook->pTarget);
				return false;
			}
		}
		
		return true;
	}
	bool CPageGuardHook::GuardEntry(SHookEntry* pEntry)
	{
		DWORD dwCurrProt = 0;
		if (!GetPageProtection(pEntry->pTarget, &dwCurrProt))
			return false;

		if (dwCurrProt & PAGE_GUARD)
			return true;

		return ProtectPage(pEntry->pTarget, dwCurrProt | PAGE_GUARD, nullptr);
	}
	bool CPageGuardHook::IsPageGuarded(LPVOID pTarget)
	{
		DWORD dwCurrProt = 0;
		if (!GetPageProtection(pTarget, &dwCurrProt))
			return false;

		return dwCurrProt & PAGE_GUARD;
	}
	bool CPageGuardHook::ProtectPage(PVOID address, DWORD protection, PDWORD oldProtect)
	{
		if (!oldProtect)
		{
			DWORD dwOldProtection = 0;
			return g_winAPIs->VirtualProtect(address, 1, protection, &dwOldProtection);
		}

		return g_winAPIs->VirtualProtect(address, 1, protection, oldProtect);
	}
	bool CPageGuardHook::GetPageProtection(LPVOID pTarget, PDWORD pProtection)
	{
		if (!pProtection)
			return false;

		SPageEntry kEntry = { 0 };
		if (!QueryPage(pTarget, &kEntry))
			return false;

		*pProtection = kEntry.Protection;
		return true;
	}
	bool CPageGuardHook::QueryPage(LPVOID pTarget, SPageEntry* pEntry)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		const auto nSize = g_winAPIs->VirtualQuery(pTarget, &mbi, sizeof(mbi));
		if (!nSize)
			return false;

		pEntry->BaseAddress = mbi.BaseAddress;
		pEntry->RegionSize = mbi.RegionSize;
		pEntry->Protection = mbi.Protect;
		return true;
	}
	SHookEntry* CPageGuardHook::AddHookEntry()
	{
		if (!g_hooks.pkItems)
		{
			g_hooks.nCapacity = INITIAL_HOOK_CAPACITY;
			g_hooks.pkItems = (SHookEntry*)g_winAPIs->HeapAlloc(m_hHeap, 0, g_hooks.nCapacity * sizeof(SHookEntry));
			if (!g_hooks.pkItems)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for hook entries with error: %u", g_winAPIs->GetLastError());
				return nullptr;
			}
		}
		else if (g_hooks.nSize >= g_hooks.nCapacity)
		{
			auto p = (SHookEntry*)g_winAPIs->HeapReAlloc(m_hHeap, 0, g_hooks.pkItems, (g_hooks.nCapacity * 2) * sizeof(SHookEntry));
			if (!p)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to reallocate memory for hook entries with error: %u", g_winAPIs->GetLastError());
				return nullptr;
			}

			g_hooks.nCapacity *= 2;
			g_hooks.pkItems = p;
		}

		return &g_hooks.pkItems[g_hooks.nSize++];
	}
	UINT CPageGuardHook::FindHookEntry(LPVOID pTarget)
	{
		for (auto i = 0u; i < g_hooks.nSize; ++i)
		{
			if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pkItems[i].pTarget)
				return i;
		}

		return INVALID_HOOK_POS;
	}
	
	
	int WINAPI PGH_TEST_MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
	{
		if (!CApplication::InstancePtr() ||
			!IS_VALID_SMART_PTR(CApplication::Instance().SelfHooksInstance()) ||
#ifndef _DEBUG
			!CApplication::Instance().AppIsInitiliazed() ||
			!CApplication::Instance().SelfHooksInstance()->IsInitialized() ||
#endif
			!IS_VALID_SMART_PTR(CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper())
		)
		{
			return 0;
		}

		if (!CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper()->DisableHook(g_winAPIs->MessageBoxA))
			return 0;

		const auto result = g_winAPIs->MessageBoxA(hWnd, xorstr_("Hooked"), lpCaption, uType);

		if (!CApplication::Instance().SelfHooksInstance()->GetPageGuardHookHelper()->EnableHook(g_winAPIs->MessageBoxA))
			return 0;

		return result;
	}
	void CPageGuardHook::CreateTestHook()
	{
		if (!Initialize())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to initialize PageGuardHook");
			return;
		}
		if (!CreateHook(g_winAPIs->MessageBoxA, PGH_TEST_MessageBoxA_Detour))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to create MessageBoxA hook");
			return;
		}
		if (!EnableHook(g_winAPIs->MessageBoxA))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to enable MessageBoxA hook");
			return;
		}
		APP_TRACE_LOG(LL_SYS, L"MessageBoxA hook created and enabled");
			
		g_winAPIs->MessageBoxA(nullptr, xorstr_("Test"), xorstr_("Test"), MB_OK);

		if (!DisableHook(g_winAPIs->MessageBoxA))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to disable MessageBoxA hook");
			return;
		}
		if (!Uninitialize())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to uninitialize PageGuardHook");
			return;
		}

		APP_TRACE_LOG(LL_SYS, L"MessageBoxA test hook completed");
	}
}
