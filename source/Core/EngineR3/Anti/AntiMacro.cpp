#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiMacro.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

// #define ENABLE_HOOK_RELOAD
#define LLKHF_LOWER_IL_INJECTED 0x00000002
#define LLMHF_LOWER_IL_INJECTED 0x00000002

namespace NoMercy
{
	static HHOOK s_hkMouseHook = 0;
	static HHOOK s_hkKeyboardHook = 0;
	static bool s_bCloseTriggered = false;

	// Low level Mouse filter proc
	LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if (nCode == HC_ACTION)
		{
			if (wParam == WM_RBUTTONDOWN || wParam == WM_LBUTTONDOWN)
			{
				const auto pHookData = (MSLLHOOKSTRUCT*)lParam;

				const auto bCond1 = (pHookData->flags & LLMHF_INJECTED) == LLMHF_INJECTED;
				const auto bCond2 = (pHookData->flags & LLMHF_LOWER_IL_INJECTED) == LLMHF_LOWER_IL_INJECTED;

				if (bCond1 || bCond2)
				{
					if (!CProcessFunctions::FindProcess(xorstr_(L"barrierc.exe")))
						return TRUE;
				}
			}
		}
		return g_winAPIs->CallNextHookEx(s_hkMouseHook, nCode, wParam, lParam);
	}

	// Low level Keyboard filter proc
	LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
	{
		if (nCode == HC_ACTION)
		{
			if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
			{
				const auto pHookData = (KBDLLHOOKSTRUCT*)lParam;

				const auto bCond1 = (pHookData->flags & LLKHF_INJECTED) == LLKHF_INJECTED;
				const auto bCond2 = (pHookData->flags & LLKHF_LOWER_IL_INJECTED) == LLKHF_LOWER_IL_INJECTED;

				if (bCond1 || bCond2)
				{
					if (!CProcessFunctions::FindProcess(xorstr_(L"barrierc.exe")))
						return TRUE;
				}
			}
		}

		return g_winAPIs->CallNextHookEx(s_hkKeyboardHook, nCode, wParam, lParam);
	}

	DWORD WINAPI AntiMacroEx(LPVOID)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti macro thread event has been started");

		if (!s_hkMouseHook)
		{
			// Initialize mouse hook
			s_hkMouseHook = g_winAPIs->SetWindowsHookExW(WH_MOUSE_LL, MouseHookProc, g_winModules->hBaseModule, NULL);
			APP_TRACE_LOG(LL_SYS, L"Mouse hook (%p) has been initialized!", s_hkMouseHook);
		}

		if (!s_hkKeyboardHook)
		{
			// Initialize keyboard hook
			s_hkKeyboardHook = g_winAPIs->SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardHookProc, g_winModules->hBaseModule, NULL);
			APP_TRACE_LOG(LL_SYS, L"Keyboard hook (%p) has been initialized!", s_hkKeyboardHook);
		}

		if (IsWindowsVistaOrGreater())
		{
			if (!s_hkMouseHook)
			{
				CApplication::Instance().OnCloseRequest(EXIT_ERR_MOUSE_MACRO_HOOK_INIT_FAIL, g_winAPIs->GetLastError());
				return 0;
			}

			if (!s_hkKeyboardHook)
			{
				CApplication::Instance().OnCloseRequest(EXIT_ERR_KEYBOARD_MACRO_HOOK_INIT_FAIL, g_winAPIs->GetLastError());
				return 0;
			}
		}

		CStopWatch <std::chrono::milliseconds> kTimer;

		MSG message;
		while (g_winAPIs->GetMessageW(&message, NULL, 0, 0))
		{
			if (s_bCloseTriggered)
				return 0;

			g_winAPIs->TranslateMessage(&message);
			g_winAPIs->DispatchMessageW(&message);

#ifndef ENABLE_HOOK_RELOAD
			if (kTimer.diff() > 5000)
			{
				// Reload hooks
				g_winAPIs->UnhookWindowsHookEx(s_hkMouseHook);
				s_hkMouseHook = g_winAPIs->SetWindowsHookExW(WH_MOUSE_LL, MouseHookProc, g_winModules->hBaseModule, NULL);

				g_winAPIs->UnhookWindowsHookEx(s_hkKeyboardHook);
				s_hkKeyboardHook = g_winAPIs->SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardHookProc, g_winModules->hBaseModule, NULL);

				kTimer.reset();
			}
#endif
		}
		return 0;
	}

	bool CAntiMacro::InitAntiMacro()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_ANTI_MACRO, AntiMacroEx, nullptr, 6000, true);
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

	bool CAntiMacro::DestroyAntiMacro()
	{
		s_bCloseTriggered = true;

		if (s_hkMouseHook)
		{
			if (!g_winAPIs->UnhookWindowsHookEx(s_hkMouseHook))
				return false;

			s_hkMouseHook = nullptr;
		}
		if (s_hkKeyboardHook)
		{
			if (!g_winAPIs->UnhookWindowsHookEx(s_hkKeyboardHook))
				return false;

			s_hkKeyboardHook = nullptr;
		}
		
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_ANTI_MACRO);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
		return true;
	}

	bool CAntiMacro::Initialized()
	{
		return !!s_hkMouseHook;
	}
};
