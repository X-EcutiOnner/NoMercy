#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Hooks.hpp"

#if defined _M_IX86
#define IP Eip
#define RP Ebp
#define MEM_LIMIT 0x80000000
#else
#define IP Rip
#define RP Rsp
#define MEM_LIMIT 0x8000000000000000
#endif
#define FUNC_SIZE sizeof(void*)

namespace NoMercy
{
	static std::vector <std::tuple <uintptr_t, uint8_t, std::string>> gs_vecFuncContainer;
	
	LONG WINAPI SingleStepHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
		{
			for (const auto& [address, opcode, func] : gs_vecFuncContainer)
			{
				if (address == (uintptr_t)ExceptionInfo->ExceptionRecord->ExceptionAddress)
				{
					DWORD dwOldProtect = 0;
					if (g_winAPIs->VirtualProtect((LPVOID)ExceptionInfo->ContextRecord->IP, 0x1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						*(BYTE*)ExceptionInfo->ContextRecord->IP = 0xC3;
						g_winAPIs->VirtualProtect((LPVOID)ExceptionInfo->ContextRecord->IP, 0x1, dwOldProtect, &dwOldProtect);

						auto pRetAddr = *(PVOID*)ExceptionInfo->ContextRecord->RP;
						SIZE_T cbRetSize = 0;
						MEMORY_BASIC_INFORMATION mbi{ 0 };
						if (!NT_SUCCESS(g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), pRetAddr, MemoryBasicInformation, &mbi, sizeof(mbi), &cbRetSize)) ||
							mbi.State != MEM_COMMIT ||
							(mbi.Type != MEM_IMAGE && mbi.RegionSize > 0x2000) ||
							*(WORD*)pRetAddr == 0x23FF || //https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
							*(WORD*)pRetAddr == 0x26FF ||
							*(WORD*)pRetAddr == 0x27FF ||
							*(WORD*)pRetAddr == 0x65FF ||
							*(WORD*)pRetAddr == 0xE3FF
						)
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SINGLE_STEP_WATCHER, 1, stdext::to_wide(func));
						}
					}
				}
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			if (ExceptionInfo->ContextRecord->IP >= MEM_LIMIT) //Perfect Injector
			{
				const auto loCaller = ExceptionInfo->ContextRecord->IP;
				const auto lstCallerFuncs = {
					*(uintptr_t*)loCaller,
					*(uintptr_t*)(loCaller + FUNC_SIZE),
					*(uintptr_t*)(loCaller + (FUNC_SIZE * 2)),
					*(uintptr_t*)(loCaller + (FUNC_SIZE * 3))
				};
				std::wstringstream wss;
				wss << xorstr_(L"Caller: ") << xorstr_(L"0x") << std::hex << loCaller << std::endl;
				for (const auto& callerFunc : lstCallerFuncs)
				{
					wss << xorstr_(L" 0x") << std::hex << callerFunc << std::endl;
				}
				
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SINGLE_STEP_WATCHER, 2, wss.str());
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	bool AddWatchedFunction(HMODULE hModule, const std::string& stFunction)
	{
		if (!hModule || stFunction.empty())
			return false;

		auto pFuncAddr = (uintptr_t)g_winAPIs->GetProcAddress_o(hModule, stFunction.c_str());
		if (!pFuncAddr)
			return false;
		
		while (*(uint8_t*)pFuncAddr != 0xC3)
			pFuncAddr += 1;

		const auto pkFuncCtx = std::make_tuple(pFuncAddr, *(uint8_t*)pFuncAddr, stFunction);
		gs_vecFuncContainer.push_back(pkFuncCtx);
		
		DWORD dwOldProtect = 0;
		if (g_winAPIs->VirtualProtect((LPVOID)pFuncAddr, 0x1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			*(uint8_t*)pFuncAddr = 0xCC;
			g_winAPIs->VirtualProtect((LPVOID)pFuncAddr, 0x1, dwOldProtect, &dwOldProtect);
		}

		return true;
	}
	
	bool CSelfApiHooks::InitializeSingleStepWatcher()
	{
		const auto mapWatchedFuncs = std::map <HMODULE, std::string> {
			{ g_winModules->hUser32,	xorstr_("GetAsyncKeyState")				},
			{ g_winModules->hUser32,	xorstr_("GetCursorPos")					},
			{ g_winModules->hKernel32,	xorstr_("IsBadReadPtr")					},
			{ g_winModules->hWin32u,	xorstr_("NtUserGetAsyncKeyState")		},
			{ g_winModules->hUser32,	xorstr_("GetForegroundWindow")			},
			{ g_winModules->hUser32,	xorstr_("CallWindowProcW")				},
			{ g_winModules->hWin32u,	xorstr_("NtUserPeekMessage")			},
			{ g_winModules->hNtdll,		xorstr_("NtSetEvent")					},
			{ g_winModules->hUcrtbase,	xorstr_("sqrtf")						},
			{ g_winModules->hUcrtbase,	xorstr_("__stdio_common_vsprintf_s"),	},
			{ g_winModules->hNtdll,		xorstr_("TppTimerpExecuteCallback")		},
		};
		
		m_pvSingleStepWatcher = g_winAPIs->AddVectoredExceptionHandler(1, SingleStepHandler);
		if (!m_pvSingleStepWatcher)
		{
			APP_TRACE_LOG(LL_ERR, L"AddVectoredExceptionHandler failed with error %u", g_winAPIs->GetLastError());
			return false;
		}

		for (const auto& [hModule, stFuncName] : mapWatchedFuncs)
		{
			if (hModule)
				AddWatchedFunction(hModule, stFuncName);
		}

		const auto hDXGI = g_winAPIs->GetModuleHandleW_o(xorstr_(L"dxgi.dll"));
		if (hDXGI)
		{
			const auto pDXGITakeLock = g_winAPIs->GetProcAddress_o(hDXGI, xorstr_("TakeLock"));
			if (pDXGITakeLock)
				AddWatchedFunction(hDXGI, xorstr_("TakeLock"));
		}


		return true;
	}

	void CSelfApiHooks::RemoveSingleStepWatcher()
	{
		if (m_pvSingleStepWatcher)
		{
			g_winAPIs->RemoveVectoredExceptionHandler(m_pvSingleStepWatcher);
			m_pvSingleStepWatcher = nullptr;
		}
	}
};
