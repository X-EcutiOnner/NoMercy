#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Helper/PatternScanner.hpp"
#include "ScannerInterface.hpp"
#include <d3d11.h>

namespace NoMercy
{
	static const auto gsc_mapTargetModules = std::unordered_map <std::wstring, std::wstring> {
		{ xorstr_(L"gameoverlayrenderer64.dll"),	xorstr_(L"33 F6 83 E5 F7 44 8B C5 8B D6 49 8B CE FF 15") },
		{ xorstr_(L"DiscordHook64.dll"),			xorstr_(L"48 89 D9 89 FA 41 89 F0 FF 15") },
		{ xorstr_(L"overlay64.dll"),				xorstr_(L"48 8B 5C 24 40 44 8B 44 24 30 8B 54 24 38 48 8B CB FF 15") },
		{ xorstr_(L"DiscordHook64.dll"),			xorstr_(L"44 8B C7 8B D6 48 8B CB FF 15") }
	};

	typedef HRESULT(__stdcall* TD3D11Present)(IDXGISwapChain* This, UINT SyncInterval, UINT Flags);
	volatile static TD3D11Present D3D11Present_o = nullptr;

	uintptr_t** ppPresentPointer = nullptr;
	IDXGISwapChain* globalchain = nullptr;
	extern "C" HRESULT __stdcall D3D11PresentDetour(IDXGISwapChain* This, UINT SyncInterval, UINT Flags)
	{
		APP_TRACE_LOG(LL_SYS, L"Handler called! Saving swapchain");
		globalchain = This;
		*ppPresentPointer = (uintptr_t*)D3D11Present_o;
		return D3D11Present_o(This, SyncInterval, Flags);
	}

	bool FuncHasAnomaly(uintptr_t& pkPresent)
	{
		auto bFound = false;
		while (true)
		{
			while (true)
			{
				while (*(BYTE*)pkPresent == 0xE9)
				{
					if (*(DWORD*)(pkPresent + 5) == 0xCCCCCCCC)
						bFound = true;
					pkPresent += *(signed int*)(pkPresent + 1) + 5;
				}

				if (*(WORD*)pkPresent != 0x25FF)
					break;

				pkPresent = *(uintptr_t*)(pkPresent + 6);
			}

			if (*(WORD*)pkPresent != 0xB848 || *((WORD*)pkPresent + 5) != 0xE0FF)
				break;

			pkPresent = *(uintptr_t*)(pkPresent + 2);
			bFound = true;
		}
		return bFound;
	}

	bool MemoryHasAnomaly(uintptr_t pkPresent)
	{
		auto bFound = false;
		
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		auto ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), (LPVOID)pkPresent, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		const auto condition1 = !NT_SUCCESS(ntStatus);
		const auto condition2 = mbi.State != MEM_COMMIT;
		const auto condition3 = mbi.Type != MEM_IMAGE && (mbi.Type != MEM_PRIVATE || mbi.State != MEM_FREE || *((uintptr_t*)pkPresent + 20) != 0xEBFFFFFF41058D48ui64);

		if (condition1 || condition2 || condition3)
		{
			pkPresent = *((uintptr_t*)pkPresent - 3);
			ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), (LPVOID)pkPresent, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

			const auto condition4 = ntStatus < 0;
			const auto condition5 = mbi.State != MEM_COMMIT;
			const auto condition6 = mbi.Type != MEM_IMAGE;

			APP_TRACE_LOG(LL_SYS, L"%d %d %d", condition4, condition5, condition6);
			if (condition4 || condition5 || condition6)
			{
				bFound = false;
			}
		}

		const auto condition7 = mbi.Protect != PAGE_EXECUTE && mbi.Protect != PAGE_EXECUTE_READ && mbi.Protect != PAGE_EXECUTE_READWRITE && mbi.Protect != PAGE_EXECUTE_WRITECOPY;
		const auto condition8 = *(uintptr_t*)pkPresent == 0x74894808245C8948i64;
		const auto condition9 = (*((uintptr_t*)pkPresent + 1) == 0x4140EC8348571024i64 || *((uintptr_t*)pkPresent + 1) == 0x5518247C89481024i64);
		const auto condition10 = *(uintptr_t*)pkPresent == 0x57565520245C8948i64;
		const auto condition11 = *(uintptr_t*)pkPresent == 0x4157551824748948i64;
		const auto condition12 = *(uintptr_t*)pkPresent == 0x8D48564157565540ui64;
		const auto condition13 = *(DWORD*)pkPresent == 1220840264 && *((WORD*)pkPresent + 2) == 22665;
		const auto condition14 = *(uintptr_t*)pkPresent == 0x5741564157565340i64;
		const auto condition15 = *(uintptr_t*)pkPresent == 0x5741564155C48B48i64;
		const auto condition16 = *(uintptr_t*)pkPresent == 0x4156415441575540i64;

		APP_TRACE_LOG(LL_SYS, L"%d %d %d %d %d %d %d %d %d %d %d %d %d %d",
			condition7, condition8, condition9, condition10, condition11, condition12, condition13, condition14, condition15, condition16
		);
		bFound = !(condition7 || condition8 || condition9 || condition10 || condition11 || condition12 || condition13 || condition14 || condition15 || condition16);
		APP_TRACE_LOG(LL_SYS, L"Is found: %d", bFound);
		
		return bFound;
	}

	void IScanner::CheckPresentHook()
	{
		auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
		if (!IS_VALID_SMART_PTR(upPatternScanner))
		{
			APP_TRACE_LOG(LL_SYS, L"Failed to allocate memory for pattern scanner");
			return;
		}

		auto idx = 0;
		auto bReported = false;
		for (const auto& [wstModuleName, stPatternBytes] : gsc_mapTargetModules)
		{
			const auto pModule = (uintptr_t)g_winAPIs->GetModuleHandleW_o(wstModuleName.c_str());
			if (!pModule)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get module handle for %s", wstModuleName.c_str());
				idx++;
				continue;
			}
			
			const auto pIDH = (PIMAGE_DOS_HEADER)pModule;
			if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get DOS header for %s", wstModuleName.c_str());
				idx++;
				continue;
			}
			
			const auto pINH = (PIMAGE_NT_HEADERS)(pModule + pIDH->e_lfanew);
			if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get NT header for %s", wstModuleName.c_str());
				idx++;
				continue;
			}
			
			const auto dwCodeBase = pINH->OptionalHeader.BaseOfCode;
			const auto dwCodeSize = pINH->OptionalHeader.SizeOfCode;
			const auto dwCodeStart = dwCodeBase + pModule;

			const auto pkPattern = Pattern(stPatternBytes, PatternType::Address);
			auto dwSigBase = (DWORD_PTR)upPatternScanner->findPatternSafe((LPVOID)dwCodeStart, dwCodeSize, pkPattern);
			if (!dwSigBase)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to find pattern for %s", wstModuleName.c_str());
				idx++;
				continue;
			}

			ppPresentPointer = 0;
				
			APP_TRACE_LOG(LL_SYS, L"Found pattern for %s at 0x%p", wstModuleName.c_str(), dwSigBase);
				
			if (idx == 0) // gameoverlayrenderer64.dll
			{
				uintptr_t pJmptDest = dwSigBase - 0x45;
				if (*(BYTE*)pJmptDest == 0xE8 &&
					(pJmptDest += *(signed int*)(pJmptDest + 1) + 5, *(DWORD*)pJmptDest != 0x83485340))
				{
					ppPresentPointer = (uintptr_t**)&pJmptDest;
				}
			}
			else if (idx == 1) // DiscordHook64.dll
			{
				uintptr_t pJmptDest = dwSigBase - 0x13;
				if (*(BYTE*)pJmptDest == 0xE8 &&
					(pJmptDest += *(signed int*)(pJmptDest + 1) + 5, *(BYTE*)pJmptDest == 0xE9) &&
					(pJmptDest += *(signed int*)(pJmptDest + 1) + 15, *(BYTE*)pJmptDest == 0xE9) &&
					(pJmptDest += *(signed int*)(pJmptDest + 1) + 5, *(BYTE*)pJmptDest != 0x56535540)
					)
				{
					ppPresentPointer = (uintptr_t**)&pJmptDest;
				}
				else
				{
					pJmptDest = dwSigBase - 0xA6;
					if (*(BYTE*)pJmptDest == 0xE9 &&
						(pJmptDest += *(signed int*)(pJmptDest + 1) + 5, *(BYTE*)pJmptDest == 0xE9) &&
						(pJmptDest += *(signed int*)(pJmptDest + 1) + 6, **(uintptr_t**)pJmptDest == 0x2454891824448944)
						)
					{
						ppPresentPointer = (uintptr_t**)pJmptDest;
					}
				}
			}
			
			APP_TRACE_LOG(LL_SYS, L"Present pointer in %s at %p (%p)", stPatternBytes.c_str(), ppPresentPointer, ppPresentPointer ? *ppPresentPointer : nullptr);
			
			if (ppPresentPointer && *ppPresentPointer)
			{
				static MEMORY_BASIC_INFORMATION mbi = { 0 };
				auto ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), *ppPresentPointer, MemoryBasicInformation, (PVOID)&mbi, sizeof(mbi), 0);
				if (!NT_SUCCESS(ntStatus) ||
					mbi.State != MEM_COMMIT ||
					mbi.Type != MEM_PRIVATE ||
					mbi.Protect != PAGE_EXECUTE_READWRITE ||
					*(DWORD*)(*ppPresentPointer) == 0x50C03148) // xor rax, rax push rax
				{
					APP_TRACE_LOG(LL_ERR, L"Present is invalid memory! %p %p", ntStatus, &mbi);
					bReported = true;
				}

				D3D11Present_o = (TD3D11Present)*ppPresentPointer;
				*ppPresentPointer = (uintptr_t*)D3D11PresentDetour;

				g_winAPIs->Sleep(1000);
				
				APP_TRACE_LOG(LL_SYS, L"[>] Found SwapChain at %p", globalchain);
				
				static MEMORY_BASIC_INFORMATION mbi_globalchain = { 0 };
				ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), globalchain, MemoryBasicInformation, (PVOID)&mbi_globalchain, sizeof(mbi_globalchain), 0);
				uintptr_t present_from_vtable = *(uintptr_t*)(*(uintptr_t*)(globalchain) + 0x40);
				if (!NT_SUCCESS(ntStatus) || FuncHasAnomaly(present_from_vtable))
				{
					bReported = true;
					APP_TRACE_LOG(LL_ERR, L"Func Anomaly at: %p", present_from_vtable);
				}
				else
				{
					APP_TRACE_LOG(LL_SYS, L"[>] No anomalys found jump chain ends at %p", present_from_vtable);
					if (MemoryHasAnomaly(present_from_vtable))
					{
						APP_TRACE_LOG(LL_ERR, L"[!!!] Memory anomaly at destination!");
						bReported = true;
					}

				}
			}
			
			idx++;
		}
		if (bReported)
		{
			APP_TRACE_LOG(LL_ERR, L"[!!!] You received reports!");
		}
		else
		{
			APP_TRACE_LOG(LL_SYS, L"[>] No reports! You're good to go");
		}
	}
};
