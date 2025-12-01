#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "MemoryAccessDetect.hpp"

namespace NoMercy
{
	static auto gs_bCanCheck = false;
	static auto gs_hCheckThread = HANDLE(nullptr);

	struct MAD_MEM
	{
		std::shared_ptr <MEMORY_BASIC_INFORMATION> mbi;
		BOOL bAccess;
	};
	std::list <MAD_MEM*> g_lstMemoryBlocks;

	BOOL RtlDispatchExceptionMemAccessDetect(PEXCEPTION_RECORD pExcptRec, CONTEXT* pContext)
	{
		ULONG_PTR Eip = (ULONG_PTR)pExcptRec->ExceptionAddress;
		if (!g_lstMemoryBlocks.empty() && pExcptRec->ExceptionCode == EXCEPTION_GUARD_PAGE)
		{
			for (auto& block : g_lstMemoryBlocks)
			{
				if (Eip >= (ULONG_PTR)block->mbi->BaseAddress &&
					Eip <= (ULONG_PTR)block->mbi->BaseAddress + block->mbi->RegionSize)
				{
					APP_TRACE_LOG(LL_WARN, L"Access detected to trap memory block: %p", block->mbi->BaseAddress);
					block->bAccess = TRUE;
					return TRUE;
				}
			}
		}

		return FALSE;
	}

	NTSTATUS NTAPI OnSecureMemoryCache(PVOID Address, SIZE_T Length)
	{
		for (const auto& block : g_lstMemoryBlocks)
		{
			if (block->mbi->BaseAddress == Address && block->mbi->RegionSize == Length)
			{
				APP_TRACE_LOG(LL_WARN, L"Secure memory: %p (%p) access changed or freed.", Address, Length);
			}
		}
		return STATUS_SUCCESS;
	}

	DWORD WINAPI MADThread(LPVOID Param)
	{
//		g_winAPIs->RtlRegisterSecureMemoryCacheCallback(&OnSecureMemoryCache);

		for (auto& block : g_lstMemoryBlocks)
		{
//			g_winAPIs->RtlFlushSecureMemoryCache(block->mbi->BaseAddress, block->mbi->RegionSize);
			
			DWORD dwOld;
			g_winAPIs->VirtualProtect(block->mbi->BaseAddress, block->mbi->RegionSize, block->mbi->Protect | PAGE_GUARD, &dwOld);
		}

		while (true)
		{
			for (auto& block : g_lstMemoryBlocks)
			{
				gs_bCanCheck = false;

				APP_TRACE_LOG(LL_SYS, L"Validating memory block: %p (%p)", block->mbi->BaseAddress, block->mbi->RegionSize);

				MEMORY_BASIC_INFORMATION mbi;
				g_winAPIs->VirtualQueryEx(NtCurrentProcess(), block->mbi->BaseAddress, &mbi, sizeof(mbi));

				if ((mbi.Protect & PAGE_GUARD) != PAGE_GUARD)
				{
					if (!block->bAccess)
					{
						CApplication::Instance().OnCloseRequest(EXIT_ERR_MEMORY_ACCESS_DETECT, g_winAPIs->GetLastError());
						return 0;
					}
				}

				PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { 0 };
				pworkingSetExInformation.VirtualAddress = mbi.BaseAddress;

				if (g_winAPIs->QueryWorkingSetEx(NtCurrentProcess(), &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
				{
					if (pworkingSetExInformation.VirtualAttributes.Shared)
					{
						APP_TRACE_LOG(LL_WARN, L"Memory block: %p (%p) is shared.", block->mbi->BaseAddress, block->mbi->RegionSize);
					}
				}

				APP_TRACE_LOG(LL_SYS, L"Validated memory block!", block->mbi->BaseAddress, block->mbi->RegionSize);

				block->bAccess = FALSE;

				if ((mbi.Protect & PAGE_GUARD) != PAGE_GUARD)
				{
					DWORD dwOldProtect = 0;
					g_winAPIs->VirtualProtect(block->mbi->BaseAddress, block->mbi->RegionSize, block->mbi->Protect | PAGE_GUARD, &dwOldProtect);
				}
//				g_winAPIs->RtlFlushSecureMemoryCache(block->mbi->BaseAddress, block->mbi->RegionSize);

				gs_bCanCheck = true;
			}

			g_winAPIs->Sleep(10000);
		}

//		g_winAPIs->RtlDeregisterSecureMemoryCacheCallback(&OnSecureMemoryCache);
		return 0;
	}

	bool InitMemoryAccessDetector(HMODULE hModule)
	{
		DWORD totalBytes = 0;

		if (!IsWindowsVistaOrGreater())
			return true;

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (!g_winAPIs->VirtualQuery(hModule, &mbi, sizeof(mbi)))
			return false;

		const auto ModuleBase = (DWORD_PTR)mbi.AllocationBase;
		if (!ModuleBase)
			return false;

		const auto pIDH = (PIMAGE_DOS_HEADER)ModuleBase;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto addr = (unsigned char*)mbi.AllocationBase;
		const auto endaddr = addr + pINH->OptionalHeader.SizeOfImage;
		while (addr < endaddr)
		{
			if (!g_winAPIs->VirtualQueryEx(NtCurrentProcess(), addr, &mbi, sizeof(mbi)))
				break;

			const auto Commited = mbi.State & MEM_COMMIT;
			const auto Readable = mbi.Protect & (PAGE_READWRITE | PAGE_READONLY);
			const auto Guarded = mbi.Protect & PAGE_GUARD;

			if (Commited && Readable && !Guarded)
			{
				totalBytes += (DWORD)mbi.RegionSize;

				auto ctx = new (std::nothrow) MAD_MEM();
				if (!ctx)
				{
					APP_TRACE_LOG(LL_WARN, L"Failed to allocate memory for MAD_MEM structure!");
					return false;
				}
				
				ctx->mbi = std::make_shared<MEMORY_BASIC_INFORMATION>(mbi);
				ctx->bAccess = FALSE;
				g_lstMemoryBlocks.emplace_back(ctx);

				APP_TRACE_LOG(LL_SYS, L"Memory access detect trap compatible memory block found: %p (%u)", mbi.BaseAddress, mbi.RegionSize);
			}

			addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
		}

		DWORD dwThreadId = 0;
		gs_hCheckThread = g_winAPIs->CreateThread(NULL, 0, MADThread, NULL, 0, &dwThreadId);
		if (!gs_hCheckThread)
		{
			APP_TRACE_LOG(LL_WARN, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Memory access detect thread created! %u (%p)", dwThreadId, gs_hCheckThread);
		return true;
	}

	void ReleaseMemoryAccessDetector()
	{
		if (gs_hCheckThread)
		{
			g_winAPIs->TerminateThread(gs_hCheckThread, 0);
			gs_hCheckThread = nullptr;
		}
	}
};
