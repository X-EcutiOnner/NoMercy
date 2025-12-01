#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"

#if 0
* Base, size, flags, block count
* Pattern
* Hash
#endif

namespace NoMercy
{
	IHeapScanner::IHeapScanner()
	{
	}
	IHeapScanner::~IHeapScanner()
	{
	}

	bool IHeapScanner::IsScanned(std::shared_ptr <SHeapScanContext> pkHeapCtx)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_HEAP, fmt::format(xorstr_(L"p:{0}|a:{1}"), fmt::ptr(pkHeapCtx->hProcess), pkHeapCtx->dwBase));
	}
	void IHeapScanner::AddScanned(std::shared_ptr <SHeapScanContext> pkHeapCtx)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_THREAD, fmt::format(xorstr_(L"p:{0}|a:{1}"), fmt::ptr(pkHeapCtx->hProcess), pkHeapCtx->dwBase));
	}
	
	void IHeapScanner::ScanSync(std::shared_ptr <SHeapScanContext> pkHeapCtx)
	{
		// TODO
	}

	bool IHeapScanner::ScanProcessHeaps(HANDLE hProcess)
	{
		SCANNER_LOG(LL_SYS, L"Heap scanner has been started! Target process: %u(%p)", g_winAPIs->GetProcessId(hProcess), hProcess);

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

		auto szProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (szProcessName.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}
		SCANNER_LOG(LL_SYS, L"Process image name: %s", szProcessName.c_str());

		return CApplication::Instance().ScannerInstance()->EnumerateHeaps(hProcess, [&](PVOID64 dwBase, SIZE_T dwAllocatedSize, SIZE_T dwComittedSize, DWORD dwFlags, DWORD dwBlockCount) {
			auto ctx = stdext::make_shared_nothrow<SHeapScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->hProcess = hProcess;
				ctx->dwBase = (DWORD_PTR)Ptr64ToPtr(dwBase);
				ctx->dwAllocatedSize = dwAllocatedSize;
				ctx->dwComittedSize = dwComittedSize;
				ctx->dwFlags = dwFlags;
				ctx->dwBlockCount = dwBlockCount;

				ScanAsync(ctx);
			}
		});
	}

	bool IHeapScanner::ScanAll()
	{
		return true;
	}

	bool IScanner::EnumerateHeaps(HANDLE hProcess, std::function<void(PVOID, SIZE_T, SIZE_T, DWORD, DWORD)> cb)
	{
		auto dwProcessId = g_winAPIs->GetProcessId(hProcess);

		SCANNER_LOG(LL_SYS, L"Heap enumerator has been started! Target process: %p(%u)", hProcess, dwProcessId);

		if (!cb)
			return false;

		auto db = g_winAPIs->RtlCreateQueryDebugBuffer(0, FALSE);
		if (!db)
		{
			SCANNER_LOG(LL_ERR, L"RtlCreateQueryDebugBuffer fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto ntStatus = g_winAPIs->RtlQueryProcessDebugInformation((HANDLE)dwProcessId, WinAPI::PDI_HEAPS | WinAPI::PDI_HEAP_BLOCKS, db);
		if (!NT_SUCCESS(ntStatus))
		{
			SCANNER_LOG(LL_ERR, L"RtlQueryProcessDebugInformation fail! Error: %p", ntStatus);

			g_winAPIs->RtlDestroyQueryDebugBuffer(db);
			return false;
		}

		for (auto i = 0UL; i < db->Heaps->NumberOfHeaps; ++i)
		{
			auto curHeap = &db->Heaps->Heaps[i];

			auto VirtualAddress = curHeap->BaseAddress;
			auto BlockCount = curHeap->NumberOfEntries;
			auto CommittedSize = curHeap->BytesCommitted;
			auto AllocatedSize = curHeap->BytesAllocated;
			auto Flags = curHeap->Flags;

			APP_TRACE_LOG(LL_SYS, L"Address: %X Block count: %u Size: %u-%u Flags: %u", VirtualAddress, BlockCount, CommittedSize, AllocatedSize, Flags);
			cb(VirtualAddress, AllocatedSize, CommittedSize, Flags, BlockCount);
		}

		g_winAPIs->RtlDestroyQueryDebugBuffer(db);
		return true;
	}
};
