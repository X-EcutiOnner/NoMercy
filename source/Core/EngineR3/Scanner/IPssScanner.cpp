#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include <ProcessSnapshot.h>

namespace NoMercy
{
	std::shared_ptr <PSS_VA_CLONE_INFORMATION> ParseVACloneInformation(HPSS SnapshotHandle)
	{
		PSS_VA_CLONE_INFORMATION pvci{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_VA_CLONE_INFORMATION, &pvci, sizeof(pvci));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_VA_CLONE_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}

		return stdext::make_shared_nothrow<PSS_VA_CLONE_INFORMATION>(pvci);
	}
	std::shared_ptr <PSS_PERFORMANCE_COUNTERS> ParsePerformanceInformation(HPSS SnapshotHandle)
	{
		PSS_PERFORMANCE_COUNTERS ppc{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_PERFORMANCE_COUNTERS, &ppc, sizeof(ppc));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_PERFORMANCE_COUNTERS) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}

		return stdext::make_shared_nothrow<PSS_PERFORMANCE_COUNTERS>(ppc);
	}
	std::shared_ptr <PSS_PROCESS_INFORMATION> ParseProcessInformation(HPSS SnapshotHandle)
	{
		PSS_PROCESS_INFORMATION ppi{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_PROCESS_INFORMATION, &ppi, sizeof(ppi));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_PROCESS_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}

		return stdext::make_shared_nothrow<PSS_PROCESS_INFORMATION>(ppi);
	}
	std::shared_ptr <PSS_VA_SPACE_INFORMATION> ParseSpaceInformation(HPSS SnapshotHandle)
	{
		PSS_VA_SPACE_INFORMATION pvsi{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_VA_SPACE_INFORMATION, &pvsi, sizeof(pvsi));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_VA_SPACE_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}
		
		return stdext::make_shared_nothrow<PSS_VA_SPACE_INFORMATION>(pvsi);
	}
	std::shared_ptr <PSS_HANDLE_INFORMATION> ParseHandleInformation(HPSS SnapshotHandle)
	{
		PSS_HANDLE_INFORMATION phi{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_HANDLE_INFORMATION, &phi, sizeof(phi));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_HANDLE_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}

		return stdext::make_shared_nothrow<PSS_HANDLE_INFORMATION>(phi);
	}
	std::shared_ptr <PSS_THREAD_INFORMATION> ParseThreadInformation(HPSS SnapshotHandle)
	{
		PSS_THREAD_INFORMATION pti{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_THREAD_INFORMATION, &pti, sizeof(pti));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_THREAD_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}

		return stdext::make_shared_nothrow<PSS_THREAD_INFORMATION>(pti);
	}
	std::shared_ptr <PSS_HANDLE_TRACE_INFORMATION> ParseHandleTraceInformation(HPSS SnapshotHandle)
	{
		PSS_HANDLE_TRACE_INFORMATION phti{ 0 };
		const auto dwResult = g_winAPIs->PssQuerySnapshot(SnapshotHandle, PSS_QUERY_HANDLE_TRACE_INFORMATION, &phti, sizeof(phti));
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssQuerySnapshot(PSS_QUERY_HANDLE_TRACE_INFORMATION) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}
		
		return stdext::make_shared_nothrow<PSS_HANDLE_TRACE_INFORMATION>(phti);
	}
	std::vector <std::shared_ptr <PSS_VA_SPACE_ENTRY>> ParseSpaceEntry(HPSS SnapshotHandle)
	{
		std::vector <std::shared_ptr <PSS_VA_SPACE_ENTRY>> vecSpaceEntries;

		HPSSWALK hWalkMarker = nullptr;
		auto dwResult = g_winAPIs->PssWalkMarkerCreate(nullptr, &hWalkMarker);
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkMarkerCreate failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}
		
		PSS_VA_SPACE_ENTRY pvse{ 0 };
		dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_VA_SPACE, hWalkMarker, &pvse, sizeof(pvse));
		while (dwResult == ERROR_SUCCESS)
		{
			static auto nIdx = 0;
			// APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_VA_SPACE) %u: %p", nIdx++, pvse.BaseAddress);

			vecSpaceEntries.push_back(stdext::make_shared_nothrow<PSS_VA_SPACE_ENTRY>(pvse));

			dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_VA_SPACE, hWalkMarker, &pvse, sizeof(pvse));
		}

		if (dwResult == ERROR_NO_MORE_ITEMS)
		{
			APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_VA_SPACE) finished.");
		}
		else if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkSnapshot(PSS_WALK_VA_SPACE) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
		}
		
		g_winAPIs->PssWalkMarkerFree(hWalkMarker);
		return vecSpaceEntries;
	}
	std::vector <std::shared_ptr <PSS_HANDLE_ENTRY>> ParseHandleEntry(HPSS SnapshotHandle)
	{
		std::vector <std::shared_ptr <PSS_HANDLE_ENTRY>> vecHandleEntries;

		HPSSWALK hWalkMarker = nullptr;
		auto dwResult = g_winAPIs->PssWalkMarkerCreate(nullptr, &hWalkMarker);
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkMarkerCreate failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}		
		
		PSS_HANDLE_ENTRY phe{ 0 };
		dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_HANDLES, hWalkMarker, &phe, sizeof(phe));
		while (dwResult == ERROR_SUCCESS)
		{
			/*
			static auto nIdx = 0;
			APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_HANDLES) %u: %p (%ls) %u %ls",
				nIdx++, phe.Handle, phe.TypeName, phe.ObjectType, phe.ObjectName
			);
			*/

			vecHandleEntries.push_back(stdext::make_shared_nothrow<PSS_HANDLE_ENTRY>(phe));

			dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_HANDLES, hWalkMarker, &phe, sizeof(phe));
		}

		if (dwResult == ERROR_NO_MORE_ITEMS)
		{
			APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_HANDLES) finished.");
		}
		else if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkSnapshot(PSS_WALK_HANDLES) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
		}

		g_winAPIs->PssWalkMarkerFree(hWalkMarker);
		return vecHandleEntries;
	}
	std::vector <std::shared_ptr <PSS_THREAD_ENTRY>> ParseThreadEntry(HPSS SnapshotHandle)
	{
		std::vector <std::shared_ptr <PSS_THREAD_ENTRY>> vecThreadEntries;

		HPSSWALK hWalkMarker = nullptr;
		auto dwResult = g_winAPIs->PssWalkMarkerCreate(nullptr, &hWalkMarker);
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkMarkerCreate failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return {};
		}
		
		PSS_THREAD_ENTRY pte{ 0 };
		dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_THREADS, hWalkMarker, &pte, sizeof(pte));
		while (dwResult == ERROR_SUCCESS)
		{
			/*
			static auto nIdx = 0;
			APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_THREADS) %u: %p", nIdx++, pte.ThreadId);
			*/
				
			vecThreadEntries.push_back(stdext::make_shared_nothrow<PSS_THREAD_ENTRY>(pte));

			dwResult = g_winAPIs->PssWalkSnapshot(SnapshotHandle, PSS_WALK_THREADS, hWalkMarker, &pte, sizeof(pte));
		}

		if (dwResult == ERROR_NO_MORE_ITEMS)
		{
			APP_TRACE_LOG(LL_SYS, L"PssWalkSnapshot(PSS_WALK_THREADS) finished.");
		}
		else if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssWalkSnapshot(PSS_WALK_THREADS) failed with error: %u (%u)", dwResult, g_winAPIs->GetLastError());
		}

		g_winAPIs->PssWalkMarkerFree(hWalkMarker);
		return vecThreadEntries;
	}

	void QuerySnapshot(HPSS SnapshotHandle, std::shared_ptr <SSnapshotContext> spCtx)
	{
//		spCtx->spVACloneInfo = ParseVACloneInformation(SnapshotHandle);
		spCtx->spPerfCounters = ParsePerformanceInformation(SnapshotHandle);
		spCtx->spProcInfo = ParseProcessInformation(SnapshotHandle);
		spCtx->spVASpaceInfo = ParseSpaceInformation(SnapshotHandle);
		spCtx->spHandleInfo = ParseHandleInformation(SnapshotHandle);
		spCtx->spThreadInfo = ParseThreadInformation(SnapshotHandle);
		spCtx->spHandleTraceInfo = ParseHandleTraceInformation(SnapshotHandle);

		spCtx->vecSpaceEntries = ParseSpaceEntry(SnapshotHandle);
		spCtx->vecHandleEntries = ParseHandleEntry(SnapshotHandle);
		spCtx->vecThreadEntries = ParseThreadEntry(SnapshotHandle);
	}

	bool CreateSnapshot(HANDLE hProcess, HPSS* phSnapshopHandle)
	{
		static const PSS_CAPTURE_FLAGS CaptureFlags =
//			PSS_CAPTURE_VA_CLONE |
			PSS_CAPTURE_VA_SPACE |
			PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE |
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_THREADS |
			PSS_CAPTURE_THREAD_CONTEXT |
			PSS_CREATE_MEASURE_PERFORMANCE;

		HPSS hSnapshotHandle = nullptr;
		const auto dwResult = g_winAPIs->PssCaptureSnapshot(hProcess, CaptureFlags, CONTEXT_ALL, &hSnapshotHandle);
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssCaptureSnapshot failed: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return false;
		}

		if (phSnapshopHandle) *phSnapshopHandle = hSnapshotHandle;
		return true;
	}

	bool IScanner::EnumerateProcessPssSnapshotEntries(HANDLE hProcess, std::function <void(std::shared_ptr <SSnapshotContext> ctx)> cb)
	{
		if (IsWindows8Point1OrGreater() == false)
			return false;

		if (!hProcess || !cb)
			return false;

		HPSS hSnapshot = nullptr;
		if (!CreateSnapshot(hProcess, &hSnapshot))
			return false;

		auto spCtx = stdext::make_shared_nothrow<SSnapshotContext>();
		if (!IS_VALID_SMART_PTR(spCtx))
		{
			APP_TRACE_LOG(LL_ERR, L"Memory allocation for SSnapshotContext failed.");
			return false;
		}
		
		QuerySnapshot(hSnapshot, spCtx);

		const auto dwResult = g_winAPIs->PssFreeSnapshot(hProcess, hSnapshot);
		if (dwResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"PssFreeSnapshot failed: %u (%u)", dwResult, g_winAPIs->GetLastError());
			return false;
		}

		cb(spCtx);
		return true;
	}
};
