#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	bool IScanner::CheckStackTrace(PVOID* UnknownFrame)
	{
		if (UnknownFrame) *UnknownFrame = nullptr;

		PVOID Trace[8]{ 0 };
		const auto wCaptureCount = g_winAPIs->RtlCaptureStackBackTrace(1, sizeof(Trace) / sizeof(*Trace), Trace, nullptr);
		if (!wCaptureCount)
		{
			APP_TRACE_LOG(LL_ERR, L"RtlCaptureStackBackTrace failed with error: %u", g_winAPIs->GetLastError());
			return true;
		}

		for (WORD i = 0; i < wCaptureCount; ++i)
		{
			const auto lpAddress = (DWORD_PTR)Trace[i];
			APP_TRACE_LOG(LL_TRACE, L"Current frame: %u Ptr: %p", i, lpAddress);

			if (!CApplication::Instance().FilterMgrInstance()->IsAddressInKnownModule(lpAddress))
			{
				if (UnknownFrame) *UnknownFrame = Trace[i];
				NoMercy::CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_10, 1, fmt::format(xorstr_(L"#{0} {1}"), i, fmt::ptr((void*)lpAddress)));
				return false;
			}
			if (CApplication::Instance().FilterMgrInstance()->IsWinHookOrigin(lpAddress))
			{
				if (UnknownFrame) *UnknownFrame = Trace[i];
				NoMercy::CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_10, 2, fmt::format(xorstr_(L"#{0} {1}"), i, fmt::ptr((void*)lpAddress)));
				return false;
			}
			if (!CApplication::Instance().FilterMgrInstance()->IsKnownMemory(lpAddress))
			{
				if (UnknownFrame) *UnknownFrame = Trace[i];
				NoMercy::CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_10, 3, fmt::format(xorstr_(L"#{0} {1}"), i, fmt::ptr((void*)lpAddress)));
				return false;
			}
		}

		return true;
	}
};
