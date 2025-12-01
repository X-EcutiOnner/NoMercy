#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Hooks.hpp"

namespace NoMercy
{
	static inline BOOL IsInFunction(PVOID Ptr, PVOID FuncBase)
	{
		return reinterpret_cast<PBYTE>(Ptr) >= reinterpret_cast<PBYTE>(FuncBase) &&
			   reinterpret_cast<PBYTE>(Ptr) < (reinterpret_cast<PBYTE>(FuncBase) + 256);
	}
	
	inline auto GetApfnTable()
	{
		return reinterpret_cast<PVOID*>(NtCurrentPeb()->KernelCallbackTable);
	}

	bool CSelfApiHooks::InitializeApfnFilter()
	{
		if (m_upFilterData->Initialized || !g_winAPIs->RtlPcToFileHeader)
			return true;
		
		const auto KernelCallbacksTable = GetApfnTable();
		if (!KernelCallbacksTable)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get kernel callbacks table");
			return false;
		}
		
		m_upFilterData->Callbacks.reserve(128);
		
		PVOID CallbackModBase = nullptr;
		for (unsigned i = 0; g_winAPIs->RtlPcToFileHeader(KernelCallbacksTable[i], &CallbackModBase) == g_winModules->hUser32; ++i)
		{
			m_upFilterData->Callbacks.emplace_back(KernelCallbacksTable[i]);
		}

		std::sort(m_upFilterData->Callbacks.begin(), m_upFilterData->Callbacks.end());
		m_upFilterData->Initialized = true;
		return true;
	}

	bool CSelfApiHooks::IsWinHookOrigin(PVOID FramePtr)
	{
		if (!m_upFilterData->Initialized && !this->InitializeApfnFilter())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to initialize APFN filter");
			return false;
		}
		
		if (m_upFilterData->ClientLoadLibrary)
		{
			return IsInFunction(FramePtr, m_upFilterData->ClientLoadLibrary);
		}
		
		if (m_upFilterData->Callbacks.empty() ||
			reinterpret_cast<PBYTE>(FramePtr) < reinterpret_cast<PBYTE>(m_upFilterData->Callbacks[0]) ||
			reinterpret_cast<PBYTE>(FramePtr) > reinterpret_cast<PBYTE>(m_upFilterData->Callbacks[m_upFilterData->Callbacks.size() - 1]))
		{
			APP_TRACE_LOG(LL_WARN, L"Frame pointer: %p is out of range", FramePtr);
			return false;
		}
		
		for (const auto& Callback : m_upFilterData->Callbacks)
		{
			if (IsInFunction(FramePtr, Callback))
			{
				m_upFilterData->ClientLoadLibrary = Callback;
				m_upFilterData->Callbacks.clear();
				return true;
			}
		}

		APP_TRACE_LOG(LL_ERR, L"Frame pointer: %p is not in any known callback", FramePtr);
		return false;
	}
};
