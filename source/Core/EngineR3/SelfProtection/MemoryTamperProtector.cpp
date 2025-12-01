#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"

namespace NoMercy
{
	static constexpr uint32_t MAX_ELAPSED = 20 * 1000;

	struct SMemoryRange
	{
		uintptr_t base_address{ 0 };
		size_t size{ 0 };
	};
	
	DWORD WINAPI AntiMemoryTamperWorker(LPVOID lpParam)
	{
		auto params = reinterpret_cast<SMemoryRange*>(lpParam);
		if (!params)
			return 0;

		auto pwsi = (PSAPI_WORKING_SET_INFORMATION*)CMemHelper::Allocate(sizeof(PSAPI_WORKING_SET_INFORMATION));
		if (!pwsi)
		{
			APP_TRACE_LOG(LL_ERR, L"Allocate (pwsi) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		SafeHandle pkProcess = g_winAPIs->OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_winAPIs->GetCurrentProcessId());
		if (!pkProcess.IsValid())
		{
			APP_TRACE_LOG(LL_ERR, L"OpenProcess failed with error: %u", g_winAPIs->GetLastError());
			CMemHelper::Free(pwsi);
			return false;
		}
	
		const auto dwStartTick = g_winAPIs->GetTickCount();
		
		auto bPolling = true;
		while (bPolling)
		{
			auto bRet = g_winAPIs->QueryWorkingSet(pkProcess.get(), pwsi, sizeof(PSAPI_WORKING_SET_INFORMATION));
			const auto dwLastError = g_winAPIs->GetLastError();
			if (!bRet && dwLastError == ERROR_BAD_LENGTH)
			{
				const auto nEntryCount = pwsi->NumberOfEntries;
				
				pwsi = (PSAPI_WORKING_SET_INFORMATION*)CMemHelper::ReAlloc(pwsi, sizeof(PSAPI_WORKING_SET_BLOCK) * nEntryCount * sizeof(pwsi->NumberOfEntries));
				
				bRet = g_winAPIs->QueryWorkingSet(
					pkProcess.get(),
					(PVOID)pwsi,
					sizeof(PSAPI_WORKING_SET_BLOCK) * nEntryCount * sizeof(pwsi->NumberOfEntries)
				);
				if (!bRet)
				{
					APP_TRACE_LOG(LL_ERR, L"QueryWorkingSet failed with error: %u", g_winAPIs->GetLastError());
					break;
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown status! Ret: %d Err: %u", bRet, dwLastError);
				break;
			}

			for (std::size_t i = 0; i < pwsi->NumberOfEntries; i++)
			{
				const auto& block = pwsi->WorkingSetInfo[i];
				const uintptr_t page_range_start = params->base_address / 0x1000;
				const uintptr_t page_range_end = ((params->base_address + params->size) + 0xfff) / 0x1000;
				
				if (block.VirtualPage >= page_range_start && block.VirtualPage <= page_range_end)
				{
					if (block.Shared == 0 || block.ShareCount == 0)
					{
						wchar_t wszMappedName[MAX_PATH]{ L'\0' };
						g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (void*)(params->base_address + params->size), wszMappedName, MAX_PATH);

						APP_TRACE_LOG(LL_ERR, L"Tamper detected in memory range %p - %p (Page VA %p, ShareCount %d) Owner: %s",
							(void*)params->base_address, (void*)(params->base_address + params->size),
							(void*)(block.VirtualPage * 0x1000), block.ShareCount,
							wszMappedName
						);

						const auto ntStatus = g_winAPIs->NtUnmapViewOfSection(NtCurrentProcess(), (void*)(params->base_address + params->size));
						APP_TRACE_LOG(LL_WARN, L"NtUnmapViewOfSection completed with status: %p", ntStatus);

						if (!NT_SUCCESS(ntStatus))
						{
							CApplication::Instance().OnCloseRequest(EXIT_ERR_MEMORY_TAMPER_DETECT, block.Shared);

							bPolling = false;
							break;
						}
					}
				}
			}

			if (bPolling)
			{
				const auto dwNowTick = g_winAPIs->GetTickCount();
				if (dwNowTick - dwStartTick > MAX_ELAPSED)
				{
					APP_TRACE_LOG(LL_SYS, L"Timeout! No memory tampering detected");
					break;
				}

				g_winAPIs->Sleep(500);
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Completed!");
		CMemHelper::Free(pwsi);
		return 0;
	}
	
	bool CSelfProtection::InitializeAntiMemoryTamper()
	{
		LPVOID lpBaseAddr = nullptr;
		SIZE_T dwSize = 0;
		if (!CPEFunctions::GetTextSectionInformation(g_winModules->hBaseModule, &lpBaseAddr, &dwSize))
		{			
			APP_TRACE_LOG(LL_ERR, L"GetTextSectionInformation failed");
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L".text section: %p (%p)", lpBaseAddr, dwSize)
		
		auto pkParams = SMemoryRange{ (uintptr_t)lpBaseAddr, dwSize };
		DWORD dwThreadID = 0;
		auto hThread = g_winAPIs->CreateThread(NULL, 0, AntiMemoryTamperWorker, &pkParams, 0, &dwThreadID);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Thread created: %u", dwThreadID);
		g_winAPIs->CloseHandle(hThread);
		return true;
	}	
}
