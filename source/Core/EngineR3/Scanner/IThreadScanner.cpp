#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ScannerInterface.hpp"
#include "../Common/Quarentine.hpp"
#include "../Helper/ThreadHelper.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"



namespace NoMercy
{
	IThreadScanner::IThreadScanner()
	{
	}
	IThreadScanner::~IThreadScanner()
	{
	}

	bool IThreadScanner::IsScanned(DWORD dwThreadId)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_THREAD, std::to_wstring(dwThreadId));
	}
	void IThreadScanner::AddScanned(DWORD dwThreadId)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_THREAD, std::to_wstring(dwThreadId));
	}

	void IThreadScanner::Scan(HANDLE hProcess, SYSTEM_THREAD_INFORMATION* pCurrThread)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		// Process params
		auto dwThreadId = pCurrThread ? reinterpret_cast<DWORD_PTR>(pCurrThread->ClientId.UniqueThread) : DWORD_PTR(0);
		auto dwProcessId = g_winAPIs->GetProcessId(hProcess);
		auto pThread = std::unique_ptr<CThread>();
		auto ntStatus = NTSTATUS(0x0);
		auto ulReadBytes = 0UL;

		SCANNER_LOG(LL_TRACE, L"Thread scanner has been started! Target thread: %lld Target proc: %p(%u)", dwThreadId, hProcess, dwProcessId);

		// Check params
		if (!IS_VALID_HANDLE(hProcess) || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Thread owner process is NOT alive!");
			goto _Complete;
		}

		if (!pCurrThread)
		{
			SCANNER_LOG(LL_ERR, L"Thread param is NULL!");
			goto _Complete;
		}

		// check already processed
		if (IsScanned(dwThreadId))
		{
			SCANNER_LOG(LL_SYS, L"Thread already scanned!");
			goto _Complete;
		}

		// Add to checked list
		AddScanned(dwThreadId);

		// Scan routine
		// TODO: forward to hook analyse func

_Complete:
		return;
	}

	void IThreadScanner::ScanSync(DWORD dwThreadID)
	{
		return;
	}
	bool IThreadScanner::ScanAll()
	{
		return true;
	}
	
	bool IThreadScanner::ScanProcessThreads(HANDLE hProcess)
	{
		SCANNER_LOG(LL_SYS, L"Thread scanner has been started! Target process: %u(%p)", g_winAPIs->GetProcessId(hProcess), hProcess);

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

		const auto stProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (stProcessName.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}
		SCANNER_LOG(LL_SYS, L"Process image name: %s", stProcessName.c_str());

		// TODO: Thread32First - EnumThreadWindows > check windowed mode

		return CApplication::Instance().ScannerInstance()->EnumerateThreads(hProcess, [&](SYSTEM_THREAD_INFORMATION* pCurrThread) {
			Scan(hProcess, pCurrThread);
		});
	}

	bool IScanner::EnumerateThreads(HANDLE hProcess, std::function<void(SYSTEM_THREAD_INFORMATION*)> cb)
	{
		SCANNER_LOG(LL_SYS, L"Thread enumerator has been started!");

		if (!cb)
			return false;

		if (!hProcess || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
			return false;

		auto ntStat = NTSTATUS(0x0);
		auto dwProcessInfoSize = 2000UL;
		auto dwProcessId = g_winAPIs->GetProcessId(hProcess);

		auto pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(CMemHelper::Allocate(dwProcessInfoSize));
		if (!pProcessInfo)
			return false;

		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemProcessInformation, pProcessInfo, dwProcessInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwProcessInfoSize *= 2;
			pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(CMemHelper::ReAlloc(pProcessInfo, dwProcessInfoSize));
		}

		if (!NT_SUCCESS(ntStat))
		{
			SCANNER_LOG(LL_ERR, L"NtQuerySystemInformation failed! Error code: %u Ntstatus: %u", g_winAPIs->GetLastError(), ntStat);

			CMemHelper::Free(pProcessInfo);
			return false;
		}

		auto pIterator = pProcessInfo;
		while (pIterator && pIterator->NextEntryOffset)
		{
			if (HandleToUlong(pIterator->UniqueProcessId) == dwProcessId)
			{
				auto pThread = pIterator->Threads;
				if (!pThread)
				{
					return false;
				}

				for (auto i = 0UL; i < pIterator->NumberOfThreads; i++)
				{
					cb(pThread);

					pThread++;
				}
			}

			if (pIterator->NextEntryOffset == 0)
				break;

			pIterator = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pIterator + pIterator->NextEntryOffset);
		}

		CMemHelper::Free(pProcessInfo);
		return true;
	}
};
