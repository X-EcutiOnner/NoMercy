#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "WMI.hpp"
#include "../../EngineR3_Core/include/WMIHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/SimpleTimer.hpp"

namespace NoMercy
{
	CWMI::CWMI() :
		m_bInitialized(false), m_bThreadsCreated(false)
	{
		std::memset(&m_hThreads, 0, sizeof(m_hThreads));
	}
	CWMI::~CWMI()
	{
	}

	std::map <std::wstring, std::wstring> CWMI::ParseWMIResponse(const std::wstring& wstResponse)
	{
		std::map <std::wstring, std::wstring> mapResponse;
				
		std::wstring wstLine;
		std::wstringstream wssResponse(wstResponse);
		while (std::getline(wssResponse, wstLine))
		{
			if (wstLine.empty())
				continue;
			if (wstLine[0] != L'\t')
				continue;
			if (wstLine.find(L'=') == std::wstring::npos)
				continue;
			
			const std::wstring wstDelim = xorstr_(L" = ");
			const auto vecStrings = stdext::split_string(wstLine, wstDelim);
			if (vecStrings.size() != 2)
				continue;

			auto wstKey		= vecStrings[0];
			auto wstValue	= vecStrings[1];
			
			if (wstKey.empty() || wstValue.empty())
				continue;

			// remove \t
			wstKey.erase(0, 1);

			if (wstValue.back() == L';')
				wstValue.pop_back();

			if (wstValue.front() == L'\"' && wstValue.back() == L'\"')
			{
				wstValue.erase(0, 1);
				wstValue.erase(wstValue.size() - 1, 1);
			}
			
			mapResponse[wstKey] = wstValue;
		}
		
		return mapResponse;
	}

	DWORD CWMI::ThreadRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"WMI Watcher thread event has been started!");

//#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (!m_bThreadsCreated)
		{		
			m_bThreadsCreated = true;
			
//			const auto wszDriverLoadQuery		= xorstr_(L"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_SystemDriver'");
//			const auto wszServiceLoadQuery		= xorstr_(L"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'");
			const auto wszProcessCreateQuery	= xorstr_(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
			const auto wszProcessDeleteQuery	= xorstr_(L"SELECT * FROM Win32_ProcessStopTrace");
//			const auto wszThreadLoadQuery		= xorstr_(L"SELECT * FROM Win32_ThreadTrace");
//			const auto wszModuleLoadQuery		= xorstr_(L"SELECT * FROM Win32_ModuleLoadTrace");
		
			/*
			m_hThreads[static_cast<uint8_t>(EWMIThreads::DRIVER_LOAD_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszDriverLoadQuery, [](wchar_t* str) {
				WMI_LOG(LL_SYS, L"WMI Watcher driver event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);
				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_DRIVER, mapResponse);
			});
			m_hThreads[static_cast<uint8_t>(EWMIThreads::SERVICE_LOAD_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszServiceLoadQuery, [](wchar_t* str) {
				WMI_LOG(LL_SYS, L"WMI Watcher service event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);
				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_SERVICE, mapResponse);
			});
			*/
			m_hThreads[static_cast<uint8_t>(EWMIThreads::PROCESS_CREATE_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszProcessCreateQuery, [](wchar_t* str) {
				WMI_LOG(LL_TRACE, L"WMI Watcher process create event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);

				auto it_dwPID = mapResponse.find(xorstr_(L"ProcessId"));
				if (it_dwPID != mapResponse.end())
				{
					const auto dwPID = stdext::str_to_u32(it_dwPID->second);
					if (dwPID)
					{
						SafeHandle pkProc = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
						if (pkProc.IsValid())
						{
							auto wstProcessName = CProcessFunctions::GetProcessName(pkProc.get());
							if (!wstProcessName.empty())
							{
								wstProcessName = stdext::to_lower_wide(wstProcessName);
								CApplication::Instance().CacheManagerInstance()->AppendToRequestQueue(
									std::make_tuple(ECacheRequestTypes::SHA1, wstProcessName)
								);
							}
						}
					}
				}

				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_PROCESS_CREATE, mapResponse);
			});
			m_hThreads[static_cast<uint8_t>(EWMIThreads::PROCESS_TERMINATE_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszProcessDeleteQuery, [](wchar_t* str) {
				WMI_LOG(LL_SYS, L"WMI Watcher process terminate event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);
				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_PROCESS_TERMINATE, mapResponse);
			});
			/*
			m_hThreads[static_cast<uint8_t>(EWMIThreads::THREAD_LOAD_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszThreadLoadQuery, [](wchar_t* str) {
				WMI_LOG(LL_TRACE, L"WMI Watcher thread event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);
				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_THREAD, mapResponse);
			});
			m_hThreads[static_cast<uint8_t>(EWMIThreads::MODULE_LOAD_WATCHER)] =
				NoMercyCore::CApplication::Instance().WMIHelperInstance()->CreateAsyncWatcherThread(wszModuleLoadQuery, [](wchar_t* str) {
				WMI_LOG(LL_TRACE, L"WMI Watcher module event: %ls", str);

				const auto mapResponse = CApplication::Instance().WMIManagerInstance()->ParseWMIResponse(str);
				CApplication::Instance().AnalyserInstance()->OnWMITriggered(EAnalyseTypes::ANALYSE_MODULE, mapResponse);
			});
			*/
			
			m_bInitialized = true;
		}
		else
		{
			const auto dwWaitRet = g_winAPIs->WaitForMultipleObjects(static_cast<DWORD>(EWMIThreads::MAX), m_hThreads, TRUE, 5000);
			
			if (dwWaitRet == WAIT_FAILED)
			{
				/*
				APP_TRACE_LOG(LL_CRI, L"WMI Watcher thread event has been failed! Error: %u, Threads: %d/%d/%d/%d/%d/%d",
					g_winAPIs->GetLastError(),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[0]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[1]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[2]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[3]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[4]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[5])
				);
				*/
				APP_TRACE_LOG(LL_CRI, L"WMI Watcher thread event has been failed! Error: %u, Threads: %d/%d",
					g_winAPIs->GetLastError(),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[0]),
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hThreads[1])
				);
				// CApplication::Instance().OnCloseRequest(EXIT_ERR_WMI_SUB_THREAD_ACCESS_LOST, 0); // TODO: temporary changed for test phase
			}
			else
			{
				APP_TRACE_LOG(LL_TRACE, L"WMI Watcher thread event has been finished!");
			}
		}
//#endif
		
		return 0;
	}

	DWORD WINAPI CWMI::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CWMI*>(lpParam);
		return This->ThreadRoutine();
	}

	bool CWMI::InitWMIWatcher()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_WMI, StartThreadRoutine, (void*)this, 10000, false);
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

	void CWMI::ReleaseWMIWatcherThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_WMI);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			NoMercyCore::CApplication::Instance().WMIHelperInstance()->TerminateThreads();

			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
