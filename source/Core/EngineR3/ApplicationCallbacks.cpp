#include "PCH.hpp"
#include "Index.hpp"
#include "Application.hpp"
#include "Core.hpp"
#include "Common/Terminator.hpp"
#include "../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../Common/StdExtended.hpp"

namespace NoMercy
{
	// See: EInitMgrErrorCodes
	void CApplication::__OnCoreInitilizationFail(uint8_t nStep)
	{
		std::lock_guard <std::recursive_mutex> sync(m_mtxCloseProcess);

		// Block another call
		SetErrorTriggered();
		m_abIsCloseTriggered.store(true);

		const auto c_nAppType = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
		const auto c_dwInitErr = CApplication::Instance().GetInitStatusCode();
		const auto c_dwInitErrSub = CApplication::Instance().GetInitSubStatusCode();
		const auto c_wstAppType = GetAppTypeNameW(c_nAppType);
		const auto c_dwSysErrCode = g_winAPIs->GetLastError();
		const auto c_wstAppVer = stdext::to_wide(xorstr_(__PRODUCT_VERSION__));

		// Write error log
		APP_TRACE_LOG(LL_CRI,
			L"Core initilization failed! Step: %u Status: %u Sub: %u SysErr: %u App: %u",
			nStep, c_dwInitErr, c_dwInitErrSub, c_dwSysErrCode, c_nAppType
		);

		// Create error message
		auto wstLocalizedMessage = L""s;
		if (NoMercyCore::CApplication::Instance().ErrorMessageHelperInstance())
		{
			wstLocalizedMessage = NoMercyCore::CApplication::Instance().ErrorMessageHelperInstance()->PrepareErrorMessage(
				EPhase::PHASE_INIT, NoMercyCore::ELocalizationPhase::I18N_PHASE_INIT, c_dwInitErr, c_dwInitErrSub, (void*)c_dwSysErrCode
			);
			APP_TRACE_LOG(LL_SYS, L"Localized message: '%s'", wstLocalizedMessage.c_str());
		}
		wstLocalizedMessage = fmt::format(xorstr_(L"{0}[{1}] Initilization failed!\n{2} ({3}#{4})[{5}]\nV:{6}"),
			c_wstAppType, c_nAppType, wstLocalizedMessage, c_dwInitErr, c_dwInitErrSub, nStep, c_wstAppVer
		);
		const auto stLocalizedMessage = stdext::to_ansi(wstLocalizedMessage);

		// Send log to sentry
		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CApplication::Instance().GetSentryManagerInstance())
		{
			const auto stSentryMessage = fmt::format(xorstr_("Initilization failed. Step: {0} Status: {1} Sub: {2} SysErr: {3} App: {4}"),
				nStep, c_dwInitErr, c_dwInitErrSub, c_dwSysErrCode, c_nAppType
			);
			NoMercyCore::CApplication::Instance().GetSentryManagerInstance()->SendLog(SENTRY_LEVEL_FATAL, xorstr_("INIT_FAIL"), stSentryMessage.c_str());
		}
		APP_TRACE_LOG(LL_WARN, L"Sent message to sentry!");

		// SDK Wrapper
		if (IS_VALID_SMART_PTR(CApplication::Instance().SDKHelperInstance()))
		{
			CApplication::Instance().SDKHelperInstance()->SendMessageToClient(NM_DATA_RECV_SUSPICIOUS_EVENT, stLocalizedMessage.c_str(), (void*)c_dwInitErr);
		}
		APP_TRACE_LOG(LL_WARN, L"Sent message to game client!");

		// Show message
		ServiceMessageBox(xorstr_(L"NoMercy Error"), wstLocalizedMessage, MB_ICONERROR);
		APP_TRACE_LOG(LL_WARN, L"Messagebox shown!");

		// Finalize
		CApplication::Instance().Finalize();
		APP_TRACE_LOG(LL_WARN, L"Finalized!");

		// Exit
		CTerminator::TerminateProcess(NtCurrentProcess());
	}

	bool CApplication::IsIgnoredCheatDetection(uint32_t id, uint32_t sub_id, const std::wstring& param)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		// Check if the cheat detection is already sent
		for (const auto& [dwID, dwSubID, wstrParam] : m_vecSendCheatDetections)
		{
			if (dwID == id && dwSubID == sub_id && wstrParam == param)
			{
				APP_TRACE_LOG(LL_SYS, L"Cheat detection is already sent, Skipped.");
				return true;
			}
		}

		// Add to the list
		m_vecSendCheatDetections.emplace_back(id, sub_id, param);
		return false;
	}

	std::wstring CApplication::OnCheatDetect(uint32_t id, uint32_t sub_id, const std::wstring& param, bool fatal, uint32_t system_error, uint32_t client_pid, const std::wstring& ref_id)
	{
#ifndef __EXPERIMENTAL__
		if (id == CHEAT_VIOLATION_MOUSE_INPUT_INJECTION || id == CHEAT_VIOLATION_HOOK_6)
			return {};
#endif
		if (id == CHEAT_VIOLATION_WINDOW_HEURISTIC && !param.empty())
		{
			const std::vector <std::wstring> vecKnownFalsePositives = {
				xorstr_(L":\\windows\\system32\\compattelrunner.exe"),
				xorstr_(L":\\windows\\system32\\wbem\\wmic.exe"),
				xorstr_(L"\\microsoft\\windows defender\\platform\\")
			};
			for (const auto& wstKnownFalsePositive : vecKnownFalsePositives)
			{
				if (param.find(wstKnownFalsePositive) != std::wstring::npos)
					return {};
			}
		}

		const auto stRefID = !ref_id.empty() ? ref_id : stdext::generate_uuid_v4();
		APP_TRACE_LOG(LL_CRI, L"Cheat detected! Ref: %s(Exist: %d) ID: %u (%u) Fatal: %d System error: %u Param: %s Client: %u",
			stRefID.c_str(), !ref_id.empty(), id, sub_id, fatal ? 1 : 0, system_error, param.c_str(), client_pid
		);

		// Check if the cheat detection is already sent
		if (IsIgnoredCheatDetection(id, sub_id, param))
			return {};

		// Take screenshot
		std::vector <std::wstring> vecScreenshots;
		if (MAX_SCREENSHOT_COUNT)
		{
			auto screenshots = NoMercyCore::CApplication::Instance().ScreenshotManagerInstance()->CreateScreenshots();

			for (const auto& data : screenshots)
			{
				auto base64 = CBase64::encode(reinterpret_cast<const unsigned char*>(data.buffer), data.length);

				if (!base64.empty())
					vecScreenshots.emplace_back(stdext::to_wide(base64));
			}
			NoMercyCore::CApplication::Instance().ScreenshotManagerInstance()->ClearScreenshotBuffer();
		}

		APP_TRACE_LOG(LL_SYS, L"%d/%d screenshots taken", vecScreenshots.size(), MAX_SCREENSHOT_COUNT);

		// Add to the queue
		auto ctx = stdext::make_shared_nothrow<SCheatQueueCtx>();
		if (!IS_VALID_SMART_PTR(ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"Cheat queue object could not allocated, error: %u", g_winAPIs->GetLastError());
			return {};
		}

		ctx->ref_id = stRefID;
		ctx->id = id;
		ctx->sub_id = sub_id;
		ctx->param = param;
		ctx->fatal = fatal;
		ctx->system_error = system_error;

#if (MAX_SCREENSHOT_COUNT > 0)
		for (size_t i = 0; i < MAX_SCREENSHOT_COUNT; i++)
		{
			if (i < vecScreenshots.size())
				ctx->screenshots[i] = vecScreenshots[i];
		}
#endif

		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);
		m_spCheatQueue->AppendCheatToQueue(ctx);

		return stRefID;
	}
	void CApplication::OnCheatProcessDetect(const std::wstring& stRefID, HANDLE hProcess, const std::wstring& stFileName)
	{
		if (stRefID.empty())
		{
			APP_TRACE_LOG(LL_WARN, L"Undefined reference ID!");
			return;
		}
		else if (!stdext::is_valid_uuid(stRefID))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid reference ID: %s", stRefID.c_str());
			return;
		}
		else if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid process handle: %p", hProcess);
			return;
		}
		else if (stFileName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid file name: %s", stFileName.c_str());
			return;
		}
		else if (!std::filesystem::exists(stFileName))
		{
			APP_TRACE_LOG(LL_ERR, L"File does not exist: %s", stFileName.c_str());
			return;
		}
		
		// Add to the queue
		auto ctx = stdext::make_shared_nothrow<SCheatDetailsQueueCtx>();
		if (!IS_VALID_SMART_PTR(ctx))
		{
			APP_TRACE_LOG(LL_ERR, L"Cheat details queue object could not allocated, error: %u", g_winAPIs->GetLastError());
			return;
		}

		ctx->ref_id = stRefID;
		ctx->process = hProcess;
		ctx->filename = stFileName;

		CApplication::Instance().CheatQueueInstance()->AppendCheatDetailsToQueue(ctx);
	}

	// See: EExitErrorCodes
	void CApplication::OnCloseRequest(EExitErrorCodes ullErrorCode, uint32_t dwSystemErrorCode, LPVOID lpParam, bool bSilent)
	{
		std::lock_guard <std::recursive_mutex> sync(m_mtxCloseProcess);

		// Block another call
		if (m_abIsCloseTriggered.load())
		{
			APP_TRACE_LOG(LL_CRI, L"Another close function request aleady works! Current code: %u Current system error: %u", ullErrorCode, dwSystemErrorCode);
			return;
		}

		// Block another call
		SetErrorTriggered();
		m_abIsCloseTriggered.store(true);

		// Stop in here when debugger is attached
#ifdef _DEBUG
		if (IsDebuggerPresent())
			DebugBreak();
#endif

		// Write error log
		APP_TRACE_LOG(LL_CRI, L"TID: %u PID: %u | Close request handled. Code: %u System error: %u Param: %p Silent: %d",
			HandleToUlong(NtCurrentThreadId()), HandleToUlong(NtCurrentProcessId()), ullErrorCode, dwSystemErrorCode, lpParam, bSilent
		);

		// Create error message string
		auto wstMessageText = L""s;
		if (NoMercyCore::CApplication::Instance().ErrorMessageHelperInstance())
		{
			wstMessageText = NoMercyCore::CApplication::Instance().ErrorMessageHelperInstance()->PrepareErrorMessage(
				EPhase::PHASE_POST, NoMercyCore::ELocalizationPhase::I18N_PHASE_POST, ullErrorCode, dwSystemErrorCode, lpParam
			);
			APP_TRACE_LOG(LL_ERR, L"Localized message: '%s'", wstMessageText.c_str());
		}

		const std::vector <EExitErrorCodes> vecIgnoredLogs = {
			EXIT_ERR_ACCESS_LOST_TO_PROTECTED_PROCESS_THREAD,
			EXIT_ERR_ACCESS_LOST_TO_TELEMETRY_PROCESS,
			EXIT_ERR_ACCESS_LOST_TO_SERVICE_PROCESS,
			EXIT_ERR_TIME_CHANGE_DETECT,
			EXIT_ERR_SERVICE_COMM_TIMEOUT,
			EXIT_ERR_TELEMETRY_ACCESS_LOST_TO_CLIENT
		};

		auto bShouldSendDetailedLog = true;
		if (stdext::in_vector(vecIgnoredLogs, ullErrorCode))
		{
			bShouldSendDetailedLog = false;
		}

		// Send stack log to Sentry
		if (bShouldSendDetailedLog)
		{
			if (NoMercyCore::CApplication::InstancePtr())
				NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();
		}
		
		// Show message
		if (!bSilent)
			ServiceMessageBox(xorstr_(L"NoMercy Error"), wstMessageText.c_str(), MB_ICONERROR);

		APP_TRACE_LOG(LL_SYS, L"Sent to sentry: %d, Silent: %d", bShouldSendDetailedLog, bSilent);

		// SDK Wrapper
		if (IS_VALID_SMART_PTR(CApplication::Instance().SDKHelperInstance()))
		{
			const auto stMessage = std::to_string(ullErrorCode);
			CApplication::Instance().SDKHelperInstance()->SendMessageToClient(NM_DATA_RECV_SUSPICIOUS_EVENT, stMessage.c_str(), (void*)dwSystemErrorCode);
		}

		APP_TRACE_LOG(LL_SYS, L"Sent to game client!");

		// Close other same processess
		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			wchar_t wszCurrProcName[MAX_PATH]{ '\0' };
			if (g_winAPIs->GetProcessImageFileNameW(NtCurrentProcess(), wszCurrProcName, MAX_PATH))
			{
				const auto wstLowerCurrProcName = stdext::to_lower_wide(wszCurrProcName);
				APP_TRACE_LOG(LL_SYS, L"Current process: %s (%u)", wszCurrProcName, g_winAPIs->GetCurrentProcessId());

				for (auto hProc : upProcEnumerator->EnumerateProcesses(true))
				{
					if (IS_VALID_HANDLE(hProc) && NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProc))
					{
						wchar_t wszProcName[MAX_PATH]{ '\0' };
						if (g_winAPIs->GetProcessImageFileNameW(hProc, wszProcName, MAX_PATH))
						{
							const auto wstLowerProcName = stdext::to_lower_wide(wszProcName);
							const auto dwProcID = CProcessFunctions::GetProcessIdNative(hProc);

							if (wstLowerCurrProcName == wstLowerProcName && dwProcID != g_winAPIs->GetCurrentProcessId())
							{
								APP_TRACE_LOG(LL_SYS, L"Closing same process: %s (%u)", wszProcName, dwProcID);
								g_winAPIs->TerminateProcess(hProc, 0);
							}
						}
					}
				}
			}

			upProcEnumerator.reset();
		}

		APP_TRACE_LOG(LL_SYS, L"Closed other same processes!");

		// Finalize
		// CApplication::Instance().Finalize();

		APP_TRACE_LOG(LL_SYS, L"Finalized!");

		// Exit
		CTerminator::TerminateProcess(NtCurrentProcess());
	}

	void CApplication::OnBackendDisconnected()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		// Ignore when finalization started
		if (m_abFinalizeTriggered.load())
			return;

		// Ignore when process termination started
		if (m_abIsCloseTriggered.load())
			return;

		// Set network availability status
		m_abNetworkReady.store(false);
		
		const auto c_wszData = xorstr_(L"Access lost to API server.");
		
		// Pass checks if controlled close
		if (!m_spNetworkMgr->GetWebSocketClient() || !m_spNetworkMgr->GetWebSocketClient()->IsInitialized())
			return;

		// File log
		APP_TRACE_LOG(LL_CRI, L"%s", c_wszData);
	}

	void CApplication::OnBackendConnected()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex);

		// Set network availability status
		m_abNetworkReady.store(true);

		// File log
		const auto c_wszData = xorstr_(L"Connection established to API server.");
		APP_TRACE_LOG(LL_SYS, L"%s", c_wszData);

		// Create websocket queue worker
		CreateWsQueueWorker();

		// Get connection availability status from websocket server
		auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();

		// Get connection availability status from websocket server
		if (IS_VALID_SMART_PTR(ws))
		{
			ws->send_can_connect_message();
		}
	}
};
