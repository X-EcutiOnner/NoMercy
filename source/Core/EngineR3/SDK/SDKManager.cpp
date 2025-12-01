#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SDKManager.hpp"
#include "Metin2/Metin2_SDK.hpp"
#include "../../../Common/GameCodes.hpp"
#include "../../../Common/MutexHelper.hpp"



namespace NoMercy
{
	CSDKManager::CSDKManager() :
		m_pMessageHandler(nullptr), m_bGameInitialized(false), m_bSessionIDSent(false)
	{
		m_spMetin2Mgr = stdext::make_shared_nothrow<CMetin2SDKMgr>();
		if (!IS_VALID_SMART_PTR(m_spMetin2Mgr))
		{
			SDK_LOG(LL_ERR, L"m_spMetin2Mgr allocation failed! Last error: %u", g_winAPIs->GetLastError());
			std::abort();
		}

		/*
#ifdef _DEBUG
		if (IsDebuggerPresent())
			m_stRenderEngine = "directx9";
#endif
		*/
	}
	CSDKManager::~CSDKManager()
	{
	}

	void CSDKManager::ReleaseSDK()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		static auto game = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
		switch (game)
		{
			case GAME_CODE_METIN2:
			{
				m_spMetin2Mgr->Release();
			} break;

			default:
				break;
		}
	}

	void CSDKManager::OnGameTick()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		static auto game = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
		switch (game)
		{
			case GAME_CODE_METIN2:
			{
				if (m_spMetin2Mgr)
					m_spMetin2Mgr->OnGameTick();
			} break;

			default:
				break;
		}
	}

	bool CSDKManager::ProcessClientMessage(int Code, LPCVOID c_lpMessage)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		SDK_LOG(LL_SYS, L"Client message handled! Code: %d Msg: %p", Code, c_lpMessage);

		if (!CApplication::InstancePtr() || CApplication::Instance().AppIsFinalized() || CApplication::Instance().AppCloseTriggered())
			return true;

		// Common data
		if (Code == NM_SIGNAL)
		{
			switch ((uint32_t)c_lpMessage)
			{
				case NM_SIG_POINTER_REDIRECTION_COMPLETED:
				{
					const auto game = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
					if (game == GAME_CODE_METIN2)
					{
						m_spMetin2Mgr->VerifyFunctionModules();
					}
				} break;

				case NM_SIG_CHECK_MULTI_GAME:
				{
					CLimitSingleInstance mutex_helper(CLIENT_MUTEX);
					if (mutex_helper.IsAnotherInstanceRunning())
						CApplication::Instance().OnCloseRequest(EXIT_ERR_MULTIPLE_GAME_INSTANCE, 0);
				} break;

				case NM_SIG_GAME_INIT:
				{
					m_bGameInitialized = true;

					const auto game = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
					if (game == GAME_CODE_METIN2)
						m_spMetin2Mgr->OnGameInitialize();
				} break;

				case NM_SIG_HEARTBEAT_V1_SETUP:
				case NM_SIG_HEARTBEAT_V2_SETUP:
				{
					const auto game = NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode();
					if (game == GAME_CODE_METIN2)
						m_spMetin2Mgr->EnableHeartbeat((uint32_t)c_lpMessage == NM_SIG_HEARTBEAT_V1_SETUP ? 1 : 2);
				} break;

				case NM_SIG_SAVE_LOGS:
				{
				} break;

				case NM_SIG_SCREEN_PROTECTION_ON:
				{
					auto hWnd = reinterpret_cast<HWND>(const_cast<LPVOID>(c_lpMessage));
					CApplication::Instance().InitScreenProtection(hWnd);
				} break;

				case NM_SIG_SCREEN_PROTECTION_OFF:
				{
					auto hWnd = reinterpret_cast<HWND>(const_cast<LPVOID>(c_lpMessage));
					CApplication::Instance().RemoveScreenProtection(hWnd);
				} break;

				case NM_SIG_GAME_POLL_EVENT:
				{
					m_spMetin2Mgr->OnGameTick();
				} break;

				case NM_SIG_VERIFY_PROTECTED_FUNCS:
				{
					// TODO
				} break;

				case NM_SIG_INIT_PYTHON_HOOKS:
				{
					m_spMetin2Mgr->InitializePythonHooks();
				} break;
				case NM_SIG_DESTROY_PYTHON_HOOKS:
				{
					m_spMetin2Mgr->DestroyPythonHooks();
				} break;
				case NM_SIG_REMOVE_PYTHON_WATCHER:
				{
					m_spMetin2Mgr->RemovePythonModuleWatcher();
				} break;

				case NM_SIG_CHECK_PYTHON_MODULES:
				{
					m_spMetin2Mgr->CheckPythonModules();
				} break;

				default:
					SDK_LOG(LL_ERR, L"Unknown signal id: %d", Code);
					break;
			}

			return true;
		}
		else if (Code == NM_SET_VERBOSE)
		{
			// TODO: ELogLevel
		}
		
		// Pointer redirections (general)
		else if (Code == NM_DATA_SEND_PRINT_MESSAGE)
		{
			// TODO: TPrintMessage
		}
		else if (Code == NM_DATA_SEND_REQUEST_RESTART)
		{
			// TODO: TRequestRestart
		}
		else if (Code == NM_DATA_SEND_DISCONNECT_PEER)
		{
			// TODO: TDisconnectPeer
		}
		else if (Code == NM_DATA_SEND_NET_SEND_PACKET)
		{
			// TODO: TNetworkPacket
		}
		else if (Code == NM_DATA_SEND_NET_RECV_PACKET)
		{
			// TODO: TNetworkPacket
		}
		else if (Code == NM_DATA_SEND_REPORT_EVENT)
		{
			// TODO: TSendReport
		}
		else if (Code == NM_DATA_SEND_CHECK_RUNNING_STATUS)
		{
			// TODO: TRunningStatusCheck
		}
		else if (Code == NM_DATA_SEND_LOG_SEND)
		{
			// TODO: TSendLog
		}
		
		// Utilities
		else if (Code == NM_DATA_SET_RENDER_ENGINE)
		{
			// TODO: SRenderEngineCtx
		}
		else if (Code == NM_DATA_CHECK_FILE_HASH)
		{
			// TODO: SFileHashCtx
		}		
		else if (Code == NM_DATA_CHECK_FUNC_HOOK)
		{
			// TODO: SFuncHookCtx
		}
		else if (Code == NM_DATA_PROTECT_FUNCTION)
		{
			// TODO: SProtectFuncCtx
		}		
		else if (Code == NM_DATA_SET_NETWORK_CRYPT_KEY)
		{
			// TODO: SNetworkCryptKey
		}
		else if (Code == NM_DATA_ENCRYPT_NETWORK_MESSAGE)
		{
			// TODO: SNetworkMessage
		}
		else if (Code == NM_DATA_DECRYPT_NETWORK_MESSAGE)
		{
			// TODO: SNetworkMessage
		}
		else if (Code == NM_DATA_SEND_GAME_NETWORK_INFORMATIONS)
		{
			// TODO: SGameNetworkInfo
		}
		else if (Code == NM_DATA_SEND_USER_TOKEN)
		{
			auto data = reinterpret_cast<SUserToken*>(const_cast<LPVOID>(c_lpMessage));
			if (!data)
			{
				SDK_LOG(LL_ERR, L"Invalid user token data!");
				return false;
			}
			const auto name = std::string(data->szToken, data->nTokenSize);

			wstPlayerName = stdext::to_wide(name);
			SDK_LOG(LL_SYS, L"Player name: %s", wstPlayerName.c_str());
		}
		else if (Code == NM_DATA_SEND_PLATFORM_TOKEN)
		{
			auto data = reinterpret_cast<SPlatformToken*>(const_cast<LPVOID>(c_lpMessage));
			if (!data)
			{
				SDK_LOG(LL_ERR, L"Invalid platform token data!");
				return false;
			}
			const auto name = std::string(data->szToken, data->nTokenSize);

			wstPlatformName = stdext::to_wide(name);
			SDK_LOG(LL_SYS, L"Platform name: %s", wstPlatformName.c_str());
		}

		// SENT data to game client //  TODO: Forward to their own implementations
		else if (Code == NM_DATA_RECV_VERSION)
		{
			// TODO: SVersionCtx
		}
		else if (Code == NM_DATA_RECV_CORE_INIT_NOTIFICATION)
		{
			// TODO: NO PARAMETER
		}
		else if (Code == NM_DATA_RECV_IS_INITIALIZED)
		{
			// TODO: SInitRetCtx
		}
		else if (Code == NM_DATA_RECV_SUSPICIOUS_EVENT)
		{
			// TODO: SSusEventCtx
		}
		else if (Code == NM_DATA_RECV_TICK_RESPONSE)
		{
			// TODO: SPollEventCtx
		}
		else if (Code == NM_DATA_RECV_SESSION_ID)
		{
			// TODO: SSessionIDCtx
		}
		
		// Game specific
		switch (NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode())
		{
			case GAME_CODE_METIN2:
			{
				m_spMetin2Mgr->OnClientMessage(Code, c_lpMessage);
			} break;

			default:
				SDK_LOG(LL_ERR, L"Game code is undefined for process client messages!");
				break;
		}

		// Test
#ifdef _DEBUG
		if (Code == NM_DATA_SEND_TEST_MESSAGE)
		{
			SDK_LOG(LL_CRI, L"Test message received!");
		}
#endif
		
		return true;
	}

	bool CSDKManager::CreateMessageHandler(TNMCallback lpMessageHandler)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		m_pMessageHandler = lpMessageHandler;
		SDK_LOG(LL_SYS, L"Message handler: %p registered!", m_pMessageHandler);

		// Send session id
		const auto wstSID = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID();
		if (!wstSID.empty())
		{
			const auto stSID = stdext::to_ansi(wstSID);
			SDK_LOG(LL_SYS, L"Session ID: %s", wstSID.c_str());

			SendSessionIDToClient(stSID.c_str());
		}

		return true;
	}

	bool CSDKManager::SendMessageToClient(int Code, const char* c_szMessage, void* lpParam)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		if (!m_pMessageHandler)
		{
			SDK_LOG(LL_ERR, L"Message handler not yet created!");
			return false;
		}

		SDK_LOG(LL_SYS, L"Sending message %d (%hs) %p - via: %p Helper: %p", Code, c_szMessage && *c_szMessage ? c_szMessage : xorstr_("<UNKNOWN>"), lpParam, m_pMessageHandler, this);
		
		m_pMessageHandler(static_cast<ENMMsgCodes>(Code), c_szMessage, lpParam);

		SDK_LOG(LL_SYS, L"Message sent!");

		return true;
	}
	bool CSDKManager::SendSessionIDToClient(const char* c_szSessionID)
	{
		if (!c_szSessionID || !*c_szSessionID)
		{
			SDK_LOG(LL_ERR, L"Invalid session id!");
			return false;
		}

		std::lock_guard <std::recursive_mutex> __lock(m_mutex);

		if (!m_bSessionIDSent)
		{
			SSessionIDCtx ctx;
			strncpy_s(ctx.szSessionID, c_szSessionID, sizeof(ctx.szSessionID));

			SendMessageToClient(NM_DATA_RECV_SESSION_ID, "", &ctx);
			m_bSessionIDSent = true;
		}

		return true;
	}
};
