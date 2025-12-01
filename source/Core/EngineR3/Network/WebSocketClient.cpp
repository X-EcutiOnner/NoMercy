#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "WebSocketClient.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../EngineR3_Core/include/FileVersion.hpp"
#include "../../../Common/FilePtr.hpp"
#include <jwt-cpp/jwt.h>
#include <sodium.h>

#define WEBSOCKET_COMM_PUBLIC_KEY xorstr_("SGEE9ZXmunuaUEoDbq58gBYUBzbgXnh2WOIxiQUYFwg=")
#define WEBSOCKET_HOST_DOMAIN xorstr_(L"nomercy.ac")



namespace NoMercy
{
	static auto gs_nConnectionTryCount = 0;

#if (WEBSOCKET_USE_SSL == TRUE)
	static context_ptr on_tls_init(const char* hostname, websocketpp::connection_hdl)
	{
		APP_TRACE_LOG(LL_SYS, L"TLS initializing with %hs (%hs)", REST_CERT_FILENAME, REST_CERT_KEY_FILENAME);
		
		// establishes a SSL connection
		// context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);
		context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::tlsv13_client);

		try
		{
			ctx->set_options(
				asio::ssl::context::default_workarounds |
				asio::ssl::context::no_sslv2 |
				asio::ssl::context::no_sslv3 |
				asio::ssl::context::single_dh_use
			);
			
			asio::error_code ec{};
			ctx->use_certificate_file(REST_CERT_FILENAME, asio::ssl::context::file_format::pem, ec);
			if (ec)
			{
				APP_TRACE_LOG(LL_CRI, L"use_certificate_file failed, error code: %d, error message: %hs", ec.value(), ec.message().c_str());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_SSL_EXCEPTION, ec.value());
			}
			
			ctx->use_private_key_file(REST_CERT_KEY_FILENAME, asio::ssl::context::file_format::pem, ec);
			if (ec)
			{
				APP_TRACE_LOG(LL_CRI, L"use_private_key_file failed, error code: %d, error message: %hs", ec.value(), ec.message().c_str());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_SSL_EXCEPTION, ec.value());
			}
		}
		catch (const std::exception& e)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp SSL exception: %hs Error: %u", e.what(), g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_SSL_EXCEPTION, 1337, (void*)e.what());
		}
		return ctx;
	}
#endif

	CWebSocketClient::CWebSocketClient(const std::string& host, uint32_t port) :
		m_bInitialized(false), m_dwPort(port), m_stToken(""), m_bConnectionLost(true), m_bConnectionFailed(false),
		m_dwLastConnectionTime(0), m_dwDisconectCounter(0), m_dwLastDisconectTime(0), m_bIsIdleClient(false)
	{
		const auto wstHost = stdext::to_wide(host);
		m_wstHost = wstHost;
		
		m_bIsRawTest =
			NoMercyCore::CApplication::Instance().GetAppType() == NM_STANDALONE &&
			m_wstHost.find(WEBSOCKET_HOST_DOMAIN) == std::wstring::npos;
	}
	CWebSocketClient::~CWebSocketClient()
	{
	}

	bool CWebSocketClient::create_jwt(std::wstring& wstToken)
	{
		static constexpr auto ATTEMPT_LIMIT = 5;
		auto fnCreateTokenEx = [&](uint8_t attempt) {
			auto stToken = CApplication::Instance().NetworkMgrInstance()->GetCurlClient()->GetWebSocketToken(
				fmt::format(
					xorstr_("https://{0}/v1/create_client_access_token"),
					stdext::to_ansi(API_SERVER_URI)
				)
			);

			wstToken = stdext::to_wide(stToken);
			if (wstToken.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"[%u/%u] Failed to get websocket token", attempt, ATTEMPT_LIMIT);
				return false;
			}

			APP_TRACE_LOG(LL_SYS, L"[%u/%u] Token (%s) created for websocket server!", attempt, ATTEMPT_LIMIT, wstToken.c_str());
			return true;
		};

		// Try to create token with 5 times and 2 second delay
		for (auto i = 0; i < ATTEMPT_LIMIT; i++)
		{
			if (fnCreateTokenEx(i + 1))
				return true;

			g_winAPIs->Sleep(2000);
		}

		return false;
	}
	void CWebSocketClient::verify_jwt()
	{
		// Verify token
		auto validated_token = false;
		try
		{
			const auto decoded = jwt::decode(m_stToken);
			const auto stSessionID = stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID());

			for (auto& e : decoded.get_payload_claims())
			{
				APP_TRACE_LOG(LL_SYS, L"jwt payload: %hs -> %hs", e.first.c_str(), e.second.to_json().to_str().c_str());

				if (e.first == xorstr_("session_id") && e.second.to_json().to_str() == stSessionID)
				{
					// TODO: check expired token
					validated_token = true;
				}
			}
		}
		catch (const std::invalid_argument& e)
		{
			APP_TRACE_LOG(LL_CRI, L"std::invalid_argument exception handled! Error: %hs", e.what());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_JWT_TOKEN_EXCEPTION, 1, (void*)e.what());
		}
		catch (const std::runtime_error& e)
		{
			APP_TRACE_LOG(LL_CRI, L"std::runtime_error exception handled! Error: %hs", e.what());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_JWT_TOKEN_EXCEPTION, 2, (void*)e.what());
		}
		catch (...)
		{
			APP_TRACE_LOG(LL_CRI, L"Caught unhandled exception!");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_JWT_TOKEN_EXCEPTION, 3);
		}

		if (!validated_token)
		{
			APP_TRACE_LOG(LL_CRI, L"Token could not validated!");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_JWT_TOKEN_VALIDATE_FAIL, 0);
		}
	}


	void CWebSocketClient::send_message(const std::wstring& message, bool queued)
	{
//		__PROTECTOR_START__("ws_send_message");

		const auto hdl(m_connection.lock().get());
		if (!hdl || m_bConnectionLost)
		{
			APP_TRACE_LOG(LL_ERR, L"Websocket message: %s could not sent, connection is not available.", message.c_str());
	
			if (!queued)
			{
				APP_TRACE_LOG(LL_WARN, L"Websocket client is not ready yet! Message append to queue");
				CApplication::Instance().EnqueueWsMessage(message);
			}

			return;
		}

		APP_TRACE_LOG(LL_SYS, L"Websocket send_message; Conn: %p Msg: %s", hdl, message.c_str());;

		const auto wstCryptedMessage = encrpyt_message(message);
		const auto stCryptedMessage = stdext::to_ansi(wstCryptedMessage);

		websocketpp::lib::error_code ec;
		m_client.send(m_connection, stCryptedMessage.c_str(), websocketpp::frame::opcode::text, ec);

		// Check error code
		if (ec)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp send failed. Message: %s Error: %hs (%d)", message.c_str(), ec.message().c_str(), ec.value());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_SEND_FAIL, ec.value());
		}

//		__PROTECTOR_END__("ws_send_message");
	}
  
	std::wstring CWebSocketClient::decrypt_message(const std::wstring& in)
	{
#if (NOMERCY_WS_CUSTOM_CRYPT == 1)
		if (in.find(xorstr_(L"9.6")) == std::wstring::npos)
		{
			APP_TRACE_LOG(LL_ERR, L"Message could not validated");
			return {};
		}

		std::wstring out = in;
		stdext::reverse_string(out);

		const auto splitted = stdext::split_string<std::wstring>(out, xorstr_(L"6.9"));
		if (splitted.size() != 2)
		{
			APP_TRACE_LOG(LL_ERR, L"Message corrupted");
			return {};
		}

		if (!NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->IsBase64(splitted[0]))
		{
			APP_TRACE_LOG(LL_ERR, L"Message content could not validated");
			return {};
		}

		if (splitted[1].size() != 32)
		{
			APP_TRACE_LOG(LL_ERR, L"Message hash size: %u is not correct!", splitted[1].size());
			return {};
		}

		const auto base64decoded = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->DecodeBase64(splitted[0]);
		if (base64decoded.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Message decode failed");
			return {};
		}
		
		const auto md5sum = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetMd5(base64decoded);
		if (md5sum != splitted[1])
		{
			APP_TRACE_LOG(LL_ERR, L"Message hash validation failed");
			return {};
		}
		
		out = base64decoded;
		return out;
#else
		return in;
#endif
	}
	std::wstring CWebSocketClient::encrpyt_message(const std::wstring& wstBuffer)
	{
#if (NOMERCY_WS_CUSTOM_CRYPT == 1)
		const auto stBuffer = stdext::to_ansi(wstBuffer);
		const auto stEncrypted = NoMercy::Encrypt(stBuffer, m_spKeyPair);
		const auto stHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetMd5(stEncrypted);

		auto stOut = stEncrypted + xorstr_("6~9") + stHash;
		stdext::reverse_string(stOut);

		return stdext::to_wide(stOut);
#else
		return wstBuffer;
#endif
	}

	void CWebSocketClient::send_can_connect_message()
	{
		auto format_message = [](const std::wstring& type, const uint32_t api_version, const std::wstring& stage, const std::wstring& stage_key) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"api_version"));
					writer.Uint(api_version);

					writer.Key(xorstr_(L"stage"));
					writer.String(stage.c_str());

					writer.Key(xorstr_(L"stage_key"));
					writer.String(stage_key.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		// Fix some informations for debug client
		if (stdext::is_debug_build_only() || // Debug build
			(stdext::is_debug_build() && NoMercyCore::CApplication::Instance().DataInstance()->GetAppType() == NM_STANDALONE)) // Debug/ReleaseDebug build and standalone app
		{
			// If connection lost to websocket server it's should not call in every re-connection
			static auto s_bOnce = false;
			if (!s_bOnce)
			{
				s_bOnce = true;
				
				NoMercyCore::CApplication::Instance().DataInstance()->SetStage(STATE_DEV, xorstr_(L"dev"));
				NoMercyCore::CApplication::Instance().DataInstance()->SetStageKey(xorstr_(L"13371338"));

				NoMercyCore::CApplication::Instance().DataInstance()->SetLicenseCode(xorstr_(L"ABCDEF123490"));
				NoMercyCore::CApplication::Instance().DataInstance()->SetGameCode(1);
				NoMercyCore::CApplication::Instance().DataInstance()->SetGameVersion(100);
			}
		}

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_CAN_CONNECT),
			NOMERCY_WS_API_VERSION,
			NoMercyCore::CApplication::Instance().DataInstance()->GetStageStr(),
			NoMercyCore::CApplication::Instance().DataInstance()->GetStageKey()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_license_message()
	{
		auto format_message = [](const std::wstring& type, const std::wstring& license_id, const uint32_t game_code, const std::vector <std::wstring>& licensed_ips,
			const std::wstring& executable, const std::wstring& file_create_time, const std::wstring& window_title, const std::wstring& sign_provider, const std::wstring& file_version
		) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"license_id"));
					writer.String(license_id.c_str());

					writer.Key(xorstr_(L"game_code"));
					writer.Uint(game_code);

					writer.Key(xorstr_(L"ip_addresses"));
					writer.StartArray();
					for (const auto& ip : licensed_ips)
					{
						writer.String(ip.c_str());
					}
					writer.EndArray();

					writer.Key(xorstr_(L"executable"));
					writer.String(executable.c_str());

					writer.Key(xorstr_(L"file_create_time"));
					writer.String(file_create_time.c_str());
					
					writer.Key(xorstr_(L"window_title"));
					writer.String(window_title.c_str());

					writer.Key(xorstr_(L"sign_provider"));
					writer.String(sign_provider.c_str());

					writer.Key(xorstr_(L"file_version"));
					writer.String(file_version.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		std::wstring wstGameFileVersion;
		std::wstring wstGameSignProvider;
		std::wstring wstGameWindowTitle;
		uint32_t dwFileCreateTime = 0;
		uint32_t dwGamePID = 0;
		std::wstring wstGameProcessExecutable;
		
		dwGamePID = g_winAPIs->GetCurrentProcessId();
		wstGameProcessExecutable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
			
		if (!wstGameProcessExecutable.empty() && dwGamePID)
		{
			SafeHandle hFile = g_winAPIs->CreateFileW(wstGameProcessExecutable.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile.IsValid())
			{
				FILETIME lpCreationTime;
				FILETIME lpLastAccessTime;
				FILETIME lpLastWriteTime;
				if (g_winAPIs->GetFileTime(hFile, &lpCreationTime, &lpLastAccessTime, &lpLastWriteTime))
				{
					dwFileCreateTime = stdext::windows_ticks_to_unix_seconds(lpCreationTime.dwHighDateTime);
					APP_TRACE_LOG(LL_SYS, L"Game file create time: %u", dwFileCreateTime);
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"GetFileTime failed with error: %u", g_winAPIs->GetLastError());
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileA failed with error: %u", g_winAPIs->GetLastError());
			}

			auto hGameWnd = CApplication::Instance().FunctionsInstance()->GetMainWindow(dwGamePID);
			if (!hGameWnd)
				hGameWnd = CApplication::Instance().FunctionsInstance()->GetFirstWindow(dwGamePID);
			
			if (hGameWnd)
			{
				wchar_t wszTitle[512]{ L'\0' };
				if (g_winAPIs->GetWindowTextW(hGameWnd, wszTitle, 512))
				{
					wstGameWindowTitle = wszTitle;
					APP_TRACE_LOG(LL_SYS, L"Game window title: %s", wstGameWindowTitle.c_str());
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"GetWindowTextA failed with error: %u", g_winAPIs->GetLastError());
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get main window for game process with PID: %u", dwGamePID);
			}

			const auto dwSignCheckRet = PeSignatureVerifier::CheckFileSignature(wstGameProcessExecutable, false); // TODO: convertSignInfo(lRetVal)
			APP_TRACE_LOG(LL_SYS, L"CheckFileSignature: %s Ret: %u", wstGameProcessExecutable.c_str(), dwSignCheckRet);
			if (dwSignCheckRet == ERROR_SUCCESS)
			{
				std::wstring wstProvider;
				// if (wstProvider.size() < 2) // Provide query failed by WinVerifyTrust, Try to query with another API
				{
					APP_TRACE_LOG(LL_WARN, L"Driver signature provider query failed!");

					CryptoApiWrapper::SignerInfoPtr si;
					const auto dwCertQueryRet = PeSignatureVerifier::GetCertificateInfo(wstGameProcessExecutable, si);
					if (dwCertQueryRet != ERROR_SUCCESS)
					{
						APP_TRACE_LOG(LL_ERR, L"Driver signature provider query failed! Error: %d", dwCertQueryRet);
					}
					else if (!IS_VALID_SMART_PTR(si))
					{
						APP_TRACE_LOG(LL_ERR, L"Driver signature provider query failed! Error: %u", g_winAPIs->GetLastError());
					}
					else
					{
						wstProvider = si->subjectName;
						APP_TRACE_LOG(LL_SYS, L"Driver signature provider query success! Provider: %ls", wstProvider.c_str());
					}
				}
				
				wstGameSignProvider = wstProvider;
				APP_TRACE_LOG(LL_SYS, L"Signature provider: %s", wstGameSignProvider.c_str());
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"CheckFileSignature failed with error: %u", dwSignCheckRet);
			}
			
			CFileVersion verInfo;
			if (verInfo.QueryFile(wstGameProcessExecutable))
			{
				wstGameFileVersion = verInfo.GetFileVersion();
				APP_TRACE_LOG(LL_SYS, L"FileVersion: %s", wstGameFileVersion.c_str());
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"QueryFile failed with error: %u", g_winAPIs->GetLastError());
			}
		}
		
		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_LICENSE),
			NoMercyCore::CApplication::Instance().DataInstance()->GetLicenseCode(),
			NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode(),
			NoMercyCore::CApplication::Instance().DataInstance()->GetLicensedIPs(),
			wstGameProcessExecutable,
			std::to_wstring(dwFileCreateTime),
			wstGameWindowTitle,
			wstGameSignProvider,
			wstGameFileVersion
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_nomercy_config_message()
	{
		auto format_message = [](const std::wstring& type, const std::wstring& license) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"license_id"));
					writer.String(license.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_NOMERCY_CONFIG),
			NoMercyCore::CApplication::Instance().DataInstance()->GetLicenseCode()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_user_auth_message()
	{
		auto format_message = [](
			const std::wstring& type,
			const std::wstring& session_id, const std::wstring& simple_hwid,
			const uint32_t nomercy_version, const uint32_t game_version,
			const std::wstring& user_locale, const std::wstring& os_info,
			const std::wstring& executable, const std::wstring& parent_executable,
			const std::wstring& process_commandline, const std::wstring& process_title,
			const uint32_t arch,
			const uint8_t app_type,
			const std::wstring& ext_hwid_gpu, const std::wstring& ext_hwid_modem, const std::wstring& ext_hwid_monitor, const std::wstring& ext_hwid_sid
		) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"session_id"));
					writer.String(session_id.c_str());

					writer.Key(xorstr_(L"hwid"));
					writer.String(simple_hwid.c_str());

					writer.Key(xorstr_(L"nomercy_version"));
					writer.Uint(nomercy_version);

					writer.Key(xorstr_(L"game_version"));
					writer.Uint(game_version);

					writer.Key(xorstr_(L"user_locale"));
					writer.String(user_locale.c_str());

					writer.Key(xorstr_(L"user_os"));
					writer.String(os_info.c_str());

					writer.Key(xorstr_(L"executable"));
					writer.String(executable.c_str());

					writer.Key(xorstr_(L"parent_executable"));
					writer.String(parent_executable.c_str());

					writer.Key(xorstr_(L"process_commandline"));
					writer.String(process_commandline.c_str());

					writer.Key(xorstr_(L"process_title"));
					writer.String(process_title.c_str());

					writer.Key(xorstr_(L"arch"));
					writer.Uint(arch);

					writer.Key(xorstr_(L"app_type"));
					writer.Uint(app_type);

					writer.Key(xorstr_(L"ext_hwid_1"));
					writer.String(ext_hwid_gpu.c_str());

					writer.Key(xorstr_(L"ext_hwid_2"));
					writer.String(ext_hwid_modem.c_str());

					writer.Key(xorstr_(L"ext_hwid_3"));
					writer.String(ext_hwid_monitor.c_str());

					writer.Key(xorstr_(L"ext_hwid_4"));
					writer.String(ext_hwid_sid.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		auto platform = std::to_wstring(NM_PLATFORM);
		if (stdext::is_wow64())
			platform += xorstr_(L"64");

		auto extHwid = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetExtHwidCtx();
		
		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_USER_AUTH),
			NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID(),
			NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSimpleHwid(),
			__NOMERCY_VERSION__,
			NoMercyCore::CApplication::Instance().DataInstance()->GetGameVersion(),
			CApplication::Instance().FunctionsInstance()->GetSystemLocale(),
			fmt::format(xorstr_(L"{0}.{1}.{2}_{3}"), GetWindowsMajorVersion(), GetWindowsMinorVersion(), GetWindowsServicePackVersion(), GetWindowsBuildNumber()),
			NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath(),
			CProcessFunctions::ParentProcessName(),
			CApplication::Instance().FunctionsInstance()->GetProcessCommandLine(),
			CApplication::Instance().FunctionsInstance()->GetMainWindowTitle(g_winAPIs->GetCurrentProcessId()),
			stdext::str_to_u32(platform),
			NoMercyCore::CApplication::Instance().DataInstance()->GetAppType(),
			extHwid->wstGPUID, extHwid->wstPhysicalMacAddress, extHwid->wstSID, L"" // , extHwid->wstMonitorIDs
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_nomercy_validation_message()
	{
		auto format_message = [](const std::wstring& type, const uint32_t version, const uint32_t stage, const std::wstring& build_date, const std::wstring& hash_list) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"version"));
					writer.Uint(version);

					writer.Key(xorstr_(L"stage"));
					writer.Uint(stage);

					writer.Key(xorstr_(L"build_date"));
					writer.String(build_date.c_str());

					writer.Key(xorstr_(L"hash_list"));
					writer.String(hash_list.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_NOMERCY_VALIDATION),
			__NOMERCY_VERSION__,
			NoMercyCore::CApplication::Instance().DataInstance()->GetStage(),
			CApplication::Instance().FunctionsInstance()->FixedBuildDate(),
			CApplication::Instance().FunctionsInstance()->GetNoMercyHashList()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_game_server_validation_message()
	{
		auto format_message = [](const std::wstring& type, const std::wstring& game_hash, const uint32_t game_version, const std::wstring& platform, const std::wstring& player_name) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"game_hash"));
					writer.String(game_hash.c_str());

					writer.Key(xorstr_(L"game_version"));
					writer.Uint(game_version);

					writer.Key(xorstr_(L"platform"));
					writer.String(platform.c_str());

					writer.Key(xorstr_(L"player_name"));
					writer.String(player_name.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		std::wstring stGameProcessExecutable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();

		const auto stProcessHash = !stGameProcessExecutable.empty() ? NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileMd5(stGameProcessExecutable) : L"";
		APP_TRACE_LOG(LL_SYS, L"Game process hash: %s", stProcessHash.c_str());

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_GAME_SERVER_VALIDATION),
			stProcessHash,
			NoMercyCore::CApplication::Instance().DataInstance()->GetGameVersion(),
			CApplication::Instance().SDKHelperInstance()->GetPlatformName(),
			CApplication::Instance().SDKHelperInstance()->GetPlayerName()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_cheat_db_request_message()
	{
		auto format_message = [](const std::wstring& type, const uint32_t game_id) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"game_id"));
					writer.Uint(game_id);
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};
		
		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_CHEAT_DB_REQUEST),
			NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_initilization_success_message()
	{
		auto format_message = [](const std::wstring& type, const std::wstring& session_id, const std::wstring& timestamp, const uint32_t tick_count, const uint32_t app_type) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"session_id"));
					writer.String(session_id.c_str());

					writer.Key(xorstr_(L"client_timestamp"));
					writer.String(timestamp.c_str());

					writer.Key(xorstr_(L"client_tickcount"));
					writer.Uint(tick_count);

					writer.Key(xorstr_(L"app_type"));
					writer.Uint(app_type);
					
					writer.Key(xorstr_(L"pid"));
					writer.Uint(g_winAPIs->GetCurrentProcessId());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		static auto s_bOnce = false;
		if (s_bOnce)
			return;
		s_bOnce = true;

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_INIT_SUCCESS_NOTIFICATION),
			NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID(),
			std::to_wstring(stdext::get_current_epoch_time()),
			g_winAPIs->GetTickCount(),
			NoMercyCore::CApplication::Instance().DataInstance()->GetAppType()
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_initilization_failure_message(const uint32_t error_code, const uint32_t system_error_code)
	{
		auto format_message = [](const std::wstring& type, const std::wstring& init_ret, const std::wstring& sub_code) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"init_ret"));
					writer.String(init_ret.c_str());

					writer.Key(xorstr_(L"sub_code"));
					writer.String(sub_code.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_INIT_FAILURE_NOTIFICATION),
			std::to_wstring(error_code),
			std::to_wstring(system_error_code)
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_client_close_notification_message(const uint32_t req_id, const uint32_t sub_code, const std::wstring& details)
	{
		auto format_message = [](const std::wstring& type, const std::wstring& req_id, const std::wstring& sub_code, const std::wstring& details) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"req_id"));
					writer.String(req_id.c_str());

					writer.Key(xorstr_(L"sub_code"));
					writer.String(sub_code.c_str());

					writer.Key(xorstr_(L"details"));
					writer.String(details.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_CLIENT_CLOSE_NOTIFICATION),
			std::to_wstring(req_id),
			std::to_wstring(sub_code),
			details
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_game_asset_validation_message(const std::map <std::wstring /* filename */, std::wstring /* hash */> files)
	{
		auto format_message = [files](const std::wstring& type) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"hash_list"));
					writer.StartObject();
					{
						for (const auto& [name, hash] : files)
						{
							writer.Key(name.c_str());
							writer.String(hash.c_str());
						}
					}
					writer.EndObject();
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_GAME_ASSET_VALIDATION)
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_cheat_detection_message(const std::wstring& ref_id, const std::wstring& cheat_id, const std::wstring& sub_id, const std::wstring& custom_message, const std::vector <std::wstring>& screenshots)
	{
		auto format_message = [](const std::wstring& type, const std::wstring& ref_id, const std::wstring& cheat_id, const std::wstring& sub_id, const std::wstring& custom_message, const std::vector <std::string>& screenshot_refs) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"ref_id"));
					writer.String(ref_id.c_str());
					
					writer.Key(xorstr_(L"cheat_id"));
					writer.String(cheat_id.c_str());

					writer.Key(xorstr_(L"sub_id"));
					writer.String(sub_id.c_str());

					writer.Key(xorstr_(L"custom_message"));
					writer.String(custom_message.c_str());

					writer.Key(xorstr_(L"screenshots"));
					writer.StartArray();
					for (std::size_t i = 0; i < screenshot_refs.size(); ++i)
					{
						auto stSSRef = stdext::to_wide(screenshot_refs[i]);
						writer.String(stSSRef.c_str());
					}
					writer.EndArray();
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_CHEAT_DETECTION),
			ref_id,
			cheat_id,
			sub_id,
			custom_message,
			{}
		);
		this->send_message(msg);
	}

	void CWebSocketClient::send_user_telemetry_message(const std::wstring& message)
	{
		auto format_message = [](const std::wstring& type, const std::wstring& message) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"custom_data"));
					writer.String(message.c_str());
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_TELEMETRY),
			message
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_cheat_db_validation_message(const uint32_t db_version)
	{
		auto format_message = [](const std::wstring& type, uint32_t db_version) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"version"));
					writer.Uint(db_version);
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(
			std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_CHEAT_DB_VALIDATION),
			db_version
		);
		this->send_message(msg);
	}
	void CWebSocketClient::send_heartbeat_response(const uint8_t status, const uint8_t key)
	{
		auto format_message = [](const std::wstring& type, const uint8_t key, const uint8_t status) {
			GenericStringBuffer<UTF16<> > s;
			PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

			writer.StartObject();
			{
				writer.Key(xorstr_(L"type"));
				writer.String(type.c_str());

				writer.Key(xorstr_(L"data"));
				writer.StartObject();
				{
					writer.Key(xorstr_(L"hb_type"));
					writer.Uint(1);

					writer.Key(xorstr_(L"hb_data"));
					writer.StartObject();
					{
						/*
						TODO: Add game window position
						*/

						writer.Key(xorstr_(L"ctx"));
						writer.Uint(g_winAPIs->GetCurrentProcessId() ^ key);

						writer.Key(xorstr_(L"status"));
						writer.Uint(status);

						writer.Key(xorstr_(L"tick"));
						writer.Uint(g_winAPIs->NtGetTickCount());
					}
					writer.EndObject();
				}
				writer.EndObject();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			return woss.str();
		};

		const auto msg = format_message(std::to_wstring(WS_OUTGOING_MESSAGE_TYPE_HEARTBEAT), key, status);
		this->send_message(msg);
	}


	void CWebSocketClient::on_binary_handle(const std::string& buffer)
	{
		APP_TRACE_LOG(LL_WARN, L"Websocket on_binary_handle; buffer size: %d", buffer.size());

		// TODO: process
	}
	void CWebSocketClient::on_error_message(const int32_t id, const std::wstring& msg)
	{
		APP_TRACE_LOG(LL_ERR, L"Error message handled; ID: %d Message: '%s'", id, msg.c_str());

		CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_ERROR_MESSAGE, id, (void*)msg.c_str());
	}
	void CWebSocketClient::on_custom_message(const int32_t id, rapidjson::GenericValue<UTF16<>>&& val)
	{
		const auto stDumpedMsg = stdext::dump_json_document(val);
		APP_TRACE_LOG(LL_SYS, L"Message handled: ID: %d Message: '%s'", id, stDumpedMsg.c_str());

		switch (id)
		{
			case WS_INCOMING_MESSAGE_TYPE_CAN_CONNECT_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Websocket server currently can not handle connection.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_CAN_NOT_HOLD_CONNECTION, static_cast<uint32_t>(EWSIncMsgErrCodes::CAN_CONNECT_RESULT));
				}
				else
				{
					this->send_license_message();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_LICENSE_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Server license is not valid.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_SV_LICENSE_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::LICENSE_RESULT));
				}
				else
				{
					this->send_nomercy_config_message();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_NOMERCY_CONFIG_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Config response is not allowed!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_CORRUPTED_CONFIG_MSG, static_cast<uint32_t>(EWSIncMsgErrCodes::NM_CONFIG_RESULT));
				}

				const auto pkSecurityLevel = val.FindMember(xorstr_(L"security_level"));
				const auto pkDisabledFuncs = val.FindMember(xorstr_(L"disabled_funcs"));

				if (pkSecurityLevel == val.MemberEnd())
				{
					APP_TRACE_LOG(LL_CRI, L"Corrupted config response! (1)");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_CORRUPTED_CONFIG_MSG, static_cast<uint32_t>(EWSIncMsgErrCodes::NM_CONFIG_PARSE_1));
				}
				else if (pkDisabledFuncs == val.MemberEnd())
				{
					APP_TRACE_LOG(LL_CRI, L"Corrupted config response! (2)");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_CORRUPTED_CONFIG_MSG, static_cast<uint32_t>(EWSIncMsgErrCodes::NM_CONFIG_PARSE_2));
				}

				if (pkSecurityLevel->value.IsNumber())
				{
					const auto security_level = pkSecurityLevel->value.GetUint();
					NoMercyCore::CApplication::Instance().DataInstance()->SetSecurityLevel(security_level);
				}
				else
				{
					APP_TRACE_LOG(LL_CRI, L"Corrupted config response! (3)");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_CORRUPTED_CONFIG_MSG, static_cast<uint32_t>(EWSIncMsgErrCodes::NM_CONFIG_PARSE_3));
				}

				if (pkDisabledFuncs->value.IsNumber())
				{
					const auto disabled_funcs = pkDisabledFuncs->value.GetUint();
					NoMercyCore::CApplication::Instance().DataInstance()->SetDisabledFuncs(disabled_funcs);
				}
				
				this->send_user_auth_message();
			} break;
			case WS_INCOMING_MESSAGE_TYPE_USER_AUTH_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"User auth failed");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_USER_AUTH_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::USER_AUTH_RESULT));
				}
				else
				{
					this->send_nomercy_validation_message();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_NOMERCY_VALIDATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					// Outdated version check
					const auto min_version = val.HasMember(xorstr_(L"min_version")) ? val[xorstr_(L"min_version")].GetInt() : 0;
					if (min_version)
					{
						APP_TRACE_LOG(LL_CRI, L"Outdated version detected! (min: %d)", min_version);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_OUTDATED_VERSION, min_version);
						break;
					}

					APP_TRACE_LOG(LL_CRI, L"NoMercy self integrity validation is failed.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_SELF_INTEGRITY_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::NM_VALIDATION_RESULT));
				}
				else
				{
					this->send_game_server_validation_message();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_GAME_SERVER_VALIDATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy server integrity validation is failed.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_SERVER_INTEGRITY_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::GS_VALIDATION_RESULT));
				}
				else
				{
					this->send_cheat_db_request_message();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_CHEAT_DB_REQUEST_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy databases are corrupted.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_CORRUPTED_CHEAT_DB, static_cast<uint32_t>(EWSIncMsgErrCodes::CDB_REQUEST_RESULT));
				}
				else
				{
					const auto& pkDB = val.FindMember(xorstr_(L"db"));
					if (pkDB != val.MemberEnd())
					{
						if (pkDB->value.IsString())
						{
							CApplication::Instance().CheatDBManagerInstance()->ProcessCheatDB(pkDB->value.GetString(), true);
						}
						else
						{
							APP_TRACE_LOG(LL_CRI, L"'db' value type: %d is not correct in remote cheat DB", pkDB->value.GetType());
						}
					}
					else
					{
						APP_TRACE_LOG(LL_CRI, L"'db' key does not exist in remote cheat DB");
					}

					const auto& pkTools = val.FindMember(xorstr_(L"tools"));
					if (pkTools != val.MemberEnd())
					{
						if (pkTools->value.IsString())
						{
							CApplication::Instance().CheatDBManagerInstance()->ProcessBlockedTools(pkTools->value.GetString());
						}
						else
						{
							APP_TRACE_LOG(LL_CRI, L"'tools' value type: %d is not correct in remote cheat DB", pkTools->value.GetType());
						}
					}
					else
					{
						APP_TRACE_LOG(LL_CRI, L"'tools' key does not exist in remote cheat DB");
					}

					// Simple sanity check for loaded game informations
					const auto bCanConnect = NoMercyCore::CApplication::Instance().DataInstance()->HasLicensedIp();
					APP_TRACE_LOG(LL_SYS, L"Can connect to ret: %d", bCanConnect ? 1 : 0);
 
					if (bCanConnect)
					{
						this->send_initilization_success_message();
					}
				}		
			} break;
			case WS_INCOMING_MESSAGE_TYPE_INIT_SUCCESS_NOTIFICATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy initilization response result is not valid.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::INIT_SUCCESS_RESULT));
				}
				else
				{
					APP_TRACE_LOG(LL_SYS, L"Websocket is ready for communication!");

					// Set flag
					CApplication::Instance().SetWsConnectionReady(true);

					// Start heartbeat timer
					CApplication::Instance().CreateWsHearbeatWorker();

					// Start single scan instances (run only once in a session due to performance)
					CApplication::Instance().RunClientSingleScanInstances();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_INIT_FAILURE_NOTIFICATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"NoMercy initilization response result is not valid.");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::INIT_FAIL_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_CLIENT_CLOSE_NOTIFICATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Client close notification response is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::CLOSE_NOTIFICATION_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_GAME_ASSET_VALIDATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Game asset validation response is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::ASSET_VALIDATION_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_CHEAT_DETECTION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Cheat detection report response is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::CHEAT_DETECT_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_TELEMETRY_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Telemetry response is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::USER_TELEMETRY_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_CHEAT_DB_VALIDATION_RESULT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Remote cheat DB message is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::CDB_VALIDATION_RESULT));
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_BROADCAST:
			{
				if (val.FindMember(xorstr_(L"type")) == val.MemberEnd())
				{
					APP_TRACE_LOG(LL_ERR, L"Message 'type' is not found!");
					return;
				}
				const auto& pkType = val[xorstr_(L"type")];
				if (!pkType.IsString())
				{
					APP_TRACE_LOG(LL_ERR, L"Message type is not a string! Type: %u", pkType.GetType());
					return;
				}
				const auto wstType = std::wstring(
					pkType.GetString(),
					pkType.GetStringLength()
				);
				if (wstType.empty())
				{
					APP_TRACE_LOG(LL_ERR, L"Message type is empty!");
					return;
				}

				APP_TRACE_LOG(LL_SYS, L"Broadcast message type: %s", wstType.c_str());
				if (wstType == xorstr_(L"patch_list_updated"))
				{
					const auto wstBranch = std::wstring(
						val[xorstr_(L"branch")].GetString(),
						val[xorstr_(L"branch")].GetStringLength()
					);
					const auto wstVersion = std::wstring(
						val[xorstr_(L"version")].GetString(),
						val[xorstr_(L"version")].GetStringLength()
					);

					APP_TRACE_LOG(LL_SYS, L"Patch list updated! Branch: %s Version: %s", wstBranch.c_str(), wstVersion.c_str());
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_UNALLOWED_CLIENT:
			{
				enum ETypes
				{
					UNDEFINED_TYPE,
					CLIENT_MULTIPLE_CONNECTION,
					CLIENT_VERSION,
					CLIENT_HASH,
					CLIENT_HWID,
					CLIENT_IP,
					CLIENT_TIMEOUT,
					CLIENT_BAN,
					CLIENT_HWID_BAN,
					CLIENT_IP_BAN
				};

				if (val.FindMember(xorstr_(L"type")) == val.MemberEnd())
				{
					APP_TRACE_LOG(LL_ERR, L"Message 'type' is not found!");
					return;
				}
				const auto& pkType = val[xorstr_(L"type")];
				if (!pkType.IsNumber())
				{
					APP_TRACE_LOG(LL_ERR, L"Message type is not a number! Type: %u", pkType.GetType());
					return;
				}
				const auto nType = pkType.GetInt();

				if (val.FindMember(xorstr_(L"reason")) == val.MemberEnd())
				{
					APP_TRACE_LOG(LL_ERR, L"Message 'reason' is not found!");
					return;
				}
				const auto& pkReason = val[xorstr_(L"reason")];
				if (!pkReason.IsString())
				{
					APP_TRACE_LOG(LL_ERR, L"Message reason is not a string! Type: %u", pkReason.GetType());
					return;
				}
				const auto wstReason = std::wstring(
					pkReason.GetString(),
					pkReason.GetStringLength()
				);

				APP_TRACE_LOG(LL_CRI, L"Unallowed client message type: %d Reason: %s", nType, wstReason.c_str());

				if (nType == CLIENT_MULTIPLE_CONNECTION)
				{
					// Do not reconnect
					m_bConnectionFailed = true;
					return;
				}
				else
				{
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_UNALLOWED_CLIENT, nType);
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_IDLE_CLIENT:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Idle client message is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::IDLE_CLIENT_RESULT));
				}
				else
				{
					APP_TRACE_LOG(LL_SYS, L"Websocket is ready for communication as idle client!");

					// Set flag
					CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient()->SetIdleClient(true);
					CApplication::Instance().SetWsConnectionReady(true);

					// Start heartbeat timer
					CApplication::Instance().CreateWsHearbeatWorker();
				}
			} break;
			case WS_INCOMING_MESSAGE_TYPE_SIGNAL_BINARY_PROCESS_COMPLETED:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"File processing signal is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::BINARY_PROCESS_RESULT));
				}


			} break;
			case WS_INCOMING_MESSAGE_TYPE_SIGNAL_HEARTBEAT_REQUEST:
			{
				const auto result = val[xorstr_(L"result")].GetInt();
				if (!result)
				{
					APP_TRACE_LOG(LL_CRI, L"Heartbeat request result is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::HEARTBEAT_RESULT_1));
				}

				if (val.FindMember(xorstr_(L"hb_type") ) == val.MemberEnd() || !val[xorstr_(L"hb_type")].IsNumber())
				{
					APP_TRACE_LOG(LL_CRI, L"Heartbeat request type is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::HEARTBEAT_RESULT_2));
				}

				if (val.FindMember(xorstr_(L"hb_data")) == val.MemberEnd() || !val[xorstr_(L"hb_data")].IsObject())
				{
					APP_TRACE_LOG(LL_CRI, L"Heartbeat request data is not validated!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::HEARTBEAT_RESULT_3));
				}
				
				const auto hb_type = val[xorstr_(L"hb_type")].GetInt();
				if (hb_type == 1)
				{
					const auto& hb_data = val[xorstr_(L"hb_data")];
					if (hb_data.FindMember(xorstr_(L"key")) == hb_data.MemberEnd() || !hb_data[xorstr_(L"key")].IsNumber())
					{
						APP_TRACE_LOG(LL_CRI, L"Heartbeat request data key is not validated!");
						CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::HEARTBEAT_RESULT_4));
					}

					const auto byKey = hb_data[xorstr_(L"key")].GetInt();
					APP_TRACE_LOG(LL_SYS, L"Heartbeat key: %u", byKey);

					CApplication::Instance().AppendWsHearbeatRequest(byKey);
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Heartbeat request type: %d is not validated!", hb_type);
					// CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_RET_REMOTE_COMMUNICATION_FAIL, static_cast<uint32_t>(EWSIncMsgErrCodes::HEARTBEAT_RESULT_5));
				}
			} break;
			default:
			{
				APP_TRACE_LOG(LL_CRI, L"Undefined message ID: %d", id);
				// CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_SERVER_UNDEFINED_MESSAGE_ID, static_cast<uint32_t>(EWSIncMsgErrCodes::UNDEFINED_MESSAGE_ID));
			} break;
		}

		return;
	}
	void CWebSocketClient::on_open(websocketpp::connection_hdl hdl)
	{
		APP_TRACE_LOG(LL_SYS, L"Websocketpp connection established");
		
		m_connection = std::move(hdl);
		CApplication::Instance().OnBackendConnected();

#ifdef _DEBUG
		m_spSysTelDispatcher->PushTestMessages();
#endif

		// gs_nConnectionTryCount = 0;
	}
	void CWebSocketClient::on_fail(websocketpp::connection_hdl hdl)
	{
		APP_TRACE_LOG(LL_ERR, L"Websocketpp connection failed");

		auto fail_data = stdext::make_shared_nothrow<SWsConnFailData>();
		if (!IS_VALID_SMART_PTR(fail_data))
		{
			APP_TRACE_LOG(LL_ERR, L"Data allocation failed");
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_CONNECTION_FAIL, 0);
		}

		const auto con = m_client.get_con_from_hdl(hdl);
		if (con)
		{
			const auto stBuffer = fmt::format(
				xorstr_(L"Fail data... State: {0} Local: {1}-{2} Remote: {3}-{4} Error: {5}-{6}"),
				(uint32_t)con->get_state(),
				con->get_local_close_code(), stdext::to_wide(con->get_local_close_reason()),
				con->get_remote_close_code(), stdext::to_wide(con->get_remote_close_reason()),
				con->get_ec().value(), stdext::to_wide(con->get_ec().message())
			);
			APP_TRACE_LOG(LL_ERR, L"%s", stBuffer.c_str());

			fail_data->state = (uint32_t)con->get_state();
			fail_data->local_code = con->get_local_close_code();
			strncpy(fail_data->local_reason, con->get_local_close_reason().c_str(), sizeof(fail_data->local_reason));
			fail_data->remote_code = con->get_remote_close_code();
			strncpy(fail_data->remote_reason, con->get_remote_close_reason().c_str(), sizeof(fail_data->remote_reason));
			fail_data->err_code = con->get_ec().value();
			strncpy(fail_data->err_msg, con->get_ec().message().c_str(), sizeof(fail_data->err_msg));
		}

		on_close(hdl);
	}
	void CWebSocketClient::on_message(websocketpp::connection_hdl hdl, message_ptr msg)
	{
		APP_TRACE_LOG(LL_SYS, L"Websocket on_message; Conn: %p Msg: '%hs'", hdl.lock().get(), msg->get_payload().c_str());;

		// Sanity check for msg param
		if (msg->get_opcode() != websocketpp::frame::opcode::text && msg->get_opcode() != websocketpp::frame::opcode::binary)
		{
			APP_TRACE_LOG(LL_ERR, L"Unallowed websocket message opcode: %u", msg->get_opcode());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_BINARY_MESSAGE_HANDLE, msg->get_opcode());
			return;
		}
		if (msg->get_opcode() == websocketpp::frame::opcode::binary)
		{
			return on_binary_handle(websocketpp::utility::to_hex(msg->get_payload()));
		}

		if (msg->get_payload().size() < 5)
		{
			APP_TRACE_LOG(LL_ERR, L"Small websocket message for parse: %u", msg->get_payload().size());
			return;
		}

		// Decrypt incoming message
		const auto stMessage = decrypt_message(stdext::to_wide(msg->get_payload()));
		if (stMessage.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"decrpyt_message failed");
			return;
		}

		APP_TRACE_LOG(LL_SYS, L"Decrypted message content: '%s'", stMessage.c_str());;

		// TODO: https://rapidjson.docsforge.com/master/schemavalidator.cpp/

		// Deserialize decrypted message
		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse(stMessage.c_str());
		if (document.HasParseError())
		{
			APP_TRACE_LOG(LL_ERR, L"Message: '%s' decode failed! Error: %hs offset: %u", stMessage.c_str(), GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			return;
		}
		if (!document.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"Message base is not an object! Type: %u", document.GetType());
			return;
		}

		// Common message fields
		if (!document.HasMember(xorstr_(L"type")))
		{
			APP_TRACE_LOG(LL_ERR, L"'type' key does not exist in message");
			return;
		}
		else if (!document.HasMember(xorstr_(L"data")))
		{
			APP_TRACE_LOG(LL_ERR, L"'data' key does not exist in message");
			return;
		}

		// Error specific message fields
		if (document.HasMember(xorstr_(L"error")))
		{
			const auto& pkDocError = document[xorstr_(L"error")];

			if (!pkDocError.IsObject())
			{
				APP_TRACE_LOG(LL_ERR, L"'error' key json type: %d is not valid!", pkDocError.GetType());
				return;
			}
			else if (!pkDocError.MemberCount())
			{
				APP_TRACE_LOG(LL_ERR, L"'error' object does not contain any member: %d", pkDocError.MemberCount());
				return;
			}

			if (!pkDocError.HasMember(xorstr_(L"id")))
			{
				APP_TRACE_LOG(LL_ERR, L"'id' key does not exist in message error object");
				return;
			}
			else if (!pkDocError.HasMember(xorstr_(L"msg")))
			{
				APP_TRACE_LOG(LL_ERR, L"'msg' key does not exist in message error object");
				return;
			}

			const auto& pkErrId = pkDocError[xorstr_(L"id")];
			const auto& pkErrMsg = pkDocError[xorstr_(L"msg")];

			if (!pkErrId.IsNumber())
			{
				APP_TRACE_LOG(LL_ERR, L"'id' key json type: %d is not valid!", pkErrId.GetType());
				return;
			}
			else if (!pkErrMsg.IsString() || !pkErrMsg.GetStringLength())
			{
				APP_TRACE_LOG(LL_ERR, L"'msg' key json type: %d is not valid!", pkErrMsg.GetType());
				return;
			}

			this->on_error_message(pkErrId.GetInt(), std::wstring(pkErrMsg.GetString(), pkErrMsg.GetStringLength()));
			return;
		}

		// Success specific message fields
		const auto& pkDocType = document[xorstr_(L"type")];
		auto& pkDocData = document[xorstr_(L"data")];

		if (!pkDocType.IsNumber())
		{
			APP_TRACE_LOG(LL_ERR, L"'type' key json type: %d is not valid!", pkDocType.GetType());
			return;
		}

		else if (!pkDocData.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"'data' key json type: %d is not valid!", pkDocData.GetType());
			return;
		}
		else if (!pkDocData.MemberCount())
		{
			APP_TRACE_LOG(LL_ERR, L"'data' object does not contain any member: %d", pkDocData.MemberCount());
			return;
		}

		if (!pkDocData.HasMember(xorstr_(L"result")))
		{
			APP_TRACE_LOG(LL_ERR, L"'result' key does not exist in message data object");
			return;
		}

		const auto& pkDataResult = pkDocData[xorstr_(L"result")];

		if (!pkDataResult.IsNumber())
		{
			APP_TRACE_LOG(LL_ERR, L"'result' key json type: %d is not valid!", pkDataResult.GetType());
			return;
		}

		// Call message dispatcher
		this->on_custom_message(pkDocType.GetInt(), std::move(pkDocData));
	}
	void CWebSocketClient::on_close(websocketpp::connection_hdl hdl)
	{
		APP_TRACE_LOG(LL_ERR, L"Websocket connection closed.");

		if (m_dwDisconectCounter++ >= 10)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocket connection closed. Too many disconnections.");
			m_bConnectionFailed = true;
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_TOO_MANY_WS_DISCONNECT, 0);
		}

		m_dwLastDisconectTime = stdext::get_current_epoch_time_ms();
		m_bConnectionLost = true;	
		m_client.stop();
		m_connection.reset();

		CApplication::Instance().ReleaseWsHeartbeatWorker();
		CApplication::Instance().OnBackendDisconnected();
		CApplication::Instance().SetWsConnectionReady(false);
	}
	bool CWebSocketClient::on_ping(websocketpp::connection_hdl hdl, std::string msg)
	{
		APP_TRACE_LOG(LL_TRACE, L"on_ping... %s", msg.c_str());

		// If connection doesnt lost since than 3 minutes reset counter
		if (m_dwLastDisconectTime)
		{
			const auto dwConnLostDiff = stdext::get_current_epoch_time_ms() - m_dwLastDisconectTime;
			APP_TRACE_LOG(LL_SYS, L"Connection lost time: %u", dwConnLostDiff);
			
			if (dwConnLostDiff > 180000)
			{
				m_dwDisconectCounter = 0;
				m_dwLastDisconectTime = 0;
			}
		}
		
		return true;
	}


	void CWebSocketClient::__CreateConnection()
	{
		// Check connection amount
		if (gs_nConnectionTryCount >= 30)
		{
			APP_TRACE_LOG(LL_CRI, L"Connection to WS server too many times failed!");
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_CONNECTION_TOO_MANY_FAIL, 0);
			m_bConnectionFailed = true;
			return;
		}

		// Check last connection time
		if (m_dwLastConnectionTime)
		{
			static constexpr auto s_ckConnectionInterval = 10 * 1000; // 10 seconds
			
			const auto nTimeDiff = stdext::get_current_epoch_time_ms() - m_dwLastConnectionTime;
			if (nTimeDiff < s_ckConnectionInterval)
			{
				APP_TRACE_LOG(LL_SYS, L"Connection interval is %d seconds, waiting for %d seconds...", s_ckConnectionInterval, s_ckConnectionInterval - nTimeDiff);
				g_winAPIs->Sleep(1000);
				return;
			}
		}

		gs_nConnectionTryCount++;

		auto bConnectionAvailable1 = false, bConnectionAvailable2 = false;
		if (!CApplication::Instance().NetworkMgrInstance()->InternetConnectionAvailable(bConnectionAvailable1))
			bConnectionAvailable1 = false;
		bConnectionAvailable2 = CApplication::Instance().NetworkMgrInstance()->CheckInternetStatus();
		
		if (!bConnectionAvailable1 && !bConnectionAvailable2)
		{
			APP_TRACE_LOG(LL_WARN, L"Internet connection is not available!");
			return;
		}
		
		APP_TRACE_LOG(LL_SYS, L"Validating DNS records...");

		auto bBypassDNSCheck = false;
		
		PDNS_RECORD dnsRecord = nullptr;
		auto dnsQueryRet = g_winAPIs->DnsQuery_W(m_wstHost.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &dnsRecord, NULL);
		if (dnsQueryRet == ERROR_SUCCESS)
		{
			auto pDnsRecord = reinterpret_cast<PDNS_RECORD>(dnsRecord);
			while (pDnsRecord)
			{
				if (pDnsRecord->wType == DNS_TYPE_A)
				{
					IN_ADDR ipaddr;
					ipaddr.S_un.S_addr = (pDnsRecord->Data.A.IpAddress);
					const auto c_szIpAddress = g_winAPIs->inet_ntoa(ipaddr);

					APP_TRACE_LOG(LL_SYS, L"IP address: %hs", c_szIpAddress);
					if (!strcmp(c_szIpAddress, xorstr_("219.87.158.116")) || // Zyxel office, wtf?
						!strcmp(c_szIpAddress, xorstr_("8.8.8.8"))) // Google DNS
					{
						APP_TRACE_LOG(LL_WARN, L"DNS record is not valid, bypassing...");
						bBypassDNSCheck = true;
						break;
					}
				}
				pDnsRecord = pDnsRecord->pNext;
			}
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"DnsQuery_A(1) failed, error code: %u", dnsQueryRet);
		}
		if (dnsRecord)
		{
			g_winAPIs->DnsRecordListFree(dnsRecord, DnsFreeRecordList);
			dnsRecord = nullptr;
		}
		
		if (!bBypassDNSCheck)
		{
			auto bValidatedDnsText = false;
			dnsQueryRet = g_winAPIs->DnsQuery_W(m_wstHost.c_str(), DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE, NULL, &dnsRecord, NULL);
			if (dnsQueryRet == ERROR_SUCCESS)
			{
				auto pDnsRecord = reinterpret_cast<PDNS_RECORD>(dnsRecord);
				while (pDnsRecord)
				{
					if (pDnsRecord->wType == DNS_TYPE_TEXT)
					{
						for (auto i = 0u; i < pDnsRecord->Data.TXT.dwStringCount; i++)
						{
							const auto wstTextData = std::wstring(pDnsRecord->Data.TXT.pStringArray[i]);
							APP_TRACE_LOG(LL_SYS, L"[%u] %s", i, wstTextData.c_str());

							if (wstTextData == xorstr_(L"1"))
								bValidatedDnsText = true;
						}
					}
					pDnsRecord = pDnsRecord->pNext;
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"DnsQuery_A(2) failed, error code: %u", dnsQueryRet);
			}
			if (dnsRecord)
			{
				g_winAPIs->DnsRecordListFree(dnsRecord, DnsFreeRecordList);
				dnsRecord = nullptr;
			}

			if (dnsQueryRet != ERROR_TIMEOUT &&
				dnsQueryRet != DNS_ERROR_NO_DNS_SERVERS &&
				dnsQueryRet != DNS_ERROR_BAD_PACKET &&
				dnsQueryRet != DNS_ERROR_RCODE_SERVER_FAILURE &&
				dnsQueryRet != DNS_ERROR_RCODE_NAME_ERROR)
			{
				if (!bValidatedDnsText)
				{
					APP_TRACE_LOG(LL_ERR, L"DNS record could not validated!");
					// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_CONNECTION_DNS_QUERY_FAIL, 0);
					return;
				}
			}
		}
		
		APP_TRACE_LOG(LL_SYS, L"Creating websocket access token...");

		std::wstring wstToken;
		if (!this->create_jwt(wstToken))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to create websocket access token.");
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WS_TOKEN_RECREATE_FAIL, 0);
			return;
		}
		m_stToken = stdext::to_ansi(wstToken);

		this->verify_jwt();
		
		const auto stAddress = stdext::to_ansi(m_wstAddress);
		const auto stSessionID = stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetBootID());
		APP_TRACE_LOG(LL_SYS, L"Creating websocket connection... Target: %s", m_wstAddress.c_str());

		try
		{
			websocketpp::lib::error_code ec;
			auto con = m_client.get_connection(stAddress, ec);
			if (ec)
			{
				APP_TRACE_LOG(LL_CRI, L"Websocketpp could not create connection because: %hs (%d)", ec.message().c_str(), ec.value());
				// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_CONNECTION_CREATE_FAIL, ec.value());
				return;
			}

			con->append_header(xorstr_("nm-client-api"), fmt::format(xorstr_("NoMercyApi_V{0}"), __MAJOR_VERSION__));
			con->append_header(xorstr_("nm-authorization"), m_stToken);
			con->append_header(xorstr_("nm-env-session"), stSessionID);

			// Note that connect here only requests a connection. No network messages are
			// exchanged until the event loop starts running in the next line.
			m_client.connect(con);
				
			// Set init flag
			m_bConnectionLost = false;
			m_dwLastConnectionTime = stdext::get_current_epoch_time_ms();

			APP_TRACE_LOG(LL_SYS, L"Websocket connection created.");

			// Start the ASIO io_service run loop
			// this will cause a single connection to be made to the server. c.run()
			// will exit when this connection is closed.
			m_client.run();

			APP_TRACE_LOG(LL_WARN, L"Websocket connection access lost.");

			// Is connection lost again?
			m_client.reset();
			m_bConnectionLost = true;
		}
		catch (const websocketpp::exception& e)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp exception: %hs (%d)", e.what(), e.code().value());
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_EXCEPTION, e.code().value());
		}
		catch (const std::exception& e)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp std exception: %hs Error: %u", e.what(), g_winAPIs->GetLastError());
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_EXCEPTION, 1337, (void*)e.what());
		}
		catch (websocketpp::lib::error_code e)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp error: %hs Error: %u", e.message().c_str(), g_winAPIs->GetLastError());
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_EXCEPTION, e.value());
		}
		catch (...)
		{
			APP_TRACE_LOG(LL_CRI, L"Websocketpp unhandled exception");
			// CApplication::Instance().OnCloseRequest(EXIT_ERR_WEBSOCKET_EXCEPTION, 0, (void*)xorstr_(L"unhandled"));
		}
	}

	DWORD CWebSocketClient::SetupConnection(void)
	{
		// APP_TRACE_LOG(LL_SYS, L"Websocket thread event has been started!");

		static auto s_bConnectionInit = false;
		if (!s_bConnectionInit)
		{
			s_bConnectionInit = true;

			// Initialize libsodium
			const auto nSodiumRet = sodium_init();
			if (nSodiumRet < 0)
			{
				APP_TRACE_LOG(LL_CRI, L"Failed to initialize libsodium: %d", nSodiumRet);
				CApplication::Instance().OnCloseRequest(EXIT_ERR_LIBSODIUM_INIT_FAIL, nSodiumRet);
				return false;
			}

			// Initialize libsodium keys
			m_spKeyPair = stdext::make_shared_nothrow<SKeyPair>();
			if (!IS_VALID_SMART_PTR(m_spKeyPair))
			{
				APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for key pair");
				CApplication::Instance().OnCloseRequest(EXIT_ERR_SODIUM_KEY_ALLOC_FAIL, 0);
				return false;
			}
			m_spKeyPair->load_public_key(WEBSOCKET_COMM_PUBLIC_KEY);

			// Create target address
			if (m_bIsRawTest)
			{
				m_wstAddress = fmt::format(xorstr_(L"ws://{0}:{1}"), m_wstHost, m_dwPort);
			}
			else
			{
#if (WEBSOCKET_USE_SSL == TRUE)
				m_wstAddress += xorstr_(L"wss://");
#else
				m_wstAddress += xorstr_(L"ws://");
#endif

				m_wstAddress += m_wstHost;
				if (m_dwPort)
					m_wstAddress += (xorstr_(L":") + std::to_wstring(m_dwPort));
			}

			APP_TRACE_LOG(LL_SYS, L"Websocket server: %s", m_wstAddress.c_str());

			// Create websocket client
			try
			{
				// Set logging to be pretty verbose (everything except message payloads)
				m_client.set_access_channels(websocketpp::log::alevel::all);
				m_client.clear_access_channels(websocketpp::log::alevel::frame_payload);
#ifdef _DEBUG
				m_client.set_error_channels(websocketpp::log::elevel::all);
#endif

				// Initialize ASIO
				m_client.init_asio();

				// Register our message handler
#if (WEBSOCKET_USE_SSL == TRUE)
				if (!m_bIsRawTest)
				{
					const auto stHost = stdext::to_ansi(m_wstHost);

					// m_client.set_tls_init_handler(std::bind(&on_tls_init));
					m_client.set_tls_init_handler(std::bind(&on_tls_init, stHost.c_str(), std::placeholders::_1));
				}
#endif
				m_client.set_open_handler(std::bind(&CWebSocketClient::on_open, this, std::placeholders::_1));
				m_client.set_close_handler(std::bind(&CWebSocketClient::on_close, this, std::placeholders::_1));
				m_client.set_fail_handler(std::bind(&CWebSocketClient::on_fail, this, std::placeholders::_1));
				m_client.set_ping_handler(std::bind(&CWebSocketClient::on_ping, this, std::placeholders::_1, std::placeholders::_2));
				m_client.set_message_handler(std::bind(&CWebSocketClient::on_message, this, std::placeholders::_1, std::placeholders::_2));

				m_bInitialized = true;
			}
			catch (const websocketpp::exception& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Websocketpp exception: %s (%d)", e.what(), e.code().value());
				m_bConnectionFailed = true;
			}
			catch (const std::exception& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Websocketpp std exception: %hs Error: %u", e.what(), g_winAPIs->GetLastError());
				m_bConnectionFailed = true;
			}
			catch (websocketpp::lib::error_code e)
			{
				APP_TRACE_LOG(LL_CRI, L"Websocketpp error: %hs Error: %u", e.message().c_str(), g_winAPIs->GetLastError());
				m_bConnectionFailed = true;
			}
			catch (...)
			{
				APP_TRACE_LOG(LL_CRI, L"Websocketpp unhandled exception");
				m_bConnectionFailed = true;
			}
		}

		if (m_bConnectionFailed)
			return 0;

		if (m_bConnectionLost)
		{
			__CreateConnection();
		}

		return 0;
	}
	DWORD WINAPI CWebSocketClient::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CWebSocketClient*>(lpParam);
		return This->SetupConnection();
	}

	bool CWebSocketClient::InitWebSocketThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_WEBSOCKET, StartThreadRoutine, (void*)this, 2000, false);
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
	void CWebSocketClient::ShutdownWebSocketConnection()
	{
		if (!m_bInitialized)
			return;
		m_bInitialized = false;
		
		m_client.stop();

		const auto thread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_WEBSOCKET);
		if (IS_VALID_SMART_PTR(thread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(thread);
		}
	}
};
