#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "CurlWebAPI.hpp"
#include <curl/curl.h>

namespace NoMercy
{
	CCurlClient::CCurlClient()
	{
		m_pkClient = new cpr::Session();
	}
	CCurlClient::~CCurlClient()
	{
		if (m_pkClient)
		{
			delete m_pkClient;
			m_pkClient = nullptr;
		}
	}
	
	int CCurlClient::GetContentLength(const std::string& stURL)
	{
		APP_TRACE_LOG(LL_SYS, L"Checking content length of %hs", stURL.c_str());

		m_pkClient->SetUrl(cpr::Url{ stURL });
		m_pkClient->SetTimeout(cpr::Timeout{ 8000 });
		m_pkClient->SetHeader(cpr::Header{ 
			{ xorstr_("User-Agent"), xorstr_("NoMercy_WebAPI_Client") }
		});
		m_pkClient->SetSslOptions(
			cpr::Ssl(
				cpr::ssl::CertFile{ REST_CERT_FILENAME },
				cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
				cpr::ssl::TLSv1_3{},
				cpr::ssl::VerifyHost{ false },
				cpr::ssl::VerifyPeer{ false }
			)
		);
		
		const auto res = m_pkClient->Head();

		if (res.error.code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_SYS, L"[HEAD] CPR internal error: %d", res.error.code);
			return -1;
		}
		else if (res.status_code != 200)
		{
			APP_TRACE_LOG(LL_SYS, L"[HEAD] HTTP error: %d", res.status_code);
			return -2;
		}

		auto nContentLength = 0;
		if (res.header.find(xorstr_("Content-Length")) == res.header.end())
		{
			APP_TRACE_LOG(LL_ERR, L"Content-Length header does not exist on HEAD request!");
			return 1; // return positive value to indicate error
		}
		else
		{
			const auto stContentLength = res.header.at(xorstr_("Content-Length"));
			nContentLength = stdext::str_to_u32(stContentLength);
		}

		APP_TRACE_LOG(LL_SYS, L"Connection established! Content-Length: %d", nContentLength);
		return nContentLength;
	}
	
	bool CCurlClient::IsConnectionEstablished(const std::string& stURL) const
	{
		APP_TRACE_LOG(LL_SYS, L"CPR request to: %hs", stURL.c_str());

		const auto res = cpr::Get(
			cpr::Url{ stURL },
			cpr::Timeout{ 1000 },
			cpr::Ssl(
				cpr::ssl::CertFile{ REST_CERT_FILENAME },
				cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
				cpr::ssl::TLSv1_3{},
				cpr::ssl::VerifyHost{ false },
				cpr::ssl::VerifyPeer{ false }
			)
		);

		if (res.error.code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_ERR, L"CPR internal error: %u", (uint32_t)res.error.code);
			return false;
		}
		else if (res.status_code != 200)
		{
			APP_TRACE_LOG(LL_ERR, L"HTTP status: %d is not OK", res.status_code);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Connection established");
		return true;
	}

	std::string CCurlClient::GetWebSocketToken(const std::string& stURL) const
	{		
		APP_TRACE_LOG(LL_SYS, L"CPR request to: %hs", stURL.c_str());

		const auto stSessionID = stdext::to_ansi(NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID());
		if (stSessionID.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Session ID is empty!");
			return "";
		}

		m_pkClient->SetUrl(stURL);
		m_pkClient->SetBody(cpr::Body{ stURL });
		m_pkClient->SetHeader(cpr::Header{
			{ xorstr_("Content-Type"), xorstr_("text/plain") },
			{ xorstr_("User-Agent"), xorstr_("NoMercy_WebAPI_Client") },
			{ xorstr_("sessionid"), stSessionID },
			{ xorstr_("nm_version"), xorstr_(__PRODUCT_VERSION__) },
		});
		m_pkClient->SetTimeout(cpr::Timeout{ 5000 });
		m_pkClient->SetSslOptions(
			cpr::Ssl(
				cpr::ssl::CertFile{ REST_CERT_FILENAME },
				cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
				cpr::ssl::TLSv1_3{},
				cpr::ssl::VerifyHost{ false },
				cpr::ssl::VerifyPeer{ false }
			)
		);

		const auto res = m_pkClient->Get();
		APP_TRACE_LOG(LL_SYS, L"CPR request completed: %u/%d", res.error.code, res.status_code);

		const auto err_code = res.error.code;
		if (err_code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_ERR, L"CPR internal error: %u", (uint32_t)err_code);
			return "";
		}

		const auto status_code = res.status_code;
		if (status_code != 200)
		{
			APP_TRACE_LOG(LL_CRI, L"CPR status is not ok: %d", status_code);
			return "";
		}

		const auto response = res.text;
		if (response.empty())
		{
			APP_TRACE_LOG(LL_CRI, L"CPR response is null");
			return "";
		}

		APP_TRACE_LOG(LL_SYS, L"CPR response: %hs", response.c_str());
		return response;
	}

	std::string CCurlClient::GetUpdateRequest(const std::string& stURL, const std::string& stAuthUser, const std::string& stAuthPwd) const
	{
		APP_TRACE_LOG(LL_SYS, L"CPR request to: %hs", stURL.c_str());

		std::string stBuffer;
		auto fnCreateRequest = [&]() -> bool {
			m_pkClient->SetUrl(stURL);
			m_pkClient->SetBody(cpr::Body{ stURL });

			const auto headers = cpr::Header{
				{ xorstr_("Content-Type"),xorstr_("application/json") },
				{ xorstr_("User-Agent"), xorstr_("NoMercy_WebAPI_Client") }
			};
			m_pkClient->SetHeader(headers);
			m_pkClient->SetTimeout(cpr::Timeout{ 5000 });
			m_pkClient->SetSslOptions(
				cpr::Ssl(
					cpr::ssl::CertFile{ REST_CERT_FILENAME },
					cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
					cpr::ssl::TLSv1_3{},
					cpr::ssl::VerifyHost{ false },
					cpr::ssl::VerifyPeer{ false }
			));
			if (!stAuthUser.empty() && !stAuthPwd.empty())
				m_pkClient->SetAuth(cpr::Authentication{ stAuthUser, stAuthPwd, cpr::AuthMode::BASIC });

			const auto res = m_pkClient->Get();

			const auto err_code = res.error.code;
			const auto status_code = res.status_code;
			const auto response = res.text;

			if (err_code != cpr::ErrorCode::OK)
			{
				APP_TRACE_LOG(LL_ERR, L"CPR internal error: %u", (uint32_t)err_code);
				return false;
			}
			else if (status_code != 200)
			{
				APP_TRACE_LOG(LL_CRI, L"CPR status is not ok: %d", status_code);
				return false;
			}
			else if (response.empty())
			{
				APP_TRACE_LOG(LL_CRI, L"CPR response is null");
				return false;
			}

			APP_TRACE_LOG(LL_TRACE, L"CPR response: %hs", response.c_str());
			stBuffer = response;
			return true;
		};
		auto fnCreateRequestSafe = [&]() {
			__try
			{
				fnCreateRequest();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		fnCreateRequestSafe();

		return stBuffer;
	}

	bool CCurlClient::UpdateFile(const std::string& stURL, HANDLE hFile, const TOnCurlProgressCallback& cb)
	{
		APP_TRACE_LOG(LL_SYS, L"Updating file(%p) from: %hs", hFile, stURL.c_str());

		const auto nContentLength = GetContentLength(stURL);
		if (!nContentLength)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get content length");
		}

		m_pkClient->SetConnectTimeout(cpr::ConnectTimeout{ 3000 });
		m_pkClient->SetTimeout(cpr::Timeout{ 120000 });
		m_pkClient->SetUserAgent(cpr::UserAgent{ fmt::format(xorstr_("NoMercySetupAgentV{0}"), __MAJOR_VERSION__) });
		
		/*
//#ifdef _DEBUG
		m_pkClient->SetVerbose(cpr::Verbose{ true });
		m_pkClient->SetDebugCallback(cpr::DebugCallback{ [&](cpr::DebugCallback::InfoType type, std::string data, intptr_t userdata) -> bool {
			if (type == cpr::DebugCallback::InfoType::TEXT || type == cpr::DebugCallback::InfoType::HEADER_IN)
			{
				APP_TRACE_LOG(LL_SYS, L"[cpr debug] type: %d data: %hs", type, data.c_str());
			}
			return true;
		} });
//#endif
		*/

		m_pkClient->SetUrl(stURL);

		m_pkClient->SetProgressCallback(cpr::ProgressCallback{ [cb, &nContentLength](cpr::cpr_off_t downloadTotal, cpr::cpr_off_t downloadNow, cpr::cpr_off_t uploadTotal, cpr::cpr_off_t uploadNow, intptr_t userdata) -> bool {
			static auto download_timer = CStopWatch<std::chrono::milliseconds>();
			if (download_timer.diff() >= 500)
			{
				APP_TRACE_LOG(LL_SYS, L"Download progress :: %llu / %llu - Upload progress :: %llu / %llu",
					downloadNow, downloadTotal,
					uploadNow, uploadTotal
				);
				
				if (cb)
					cb(downloadTotal, nContentLength);
				
				download_timer.reset();
			}
			return true;
		} });

		DWORD dwErrorCode = 0;
		uint32_t nTotalSize = 0;
		const auto res = m_pkClient->Download(cpr::WriteCallback{ [&](std::string data, intptr_t userdata) -> bool {
			nTotalSize += data.size();

			static auto download_timer = CStopWatch<std::chrono::milliseconds>();
			if (download_timer.diff() >= 500)
			{
				APP_TRACE_LOG(LL_SYS, L"Downloading file... Current: %lu Total: %lu", data.size(), nTotalSize);
				download_timer.reset();
			}

			DWORD dwWrittenSize = 0;
			if (!g_winAPIs->WriteFile(hFile, data.c_str(), data.size(), &dwWrittenSize, nullptr) || dwWrittenSize != data.size())
			{
				dwErrorCode = g_winAPIs->GetLastError();
				APP_TRACE_LOG(LL_ERR, L"WriteFile failed with error: %u Written size: %u", dwErrorCode, dwWrittenSize);
				return false;
			}
			return true;
		} });

		if (res.error.code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_ERR, L"CPR internal error: %u", (uint32_t)res.error.code);
			return false;
		}
		else if (res.status_code != 200)
		{
			APP_TRACE_LOG(LL_ERR, L"HTTP status: %d is not OK", res.status_code);
			return false;
		}

		return true;
	}

	bool CCurlClient::SendNotification(const std::string& stURL, const std::string& stData) const
	{
		APP_TRACE_LOG(LL_SYS, L"CPR request: %hs to: %hs", stData.c_str(), stURL.c_str());

		m_pkClient->SetUrl(stURL);
		m_pkClient->SetBody(cpr::Body{ stData });
		m_pkClient->SetHeader(cpr::Header{
			{ xorstr_("Content-Type"),xorstr_("text/html") },
			{ xorstr_("User-Agent"), xorstr_("NoMercy_WebAPI_Client") },
		});
		m_pkClient->SetTimeout(cpr::Timeout{ 5000 });
		m_pkClient->SetSslOptions(
			cpr::Ssl(
				cpr::ssl::CertFile{ REST_CERT_FILENAME },
				cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
				cpr::ssl::TLSv1_3{},
				cpr::ssl::VerifyHost{ false },
				cpr::ssl::VerifyPeer{ false }
			)
		);

		const auto res = m_pkClient->Get();

		const auto err_code = res.error.code;
		if (err_code != cpr::ErrorCode::OK)
		{
			APP_TRACE_LOG(LL_CRI, L"CPR internal error: %u", (uint32_t)err_code);
			return false;
		}

		const auto status_code = res.status_code;
		if (status_code != 200)
		{
			APP_TRACE_LOG(LL_CRI, L"CPR status is not ok: %d", status_code);
			return false;
		}

		const auto response = res.text;
		if (response.empty())
		{
			APP_TRACE_LOG(LL_CRI, L"CPR response is null");
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"CPR response: %hs", response.c_str());
		return true;
	}

	bool CCurlClient::SendDataToRemoteServer(const std::wstring& stMessage, const std::vector <std::wstring>& vLogFiles)
	{
		APP_TRACE_LOG(LL_SYS, L"Sending data: '%s' w %u files to remote server...", stMessage.c_str(), vLogFiles.size());

		const auto stTempPath = std::filesystem::temp_directory_path().wstring();
		std::vector <std::wstring> vCopiedFiles;
		if (!vLogFiles.empty())
		{
			for (const auto& stFile : vLogFiles)
			{
				const auto stTargetFile = fmt::format(xorstr_(L"{0}\\{1}.log"), stTempPath, stdext::generate_uuid_v4());
				if (std::filesystem::exists(stTargetFile))
				{
					APP_TRACE_LOG(LL_ERR, L"Target file: %s is already exist!", stTargetFile.c_str());

					std::error_code ec{};
					if (!std::filesystem::remove(stTargetFile, ec) || ec)
					{
						APP_TRACE_LOG(LL_ERR, L"File: %s remove failed error: %u", stTargetFile.c_str(), ec.value());
						continue;
					}
				}

				std::error_code ec{};
				if (!std::filesystem::copy_file(stFile, stTargetFile, ec) || ec)
				{
					APP_TRACE_LOG(LL_ERR, L"File: %s copy to: %s failed with error: %u", stFile.c_str(), stTargetFile.c_str(), ec.value());
					continue;
				}

				vCopiedFiles.push_back(stTargetFile);

				APP_TRACE_LOG(LL_SYS, L"File: %s copied to: %s", stFile.c_str(), stTargetFile.c_str());
			}
		}

		std::string stResText;
		auto fnSendDataEx = [&]() {
			auto data_list = cpr::Multipart{
				{ xorstr_("data"), stdext::to_ansi(stMessage) }
			};

			if (!vCopiedFiles.empty())
			{
				for (const auto& wstLogFile : vCopiedFiles)
				{
					const auto stLogFile = stdext::to_ansi(wstLogFile);
					data_list.parts.push_back({ stLogFile, cpr::File{ stLogFile } });
				}
			}

			const auto stURL = stdext::to_ansi(ERROR_POST_URL);
			const auto res = cpr::Post(
				cpr::Url{ stURL },
				data_list,
				cpr::Timeout{ 60000 },
				cpr::SslOptions{
				cpr::Ssl(
					cpr::ssl::CertFile{ REST_CERT_FILENAME },
					cpr::ssl::KeyFile{ REST_CERT_KEY_FILENAME },
					cpr::ssl::TLSv1_3{},
					cpr::ssl::VerifyHost{ false },
					cpr::ssl::VerifyPeer{ false }
				)
			});

			const auto err_code = res.error.code;
			if (err_code != cpr::ErrorCode::OK)
			{
				APP_TRACE_LOG(LL_CRI, L"CPR internal error: %u", (uint32_t)err_code);
				return false;
			}

			const auto status_code = res.status_code;
			if (status_code != 200)
			{
				APP_TRACE_LOG(LL_CRI, L"CPR status is not ok: %d", status_code);
				return false;
			}

			stResText = res.text;
			return true;
		};
		auto fnSendDataSafe = [&]() {
			__try
			{
				fnSendDataEx();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};

		fnSendDataSafe();

		if (!vCopiedFiles.empty())
		{
			for (const auto& stLogFile : vCopiedFiles)
			{
				NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ForceDeleteFile(stLogFile);
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Telemetry message: %u and %u files sent succesfully! Response: %hs", stMessage.size(), vLogFiles.size(), stResText.c_str());
		return true;
	}

	bool CCurlClient::SendDataToRemoteServerWithLogs(const std::wstring& stMessage)
	{
		std::vector <std::wstring> vLogFiles;

		std::error_code ec;
		if (std::filesystem::exists(CUSTOM_LOG_FILENAME_W, ec))
			vLogFiles.push_back(CUSTOM_LOG_FILENAME_W);

		const auto stLogPath = fmt::format(xorstr_(L"{0}\\NoMercy\\Log"), NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExePath());
		if (std::filesystem::exists(stLogPath, ec))
		{
			for (const auto& entry : std::filesystem::directory_iterator(stLogPath, ec))
			{
				if (!entry.is_regular_file())
					continue;

				vLogFiles.emplace_back(entry.path().wstring());
			}
			if (ec)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to iterate log directory! Error: %hs", ec.message().c_str());
			}
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_ERR, L"Log path: '%s' is not exist! Error: %hs", stLogPath.c_str(), ec.message().c_str());
		}

		return this->SendDataToRemoteServer(stMessage, vLogFiles);
	}
}
