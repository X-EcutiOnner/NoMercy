#pragma once
#include <cpr/cpr.h>
#include "WebSocketClient.hpp"
#include "CurlWebAPI.hpp"

namespace NoMercy
{
	class CNetworkManager : public std::enable_shared_from_this <CNetworkManager>
	{
	public:
		CNetworkManager();
		virtual ~CNetworkManager();

		bool InitializeNetwork();
		bool InitializeWebSocketClient(const std::string& address, uint32_t port = 0);
		void CleanupNetwork();

		auto GetWebSocketClient() const { std::lock_guard <std::mutex> lock(m_mtxNetworkManager); return m_spWebSocketClient; };
		auto GetCurlClient() const		{ std::lock_guard <std::mutex> lock(m_mtxNetworkManager); return m_spCurlClient; };

		bool IsExistOnHostsFile(const std::wstring& stEntry);
		bool InternetConnectionAvailable(bool& avaliable);
		bool CheckInternetStatus();
		bool CheckInternetConnection(const std::wstring& stTargetUrl);
		bool IsCorrectIPAddressOfWebsite(const std::wstring& stWebsite, const std::wstring& stIPAddress);
		bool IsWebsiteDown(const std::wstring& stWebsite, const std::wstring& stMethod);

	private:
		mutable std::mutex					m_mtxNetworkManager;
		std::shared_ptr <CWebSocketClient>	m_spWebSocketClient;
		std::shared_ptr <CCurlClient>		m_spCurlClient;
	};
};