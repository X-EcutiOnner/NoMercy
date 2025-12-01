#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "NetManager.hpp"
#include <netlistmgr.h>

namespace NoMercy
{
	CNetworkManager::CNetworkManager() : 
		m_spWebSocketClient(nullptr)
	{
	}
	CNetworkManager::~CNetworkManager()
	{	
		CleanupNetwork();
	}

	bool CNetworkManager::InitializeNetwork()
	{
		m_spCurlClient = stdext::make_shared_nothrow<CCurlClient>();
		if (!IS_VALID_SMART_PTR(m_spCurlClient))
		{
			APP_TRACE_LOG(LL_ERR, L"Curl client could not allocated!");
			return false;
		}
		return true;
	}
	bool CNetworkManager::InitializeWebSocketClient(const std::string& address, uint32_t port)
	{
		m_spWebSocketClient = stdext::make_shared_nothrow<CWebSocketClient>(address, port);
		if (!IS_VALID_SMART_PTR(m_spWebSocketClient))
		{
			APP_TRACE_LOG(LL_ERR, L"Websocket client could not allocated!");
			return false;
		}
		return true;
	}
	void CNetworkManager::CleanupNetwork()
	{
		if (m_spWebSocketClient)
		{
			m_spWebSocketClient->ShutdownWebSocketConnection();
			m_spWebSocketClient.reset();
		}
//		if (m_spCurlClient)
//		{
//			m_spCurlClient.reset();
//		}
	}

	bool CNetworkManager::IsExistOnHostsFile(const std::wstring& stEntry)
	{
		const auto stHosts = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath() + xorstr_(L"\\System32\\drivers\\etc\\hosts");
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stHosts))
		{
			const auto stContent = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ReadFileContent(stHosts);
			if (!stContent.empty())
			{
				if (stContent.find(stEntry) != std::wstring::npos)
				{
					return true;
				}
			}
		}
		return false;
	}
	bool CNetworkManager::InternetConnectionAvailable(bool& avaliable)
	{
		auto hr = g_winAPIs->CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		if (hr != RPC_E_CHANGED_MODE && FAILED(hr))
		{
			APP_TRACE_LOG(LL_ERR, L"CoInitializeEx fail! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		INetworkListManager* pNetListManager = nullptr;
		if (FAILED(hr = g_winAPIs->CoCreateInstance(CLSID_NetworkListManager, nullptr, CLSCTX_INPROC_SERVER, IID_INetworkListManager, (void**)&pNetListManager)))
		{
			APP_TRACE_LOG(LL_ERR, L"CoCreateInstance fail!  Status: %p", hr);
			return false;
		}

		VARIANT_BOOL is_connected;
		if (FAILED(hr = pNetListManager->get_IsConnectedToInternet(&is_connected)))
		{
			APP_TRACE_LOG(LL_ERR, L"get_IsConnectedToInternet fail! Status: %p", hr);
			pNetListManager->Release();
			return false;
		}
		
		pNetListManager->Release();

		// Normally VARIANT_TRUE/VARIANT_FALSE are used with the type VARIANT_BOOL
		// but in this case the docs explicitly say to use FALSE.
		// https://docs.microsoft.com/en-us/windows/desktop/api/Netlistmgr/nf-netlistmgr-inetworklistmanager-get_isconnectedtointernet

		avaliable = (is_connected != FALSE);
		return true;
	}
	bool CNetworkManager::CheckInternetStatus()
	{
		DWORD dwFlags = 0;
		if (!g_winAPIs->InternetGetConnectedState(&dwFlags, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"InternetGetConnectedState fail! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto dwTestConnectionRet = g_winAPIs->InternetAttemptConnect(0);
		if (dwTestConnectionRet != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"InternetAttemptConnect fail! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		/*
		if (!g_winAPIs->InternetCheckConnectionW(xorstr_(L"https://google.com"), FLAG_ICC_FORCE_CONNECTION, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"InternetCheckConnectionW fail! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}
		*/
		return true;
	}
	bool CNetworkManager::CheckInternetConnection(const std::wstring& stTargetUrl)
	{
		const auto bConnect = g_winAPIs->InternetCheckConnectionW(stTargetUrl.c_str(), FLAG_ICC_FORCE_CONNECTION, 0);
		if (!bConnect)
		{
			APP_TRACE_LOG(LL_ERR, L"InternetCheckConnectionA fail! Last error: %u", g_winAPIs->GetLastError());
		}
		return bConnect;
	}
	bool CNetworkManager::IsCorrectIPAddressOfWebsite(const std::wstring& wstWebsite, const std::wstring& wstIPAddress)
	{
		WSADATA wsaData;
		const auto iResult = g_winAPIs->WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"WSAStartup fail! Ret: %d Last error: %d", iResult, WSAGetLastError());
			return false;
		}

		const auto stWebsite = stdext::to_ansi(wstWebsite);
		const auto remoteHost = g_winAPIs->gethostbyname(stWebsite.c_str());
		if (!remoteHost)
		{
			APP_TRACE_LOG(LL_ERR, L"gethostbyname fail! Last error: %d", WSAGetLastError());
			g_winAPIs->WSACleanup();
			return false;
		}
		g_winAPIs->WSACleanup();

		const auto stIPAddress = stdext::to_ansi(wstIPAddress);
		if (remoteHost && remoteHost->h_addrtype == AF_INET)
		{
			int i = 0;
			while (remoteHost->h_addr_list[i] != 0)
			{
				in_addr addr;
				addr.s_addr = *(DWORD*)remoteHost->h_addr_list[i++];
				const auto& stCorrectAddr = std::string(g_winAPIs->inet_ntoa(addr));

				APP_TRACE_LOG(LL_SYS, L"IsCorrectIPAddressOfWebsite event new addr detected. Correct Addr: %s Addr: %s", g_winAPIs->inet_ntoa(addr), stIPAddress.c_str());
				if (stIPAddress == stCorrectAddr)
					return true;
			}
		}

		APP_TRACE_LOG(LL_ERR, L"IsCorrectIPAddressOfWebsite failed! Remotehost: %p Addrtype: %d", remoteHost, remoteHost->h_addrtype);
		return false;
	}

	bool CNetworkManager::IsWebsiteDown(const std::wstring& stWebsite, const std::wstring& stMethod)
	{
		auto hSession = g_winAPIs->InternetOpenW(xorstr_(L"Mozilla/5.0"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (!hSession)
		{
			APP_TRACE_LOG(LL_ERR, L"InternetOpenA fail! Last error: %u", g_winAPIs->GetLastError());
			return true;
		}

		auto hConnect = g_winAPIs->InternetConnectW(hSession, stWebsite.c_str(), 0, L"", L"", INTERNET_SERVICE_HTTP, 0, 0);
		if (!hConnect)
		{
			APP_TRACE_LOG(LL_ERR, L"InternetConnectA fail! Last error: %u", g_winAPIs->GetLastError());
			g_winAPIs->InternetCloseHandle(hSession);
			return true;
		}

		auto hHttpFile = g_winAPIs->HttpOpenRequestW(hConnect, stMethod.c_str(), xorstr_(L"/"), NULL, NULL, NULL, 0, 0);
		if (!hHttpFile)
		{
			APP_TRACE_LOG(LL_ERR, L"HttpOpenRequestA fail! Last error: %u", g_winAPIs->GetLastError());
			g_winAPIs->InternetCloseHandle(hConnect);
			g_winAPIs->InternetCloseHandle(hSession);
			return true;
		}

		wchar_t responseText[256]{ L'\0' };
		DWORD responseTextSize = sizeof(responseText) / sizeof(wchar_t);

		if (!g_winAPIs->HttpQueryInfoW(hHttpFile, HTTP_QUERY_STATUS_CODE, &responseText, &responseTextSize, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"HttpQueryInfoA fail! Last error: %u", g_winAPIs->GetLastError());
			g_winAPIs->InternetCloseHandle(hHttpFile);
			g_winAPIs->InternetCloseHandle(hConnect);
			g_winAPIs->InternetCloseHandle(hSession);
			return true;
		}

		const auto statusCode = _wtoi(responseText);
		const auto ret = statusCode != 200;

		g_winAPIs->InternetCloseHandle(hHttpFile);
		g_winAPIs->InternetCloseHandle(hConnect);
		g_winAPIs->InternetCloseHandle(hSession);

		APP_TRACE_LOG(LL_SYS, L"Website: %s status: %d", stWebsite.c_str(), statusCode);
		return ret;
	}
};
