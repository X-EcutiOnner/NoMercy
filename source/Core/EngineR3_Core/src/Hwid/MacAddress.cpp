#include "../../include/PCH.hpp"
#include "../../include/MacAddress.hpp"
#include "../../include/HW-Info.hpp"
#include <NtDDNdis.h>

namespace NoMercyCore
{
	CMacAddress::CMacAddress()
	{
		FindValidMac();
		FindPhysicalMacAddress();
	}

	CMacAddress::~CMacAddress()
	{
		if (m_pAdapters)
		{
			delete[] m_pAdapters;
			m_pAdapters = nullptr;
		}
	}

	bool CMacAddress::IsPrimaryAdapter(std::uint32_t dwIndex)
	{
		bool bIsPrimaryAdapter = false;

		if (m_pAdapters)
		{
			auto dwMinIndex = m_pAdapters->GetAdapterIndex();
			for (auto i = 0UL; i < m_nCount; i++)
			{
				auto pAdapt = &m_pAdapters[i];

				// Ignore if desc contains VPN
				auto wstDesc = pAdapt->GetAdapterDescription();
				if (wstDesc.find(xorstr_("VPN")) != std::wstring::npos)
				{
					continue;
				}

				// Ignore if ip addresses are 0.0.0.0
				auto wstIp = pAdapt->GetGatewayAddr();
				if (wstIp.empty() || wstIp == xorstr_(" "))
				{
					continue;
				}

				if (pAdapt->GetAdapterIndex() < dwMinIndex)
				{
					dwMinIndex = pAdapt->GetAdapterIndex();
				}
			}

			if (dwIndex == dwMinIndex)
			{
				bIsPrimaryAdapter = true;
			}
		}

		return bIsPrimaryAdapter;
	}

	bool CMacAddress::InitAdapters()
	{
		DWORD dwErr = 0;
		ULONG ulNeeded = 0;

		dwErr = EnumNetworkAdapters(m_pAdapters, 0, &ulNeeded);
		if (dwErr == ERROR_INSUFFICIENT_BUFFER)
		{
			m_nCount = ulNeeded / sizeof(CNetworkAdapter);
			m_pAdapters = new(std::nothrow) CNetworkAdapter[ulNeeded / sizeof(CNetworkAdapter)];
			if (!m_pAdapters)
			{
				return false;
			}

			dwErr = EnumNetworkAdapters(m_pAdapters, ulNeeded, &ulNeeded);
			if (dwErr != NO_ERROR)
			{
				APP_TRACE_LOG(LL_ERR, L"EnumNetworkAdapters failed with status: %u", dwErr);
				return false;
			}
		}
		else
		{
			return false;
		}
		return true;
	}

	bool CMacAddress::FindValidMac()
	{
		InitAdapters();

		if (m_pAdapters)
		{
			for (UINT i = 0; i < m_nCount; i++)
			{
				auto pAdapter = &m_pAdapters[i];

				auto dwIndex = pAdapter->GetAdapterIndex();
				if (this->IsPrimaryAdapter(dwIndex))
				{
					this->SetMacAdapterInfo(pAdapter->GetAdapterAddress(), pAdapter->GetAdapterName());
					return true;
				}
			}
		}
		return false;
	}

	void CMacAddress::SetMacAdapterInfo(const std::wstring& wstAdapterAddress, const std::wstring& wstAdapterName)
	{
		m_wstPrimaryAdapterAddress = wstAdapterAddress;
		m_wstPrimaryAdapterName = wstAdapterName;
	}


	bool CMacAddress::FindPhysicalMacAddress()
	{
		DWORD dwLength;
		IP_INTERFACE_INFO* pInterface = nullptr;
		auto dwRet = g_winAPIs->GetInterfaceInfo(pInterface, &dwLength);
		if (dwRet != ERROR_INSUFFICIENT_BUFFER)
		{
			APP_TRACE_LOG(LL_ERR, L"GetInterfaceInfo failed with status: %u error: %u", dwRet, g_winAPIs->GetLastError());
			return false;
		}
		
		pInterface = (IP_INTERFACE_INFO*)malloc(dwLength);
		if (!pInterface)
		{
			APP_TRACE_LOG(LL_ERR, L"%u bytes memory allocation failed! Last error: %u", dwLength, g_winAPIs->GetLastError());
			return false;
		}

		dwRet = g_winAPIs->GetInterfaceInfo(pInterface, &dwLength);
		if (dwRet != NO_ERROR)
		{
			APP_TRACE_LOG(LL_ERR, L"GetInterfaceInfo failed with status: %u", dwRet);
			free(pInterface);
			return false;
		}

		for (int i = 0; i < pInterface->NumAdapters; i++)
		{
			const auto wszBuffer = std::wstring(pInterface->Adapter[i].Name);
			if (wszBuffer.size() != 38 && wszBuffer.size() != 52) // 38 = adapter name, 14 = '\DEVICE\TCPIP_' tag
				continue;

			const auto wstAdapterName = wszBuffer.substr(wszBuffer.size() - 38, 38);

			if (wstAdapterName != m_wstPrimaryAdapterName) // current adapter is not primary adapter
				continue;

			WCHAR wszPath[MAX_PATH]{ L'\0' };
			swprintf(wszPath, MAX_PATH, xorstr_(L"\\\\.\\%ls"), wstAdapterName.c_str());

			auto hDevice = g_winAPIs->CreateFileW(wszPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
			if (!IS_VALID_HANDLE(hDevice))
				continue;

			UCHAR uch[12]{ 0 };
			dwLength = 0;
			DWORD dwIoObj = OID_802_3_PERMANENT_ADDRESS;
			if (!g_winAPIs->DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwIoObj, sizeof(dwIoObj), &uch, sizeof(uch), &dwLength, nullptr))
			{
				dwIoObj = OID_802_3_CURRENT_ADDRESS;
				if (!g_winAPIs->DeviceIoControl(hDevice, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwIoObj, sizeof(dwIoObj), &uch, sizeof(uch), &dwLength, nullptr))
				{
					g_winAPIs->CloseHandle(hDevice);
					continue;
				}
			}

			if (dwLength != 6)
			{
				g_winAPIs->CloseHandle(hDevice);
				continue;
			}
			
			if (uch[0] == 0 && uch[1] == 0 && uch[2] == 0 && uch[3] == 0 && uch[4] == 0 && uch[5] == 0)
			{
				g_winAPIs->CloseHandle(hDevice);
				continue;
			}

			wchar_t wszOutput[128]{ L'\0' };
			_snwprintf(wszOutput, sizeof(wszOutput), xorstr_(L"%02X:%02X:%02X:%02X:%02X:%02X"), uch[0], uch[1], uch[2], uch[3], uch[4], uch[5]);
			m_wstPhysicalMacAddress = wszOutput;
			
			g_winAPIs->CloseHandle(hDevice);
			break;
		}

		free(pInterface);
		return TRUE;
	}
};
