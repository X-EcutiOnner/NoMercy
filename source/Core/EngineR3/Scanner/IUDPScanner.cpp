#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
    extern std::wstring GetIpAddress(DWORD dwAddress);

    void IScanner::CheckUdpConnections()
	{		
		DWORD dwSize = 0;
		auto ret = g_winAPIs->GetExtendedUdpTable(NULL, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, NULL);
		if (ret != ERROR_INSUFFICIENT_BUFFER)
		{
			APP_TRACE_LOG(LL_ERR, L"GetExtendedUdpTable(1) failed with error: %u", ret);
			return;
		}

		auto pTable = (MIB_UDPTABLE_OWNER_PID*)CMemHelper::Allocate(dwSize);
		if (!pTable)
		{
			APP_TRACE_LOG(LL_ERR, L"pTable could not allocated with error: %u", g_winAPIs->GetLastError());
			return;
		}

		ret = g_winAPIs->GetExtendedUdpTable(pTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, NULL);
		if (ret != NO_ERROR || !pTable)
		{
			APP_TRACE_LOG(LL_ERR, L"GetExtendedUdpTable(2) failed with error: %u", ret);
			CMemHelper::Free(pTable);
			return;
		}

		for (std::size_t i = 0; i < pTable->dwNumEntries; ++i)
		{
			auto table = &pTable->table[i];

            struct sockaddr_in sAddrIn;
            sAddrIn.sin_family = AF_INET;
            sAddrIn.sin_addr.s_addr = table->dwLocalAddr;
            sAddrIn.sin_port = (u_short)table->dwLocalPort;

			/*
			APP_TRACE_LOG(LL_SYS,
				"PID: %u Local addr: %s:%u",
				table->dwOwningPid,
				GetIpAddress(table->dwLocalAddr).c_str(),
				table->dwLocalPort
			);
			*/

			// TODO: Check value

			/*
            char hostName[NI_MAXHOST]{ 0 };
            char hostAddress[NI_MAXHOST]{ 0 };
            char serviceName[NI_MAXSERV]{ 0 };

            getnameinfo((struct sockaddr*)&sAddrIn, sizeof(sockaddr_in), hostAddress, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
            getnameinfo((struct sockaddr*)&sAddrIn, sizeof(sockaddr_in), hostName, NI_MAXHOST, serviceName, NI_MAXSERV, NI_NUMERICSERV);

			APP_TRACE_LOG(LL_SYS, L"Host: %s (%s) Service: %s", hostName, hostAddress, serviceName);
			*/
		}

		CMemHelper::Free(pTable);
	}
};
