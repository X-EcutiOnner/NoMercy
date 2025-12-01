#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

// check infos inet_ntoa, getsockname, getpeername | close if required closesocket

namespace NoMercy
{
	std::string GetIpAddress(DWORD dwAddress)
	{
		struct in_addr addr;
		addr.S_un.S_addr = dwAddress;
		return g_winAPIs->inet_ntoa(addr);
	}

	void IScanner::CheckTcpConnections()
	{		
		DWORD dwSize = 0;
		auto ret = g_winAPIs->GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, NULL);
		if (ret != ERROR_INSUFFICIENT_BUFFER)
		{
			APP_TRACE_LOG(LL_ERR, L"GetExtendedTcpTable(1) failed with error: %u", ret);
			return;
		}

		auto pTable = (MIB_TCPTABLE_OWNER_PID*)CMemHelper::Allocate(dwSize);
		if (!pTable)
		{
			APP_TRACE_LOG(LL_ERR, L"pTable could not allocated with error: %u", g_winAPIs->GetLastError());
			return;
		}

		ret = g_winAPIs->GetExtendedTcpTable(pTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, NULL);
		if (ret != NO_ERROR || !pTable)
		{
			APP_TRACE_LOG(LL_ERR, L"GetExtendedTcpTable(2) failed with error: %u", ret);
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
				"PID: %u Local addr: %s:%u Remote addr: %s:%u State: %u",
				table->dwOwningPid,
				GetIpAddress(table->dwLocalAddr).c_str(),
				table->dwLocalPort,
				GetIpAddress(table->dwRemoteAddr).c_str(),
				table->dwRemotePort,
				table->dwState
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
