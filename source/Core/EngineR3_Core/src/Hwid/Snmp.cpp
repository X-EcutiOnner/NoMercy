#include "../../include/PCH.hpp"
#include "../../include/Snmp.hpp"
#include "../../include/MemAllocator.hpp"

namespace NoMercyCore
{
	static DWORD snmpIds[14] = { 1, 3, 6, 1, 2, 1, 4, 0x15, 1, 7, 0, 0, 0, 0 };
	static DWORD snmpIds2[10] = { 1, 3, 6, 1, 2, 1, 4, 0x16, 1, 2 };

	CSnmpHelper::CSnmpHelper()
	{
	}
	CSnmpHelper::~CSnmpHelper()
	{
	}

	bool CSnmpHelper::Initialize()
	{
		/*
		WSADATA WinsockData;
		const auto nWsaRet = g_winAPIs->WSAStartup(MAKEWORD(2, 0), &WinsockData);
		if (nWsaRet)
		{
			APP_TRACE_LOG(LL_ERR, L"WSAStartup failed with status: %d error: %u", nWsaRet, g_winAPIs->GetLastError());
			return false;
		}
		*/

		HANDLE PollForTrapEvent;
		AsnObjectIdentifier SupportedView;
		if (!g_winAPIs->SnmpExtensionInit(g_winAPIs->GetTickCount(), &PollForTrapEvent, &SupportedView))
		{
			APP_TRACE_LOG(LL_ERR, L"SnmpExtensionInit failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		return true;
	}

	void CSnmpHelper::Release()
	{
		SnmpExtensionClose();
		// g_winAPIs->WSACleanup();
	}

	bool CSnmpHelper::__IsEthernet(uint32_t uType)
	{
		switch (uType)
		{
			case 6:
			case 7:
			case 26:
			case 62:
			case 69:
			case 117:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsTokenRing(uint32_t uType)
	{
		switch (uType)
		{
			case 9:
			case 115:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsTokenBus(uint32_t uType)
	{
		switch (uType)
		{
			case 8:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsISDN(uint32_t uType)
	{
		switch (uType)
		{
			case 20:
			case 21:
			case 63:
			case 75:
			case 76:
			case 77:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsATM(uint32_t uType)
	{
		switch (uType)
		{
			case 37:
			case 49:
			case 105:
			case 106:
			case 107:
			case 114:
			case 134:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsLAN(uint32_t uType)
	{
		switch (uType)
		{
			case 11:
			case 15:
			case 55:
			case 59:
			case 60:
				return true;

			default:
				break;
		}

		if (__IsEthernet(uType) || __IsTokenBus(uType) || __IsTokenRing(uType))
			return true;

		return false;
	}
	bool CSnmpHelper::__IsDSL(uint32_t uType)
	{
		switch (uType)
		{
			case 94:
			case 95:
			case 96:
			case 97:
			case 143:
				return true;

			default:
				return false;
		}
	}
	bool CSnmpHelper::__IsDialup(uint32_t uType)
	{
		switch (uType)
		{
			case 23:
			case 81:
			case 82:
			case 108:
				return true;

			default:
				break;
		}

		if (__IsISDN(uType) || __IsDSL(uType))
			return true;

		return false;
	}
	bool CSnmpHelper::__IsLoopback(uint32_t uType)
	{
		return uType == 24;
	}

	bool CSnmpHelper::MakeQuery()
	{
		// Network adapter(s) description and MAC address in
		// <.iso.org.dod.internet.mgmt.mib-2.interfaces> MIB tree
		// Entry for number of network interface
		static UINT OID_ifEntryNumber[] = {
			1, 3, 6, 1, 2, 1, 2, 1
		};
		// Entry for network interface index
		static UINT OID_ifEntryIndex[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 1
		};
		// Entry for network interface description
		static UINT OID_ifDesc[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 2
		};
		// Entry for network interface type
		static UINT OID_ifEntryType[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 3
		};
		// Entry for network interface speed
		static UINT OID_ifSpeed[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 5
		};                          //, 1 ,5 };
		// Entry for network interface physical address
		static UINT OID_ifMACAddr[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 6
		};
		// Entry for network interface operational status
		static UINT OID_ifOperStatus[] = {
			1, 3, 6, 1, 2, 1, 2, 2, 1, 8
		};

		AsnObjectIdentifier MIB_ifMACAddr = {
			sizeof(OID_ifMACAddr) / sizeof(UINT), OID_ifMACAddr
		};
		AsnObjectIdentifier MIB_ifEntryType = {
			sizeof(OID_ifEntryType) / sizeof(UINT), OID_ifEntryType
		};
		AsnObjectIdentifier MIB_ifEntryNumber = {
			sizeof(OID_ifEntryNumber) / sizeof(UINT), OID_ifEntryNumber
		};
		AsnObjectIdentifier MIB_ifSpeed = {
			sizeof(OID_ifSpeed) / sizeof(UINT), OID_ifSpeed
		};
		AsnObjectIdentifier MIB_ifDesc = {
			sizeof(OID_ifDesc) / sizeof(UINT), OID_ifDesc
		};
		AsnObjectIdentifier MIB_ifIndex = {
			sizeof(OID_ifEntryIndex) / sizeof(UINT), OID_ifEntryIndex
		};
		AsnObjectIdentifier MIB_ifOperStatus = {
			sizeof(OID_ifOperStatus) / sizeof(UINT), OID_ifOperStatus
		};

		// Network adapter(s) IP address and Net Mask in
		// <.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable> MIB tree
		// Entry for network interfaces IP Address
		static UINT OID_ipAdEntAddr[] = {
			1, 3, 6, 1, 2, 1, 4, 20, 1, 1
		};
		// Entry for network interfaces index
		static UINT OID_ipAdEntIfIndex[] = {
			1, 3, 6, 1, 2, 1, 4, 20, 1, 2
		};
		// Entry for network interfaces IP Net Mask
		static UINT OID_ipAdEntNetMask[] = {
			1, 3, 6, 1, 2, 1, 4, 20, 1, 3
		};

		AsnObjectIdentifier MIB_ipAdEntAddr = {
			sizeof(OID_ipAdEntAddr) / sizeof(UINT), OID_ipAdEntAddr
		};
		AsnObjectIdentifier MIB_ipAdEntIfIndex = {
			sizeof(OID_ipAdEntIfIndex) / sizeof(UINT), OID_ipAdEntIfIndex
		};
		AsnObjectIdentifier MIB_ipAdEntNetMask = {
			sizeof(OID_ipAdEntNetMask) / sizeof(UINT), OID_ipAdEntNetMask
		};

		AsnObjectIdentifier MIB_NULL = {
			0, 0
		};

		// Initialize the variable list to be retrieved by SnmpExtensionQuery
		RFC1157VarBindList	varBindList;
		RFC1157VarBind		varBind[6];

		varBindList.list = varBind;
		varBind[0].name = MIB_NULL;
		varBind[1].name = MIB_NULL;
		varBind[2].name = MIB_NULL;
		varBind[3].name = MIB_NULL;
		varBind[4].name = MIB_NULL;
		varBind[5].name = MIB_NULL;

		// Copy in the OID to find the number of entries in the Inteface table
		varBindList.len = 1;  // Only retrieving one item
		if (!g_winAPIs->SnmpUtilOidCpy(&varBind[0].name, &MIB_ifEntryNumber))
		{
			APP_TRACE_LOG(LL_ERR, L"SnmpUtilOidCpy(1) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		AsnInteger errorStatus, errorIndex;
		if (!g_winAPIs->SnmpExtensionQuery(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex))
		{
			APP_TRACE_LOG(LL_ERR, L"SnmpExtensionQuery failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Copy in the OID to retrieve interface properties in the Inteface table
		varBindList.len = 6;

		// Copy in the OID of ifType, the type of interface
		g_winAPIs->SnmpUtilOidCpy(&varBind[0].name, &MIB_ifEntryType);

		// Copy in the OID of ifphysAddress, the address
		g_winAPIs->SnmpUtilOidCpy(&varBind[1].name, &MIB_ifMACAddr);

		// Copy in the OID of ifPhysSpeed, the speed
		g_winAPIs->SnmpUtilOidCpy(&varBind[2].name, &MIB_ifSpeed);

		// Copy in the OID of ifDesc, the adapter description
		g_winAPIs->SnmpUtilOidCpy(&varBind[3].name, &MIB_ifDesc);

		// Copy in the OID of ifIndex, the adapter index
		g_winAPIs->SnmpUtilOidCpy(&varBind[4].name, &MIB_ifIndex);

		/* Copy in the OID of ifOperStatus, the adapter operational status */
		g_winAPIs->SnmpUtilOidCpy(&varBind[5].name, &MIB_ifOperStatus);

		int ret = 0;
		do
		{
			// Submit the query.  Responses will be loaded into varBindList.
			// We can expect this call to succeed a # of times corresponding
			// to the # of adapters reported to be in the system
			if (!g_winAPIs->SnmpExtensionQuery(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex))
				ret = 1;
			else
				// Confirm that the proper type has been returned
				ret = g_winAPIs->SnmpUtilOidNCmp(&varBind[0].name, &MIB_ifEntryType, MIB_ifEntryType.idLength);

			if (!ret)
			{
				// Get type of adapter
				const auto nType = varBind[0].value.asnValue.number;
				if (this->__IsLoopback(nType))
				{
					// Loopback adapter => skip it
					continue;
				}

				// Confirm that we have an address here
				ret = g_winAPIs->SnmpUtilOidNCmp(&varBind[1].name, &MIB_ifMACAddr, MIB_ifMACAddr.idLength);

				// Get adapter speed
				const auto speed = varBind[2].value.asnValue.gauge;
				if (!ret && varBind[1].value.asnValue.address.stream)
				{
					char szBuffer[24]{ 0 };
					snprintf(szBuffer, sizeof(szBuffer),
						xorstr_("%02X:%02X:%02X:%02X:%02X:%02X"),
						varBind[1].value.asnValue.address.stream[0],
						varBind[1].value.asnValue.address.stream[1],
						varBind[1].value.asnValue.address.stream[2],
						varBind[1].value.asnValue.address.stream[3],
						varBind[1].value.asnValue.address.stream[4],
						varBind[1].value.asnValue.address.stream[5]
					);

					SSnmpAdapterCtx ctx;
					ctx.nIfIndex = varBind[4].value.asnValue.number;
					ctx.stDescription = std::string((LPCSTR)varBind[3].value.asnValue.string.stream, varBind[3].value.asnValue.string.length);
					ctx.nType = nType;
					ctx.nSpeed = speed;
					ctx.stMacAddress = szBuffer;
					ctx.nStatus = varBind[5].value.asnValue.number;

					m_vAdapters.push_back(ctx);
				}
			}
		} 	while (!ret);

		// Stop only on an error.  An error will occur when we go exhaust
		// the list of interfaces to be examined
		// Free the bindings
		g_winAPIs->SnmpUtilVarBindFree(&varBind[0]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[1]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[2]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[3]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[4]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[5]);

		//////////////////////////////////////////////////////////////////
		// Next, get network interfaces IP from <.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable> MIB tree
		//////////////////////////////////////////////////////////////////
		varBind[0].name = MIB_NULL;
		varBind[1].name = MIB_NULL;
		varBind[2].name = MIB_NULL;

		// Copy in the OID to retrieve interface IP properties in the IPAddr table
		varBindList.len = 3;

		// Copy in the OID of ipAdEntIfIndex, the index of interface
		g_winAPIs->SnmpUtilOidCpy(&varBind[0].name, &MIB_ipAdEntIfIndex);

		// Copy in the OID of ipAdEntAddr, the IP address
		g_winAPIs->SnmpUtilOidCpy(&varBind[1].name, &MIB_ipAdEntAddr);

		// Copy in the OID of ipAdEntNetMask, the IP Net Mask
		g_winAPIs->SnmpUtilOidCpy(&varBind[2].name, &MIB_ipAdEntNetMask);

		do
		{
			// Submit the query.  Responses will be loaded into varBindList.
			// We can expect this call to succeed a # of times corresponding
			// to the # of adapters reported to be in the system
			if (!g_winAPIs->SnmpExtensionQuery(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex))
				ret = 1;
			else
				// Confirm that the proper type has been returned
				ret = g_winAPIs->SnmpUtilOidNCmp(&varBind[0].name, &MIB_ipAdEntIfIndex, MIB_ipAdEntIfIndex.idLength);

			if (!ret)
			{
				// Get IfIndex of adapter
				const auto nType = varBind[0].value.asnValue.number;

				// Confirm that we have an address here
				ret = g_winAPIs->SnmpUtilOidNCmp(&varBind[1].name, &MIB_ipAdEntAddr, MIB_ipAdEntAddr.idLength);
				if (!ret && varBind[1].value.asnValue.address.stream && varBind[2].value.asnValue.address.stream)
				{
					// We can save the infos

					char szIP[128]{ 0 };
					snprintf(szIP, sizeof(szIP),
						xorstr_("%d.%d.%d.%d"),
						varBind[1].value.asnValue.address.stream[0],
						varBind[1].value.asnValue.address.stream[1],
						varBind[1].value.asnValue.address.stream[2],
						varBind[1].value.asnValue.address.stream[3]
					);

					char szNetMask[128]{ 0 };
					snprintf(szNetMask, sizeof(szNetMask),
						xorstr_("%d.%d.%d.%d"),
						varBind[2].value.asnValue.address.stream[0],
						varBind[2].value.asnValue.address.stream[1],
						varBind[2].value.asnValue.address.stream[2],
						varBind[2].value.asnValue.address.stream[3]
					);

					// Update network number
					const auto ipAdr = g_winAPIs->ntohl(g_winAPIs->inet_addr(szIP));
					const auto ipMsk = g_winAPIs->ntohl(g_winAPIs->inet_addr(szNetMask));
					const auto nbRez = ipAdr & ipMsk;

					in_addr ipa;
					ipa.S_un.S_addr = g_winAPIs->htonl(nbRez);
					const auto szNetNumber = g_winAPIs->inet_ntoa(ipa);

					SSnmpInterfaceCtx ctx;
					ctx.nType = nType;
					ctx.stIPAddress = szIP;
					ctx.stNetMask = szNetMask;
					ctx.stNetNumber = szNetNumber;

					m_vInterfaces.push_back(ctx);
				}
			}
		} 	while (!ret);

		// Stop only on an error.  An error will occur when we go exhaust
		// the list of interfaces to be examined
		// Free the bindings
		g_winAPIs->SnmpUtilVarBindFree(&varBind[0]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[1]);
		g_winAPIs->SnmpUtilVarBindFree(&varBind[2]);

		return true;
	}
}
