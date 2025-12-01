#pragma once

namespace NoMercyCore
{
	struct SSnmpAdapterCtx
	{
		int32_t nIfIndex;
		std::string stDescription;
		int32_t nType;
		uint32_t nSpeed;
		std::string stMacAddress;
		int32_t nStatus;
	};

	struct SSnmpInterfaceCtx
	{
		int32_t nType;
		std::string stIPAddress;
		std::string stNetMask;
		std::string stNetNumber;
	};

	class CSnmpHelper
	{
	public:
		CSnmpHelper();
		~CSnmpHelper();

		bool Initialize();
		void Release();

		bool MakeQuery();

	protected:
		bool __IsEthernet(uint32_t uType);
		bool __IsTokenRing(uint32_t uType);
		bool __IsTokenBus(uint32_t uType);
		bool __IsISDN(uint32_t uType);
		bool __IsATM(uint32_t uType);
		bool __IsLAN(uint32_t uType);
		bool __IsDSL(uint32_t uType);
		bool __IsDialup(uint32_t uType);
		bool __IsLoopback(uint32_t uType);

	private:
		std::vector <SSnmpAdapterCtx> m_vAdapters;
		std::vector <SSnmpInterfaceCtx> m_vInterfaces;
	};
};
