#pragma once

namespace NoMercyCore
{
	struct SExtHwidCtx
	{
		std::wstring wstGPUID;
		std::wstring wstSID;
		std::wstring wstMonitorIDs;
		std::wstring wstPhysicalMacAddress;
	};

	class CHwidManager : public CSingleton <CHwidManager>
	{
	public:
		CHwidManager();
		virtual ~CHwidManager();

		bool Initilize();
		void SetSessionID(const std::wstring& wstSessionID);

		auto GetVolumeSerials() const { return m_vVolumeSerials; }
		auto GetHwidBundle() const { return m_wstHwidBundle; }
		auto GetSimpleHwid() const { return m_wstSimpleHwid; }
		auto GetSimpleHwidVersion() const { return m_dwSimpleHwidVersion; }
		auto GetSessionID() const { return m_wstSessionID; }
		auto GetBootID() const { return m_wstBootID; }
		std::shared_ptr <SExtHwidCtx> GetExtHwidCtx();

	protected:
		void __LoadRegistryInformations1();
		void __LoadRegistryInformations2();
		void __LoadRegistryInformations3();
		void __LoadRegistryInformations4();
		void __LoadRegistryInformations5();
		void __LoadRegistryInformations6();
		void __LoadRegistryInformations7();
		void __LoadRegistryInformations8();
		void __LoadRegistryInformations9();

		bool __LaunchWMIQueries();
		std::wstring __GenerateCpuID();
		std::wstring __GenerateComputerName();
		std::wstring __GenerateUserName();
		std::wstring __GenerateGuidFromWinapi();
		std::wstring __GenerateVolumeHashFromWinapi();
		std::wstring __GenerateMacAddressFromNetbios();
		void __GenerateRegistrySpecificInformations();
		void __GenerateSMBiosHwid();
		void __GenerateVolumeSerials();
		void __GenerateSteamIDList();
		void __GenerateSystemHashList();
		void __CreateSessionID();
		void __CreateBootID();
		void __CreateHwidBundle();
		bool __DI_GetMacAddresses();
		bool __GetIPAddress();
		bool __GetArpMacHashes();
		bool __GetNetworkAdaptersMac();
		bool __GetIPTable();
		bool __GetSID();
		bool __GetGpuID();
		bool __GetMonitorList();

	protected:
		DWORD					ThreadRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool m_bThreadCompleted;
		std::wstring m_wstHwidBundle;
		std::wstring m_wstSimpleHwid;
		DWORD m_dwSimpleHwidVersion;
		std::wstring m_wstSessionID;
		std::wstring m_wstBootID;

		std::map <std::wstring /* id */, std::wstring /* hwid*/> m_mapContainer; // generic hwid container
		std::map <std::wstring /* type */, std::wstring /* context */> m_mapWmiContainer; // wmi hwid container
		std::vector <std::wstring> m_vVolumeSerials;
	};
};
