#include "../../include/PCH.hpp"
#include "../../include/HW-Info.hpp"
#include "../../include/NetworkAdapter.hpp"
#include "../../include/Disk_data.hpp"
#include "../../include/MacAddress.hpp"
#include "../../include/Smbios.hpp"
#include "../../include/FileVersion.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/DI_hwid.hpp"
#include "../../../../Common/BasicCrypt.hpp"
#include <ntddndis.h>
#include <vdf_parser.hpp>
#include <d3d9.h>

namespace NoMercyCore
{
	static const ULONG gsc_uCpuIDValueList[] = {
		0,
		7,
		4,
		0x80000008,
		0x80000007,
		0x80000005,
		0x80000006,
		0x80000001,
		0x80000000
	};

	CHwidManager::CHwidManager() :
		m_dwSimpleHwidVersion(0), m_bThreadCompleted(false)
	{
	}
	CHwidManager::~CHwidManager()
	{
	}

	DWORD CHwidManager::ThreadRoutine(void)
	{
		APP_TRACE_LOG(LL_SYS, L"Hwid manager thread started.");
		
		const auto spMacAddressMgr = stdext::make_unique_nothrow<CMacAddress>();
		if (IS_VALID_SMART_PTR(spMacAddressMgr))
		{
			m_mapContainer.emplace(xorstr_(L"mac1"), spMacAddressMgr->GetMacAddress());
			m_mapContainer.emplace(xorstr_(L"mac2"), spMacAddressMgr->GetPhysicalMacAddress());
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 1 initialized.");

		const auto spDiskMgr = stdext::make_unique_nothrow<CDiskData>();
		if (IS_VALID_SMART_PTR(spDiskMgr))
		{
			m_mapContainer.emplace(xorstr_(L"disk_serial_smart"), spDiskMgr->getHDDSerialNumber());
			m_mapContainer.emplace(xorstr_(L"disk_model_smart"), spDiskMgr->getHDDModelNumber());
			m_mapContainer.emplace(xorstr_(L"disk_info"), spDiskMgr->ReadPhysicalDriveStorageDeviceData());
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 2 initialized.");

		m_mapContainer.emplace(xorstr_(L"cpu_id"), __GenerateCpuID());
		m_mapContainer.emplace(xorstr_(L"user_name"), __GenerateUserName());
		m_mapContainer.emplace(xorstr_(L"computer_name"), __GenerateComputerName());

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 3 initialized.");

		m_mapContainer.emplace(xorstr_(L"machine_guid"), __GenerateGuidFromWinapi());
		m_mapContainer.emplace(xorstr_(L"machine_volume_hash"), __GenerateVolumeHashFromWinapi());

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 4 initialized.");

		m_mapContainer.emplace(xorstr_(L"mac3"), __GenerateMacAddressFromNetbios());

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 5 initialized.");

		__GenerateRegistrySpecificInformations();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 6 initialized.");

		if (g_winAPIs && g_winAPIs.get() && g_winAPIs->RtlGetVersion)
		{
			RTL_OSVERSIONINFOEXW verInfo{ 0 };
			verInfo.dwOSVersionInfoSize = sizeof(verInfo);
			if (g_winAPIs->RtlGetVersion(&verInfo) == 0)
			{
				m_mapContainer.emplace(xorstr_(L"os"), fmt::format(xorstr_(L"OS {0}.{1} SP {2}.{3} B {4} P {5}"),
					verInfo.dwMajorVersion, verInfo.dwMinorVersion,
					verInfo.wServicePackMajor, verInfo.wServicePackMinor,
					verInfo.dwBuildNumber, verInfo.wProductType
				));
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 7 initialized.");

		__GenerateSMBiosHwid();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 8 initialized.");

		__GenerateVolumeSerials();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 9 initialized.");

		__GenerateSteamIDList();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 10 initialized.");

		__GenerateSystemHashList();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 11 initialized.");

		__DI_GetMacAddresses();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 12 initialized.");

		__GetIPAddress();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 13 initialized.");

		__GetNetworkAdaptersMac();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 14 initialized.");

		__GetIPTable();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 15 initialized.");

		__GetSID();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 16 initialized.");

		__GetGpuID();
		
		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 17 initialized.");

		__GetArpMacHashes();
		
		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 18 initialized.");

		__GetMonitorList();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 19 initialized.");

		BYTE seed[0x1000]{ 0x0 };	
		const auto dwLength = g_winAPIs->GetFirmwareEnvironmentVariableW(
			xorstr_(L"OfflineUniqueIDRandomSeed"),
			xorstr_(L"{EAEC226F-C9A3-477A-A826-DDC716CDC0E3}"),
			&seed[0],
			sizeof(seed)
		);
		if (dwLength > 0) {
			const auto wstSerialized = stdext::dump_hex(&seed[0], dwLength);
			m_mapContainer.emplace(xorstr_(L"offline_unique_id_random_seed"), wstSerialized);
		} else {
			APP_TRACE_LOG(LL_ERR, L"GetFirmwareEnvironmentVariableW failed with error code: %d", g_winAPIs->GetLastError());
		}
			
		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 20 initialized.");

		__LaunchWMIQueries();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 21 initialized.");

		__CreateSessionID();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 22 initialized.");

		__CreateBootID();
		
		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 23 initialized.");

		const auto wstMachineGuidFilename = xorstr_(L"%SystemRoot%\\System32\\restore\\MachineGuid.txt");
		if (CApplication::Instance().DirFunctionsInstance()->IsFileExist(wstMachineGuidFilename))
		{
			const auto wstMachineGuidFileContent = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(wstMachineGuidFilename);
			if (!wstMachineGuidFileContent.empty())
				m_mapContainer.emplace(xorstr_(L"machine_guid_file"), wstMachineGuidFileContent);
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 24 initialized.");

		const auto wstSimpleHwid = fmt::format(xorstr_(L"{0}{1}"), m_mapContainer[xorstr_(L"mac2")], m_mapContainer[xorstr_(L"cpu_id")]);
		if (wstSimpleHwid.empty())
		{
			APP_TRACE_LOG(LL_CRI, L"Hwid manager failed to generate simple hwid.");
			CMiniDump::TriggerSEH(MINIDUMP_HWID);
		}
		
		m_wstSimpleHwid = CApplication::Instance().CryptFunctionsInstance()->GetMd5(wstSimpleHwid);
		m_dwSimpleHwidVersion = NOMERCY_HWID_VERSION;

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 25 initialized.");

		__CreateHwidBundle();

		APP_TRACE_LOG(LL_SYS, L"Hwid manager step 26 initialized.");

		m_bThreadCompleted = true;
		return 0;
	}
	DWORD WINAPI CHwidManager::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CHwidManager*>(lpParam);
		return This->ThreadRoutine();
	}

	bool CHwidManager::Initilize()
	{
		APP_TRACE_LOG(LL_SYS, L"Hwid manager initializing...");

		auto hThread = g_winAPIs->CreateThread(nullptr, 0, StartThreadRoutine, this, 0, nullptr);
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager thread created!");

		CStopWatch <std::chrono::milliseconds> timer;
		while (timer.diff() < 75000)
		{
			if (m_bThreadCompleted)
				break;

			g_winAPIs->Sleep(500);
		}

		if (!m_bThreadCompleted)
		{
			APP_TRACE_LOG(LL_ERR, L"Hwid manager thread timeout!");
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Hwid manager initialized in: %lu ms. Session ID: %s", timer.diff(), m_wstSessionID.c_str());
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hThread);
		return true;
	}

	void CHwidManager::SetSessionID(const std::wstring& wstSessionID)
	{
		APP_TRACE_LOG(LL_SYS, L"Session ID changed from: %s to: %s", m_wstSessionID.c_str(), wstSessionID.c_str());
		m_wstSessionID = wstSessionID;
	}
	
	void CHwidManager::__CreateHwidBundle()
	{
		auto wstVolumeSerials = L""s;
		if (!m_vVolumeSerials.empty())
		{
			for (const auto& stSerial : m_vVolumeSerials)
				wstVolumeSerials += (stSerial + xorstr_(L"-"));
			wstVolumeSerials.pop_back();
		}

		stdext::json_data_container_t mapDataContainer;
		
		for (const auto& [key, value] : m_mapContainer)
			mapDataContainer.emplace(key, NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA1(value));

		for (const auto& [key, value] : m_mapWmiContainer)
			mapDataContainer.emplace(fmt::format(xorstr_(L"{0}_wmi"), key), value);

		mapDataContainer.emplace(xorstr_(L"VOLUME_SERIALS"), wstVolumeSerials);
		mapDataContainer.emplace(xorstr_(L"SIMPLE"), m_wstSimpleHwid);

		const auto wstJsonDump = stdext::dump_json(mapDataContainer);
		const auto wstEncoded = CApplication::Instance().CryptFunctionsInstance()->EncodeBase64(wstJsonDump);

		// m_mapContainer.clear();
		mapDataContainer.clear();
		m_mapWmiContainer.clear();
		m_vVolumeSerials.clear();
		wstVolumeSerials.clear();

		m_wstHwidBundle = wstJsonDump;
	}

	void CHwidManager::__CreateSessionID()
	{
		if (!m_wstSessionID.empty())
		{
			APP_TRACE_LOG(LL_CRI, L"Session ID is already created!");
			return;
		}

		const auto dwProcessID = HandleToUlong(NtCurrentProcessId());
		const auto dwThreadID = HandleToUlong(NtCurrentThreadId());

		const auto bundle = std::wstring(
			std::to_wstring(dwProcessID) + std::to_wstring(dwThreadID) +
			std::to_wstring(stdext::get_current_epoch_time()) + std::to_wstring(__NOMERCY_VERSION__) +
			stdext::generate_uuid_v4()
		);

		m_wstSessionID = CApplication::Instance().CryptFunctionsInstance()->GetSHA1(bundle);
		return;
	}

	void CHwidManager::__CreateBootID()
	{
		SYSTEM_TIMEOFDAY_INFORMATION sti{ 0 };
		const auto ntStat = g_winAPIs->NtQuerySystemInformation(SystemTimeOfDayInformation, &sti, sizeof(sti), nullptr);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQuerySystemInformation failed with error: %p", ntStat);
			return;
		}

		const auto ullBootTime = sti.BootTime.QuadPart ? sti.BootTime.QuadPart / 1000000 : 0;
		if (!ullBootTime)
		{
			APP_TRACE_LOG(LL_ERR, L"Boot time is not correct!");
			return;
		}

		const auto ullHash = XXH64(&ullBootTime, sizeof(ullBootTime), 69699669);
		if (!ullHash)
		{
			APP_TRACE_LOG(LL_ERR, L"Boot time hash calculation failed!");
			return;
		}

		m_wstBootID = std::to_wstring(ullHash);
	}

	std::wstring CHwidManager::__GenerateCpuID()
	{
		auto wszCpuID = (LPWSTR)CMemHelper::Allocate(256 * sizeof(WCHAR) + sizeof(UNICODE_NULL));
		if (!wszCpuID)
			return {};

		auto ulIndex = 0UL;
		for (std::size_t i = 0; i < _countof(gsc_uCpuIDValueList); i++)
		{
			int iCpuinfo[4] = { 0, 0, 0, 0 };
			__cpuid(iCpuinfo, gsc_uCpuIDValueList[i]);

			auto pBlockInfo = (LPBYTE)iCpuinfo;

			for (auto ulBlock = 0UL; ulBlock < 16; ulBlock++)
			{
				stdext::uint32_to_hex_wstring((ULONG)pBlockInfo[ulBlock], &wszCpuID[ulIndex]);
				ulIndex += 1;
			}
		}

		wszCpuID[256] = L'\0';

		const auto wstCpuID = std::wstring(wszCpuID, 256);
		const auto wszHashedId = CApplication::Instance().CryptFunctionsInstance()->GetSHA256(wstCpuID);

		CMemHelper::Free(wszCpuID);
		return wszHashedId;
	}

	std::wstring CHwidManager::__GenerateComputerName()
	{
		auto dwComputerNameSize = 1024UL;
		wchar_t wszComputerName[1024]{ L'\0' };

		g_winAPIs->GetComputerNameW(wszComputerName, &dwComputerNameSize);
		return wszComputerName;
	}

	std::wstring CHwidManager::__GenerateUserName()
	{
		auto dwUserNameSize = 1024UL;
		wchar_t wszUserName[1024]{ L'\0' };

		g_winAPIs->GetUserNameW(wszUserName, &dwUserNameSize);
		return wszUserName;
	}

	std::wstring CHwidManager::__GenerateGuidFromWinapi()
	{
		wchar_t szMainDisk[MAX_PATH]{ L'\0' };
		if (g_winAPIs->GetLogicalDriveStringsW(_countof(szMainDisk) - 1, szMainDisk))
		{
			wchar_t wszGuid[1024]{ L'\0' };
			if (g_winAPIs->GetVolumeNameForVolumeMountPointW(szMainDisk, wszGuid, 1024))
			{
				std::wstring wstGuid = wszGuid;
				wstGuid = wstGuid.substr(11);
				wstGuid = wstGuid.substr(0, wstGuid.size() - 2);
				return wstGuid;
			}
		}
		return {};
	}

	std::wstring CHwidManager::__GenerateVolumeHashFromWinapi()
	{
		wchar_t szMainDisk[MAX_PATH]{ L'\0' };
		if (g_winAPIs->GetLogicalDriveStringsW(_countof(szMainDisk) - 1, szMainDisk))
		{
			auto dwSerialNum = 0UL;
			if (g_winAPIs->GetVolumeInformationW(szMainDisk, nullptr, 0, &dwSerialNum, nullptr, nullptr, nullptr, 0))
			{
				return std::to_wstring(dwSerialNum);
			}
		}
		return {};
	}

	std::wstring CHwidManager::__GenerateMacAddressFromNetbios()
	{
		WinAPI::ASTAT Adapter{ 0 };

		auto getmac_one = [&](int lana_num)
		{
			std::wstring out;

			NCB ncb{ 0 };
			ncb.ncb_command = NCBRESET;
			ncb.ncb_lana_num = lana_num;

			auto uRetCode = g_winAPIs->Netbios(&ncb);
			if (uRetCode == NRC_GOODRET)
			{
				memset(&ncb, 0, sizeof(ncb));
				ncb.ncb_command = NCBASTAT;
				ncb.ncb_lana_num = lana_num;
				strcpy((char*)ncb.ncb_callname, xorstr_("* "));
				ncb.ncb_buffer = (unsigned char*)&Adapter;
				ncb.ncb_length = sizeof(Adapter);

				uRetCode = g_winAPIs->Netbios(&ncb);
				if (uRetCode == NRC_GOODRET)
				{
					constexpr auto MACSESION = 6;

					int bAddressInt[MACSESION] { 0 };
					for (int i = 0; i < MACSESION; ++i)
					{
						bAddressInt[i] = Adapter.adapt.adapter_address[i];
						bAddressInt[i] &= 0x000000ff;
					}

					wchar_t wszBuffer[MACSESION * 3]{ L'\0' };
					_snwprintf(wszBuffer, sizeof(wszBuffer),
						xorstr_(L"%02x:%02x:%02x:%02x:%02x:%02x"),
						bAddressInt[0], bAddressInt[1],
						bAddressInt[2], bAddressInt[3],
						bAddressInt[4], bAddressInt[5]
					);
					
					out = wszBuffer;
				}	
			}

			return out;
		};

		LANA_ENUM lana_enum{ 0 };

		NCB ncb{ 0 };
		ncb.ncb_command = NCBENUM;
		ncb.ncb_buffer = (PUCHAR)&lana_enum;
		ncb.ncb_length = sizeof(lana_enum);

		auto uRetCode = g_winAPIs->Netbios(&ncb);
		if (uRetCode == NRC_GOODRET)
		{
			for (int i = 0; i < lana_enum.length; ++i)
			{
				const auto stCurrMac = getmac_one(lana_enum.lana[i]);
				if (!stCurrMac.empty())
				{
					return stCurrMac;
				}
			}
		}

		return {};
	}

	void CHwidManager::__LoadRegistryInformations1()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		APP_TRACE_LOG(LL_SYS, L"1#1 Loading registry informations...");

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Cryptography"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"MachineGuid"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"machine_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		APP_TRACE_LOG(LL_SYS, L"1#2 Loading registry informations...");

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ProductId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"product_id_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"RegisteredOrganization"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"registered_org_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"RegisteredOwner"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"registered_owner_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BuildGUID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"os_buildguild_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BuildLab"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"os_buildlab_registry"), wszBuffer);
			}

			dwDataType = REG_DWORD;
			nBufSize = sizeof(dwBuffer);
			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"InstallDate"), NULL, &dwDataType, (LPBYTE)&dwBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"install_date_registry"), std::to_wstring(dwBuffer));
			}
			nBufSize = 1024;

			g_winAPIs->RegCloseKey(hKey);
		}

		APP_TRACE_LOG(LL_SYS, L"1#3 Loading registry informations...");

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Identifier"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"scsi_id_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SerialNumber"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"scsi_serial_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		APP_TRACE_LOG(LL_SYS, L"1#4 Loading registry informations...");

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ComputerHardwareId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"computer_hwid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		APP_TRACE_LOG(LL_SYS, L"1#5 Loading registry informations completed.");
	}

	void CHwidManager::__LoadRegistryInformations2()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\SQMClient"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"MachineId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"sqm_machineid_registry"), wszBuffer);
			}

			dwDataType = REG_QWORD;
			nBufSize = sizeof(qwBuffer);
			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"WinSqmFirstSessionStartTime"), NULL, &dwDataType, (LPBYTE)&qwBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"sqm_firsesstime_registry"), std::to_wstring(qwBuffer));
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"LastLoggedOnUser"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"last_logged_user_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"LastUsedUsername"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"last_used_user_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"HARDWARE\\DESCRIPTION\\System\\BIOS"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BIOSReleaseDate"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"bios_date_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BIOSVendor"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"bios_vendor_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BIOSVersion"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"bios_version_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemManufacturer"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"bios_sys_manufacturer_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemProductName"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"bios_sys_product_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations3()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SusClientId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"sus_client_id_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\HardwareConfig"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"LastConfig"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"hw_lastconfig_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\ControlSet001\\Control\\Diagnostics\\Performance\\BootCKCLSettings"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"GUID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"boot_ckcl_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"HwProfileGuid"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"hw_profile_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Hostname"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"tcpip_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations4()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Internet Explorer\\Registration"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ProductId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"ie_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SignatureCategoryID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"defender_id_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Tracing\\Microsoft\\FirewallAPI\\FirewallAPI"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Guid"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"firewall_id_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"BackupProductKeyDefault"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"backup_productkey_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DefaultProductKey"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ProductId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"os_productkey_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations5()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"OSProductPfn"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"os_product_pfn_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"OSProductContentId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"os_product_cid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\NVIDIA Corporation\\Global"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ClientUUID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"nvidia_cid_registry"), wszBuffer);
			}

			lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"PersistenceIdentifier"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"nvidia_persid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\NVIDIA Corporation\\Installer2"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"nvidia_sysid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral\\0"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Identifier"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"disk_perid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ChipsetMatchID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"nvidia_chipsetid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations6()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"UserModeDriverGUID"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"gpu_guid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		// REG_BINARY
		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_BINARY;

			std::array <uint8_t, 1024> arrBuffer;
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"WindowsAIKHash"), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto data = XXH64(arrBuffer.data(), nBufSize, 0);
				m_mapContainer.emplace(xorstr_(L"wmi_aikhash_registry"), std::to_wstring(data));
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_BINARY;

			std::array <uint8_t, 512> arrBuffer;
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Dhcpv6DUID"), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto data = stdext::dump_hex(arrBuffer.data(), nBufSize);
				m_mapContainer.emplace(xorstr_(L"ipv6_id_registry"), data);
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		// HKEY_USERS
		res = g_winAPIs->RegOpenKeyExW(HKEY_USERS, xorstr_(L".DEFAULT\\Software\\Microsoft\\IdentityCRL\\DeviceIdentities\\production\\S-1-5-20"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"ValidDeviceId"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"user_devid_registry"), wszBuffer);
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations7()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\MountedDevices"), NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey);
		if (res == ERROR_SUCCESS && hKey)
		{
			std::vector <std::wstring> vDevices;
			
			DWORD dwIndex = 0;
			DWORD dwValueLen = MAX_PATH;
			wchar_t wszValueName[MAX_PATH]{ L'\0' };
			
			while (g_winAPIs->RegEnumValueW(hKey, dwIndex, wszValueName, &dwValueLen, 0, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				if (wszValueName[0] != L'\0')
					vDevices.push_back(wszValueName);
				
				dwIndex++;
			}

			for (const auto& dev : vDevices)
			{
				auto dwDataType = REG_BINARY;

				std::array <uint8_t, 1024> arrBuffer;
				auto lVal = g_winAPIs->RegQueryValueExW(hKey, dev.c_str(), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
				if (lVal == ERROR_SUCCESS)
				{
					const auto data = XXH64(arrBuffer.data(), nBufSize, 0);
					m_mapContainer.emplace(fmt::format(xorstr_(L"mdev_reg_{0}"), dev), std::to_wstring(data));
				}
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}
	
	void CHwidManager::__LoadRegistryInformations8()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY"), NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey);
		if (res == ERROR_SUCCESS && hKey)
		{
			std::vector <std::wstring> vDisplayDevList;
			
			{
				DWORD dwIndex = 0;
				DWORD dwKeyLen = MAX_PATH;
				wchar_t wszNewKeyName[MAX_PATH]{ L'\0' };
				while (g_winAPIs->RegEnumKeyExW(hKey, dwIndex, wszNewKeyName, &dwKeyLen, 0, NULL, NULL, NULL) == ERROR_SUCCESS)
				{
					if (wszNewKeyName[0] != L'\0')
						vDisplayDevList.push_back(wszNewKeyName);

					dwIndex++;
				}
			}

			stdext::json_data_container_t mapDisplayDevIDs;
			for (const auto& wstDisplayDevice : vDisplayDevList)
			{
				const auto wstSubKey = fmt::format(xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\{0}"), wstDisplayDevice);

				HKEY hSubKey = nullptr;
				res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, wstSubKey.c_str(), NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hSubKey);
				if (res == ERROR_SUCCESS && hSubKey)
				{
					DWORD dwIndexSub = 0;
					DWORD dwKeyLen = MAX_PATH;
					wchar_t wszNewKeyName[MAX_PATH]{ L'\0' };
					
					while (g_winAPIs->RegEnumKeyExW(hSubKey, dwIndexSub, wszNewKeyName, &dwKeyLen, 0, NULL, NULL, NULL) == ERROR_SUCCESS)
					{					
						const auto stParamPath = fmt::format(xorstr_(L"{0}\\{1}\\Device Parameters"), wstSubKey, wszNewKeyName);
							
						HKEY hSubPathKey = nullptr;
						res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, stParamPath.c_str(), NULL, dwFlags, &hSubPathKey);
						if (res == ERROR_SUCCESS)
						{
							std::array <uint8_t, 512> arrBuffer;
							auto dwDataType = REG_BINARY;

							res = g_winAPIs->RegQueryValueExW(hSubPathKey, xorstr_(L"EDID"), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
							if (res == ERROR_SUCCESS && nBufSize > 0)
							{
								const auto wstSerialized = stdext::dump_hex(arrBuffer.data(), nBufSize);
								mapDisplayDevIDs.emplace(wstDisplayDevice, wstSerialized);
								break;
							}

							g_winAPIs->RegCloseKey(hSubPathKey);
						}

						dwIndexSub++;
					}
					g_winAPIs->RegCloseKey(hSubKey);
				}

				const auto wstSerialized = stdext::dump_json(mapDisplayDevIDs);
				m_mapContainer.emplace(xorstr_(L"display_devs_registry"), wstSerialized);
			}
			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__LoadRegistryInformations9()
	{
		auto nBufSize = 1024UL;
		wchar_t wszBuffer[1024]{ L'\0' };
		auto dwBuffer = 0UL;
		auto qwBuffer = 0ULL;

		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = NULL;
		auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Win32kWPP\\Parameters"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"WppRecorder_TraceGuid"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"wpp_recorder_trace_guid"), wszBuffer);
			}
			
			g_winAPIs->RegCloseKey(hKey);
		}

		hKey = NULL;
		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_BINARY;
			
			std::array <uint8_t, 1024> arrBuffer;
			nBufSize = arrBuffer.size();
			
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"RandomSeed"), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto data = XXH64(arrBuffer.data(), nBufSize, 0);
				m_mapContainer.emplace(xorstr_(L"tpm_random_seed"), std::to_wstring(data));
			}
			
			g_winAPIs->RegCloseKey(hKey);
		}

		hKey = NULL;
		res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_BINARY;

			std::array <uint8_t, 1024> arrBuffer;
			nBufSize = arrBuffer.size();

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"WindowsAIKHash"), NULL, &dwDataType, (LPBYTE)arrBuffer.data(), &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto data = XXH64(arrBuffer.data(), nBufSize, 0);
				m_mapContainer.emplace(xorstr_(L"tpm_windows_aik_hash"), std::to_wstring(data));
			}

			g_winAPIs->RegCloseKey(hKey);
		}

		hKey = NULL;
		res = g_winAPIs->RegOpenKeyExW(HKEY_CURRENT_USER, xorstr_(L"SOFTWARE\\Microsoft\\OneDrive\\Accounts\\Personal"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"UserEmail"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				m_mapContainer.emplace(xorstr_(L"onedrive_user_email"), wszBuffer);
			}
		}
		
		hKey = NULL;
		res = g_winAPIs->RegOpenKeyExW(HKEY_CURRENT_USER, xorstr_(L"SOFTWARE\\Microsoft\\IdentityCRL\\UserExtendedProperties"), NULL, dwFlags, &hKey);
		if (res == ERROR_SUCCESS)
		{
			auto dwIndexSub = 0UL;
			auto dwSubKeyCount = 0UL;
			g_winAPIs->RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &dwSubKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			if (dwSubKeyCount > 0)
			{
				std::map <std::string, std::string> mapUserExtendedProperties;
				while (dwIndexSub < dwSubKeyCount)
				{
					auto szSubKeyName = std::array <wchar_t, 1024> { L'\0' };
					nBufSize = szSubKeyName.size();
					auto lVal = g_winAPIs->RegEnumKeyExW(hKey, dwIndexSub, szSubKeyName.data(), &nBufSize, NULL, NULL, NULL, NULL);
					if (lVal == ERROR_SUCCESS)
					{					
						m_mapContainer.emplace(fmt::format(xorstr_(L"os_mail_{0}"), dwIndexSub + 1), szSubKeyName.data());
					}
					dwIndexSub++;

					if (dwIndexSub >= dwSubKeyCount)
						break;
				}
			}
			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__GenerateRegistrySpecificInformations()
	{		
		APP_TRACE_LOG(LL_SYS, L"Registry informations loading...");

		__LoadRegistryInformations1();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 1 loaded!");

		__LoadRegistryInformations2();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 2 loaded!");

		__LoadRegistryInformations3();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 3 loaded!");

		__LoadRegistryInformations4();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 4 loaded!");

		__LoadRegistryInformations5();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 5 loaded!");

		__LoadRegistryInformations6();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 6 loaded!");

		__LoadRegistryInformations7();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 7 loaded!");

		__LoadRegistryInformations8();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 8 loaded!");

		__LoadRegistryInformations9();
		APP_TRACE_LOG(LL_SYS, L"Registry informations part 9 loaded!");
	}

	void CHwidManager::__GenerateVolumeSerials()
	{
		auto GetSystemVolumeSerial = [&](const std::wstring& wstVolume)
		{
			wchar_t wszVolumeName[MAX_PATH + 1]{ L'\0' };
			wchar_t wszFileSystemName[MAX_PATH + 1]{ L'\0' };

			DWORD dwVolumeSerialNumber = 0xFFFFFFFF, dwMaximumComponentLength = 0, dwFileSystemFlags = 0;
			g_winAPIs->GetVolumeInformationW(wstVolume.c_str(), wszVolumeName, MAX_PATH + 1, &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, wszFileSystemName, MAX_PATH + 1);

			return dwVolumeSerialNumber;
		};

		for (wchar_t dev = L'A'; dev <= 'Z'; dev++)
		{
			const auto& stDevPath = fmt::format(xorstr_(L"{}://"), dev);
			if (g_winAPIs->GetDriveTypeW(stDevPath.c_str()) == DRIVE_FIXED)
			{
				const auto dwSerial = GetSystemVolumeSerial(stDevPath);
				m_vVolumeSerials.emplace_back(fmt::format(xorstr_(L"{}:{}"), dev, dwSerial));
			}
		}
	}

	void CHwidManager::__GenerateSteamIDList()
	{
		std::vector <std::wstring> vSteamIDList;
		auto fnGetSteamIDListImpl = [&](const std::wstring& stFileContent) {
			auto root = tyti::vdf::read(stFileContent.cbegin(), stFileContent.cend());
			if (root.name == xorstr_(L"InstallConfigStore"))
			{
				const auto child1 = root.childs[xorstr_(L"Software")];
				if (IS_VALID_SMART_PTR(child1))
				{
					const auto child2 = child1->childs[xorstr_(L"Valve")];
					if (IS_VALID_SMART_PTR(child2))
					{
						const auto child3 = child2->childs[xorstr_(L"Steam")];
						if (IS_VALID_SMART_PTR(child3))
						{
							const auto child4 = child3->childs[xorstr_(L"Accounts")];
							if (IS_VALID_SMART_PTR(child4))
							{
								for (const auto& pkAccDetails : child4->childs)
								{
									if (pkAccDetails.second)
										vSteamIDList.emplace_back(pkAccDetails.second->attribs[xorstr_(L"SteamID")]);
								}
							}
						}
					}
				}
			}
		};
		auto fnGetSteamIDListSafe = [&](const std::wstring& stFileContent) {
			__try
			{
				fnGetSteamIDListImpl(stFileContent);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		
		auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
		if (stdext::is_wow64())
			dwFlags |= KEY_WOW64_64KEY;

		HKEY hKey = nullptr;
		auto lStatus = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Valve\\Steam"), NULL, KEY_READ | KEY_QUERY_VALUE, &hKey);
		if (lStatus == ERROR_SUCCESS)
		{
			auto dwDataType = REG_SZ;
			auto nBufSize = 512UL;
			wchar_t wszBuffer[512]{ L'\0' };

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"InstallPath"), NULL, &dwDataType, (LPBYTE)&wszBuffer, &nBufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto stConfigFile = fmt::format(xorstr_(L"{0}\\config\\config.vdf"), wszBuffer);

				std::error_code ec{};
				if (std::filesystem::exists(stConfigFile, ec) && !ec)
				{
					const auto stFileBuffer = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(stConfigFile);
					if (!stFileBuffer.empty())
					{
						fnGetSteamIDListSafe(stFileBuffer);
						
						if (!vSteamIDList.empty())
						{
							stdext::json_data_container_t mapDataContainer;
							for (auto i = 0u; i < vSteamIDList.size(); ++i)
							{
								mapDataContainer.emplace(fmt::format(xorstr_(L"steam_{0}"), i), vSteamIDList.at(i));
							}

							const auto wstSteamIDList = stdext::dump_json(mapDataContainer);
							m_mapContainer.emplace(xorstr_(L"steam_ids"), wstSteamIDList);
						}
					}
				}
				else if (ec)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to check if file exists: %hs", ec.message().c_str());
				}
			}

			g_winAPIs->RegCloseKey(hKey);
		}
	}

	void CHwidManager::__GenerateSystemHashList()
	{
		const auto GetIDDHash = [](const std::wstring& target) {
			const auto hModule = g_winAPIs->GetModuleHandleW_o(target.c_str());
			if (!hModule)
				return 0ULL;

			const auto pIDH = (PIMAGE_DOS_HEADER)hModule;
			if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
				return 0ULL;

			const auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);
			if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
				return 0ULL;

			const auto pIOH = &pINH->OptionalHeader;
			if (!pIOH)
				return 0ULL;

			const auto qwHash = XXH64(&pIOH->DataDirectory, sizeof(pIOH->DataDirectory), 0);
			return qwHash;
		};

		stdext::json_data_container_t mapDataContainer;

		// 
		int cpuInfo[4][4]{ 0 };
		__cpuid(cpuInfo[0], 0x1);
		__cpuid(cpuInfo[1], 0x8000002);
		__cpuid(cpuInfo[2], 0x8000003);
		__cpuid(cpuInfo[3], 0x8000004);

		const auto qwCpuIdHash = XXH64(&cpuInfo, sizeof(cpuInfo), 0);
		mapDataContainer.emplace(xorstr_(L"cpu_id_hash"), std::to_wstring(qwCpuIdHash));

		//
		std::wstring wstModulesHash;
		const auto arHashedModules = { xorstr_(L"kernel32.dll"), xorstr_(L"ntdll.dll"), xorstr_(L"kernelbase.dll") };
		for (const auto& name : arHashedModules)
		{
			wstModulesHash.append(fmt::format(xorstr_(L"{0} # "), GetIDDHash(name)));
		}
		wstModulesHash = wstModulesHash.substr(0, wstModulesHash.size() - 3);
		mapDataContainer.emplace(xorstr_(L"module_hash_list"), wstModulesHash);

		// ignore in win11 > https://twitter.com/33y0re/status/1496504379351916547
		auto vKsdHashes = std::vector <uint64_t>();
		if (!IsWindows11OrGreater())
		{
			static const auto pUserSharedData = (KUSER_SHARED_DATA*)0x7FFE0000; // The fixed user mode address of KUSER_SHARED_DATA

			vKsdHashes.emplace_back(XXH64(&pUserSharedData->NtMajorVersion, sizeof(pUserSharedData->NtMajorVersion), 0));
			vKsdHashes.emplace_back(XXH64(&pUserSharedData->NtMinorVersion, sizeof(pUserSharedData->NtMinorVersion), 0));
			vKsdHashes.emplace_back(XXH64(&pUserSharedData->NtSystemRoot, sizeof(pUserSharedData->NtSystemRoot), 0));
			vKsdHashes.emplace_back(XXH64(&pUserSharedData->NumberOfPhysicalPages, sizeof(pUserSharedData->NumberOfPhysicalPages), 0));
			vKsdHashes.emplace_back(XXH64(&pUserSharedData->ProcessorFeatures, sizeof(pUserSharedData->ProcessorFeatures), 0));
			vKsdHashes.emplace_back(XXH64(&pUserSharedData->CryptoExponent, sizeof(pUserSharedData->CryptoExponent), 0));
		}
		
		std::wstring wstKsdHash;
		for (const auto& hash : vKsdHashes)
		{
			wstKsdHash.append(std::to_wstring(hash));
		}
		wstKsdHash = std::to_wstring(XXH64(wstKsdHash.data(), wstKsdHash.size(), 0));
		mapDataContainer.emplace(xorstr_(L"kuser_shared_data_hash"), wstKsdHash);

		//
		const auto qwPebHash = XXH64(NtCurrentPeb(), sizeof(*NtCurrentPeb()), 0);
		mapDataContainer.emplace(xorstr_(L"peb_hash"), std::to_wstring(qwPebHash));

		//
		CFileVersion fileVer;
		if (fileVer.QueryFile(fmt::format(xorstr_(L"{0}\\ntoskrnl.exe"), CApplication::Instance().DirFunctionsInstance()->SystemPath())))
		{
			auto wstKernelVersion = fileVer.GetProductVersion();
			if (wstKernelVersion.empty())
				wstKernelVersion = fileVer.GetFixedProductVersion();

			mapDataContainer.emplace(xorstr_(L"ntoskrnl_ver"), wstKernelVersion);
		}
		//

		const auto wstHashList = stdext::dump_json(mapDataContainer);
		m_mapContainer.emplace(xorstr_(L"sys_hash_list"), wstHashList);
		return;
	}

	void CHwidManager::__GenerateSMBiosHwid()
	{
		auto fnSmbiosHwidImpl = [&]() {
			CSmbiosParser smbios;
			if (!smbios.parse())
				return;

			try
			{
				smbios.enum_tables([&](std::uint8_t table_type, detail::entry_handle entry_handle) {
					const auto version = smbios.get_version();

					switch (static_cast<smbios_table_types>(table_type))
					{
					case smbios_table_types::system_information:
					{
						auto sys_info = smbios.get_table_by_handle<system_information_t>(entry_handle);

						stdext::json_data_container_t container;

						if (version >= 2)
						{
							container.emplace(xorstr_(L"manufacturer"), stdext::to_wide(sys_info[sys_info->id_manufacturer].data()));
							container.emplace(xorstr_(L"product"), stdext::to_wide(sys_info[sys_info->id_product_name].data()));
							container.emplace(xorstr_(L"version"), stdext::to_wide(sys_info[sys_info->id_version].data()));
							container.emplace(xorstr_(L"serial"), stdext::to_wide(sys_info[sys_info->id_serial_number].data()));
						}

						if (version >= 2.4)
						{
							container.emplace(xorstr_(L"sku"), stdext::to_wide(sys_info[sys_info->id_sku_number].data()));
							container.emplace(xorstr_(L"family"), stdext::to_wide(sys_info[sys_info->id_family].data()));
						}

						UUID uuid;

						uuid_t guid;
						memcpy(&guid, reinterpret_cast<BYTE*>(&sys_info->uuid) + 0x08, 16);
						if (memcmp(&guid, xorstr_("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"), 16))
						{
							*reinterpret_cast<uint32_t*>(&guid) = g_winAPIs->htonl(*reinterpret_cast<uint32_t*>(&guid));
							*reinterpret_cast<uint16_t*>(reinterpret_cast<BYTE*>(&guid) + 4) = g_winAPIs->htons(*reinterpret_cast<uint16_t*>(reinterpret_cast<BYTE*>(&guid) + 4));
							*reinterpret_cast<uint16_t*>(reinterpret_cast<BYTE*>(&guid) + 6) = g_winAPIs->htons(*reinterpret_cast<uint16_t*>(reinterpret_cast<BYTE*>(&guid) + 6));
							uuid = UUID(guid);
						}

						wchar_t wszGUID[128]{ 0 };
						stdext::guid_to_str(&uuid, wszGUID);
						container.emplace(xorstr_(L"uuid"), wszGUID);

						const auto wstSerialized = stdext::dump_json(container);
						m_mapContainer.emplace(xorstr_(L"smbios_data"), wstSerialized);
						break;
					}
					}
				});
			}
			catch (const std::exception& ex)
			{
				APP_TRACE_LOG(LL_ERR, L"An exception handled in smbios parse: %hs", ex.what());
				return;
			}
		};

		// FIXMe
		/*
		__try
		{
			fnSmbiosHwidImpl();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// APP_TRACE_LOG(LL_ERR, L"An exception handled in smbios parse");
		}
		*/
	}

	bool CHwidManager::__DI_GetMacAddresses()
	{
		auto GetMacAddress = [](const wchar_t* c_wszDevicePath) -> std::wstring {
			stdext::json_data_container_t ctx;

			if (_tcsnicmp(c_wszDevicePath + 4, xorstr_(L"root"), 4) == 0)
				return {};

			if (_tcsnicmp(c_wszDevicePath + 4, xorstr_(L"usb"), 4) == 0)
				return {};

			const auto hDeviceFile = g_winAPIs->CreateFileW(c_wszDevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (!IS_VALID_HANDLE(hDeviceFile))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileW(%s) failed with error: %u", c_wszDevicePath, g_winAPIs->GetLastError());
				return {};
			}

			ctx.emplace(xorstr_(L"device"), c_wszDevicePath);

			BYTE ucData[8]{ 0 };
			DWORD dwByteRet = 0;

			ULONG dwID = OID_802_3_CURRENT_ADDRESS;
			auto bRet = g_winAPIs->DeviceIoControl(hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL);
			if (!bRet)
			{
				APP_TRACE_LOG(LL_ERR, L"DeviceIoControl(OID_802_3_CURRENT_ADDRESS) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hDeviceFile);
				return {};
			}

			ctx.emplace(xorstr_(L"curr"), stdext::dump_hex(ucData, dwByteRet));

			dwID = OID_802_3_PERMANENT_ADDRESS;
			bRet = g_winAPIs->DeviceIoControl(hDeviceFile, IOCTL_NDIS_QUERY_GLOBAL_STATS, &dwID, sizeof(dwID), ucData, sizeof(ucData), &dwByteRet, NULL);
			if (bRet)
			{
				ctx.emplace(xorstr_(L"src"), stdext::dump_hex(ucData, dwByteRet));
			}

			g_winAPIs->CloseHandle(hDeviceFile);
			return stdext::dump_json(ctx);
		};

		stdext::json_data_container_t container;
		int nTotal = 0;

		const GUID GUID_QUERY = { 0xAD498944, 0x762F, 0x11D0, 0x8D, 0xCB, 0x00, 0xC0, 0x4F, 0xC3, 0x35, 0x8C };
		const auto hDevInfo = g_winAPIs->SetupDiGetClassDevsW(&GUID_QUERY, NULL, NULL, DIGCF_PRESENT | DIGCF_INTERFACEDEVICE);
		if (hDevInfo == INVALID_HANDLE_VALUE)
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiGetClassDevsW failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;
		DeviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		for (DWORD MemberIndex = 0; ; MemberIndex++)
		{
			if (!g_winAPIs->SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_QUERY, MemberIndex, &DeviceInterfaceData))
				break;

			DWORD RequiredSize = 0;
			g_winAPIs->SetupDiGetDeviceInterfaceDetailW(hDevInfo, &DeviceInterfaceData, NULL, 0, &RequiredSize, NULL);

			auto DeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(RequiredSize);
			if (!DeviceInterfaceDetailData)
				break;

			DeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			if (g_winAPIs->SetupDiGetDeviceInterfaceDetailW(hDevInfo, &DeviceInterfaceData, DeviceInterfaceDetailData, RequiredSize, NULL, NULL))
			{
				const auto c_wstMacAddr = GetMacAddress(DeviceInterfaceDetailData->DevicePath);
				if (!c_wstMacAddr.empty())
				{
					container.emplace(std::to_wstring(nTotal), c_wstMacAddr);
					nTotal++;
				}
			}

			free(DeviceInterfaceDetailData);
		}

		g_winAPIs->SetupDiDestroyDeviceInfoList(hDevInfo);

		const auto serialized = stdext::dump_json(container);
		m_mapContainer.emplace(xorstr_(L"di_mac"), serialized);

		return nTotal ? true : false;
	}

	bool CHwidManager::__GetIPAddress()
	{
		WSADATA wsaData{ 0 };
		const auto wVersionRequested = MAKEWORD(1, 1);
		auto nRet = g_winAPIs->WSAStartup(wVersionRequested, &wsaData);
		if (nRet != 0)
		{
			APP_TRACE_LOG(LL_ERR, L"WSAStartup failed with status: %d error: %u", nRet, g_winAPIs->GetLastError());
			return false;
		}

		if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
		{
			APP_TRACE_LOG(LL_ERR, L"Unsupported WSA version!");
			g_winAPIs->WSACleanup();
			return false;
		}

		char szHostName[256]{ 0 };
		nRet = g_winAPIs->gethostname(szHostName, 256);
		if (nRet == SOCKET_ERROR)
		{
			APP_TRACE_LOG(LL_ERR, L"gethostname failed with status: %d error: %u", nRet, g_winAPIs->GetLastError());
			g_winAPIs->WSACleanup();
			return false;
		}

		const auto pHostEnt = g_winAPIs->gethostbyname(szHostName);
		if (!pHostEnt)
		{
			APP_TRACE_LOG(LL_ERR, L"gethostbyname failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->WSACleanup();
			return false;
		}

		if (pHostEnt->h_addrtype != AF_INET)
		{
			// Not 32 bits IP adresses
			APP_TRACE_LOG(LL_ERR, L"Failed because no IPv4 Address !");
			g_winAPIs->WSACleanup();
			return false;
		}
		
		// Computer as an IP Address => get the first one
		struct in_addr pInetAddr;
		pInetAddr.s_addr = *(u_long*)pHostEnt->h_addr_list[0];
		const auto c_szIpAddr = g_winAPIs->inet_ntoa(pInetAddr);
		
		m_mapContainer.emplace(xorstr_(L"ip_addr"), stdext::to_wide(c_szIpAddr));

		g_winAPIs->WSACleanup();
		return true;
	}

	bool CHwidManager::__GetNetworkAdaptersMac()
	{
		ULONG ulLength = 0;
		PMIB_IFTABLE pIfTable = nullptr;
		switch (g_winAPIs->GetIfTable(pIfTable, &ulLength, TRUE))
		{
			case NO_ERROR: // No error => no adapters
				APP_TRACE_LOG(LL_ERR, L"Failed because no network adapters");
				return false;
			case ERROR_NOT_SUPPORTED: // Not supported
				APP_TRACE_LOG(LL_ERR, L"Failed because OS not support GetIfTable API function");
				return false;
			case ERROR_BUFFER_OVERFLOW: // We must allocate memory
			case ERROR_INSUFFICIENT_BUFFER:
				break;
			default:
				APP_TRACE_LOG(LL_ERR, L"Failed because unknown error");
				return false;
		};

		pIfTable = (PMIB_IFTABLE)CMemHelper::Allocate(ulLength + 1);
		if (!pIfTable)
		{
			APP_TRACE_LOG(LL_ERR, L"Memory allocation failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		switch (g_winAPIs->GetIfTable(pIfTable, &ulLength, TRUE))
		{
			case NO_ERROR: // No error
				break;
			case ERROR_NOT_SUPPORTED: // Not supported
				CMemHelper::Free(pIfTable);
				APP_TRACE_LOG(LL_ERR, L"Failed because OS not support GetIfTable API function");
				return false;
			case ERROR_BUFFER_OVERFLOW: // We have allocated needed memory, but not sufficient
			case ERROR_INSUFFICIENT_BUFFER:
				CMemHelper::Free(pIfTable);
				APP_TRACE_LOG(LL_ERR, L"Failed because memory error");
				return false;
			default:
				CMemHelper::Free(pIfTable);
				APP_TRACE_LOG(LL_ERR, L"Failed because unknown error");
				return false;
		}

		stdext::json_data_container_t container;

		// Call GetIfEntry for each interface
		for (auto dwIndex = 0u; dwIndex < pIfTable->dwNumEntries; dwIndex++)
		{
			const auto pIfEntry = &(pIfTable->table[dwIndex]);
			if (pIfEntry->dwType != IF_TYPE_ETHERNET_CSMACD || pIfEntry->dwPhysAddrLen == 0)
				continue;

			// Get MAC Address 
			wchar_t wszBuffer[64]{ L'\0' };
			_snwprintf(wszBuffer, sizeof(wszBuffer),
				xorstr_(L"%02X:%02X:%02X:%02X:%02X:%02X"),
				pIfEntry->bPhysAddr[0], pIfEntry->bPhysAddr[1],
				pIfEntry->bPhysAddr[2], pIfEntry->bPhysAddr[3],
				pIfEntry->bPhysAddr[4], pIfEntry->bPhysAddr[5]
			);
			const auto wstCurrMacAddr = std::wstring(wszBuffer);

			auto bCheckedMac = false;
			for (const auto& [key, val] : container)
			{
				if (wstCurrMacAddr == val)
					bCheckedMac = true;
			}

			if (bCheckedMac)
				continue;

			// APP_TRACE_LOG(LL_SYS, L"Found MAC Address: %s of %ls", szBuffer, pIfEntry->wszName);
			container.emplace(std::to_wstring(dwIndex), wszBuffer);
		}

		CMemHelper::Free(pIfTable);

		const auto wstSerialized = stdext::dump_json(container);
		m_mapContainer.emplace(xorstr_(L"net_adapter_mac"), wstSerialized);

		return container.size() > 0;
	}

	bool CHwidManager::__GetIPTable()
	{
#define IPADDR_BUF_SIZE 128
#define IPTYPE_BUF_SIZE 128
#define PHYSADDR_BUF_SIZE 256

		auto MyGetIpAddrTable = [](PMIB_IPADDRTABLE& pIpAddrTable, bool fOrder) {
			DWORD dwActualSize = 0;
			auto dwStatus = g_winAPIs->GetIpAddrTable(pIpAddrTable, &dwActualSize, fOrder);
			if (dwStatus == NO_ERROR)
				return true;

			if (dwStatus == ERROR_INSUFFICIENT_BUFFER)
			{
				pIpAddrTable = (PMIB_IPADDRTABLE)CMemHelper::Allocate(dwActualSize);
				assert(pIpAddrTable);

				dwStatus = g_winAPIs->GetIpAddrTable(pIpAddrTable, &dwActualSize, fOrder);
				return dwStatus == NO_ERROR;
			}
			
			return false;
		};

		auto MyGetIpNetTable = [](PMIB_IPNETTABLE& pIpNetTable, bool fOrder) {
			DWORD dwActualSize = 0;
			auto dwStatus = g_winAPIs->GetIpNetTable(pIpNetTable, &dwActualSize, fOrder);
			if (dwStatus == NO_ERROR)
				return true;

			if (dwStatus == ERROR_INSUFFICIENT_BUFFER)
			{
				pIpNetTable = (PMIB_IPNETTABLE)CMemHelper::Allocate(dwActualSize);
				assert(pIpNetTable);

				dwStatus = g_winAPIs->GetIpNetTable(pIpNetTable, &dwActualSize, fOrder);
				return dwStatus == NO_ERROR;
			}
			
			return false;
		};

		auto InterfaceIdxToInterfaceIp = [](PMIB_IPADDRTABLE pIpAddrTable, DWORD dwIndex, std::wstring& str) {
			if (!pIpAddrTable)
				return false;

			str[0] = '\0';

			for (DWORD dwIdx = 0; dwIdx < pIpAddrTable->dwNumEntries; dwIdx++)
			{
				if (dwIndex == pIpAddrTable->table[dwIdx].dwIndex)
				{
					struct in_addr inadTmp;
					inadTmp.s_addr = pIpAddrTable->table[dwIdx].dwAddr;

					const auto wstIpAddr = stdext::to_wide(g_winAPIs->inet_ntoa(inadTmp));
					if (!wstIpAddr.empty())
					{
						str = wstIpAddr;
						return true;
					}
					return false;
				}
			}
			return false;
		};

		auto PhysAddrToString = [](BYTE PhysAddr[], DWORD PhysAddrLen, wchar_t str[]) {
			if (!PhysAddr || !PhysAddrLen || !str)
				return false;

			str[0] = L'\0';

			for (DWORD dwIdx = 0; dwIdx < PhysAddrLen; dwIdx++)
			{
				if (dwIdx == PhysAddrLen - 1)
					swprintf_s(str + (dwIdx * 3), IPADDR_BUF_SIZE - (dwIdx * 3), xorstr_(L"%02X"), ((int)PhysAddr[dwIdx]) & 0xff);
				else
					swprintf_s(str + (dwIdx * 3), IPADDR_BUF_SIZE - (dwIdx * 3), xorstr_(L"%02X-"), ((int)PhysAddr[dwIdx]) & 0xff);

			}

			return true;
		};

		auto PrintIpNetTable = [&](PMIB_IPNETTABLE pIpNetTable)
		{
			if (!pIpNetTable)
			{
				APP_TRACE_LOG(LL_ERR, L"Net table is null");
				return;
			}

			PMIB_IPADDRTABLE pIpAddrTable = nullptr;
			if (!MyGetIpAddrTable(pIpAddrTable, true) || !pIpAddrTable)
			{
				APP_TRACE_LOG(LL_ERR, L"MyGetIpAddrTable is failed!");
				if (pIpAddrTable)
					CMemHelper::Free(pIpAddrTable);
				return;
			}

			stdext::json_data_container_t container;

			std::wstring wstIpAddr;
			const auto dwCurrIndex = pIpNetTable->table[0].dwIndex;
			if (InterfaceIdxToInterfaceIp(pIpAddrTable, dwCurrIndex, wstIpAddr))
			{
				container.emplace(fmt::format(xorstr_(L"interface_{}"), dwCurrIndex), wstIpAddr);
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Could not convert Interface number 0x%X to IP address.", pIpNetTable->table[0].dwIndex);
				if (pIpAddrTable)
					CMemHelper::Free(pIpAddrTable);
				return;
			}

			for (auto i = 0u; i < pIpNetTable->dwNumEntries; ++i)
			{
				if (pIpNetTable->table[i].dwIndex != dwCurrIndex)
				{
					const auto dwCurrSubIndex = pIpNetTable->table[i].dwIndex;
					if (InterfaceIdxToInterfaceIp(pIpAddrTable, dwCurrSubIndex, wstIpAddr))
					{
						container.emplace(fmt::format(xorstr_(L"interface_{}"), dwCurrSubIndex), wstIpAddr);
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"Error: Could not convert Interface number 0x%X to IP address.", pIpNetTable->table[0].dwIndex);
						if (pIpAddrTable)
							CMemHelper::Free(pIpAddrTable);
						return;
					}
				}

				wchar_t wszPrintablePhysAddr[PHYSADDR_BUF_SIZE]{ L'\0' };
				PhysAddrToString(pIpNetTable->table[i].bPhysAddr, pIpNetTable->table[i].dwPhysAddrLen, wszPrintablePhysAddr);

				struct in_addr inadTmp{ 0 };;
				inadTmp.s_addr = pIpNetTable->table[i].dwAddr;

				wchar_t wszType[IPTYPE_BUF_SIZE]{ L'\0' };
				switch (pIpNetTable->table[i].dwType)
				{
				case 1:
					wcscpy_s(wszType, IPTYPE_BUF_SIZE, xorstr_(L"other"));
					break;
				case 2:
					wcscpy_s(wszType, IPTYPE_BUF_SIZE, xorstr_(L"invalidated"));
					break;
				case 3:
					wcscpy_s(wszType, IPTYPE_BUF_SIZE, xorstr_(L"dynamic"));
					break;
				case 4:
					wcscpy_s(wszType, IPTYPE_BUF_SIZE, xorstr_(L"static"));
					break;
				default:
					wcscpy_s(wszType, IPTYPE_BUF_SIZE, xorstr_(L"invalidType"));
				}

				container.emplace(fmt::format(xorstr_(L"ip_{}"), i), stdext::to_wide(g_winAPIs->inet_ntoa(inadTmp)));
				container.emplace(fmt::format(xorstr_(L"phys_{}"), i), wszPrintablePhysAddr);
				container.emplace(fmt::format(xorstr_(L"type_{}"), i), wszType);
			}

			if (pIpAddrTable)
				CMemHelper::Free(pIpAddrTable);

			const auto wstSerialized = stdext::dump_json(container);
			m_mapContainer.emplace(xorstr_(L"ip_table"), wstSerialized);
		};

		PMIB_IPNETTABLE pIpArpTab = nullptr;
		if (MyGetIpNetTable(pIpArpTab, true))
		{
			PrintIpNetTable(pIpArpTab);
			return true;
		}

		if (pIpArpTab)
			CMemHelper::Free(pIpArpTab);
		return false;
	}

	bool CHwidManager::__GetSID()
	{
		HANDLE hToken = nullptr;
		if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		DWORD dwBufferSize = 0;
		if (!g_winAPIs->GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwBufferSize) &&
			g_winAPIs->GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			APP_TRACE_LOG(LL_ERR, L"GetTokenInformation(1) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hToken);
			return false;
		}

		std::vector <BYTE> buffer(dwBufferSize);
		const auto pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

		if (!g_winAPIs->GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize))
		{
			APP_TRACE_LOG(LL_ERR, L"GetTokenInformation(2) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hToken);
			return false;
		}

		if (!g_winAPIs->IsValidSid(pTokenUser->User.Sid))
		{
			APP_TRACE_LOG(LL_ERR, L"IsValidSid failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hToken);
			return false;
		}
		g_winAPIs->CloseHandle(hToken);

		LPWSTR wszSID = nullptr;
		if (!g_winAPIs->ConvertSidToStringSidW(pTokenUser->User.Sid, &wszSID))
		{
			APP_TRACE_LOG(LL_ERR, L"ConvertSidToStringSidA failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		m_mapContainer.emplace(xorstr_(L"sid"), wszSID);
		return true;
	}

	bool CHwidManager::__GetGpuID()
	{
		auto fnTryCreateDevice = [](decltype(Direct3DCreate9)* fnCreateDevice) -> IDirect3D9* {
			__try {
				return fnCreateDevice(D3D_SDK_VERSION);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				return nullptr;
			};
		};

		const auto hD3D9 = g_winAPIs->LoadLibraryW(xorstr_(L"d3d9.dll"));
		if (!hD3D9)
		{
			APP_TRACE_LOG(LL_ERR, L"LoadLibraryW(d3d9.dll) failed with error: %u", g_winAPIs->GetLastError());
			return true;
		}
		const auto pDirect3DCreate9 = reinterpret_cast<decltype(Direct3DCreate9)*>(g_winAPIs->GetProcAddress(hD3D9, xorstr_("Direct3DCreate9")));
		if (!pDirect3DCreate9)
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcAddress(Direct3DCreate9) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->FreeLibrary(hD3D9);
			return false;
		}
		
		auto d3d = fnTryCreateDevice(pDirect3DCreate9);
		if (!d3d)
		{
			APP_TRACE_LOG(LL_ERR, L"Direct3DCreate9 failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->FreeLibrary(hD3D9);
			return false;
		}

		const auto adapter_count = d3d->GetAdapterCount();
		if (!adapter_count)
		{
			APP_TRACE_LOG(LL_ERR, L"GetAdapterCount failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->FreeLibrary(hD3D9);
			return false;
		}
		const auto adapters = new (std::nothrow) D3DADAPTER_IDENTIFIER9[sizeof(adapter_count)]{};
		if (!adapters)
		{
			APP_TRACE_LOG(LL_ERR, L"Memory allocation for adapters failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->FreeLibrary(hD3D9);
			return false;
		}

		for (auto i = 0u; i < adapter_count; i++)
			d3d->GetAdapterIdentifier(i, 0, &adapters[i]);

		std::wstringstream wss;
		const auto [Data1, Data2, Data3, Data4] = adapters->DeviceIdentifier;
		wss << Data1 << Data2 << Data3;

		for (int i = 0; i < 7; ++i)
			wss << static_cast<short>(Data4[i]);

		// Cleanup
		delete[] adapters;

		g_winAPIs->FreeLibrary(hD3D9);
		m_mapContainer.emplace(xorstr_(L"gpu_id"), wss.str());
		return true;
	}

	bool CHwidManager::__GetArpMacHashes()
	{
		if (!IsWindowsVistaOrGreater())
			return true;
		
		std::vector <std::wstring> hashes{};
		
		// Pointer to ARP table
		NoMercyCore::WinAPI::MIB_IPNET_TABLE2* arp;

		const auto result = g_winAPIs->GetIpNetTable2(AF_UNSPEC, &arp);
		if (result != NO_ERROR && result != ERROR_NOT_FOUND)
		{
			APP_TRACE_LOG(LL_ERR, L"GetIpNetTable2 failed with error: %u", result);
			return false;
		}

		// Blacklist of the beginning of placeholder mac addresses
		const std::vector blacklist{ 0x0, 0xff, 0x33, 0x01 };

		// Loop over all the entries in the ARP table
		for (std::size_t i = 0; i < arp->NumEntries; ++i)
		{
			const auto row = arp->Table[i];

			// Check the start of the mac address against the blacklist of placeholder addresses
			const auto current_bit = static_cast<int>(row.PhysicalAddress[0]);
			if (std::find(blacklist.begin(), blacklist.end(), current_bit) != blacklist.end())
				continue;

			std::wstringstream wss{};

			for (std::size_t j = 0; j < row.PhysicalAddressLength; j++)
			{
				if (j == row.PhysicalAddressLength - 1)
					wss << std::hex << static_cast<int>(row.PhysicalAddress[j]);
				else
					wss << std::hex << static_cast<int>(row.PhysicalAddress[j]) << '-';
			}

			// APP_TRACE_LOG(LL_SYS, L"Found Arp MAC address: %s", ss.str().c_str());
			hashes.push_back(wss.str());
		}

		// Serialize the hashes into a json
		stdext::json_data_container_t json_data{};
		
		auto idx = 0;
		for (const auto& hash : hashes)
		{
			json_data.emplace(std::to_wstring(idx++), hash);
		}

		// Save the hashes to the container
		const auto wstJsonDump = stdext::dump_json(json_data);
		m_mapContainer.emplace(xorstr_(L"arp_mac_hashes"), wstJsonDump);

		// Cleanup
		g_winAPIs->FreeMibTable(arp);
		return true;
	}

	bool CHwidManager::__GetMonitorList()
	{
		// https://en.wikipedia.org/wiki/Extended_Display_Identification_Data
		auto __ExtractSerialNumber = [](const unsigned char* EDID, std::string& serialNumber) {
			// Extract the serial number bytes (little-endian)
			unsigned int serialNumberBytes = 0;
			for (int i = 12; i <= 15; ++i) {
				serialNumberBytes <<= 8;
				serialNumberBytes |= EDID[i];
			}

			// Convert the serial number to a string
			serialNumber = std::to_string(serialNumberBytes);
		};

		stdext::json_data_container_t json_data{};

		const auto wstRootKey = std::wstring(xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY"));
		// Sample path: L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\VSC0D39\7&27256af&0&UID256\Device Parameters\EDID"

		HKEY hKey{};
		LONG result = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, wstRootKey.c_str(), 0, KEY_READ, &hKey);
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegOpenKeyExW (%s) failed with error: %u", wstRootKey.c_str(), result);
			return false;
		}

		DWORD dwMonitorIdx = 0;
		wchar_t wszMonitorID[256]{ L'\0' };
		DWORD dwMonitorIDSize = sizeof(wszMonitorID);
		while (g_winAPIs->RegEnumKeyExW(hKey, dwMonitorIdx, wszMonitorID, &dwMonitorIDSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			HKEY hMonitorKey{};
			result = g_winAPIs->RegOpenKeyExW(hKey, wszMonitorID, 0, KEY_READ, &hMonitorKey);
			if (result == ERROR_SUCCESS)
			{
				DWORD dwDisplayIdx = 0;
				wchar_t wszDisplayID[256]{ L'\0' };
				DWORD dwDisplayIDSize = sizeof(wszDisplayID);
				
				while (g_winAPIs->RegEnumKeyExW(hMonitorKey, dwDisplayIdx, wszDisplayID, &dwDisplayIDSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
				{
					HKEY hDisplayKey{};
					result = g_winAPIs->RegOpenKeyExW(hMonitorKey, wszDisplayID, 0, KEY_READ, &hDisplayKey);
					if (result == ERROR_SUCCESS)
					{
						auto wstFinalKey = fmt::format(xorstr_(L"{0}\\{1}\\{2}\\Device Parameters"), wstRootKey.c_str(), wszMonitorID, wszDisplayID);

						HKEY hEDIDRegKey{};
						result = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, wstFinalKey.c_str(), 0, KEY_READ, &hEDIDRegKey);
						if (result == ERROR_SUCCESS)
						{
							BYTE EDID[1024]{ 0x0 };
							DWORD edidsize = sizeof(EDID);

							result = g_winAPIs->RegQueryValueExW(hEDIDRegKey, xorstr_(L"EDID"), nullptr, nullptr, EDID, &edidsize);
							if (result == ERROR_SUCCESS)
							{
								std::string stSerialNumber;
								__ExtractSerialNumber(EDID, stSerialNumber);
								
								if (!stSerialNumber.empty())
								{
									json_data.emplace(fmt::format(xorstr_(L"{0}_{1}"), wszMonitorID, wszDisplayID), stdext::to_wide(stSerialNumber));
								}
							}
							g_winAPIs->RegCloseKey(hEDIDRegKey);
						}

						g_winAPIs->RegCloseKey(hDisplayKey);
					}

					dwDisplayIdx++;
				}

				g_winAPIs->RegCloseKey(hMonitorKey);
			}

			dwMonitorIdx++;
		}

		g_winAPIs->RegCloseKey(hKey);

		// Save the hashes to the container
		const auto wstJsonDump = stdext::dump_json(json_data);
		m_mapContainer.emplace(xorstr_(L"monitor_data"), wstJsonDump);

		return true;
	}

	std::shared_ptr <SExtHwidCtx> CHwidManager::GetExtHwidCtx()
	{
		auto ctx = std::make_shared <SExtHwidCtx>();
		ctx->wstGPUID = m_mapContainer[xorstr_(L"gpu_id")];
		ctx->wstSID = m_mapContainer[xorstr_(L"sid")];
		ctx->wstPhysicalMacAddress = m_mapContainer[xorstr_(L"mac2")];
		ctx->wstMonitorIDs = m_mapContainer[xorstr_(L"monitor_data")];
		return ctx;
	}
};
