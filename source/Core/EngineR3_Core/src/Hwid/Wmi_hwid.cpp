#include "../../include/PCH.hpp"
#include "../../include/HW-Info.hpp"
#include "../../include/WMIHelper.hpp"

namespace NoMercyCore
{
	bool CHwidManager::__LaunchWMIQueries()
	{
		APP_TRACE_LOG(LL_SYS, L"Launching WMI queries...");

		// Validate WMI integrity
		if (!CApplication::Instance().WMIHelperInstance()->CheckWMIIntegirty())
		{
			APP_TRACE_LOG(LL_ERR, L"WMI integrity verify failed!");
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"WMI integrity verify success!");

		// Launch queries
		uint32_t idx = 0;

		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT UUID FROM Win32_ComputerSystemProduct"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"csp_id_{0}"), idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_ComputerSystemProduct query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_ComputerSystemProduct query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem"),
			[&](std::map <std::wstring, std::wstring> data) {
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"cs_data_{0}"), key), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_ComputerSystem query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);
		
		APP_TRACE_LOG(LL_SYS, L"Win32_ComputerSystem query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Manufacturer, SerialNumber, SMBIOSAssetTag FROM Win32_SystemEnclosure"),
			[&](std::map <std::wstring, std::wstring> data) {
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"se_data_{0}"), key), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_SystemEnclosure query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_SystemEnclosure query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Caption, Description, MonitorType, MonitorManufacturer, PNPDeviceID FROM Win32_DesktopMonitor"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"dm_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_DesktopMonitor query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_DesktopMonitor query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2\\power"),
			xorstr_(L"SELECT CreationClassName, DeviceID, Name, SystemName FROM Win32_PowerSupply WHERE Status=\"OK\""),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"psu_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_PowerSupply query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_PowerSupply query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Caption, Description, DeviceID, HardwareType, Manufacturer, PnpDeviceID FROM Win32_PointingDevice WHERE Status=\"OK\""),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"inp_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_PointingDevice query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_PointingDevice query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT SerialNumber, Manufacturer, Product FROM Win32_BaseBoard"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"bb_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_BaseBoard query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_BaseBoard query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Caption, Manufacturer, SerialNumber FROM Win32_BIOS"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"bios_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_BIOS query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_BIOS query success!");
		
		/*
		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT SerialNumber, InstallDate, Version, Organization, Debug FROM Win32_OperatingSystem"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"os_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_OperatingSystem query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_OperatingSystem query success!");
		*/

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Caption, PnpDeviceId, VideoProcessor, DeviceID, DriverVersion, InstallDate FROM Win32_VideoController"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"gpu_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_VideoController query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_VideoController query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Caption, DeviceID, FirmwareRevision, Model, PnpDeviceID, SerialNumber FROM Win32_DiskDrive WHERE MediaType LIKE '%Fixed%'"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"disk_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_DiskDrive query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_DiskDrive query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT GUID,MACAddress,NetConnectionID,PNPDeviceID,NetConnectionStatus FROM Win32_NetworkAdapter"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"na_data_{0}_{1}"), key, idx), value);
				}
			},
			[&](HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_NetworkAdapter query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_NetworkAdapter query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT MACAddress FROM Win32_NetworkAdapterConfiguration"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"nac_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_NetworkAdapterConfiguration query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_NetworkAdapterConfiguration query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT SerialNumber,PartNumber FROM Win32_PhysicalMemory"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"pmem_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_PhysicalMemory query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_PhysicalMemory query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT PnpDeviceId FROM Win32_SoundDevice"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"snd_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_SoundDevice query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_SoundDevice query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT PnpDeviceId,Name FROM Win32_IDEController"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"idec_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_IDEController query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_IDEController query success!");

		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT UniqueId, ProcessorId, Name, Caption, SocketDesignation FROM Win32_Processor"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"cpu_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_Processor query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);

		APP_TRACE_LOG(LL_SYS, L"Win32_Processor query success!");

		/*
		idx = 0;
		NoMercyCore::CApplication::Instance().WMIHelperInstance()->ExecuteQuery(
			xorstr_(L"ROOT\\CIMV2"),
			xorstr_(L"SELECT Name,MediaType,Capacity,Manufacturer,SerialNumber FROM Win32_PhysicalMedia"),
			[&](std::map <std::wstring, std::wstring> data) {
				idx++;
				for (const auto& [key, value] : data)
				{
					m_mapWmiContainer.emplace(fmt::format(xorstr_(L"phymed_data_{0}_{1}"), key, idx), value);
				}
			},
			[&] (HRESULT hr) {
				_com_error err(hr);
				APP_TRACE_LOG(LL_ERR, L"Win32_PhysicalMedia query failed with error: %p (%s)", hr, err.ErrorMessage());
			}
		);
		*/

		APP_TRACE_LOG(LL_SYS, L"Win32_PhysicalMedia query success!");

		return true;
	}
}
