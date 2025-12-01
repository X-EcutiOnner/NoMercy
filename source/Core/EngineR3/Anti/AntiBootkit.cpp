#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiDebug.hpp"
#include "../Helper/MBRHelper.hpp"
#include "../Helper/BcdHelper.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include <cguid.h>

// #define ENABLE_DEBUG_MODE

namespace NoMercy
{	
	std::wstring GetRootDevice()
	{
		wchar_t wszDirectory[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->GetCurrentDirectoryW(MAX_PATH, wszDirectory))
		{
			APP_TRACE_LOG(LL_ERR, L"GetCurrentDirectoryW failed with error code %u", g_winAPIs->GetLastError());
			return {};
		}
		
		wszDirectory[3] = L'\0';
		return wszDirectory;
	}
	
	extern std::string GetVolumePath(PCHAR VolumeName);
	bool EnumerateSystemVolumes(std::function<bool(std::wstring, std::wstring, void*)> cb, void* lpUserData)
	{
		auto bRet = false;

		if (!cb)
			return bRet;

		wchar_t wszVolumeName[MAX_PATH]{ L'\0' };
		auto FindHandle = g_winAPIs->FindFirstVolumeW(wszVolumeName, ARRAYSIZE(wszVolumeName));
		if (!IS_VALID_HANDLE(FindHandle))
		{
			APP_TRACE_LOG(LL_ERR, L"FindFirstVolumeW failed with error: %u", g_winAPIs->GetLastError());
			return bRet;
		}

		do
		{
			auto Index = wcslen(wszVolumeName) - 1;

			if (wszVolumeName[0] != L'\\' || wszVolumeName[1] != L'\\' || wszVolumeName[2] != L'?' ||
				wszVolumeName[3] != L'\\' || wszVolumeName[Index] != L'\\')
			{
				APP_TRACE_LOG(LL_ERR, L"FindFirstVolume/FindNextVolume returned a bad path: %s", wszVolumeName);
				break;
			}

			wszVolumeName[Index] = L'\0';

			wchar_t wszDeviceName[MAX_PATH]{ L'\0' };
			const auto CharCount = g_winAPIs->QueryDosDeviceW(&wszVolumeName[4], wszDeviceName, ARRAYSIZE(wszDeviceName));
			if (CharCount == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"QueryDosDeviceA failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			wszVolumeName[Index] = '\\';

//			APP_TRACE_LOG(LL_SYS, L"Found a device: %s", wszDeviceName);
//			APP_TRACE_LOG(LL_SYS, L"Volume name: %s", wszVolumeName);

			const auto stVolumeName = stdext::to_ansi(wszVolumeName);
			const auto wstPath = stdext::to_wide(GetVolumePath(const_cast<char*>(stVolumeName.c_str())));
			
			if (!cb(wszDeviceName, wstPath, lpUserData))
			{
				bRet = true;
				break;
			}
		} while (g_winAPIs->FindNextVolumeW(FindHandle, wszVolumeName, ARRAYSIZE(wszVolumeName)));

		g_winAPIs->FindVolumeClose(FindHandle);
		return bRet;
	}
	
	bool ScanBCDEntries(LPDWORD pdwDetectType)
	{
		const auto spBCDHelper = stdext::make_shared_nothrow<CBCDHelper>();
		if (!IS_VALID_SMART_PTR(spBCDHelper))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to create BCDHelper");
			return false;
		}

		static auto ProcessBCDEntry = [&](HANDLE hObject, ULONG ulElementType) {
			if (ulElementType == BcdLibraryString_ApplicationPath)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted)
				{
					APP_TRACE_LOG(LL_SYS, L"[BcdLibraryString_ApplicationPath] BCD Entry: %s", wstElementData.c_str());

#ifndef ENABLE_DEBUG_MODE
					const auto wstLowerAppPath = stdext::to_lower_wide(wstElementData);
					if (wstLowerAppPath.find(xorstr_(L"\\windows\\system32\\winload.efi")) == std::wstring::npos &&
						wstLowerAppPath.find(xorstr_(L"\\windows\\system32\\winload.exe")) == std::wstring::npos)
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry: %s", wstElementData.c_str());
						if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_UNKNOWN_APP_PATH;
						return false;
					}
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryString_LoadOptionsString)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted)
				{
					APP_TRACE_LOG(LL_SYS, L"[BcdLibraryString_LoadOptionsString] BCD Entry: %s", wstElementData.c_str());

#ifndef ENABLE_DEBUG_MODE
					const auto wstLowerAppPath = stdext::to_lower_wide(wstElementData);
					if (wstLowerAppPath.find(xorstr_(L"nointegritychecks")) != std::wstring::npos)
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry: %s", wstElementData.c_str());
						if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_UNKNOWN_LOAD_OPTS;
						return false;
					}
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryString_AdditionalCiPolicy)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted)
				{
					APP_TRACE_LOG(LL_SYS, L"[BcdLibraryString_AdditionalCiPolicy] BCD Entry: %s", wstElementData.c_str());

#ifndef ENABLE_DEBUG_MODE
					if (!wstElementData.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry: %s", wstElementData.c_str());
						if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_UNKNOWN_CI_POLICY;
						return false;
					}
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryString_Description)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted)
				{
					APP_TRACE_LOG(LL_SYS, L"[BcdLibraryString_Description] BCD Entry: %s", wstElementData.c_str());
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryDevice_ApplicationDevice ||
					 ulElementType == BcdLibraryDevice_WindowsSystemDevice ||
					 ulElementType == BcdOSLoaderDevice_OSDevice)
			{
				auto fnValidateDeviceName = [](const auto c_wszInDevice, std::wstring& wstRefDeviceName) {
					if (!c_wszInDevice || !*c_wszInDevice)
						return false;
					wstRefDeviceName = c_wszInDevice;
					
					if (wstRefDeviceName.find(xorstr_(L"\\")) == std::wstring::npos)
					{
						wstRefDeviceName.clear();
						return false;
					}

					auto wstDeviceName = wstRefDeviceName.substr(wstRefDeviceName.find_last_of(xorstr_(L"\\")) + 1);
					if (wstDeviceName.empty())
					{
						wstRefDeviceName.clear();
						return false;
					}

					// TODO: check partition is enabled https://stackoverflow.com/questions/27097632/how-to-tell-if-windows-partition-is-active-by-a-path-on-it

					wstRefDeviceName = wstDeviceName;
					return true;
				};
				
				std::shared_ptr <BCD_ELEMENT_DEVICE> spElementDevice;
				const auto bCompleted = spBCDHelper->GetElementDevice(hObject, ulElementType, spElementDevice);
				if (bCompleted && IS_VALID_SMART_PTR(spElementDevice))
				{
					APP_TRACE_LOG(LL_SYS, L"[BcdLibraryDevice_ApplicationDevice] BCD Entry: %s", spElementDevice->File.Path ? spElementDevice->File.Path : L"");

#ifndef ENABLE_DEBUG_MODE
					if (spElementDevice->DeviceType != BCD_ELEMENT_DEVICE_TYPE_PARTITION)
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid device type: %d", spElementDevice->DeviceType);
						return true; // ignore 4 now
					}

					std::wstring wstFileName;
					if (!fnValidateDeviceName(spElementDevice->File.Path, wstFileName))
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry(File): %s", spElementDevice->File.Path ? spElementDevice->File.Path : L"");
						return true; // ignore 4 now
					}
					std::wstring wstPartitionName;
					if (!fnValidateDeviceName(spElementDevice->Partition.Path, wstPartitionName))
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry(Partition): %s", spElementDevice->Partition.Path ? spElementDevice->Partition.Path : L"");
						return true; // ignore 4 now
					}
					std::wstring wstLocateName;
					if (!fnValidateDeviceName(spElementDevice->Locate.Path, wstLocateName))
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid BCD Entry(Locate): %s", spElementDevice->Locate.Path ? spElementDevice->Locate.Path : L"");
						return true; // ignore 4 now
					}

					APP_TRACE_LOG(LL_SYS, L"BCD Entry; File: %s, Partition: %s, Locate: %s", wstFileName.c_str(), wstPartitionName.c_str(), wstLocateName.c_str());

					if (wstFileName != wstPartitionName || wstFileName != wstLocateName)
					{
						APP_TRACE_LOG(LL_ERR, L"Device values are not equal!");
						return true; // ignore 4 now
					}

					std::wstring wstTargetVolumePath;
					const auto bEnumRet = EnumerateSystemVolumes([&](std::wstring wstDeviceName, std::wstring wstPath, void* lpUserData) {
						if (!wstTargetVolumePath.empty())
							return false;

						std::wstring wstLookingPath = reinterpret_cast<wchar_t*>(lpUserData);
						APP_TRACE_LOG(LL_SYS, L"Device name: %s, Volume path: %s, Looking path: %s", wstDeviceName.c_str(), wstPath.c_str(), wstLookingPath.c_str());

						if (wstDeviceName.find(wstLookingPath) != std::wstring::npos)
						{
							wstTargetVolumePath = wstPath;
							return false;
						}
						return true;
						}, wstFileName.data());
					if (!bEnumRet)
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to enumerate system volumes");
						return true; // ignore 4 now
					}
					else if (wstTargetVolumePath.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to find target volume path");
						return true; // ignore 4 now
					}

					const auto wstRootDevice = GetRootDevice();
					if (wstRootDevice.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to get root device, last error: %u", g_winAPIs->GetLastError());
						return true; // ignore 4 now
					}
					APP_TRACE_LOG(LL_SYS, L"Target volume path: %s, Root device: %s", wstTargetVolumePath.c_str(), wstRootDevice.c_str());

					if (wstRootDevice != wstTargetVolumePath)
					{
						APP_TRACE_LOG(LL_ERR, L"Root device is not equal to target volume path");
						if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_UNKNOWN_APP_DEV_PATH;
						return false;
					}

					// APP_TRACE_LOG(LL_SYS, L"Application device partition style: %p", spElementDevice->QualifiedPartition.PartitionStyle);

					if (!spElementDevice->QualifiedPartition.Mbr.DiskSignature &&
						!spElementDevice->QualifiedPartition.Gpt.DiskSignature.Data1)
					{
						APP_TRACE_LOG(LL_ERR, L"Invalid disk signature");
						if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_UNKNOWN_APP_DEV;
						return false;
					}
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryBoolean_DebuggerEnabled)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Debugger enabled: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_DEBUGGER_ENABLED;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryBoolean_DisableIntegrityChecks)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Disable integrity checks: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_DISABLED_INTEGRITY_CHECKS;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryBoolean_AllowFlightSignatures)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Allow flight signatures: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_ALLOWED_FLIGHT_SIGNATURES;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdLibraryBoolean_AllowPrereleaseSignatures)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Allow prerelease signatures: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_LIB_ALLOWED_PRERELEASE_SIGNATURES;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			
			
			else if (ulElementType == BcdOSLoaderInteger_NxPolicy)
			{
				ULONG64 ul64ElementData = 0;
				const auto bCompleted = spBCDHelper->GetElementInteger(hObject, ulElementType, ul64ElementData);
				if (bCompleted && ul64ElementData == NxPolicyAlwaysOff)
				{
					APP_TRACE_LOG(LL_SYS, L"Nx policy always off!");
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_NX_ALWAYS_OFF;
					return false;
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderBoolean_KernelDebuggerEnabled)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Kernel debugger enabled: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_KERNEL_DEBUGGER_ENABLED;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderBoolean_DisableCodeIntegrityChecks)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Disable code integrity checks: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_DISABLED_CODE_INTEGRITY_CHECKS;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderBoolean_AllowPrereleaseSignatures)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Allow prerelease signatures: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_ALLOWED_PRERELEASE_SIGNATURES;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderBoolean_HypervisorDebuggerEnabled)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Hypervisor debugger enabled: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_HYPERVISOR_DEBUGGER_ENABLED;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderBoolean_WinPEMode)
			{
				bool bElementData = false;
				const auto bCompleted = spBCDHelper->GetElementBoolean(hObject, ulElementType, bElementData);
				if (bCompleted && bElementData)
				{
					APP_TRACE_LOG(LL_SYS, L"Win PE mode enabled: %d", bElementData);
#ifndef ENABLE_DEBUG_MODE
					if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_WINPE_MODE;
					return false;
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderString_SystemRoot)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted && !wstElementData.empty())
				{
					APP_TRACE_LOG(LL_SYS, L"System root: '%s'", wstElementData.c_str());

#ifndef ENABLE_DEBUG_MODE
					const auto wstLowerSystemRoot = stdext::to_lower_wide(wstElementData);
					if (wstLowerSystemRoot.size() < 8 || wstLowerSystemRoot.substr(0, 8) != xorstr_(L"\\windows"))
					{
						APP_TRACE_LOG(LL_SYS, L"System root is not windows: %s", wstElementData.c_str());
						if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_SYSTEM_ROOT_NOT_WINDOWS;
						return false;
					}
#endif
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get BCD Entry for: %p", ulElementType);
				}
			}
			else if (ulElementType == BcdOSLoaderString_KernelPath)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted && !wstElementData.empty())
				{
					APP_TRACE_LOG(LL_CRI, L"***Custom kernel path detected: %s", wstElementData.c_str());
				}
			}
			else if (ulElementType == BcdOSLoaderString_HalPath)
			{
				std::wstring wstElementData;
				const auto bCompleted = spBCDHelper->GetElementString(hObject, ulElementType, wstElementData);
				if (bCompleted && !wstElementData.empty())
				{
					APP_TRACE_LOG(LL_CRI, L"***Custom HAL path detected: %s", wstElementData.c_str());
				}
			}

			return true;
		};
		
		if (!spBCDHelper->Initialize())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to initialize BCDHelper");
			return false;
		}
		// spBCDHelper->SetVerbose();
		
#if 0
		std::vector <std::shared_ptr <SBCDObjectEntry>> vecObjects;

		auto vecObjects1 = spBCDHelper->QueryBootApplicationList(true);
		auto vecObjects2 = spBCDHelper->QueryBootApplicationList(false);
		auto vecObjects3 = spBCDHelper->QueryFirmwareBootApplicationList();

		vecObjects.insert(vecObjects.end(), vecObjects1.begin(), vecObjects1.end());
		vecObjects.insert(vecObjects.end(), vecObjects2.begin(), vecObjects2.end());
		vecObjects.insert(vecObjects.end(), vecObjects3.begin(), vecObjects3.end());
		
		for (const auto& spObjectCtx : vecObjects)
		{
			APP_TRACE_LOG(LL_SYS, L"BCD Object: %s", spObjectCtx->wstObjectName.c_str());

			HANDLE hObject = nullptr;
			if (!spBCDHelper->OpenObject(&spObjectCtx->guidObject, &hObject))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to open BCD object: %s", spObjectCtx->wstObjectName.c_str());
				continue;
			}
			
			std::vector <BCD_ELEMENT> vecElements;
			if (spBCDHelper->EnumerateElements(hObject, vecElements))
			{
				for (const auto& pkValue : vecElements)
				{
					/*
					APP_TRACE_LOG(LL_SYS, L"Value :: Ver: %u Data: %p (%u), Type: %p",
						pkValue.Description->Version, pkValue.Data, pkValue.Description->DataSize, pkValue.Description->Type
					);
					*/

					ProcessBCDEntry(hObject, pkValue.Description->Type);
				}
			}

			spBCDHelper->CloseObject(hObject);
		}

#else
		// Windows Boot Manager
		const auto lstCheckedGUIDs = {
//			GUID_DEFAULT_BOOT_ENTRY,
//			GUID_CURRENT_BOOT_ENTRY,
//			GUID_WINDOWS_SETUP_BOOT_ENTRY,
			GUID_WINDOWS_BOOTMGR,
//			GUID_WINDOWS_LEGACY_NTLDR,
//			GUID_FIRMWARE_BOOTMGR
		};
		
		uint8_t idx = 0;
		for (auto guidID : lstCheckedGUIDs)
		{
			idx++;
			
			std::vector <std::shared_ptr <SBCDObjectValueEntry>> vecObjects;
			if (!spBCDHelper->EnumerateValueObjects(&guidID, BcdBootMgrObjectList_DisplayOrder, vecObjects))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to enumerate value objects for index: %u", idx);
				continue;
			}
			
			for (const auto& spObject : vecObjects)
			{
				wchar_t wszGUID[128]{ L'\0' };
				stdext::guid_to_str(&spObject->guidObject, wszGUID);

				// APP_TRACE_LOG(LL_SYS, L"Object: %p >> %s", hObject, szGUID);

				std::vector <BCD_ELEMENT> vecElements;
				if (spBCDHelper->EnumerateElements(spObject->hValueObject, vecElements))
				{
					for (const auto& pkValue : vecElements)
					{
						/*
						APP_TRACE_LOG(LL_SYS, L"Value :: Ver: %u Data: %p (%u), Type: %p",
							pkValue.Description->Version, pkValue.Data, pkValue.Description->DataSize, ulElementType
						);
						*/

						ProcessBCDEntry(spObject->hValueObject, pkValue.Description->Type);
					}
				}

				spBCDHelper->CloseObject(spObject->hValueObject);
			}
		}
#endif
		
		// Firmware Boot Apps
		auto vecObjects = spBCDHelper->QueryFirmwareBootApplicationList();
		for (const auto& spObjectCtx : vecObjects)
		{
			APP_TRACE_LOG(LL_SYS, L"BCD Object: %s", spObjectCtx->wstObjectName.c_str());

			HANDLE hObject = nullptr;
			if (!spBCDHelper->OpenObject(&spObjectCtx->guidObject, &hObject))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to open BCD object: %s", spObjectCtx->wstObjectName.c_str());
				continue;
			}

			std::vector <BCD_ELEMENT> vecElements;
			if (spBCDHelper->EnumerateElements(hObject, vecElements))
			{
				for (const auto& pkValue : vecElements)
				{
					/*
					APP_TRACE_LOG(LL_SYS, L"Value :: Ver: %u Data: %p (%u), Type: %p",
						pkValue.Description->Version, pkValue.Data, pkValue.Description->DataSize, pkValue.Description->Type
					);
					*/
					if (pkValue.Description->Type == BcdLibraryString_Description)
					{
						std::wstring wstElementData;
						const auto bCompleted = spBCDHelper->GetElementString(hObject, pkValue.Description->Type, wstElementData);
						if (bCompleted)
						{
							APP_TRACE_LOG(LL_SYS, L"[BcdLibraryString_Description] BCD Entry: %s", wstElementData.c_str());

							if (!wstElementData.empty())
							{
								if (wstElementData.substr(0, 5) == xorstr_(L"UEFI:"))
								{
									APP_TRACE_LOG(LL_ERR, L"UEFI entry found: '%s'", wstElementData.c_str());
#ifdef _RELEASE_DEBUG_MODE_
									if (pdwDetectType) *pdwDetectType = BOOTKIT_OSL_UEFI_BOOT_DEVICE;
									return false;
#endif
								}
							}
						}
					}
				}
			}

			spBCDHelper->CloseObject(hObject);
		}
		
		spBCDHelper->Release();
		return true;
	}
	
	bool IsEfiSupported()
	{
		UNICODE_STRING uVarName = RTL_CONSTANT_STRING(L" ");
		PVOID pvVarValue = NULL;
		ULONG ulVarLength = 0;

		return (g_winAPIs->NtQuerySystemEnvironmentValueEx(&uVarName, (PGUID)&GUID_NULL, pvVarValue, &ulVarLength, NULL) == STATUS_VARIABLE_NOT_FOUND);
	}

	bool ReadEfiBootEntries(LPDWORD pdwDetectType)
	{
		bool bRet = false;
		PBOOT_OPTIONS pBootOptions = nullptr;
		PULONG pulOrder = nullptr;
		PBOOT_ENTRY_LIST pBootEntryList = nullptr;
		
		do {
			// Enable privilege to get access to query NVRAM variables
			BOOLEAN boAdjustPrivRet = FALSE;
			auto ntStatus = g_winAPIs->RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &boAdjustPrivRet);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"RtlAdjustPrivilege failed: %p", ntStatus);
				break;
			}
			
			// Get the boot options
			ULONG ulLength = 0;
			ntStatus = g_winAPIs->NtQueryBootOptions(nullptr, &ulLength);
			if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryBootOptions(1) failed with status 0x%p", ntStatus);
				break;
			}

			pBootOptions = (PBOOT_OPTIONS)CMemHelper::Allocate(ulLength);
			if (!pBootOptions)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for BootOptions, Error: %u", errno);
				break;
			}

			ntStatus = g_winAPIs->NtQueryBootOptions(pBootOptions, &ulLength);
			if (ntStatus != STATUS_SUCCESS)
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryBootOptions(2) failed with status 0x%p", ntStatus);
				break;
			}

			// Get the boot order list
			ULONG ulCount = 0;
			ntStatus = g_winAPIs->NtQueryBootEntryOrder(NULL, &ulCount);
			if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			{
				if (ntStatus == STATUS_SUCCESS) // No entries
				{
					ulCount = 0;
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"NtQueryBootEntryOrder(1) failed with status 0x%p", ntStatus);
					break;
				}
			}
			
			if (ulCount)
			{
				pulOrder = (PULONG)CMemHelper::Allocate(ulCount * sizeof(ULONG));
				if (!pulOrder)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for BootEntryOrder, Error: %u", errno);
					break;
				}

				ntStatus = g_winAPIs->NtQueryBootEntryOrder(pulOrder, &ulCount);
				if (ntStatus != STATUS_SUCCESS)
				{
					APP_TRACE_LOG(LL_ERR, L"NtQueryBootEntryOrder(2) failed with status 0x%p", ntStatus);
					break;
				}
			}

			// Get the boot entries
			ulLength = 0;
			ntStatus = g_winAPIs->NtEnumerateBootEntries(NULL, &ulLength);
			if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			{
				if (ntStatus == STATUS_SUCCESS) // No entries in NVRAM
				{
					APP_TRACE_LOG(LL_ERR, L"No entries in NVRAM");
					break;
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"NtEnumerateBootEntries(1) failed with status 0x%p", ntStatus);
					break;
				}
			}

			if (!ulLength)
			{
				APP_TRACE_LOG(LL_ERR, L"Invalid length returned by NtEnumerateBootEntries");
				break;
			}

			pBootEntryList = (PBOOT_ENTRY_LIST)CMemHelper::Allocate(ulLength);
			if (!pBootEntryList)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for BootEntryList, Error: %u", errno);
				break;
			}

			ntStatus = g_winAPIs->NtEnumerateBootEntries(pBootEntryList, &ulLength);
			if (ntStatus != STATUS_SUCCESS)
			{
				APP_TRACE_LOG(LL_ERR, L"NtEnumerateBootEntries(2) failed with status 0x%p", ntStatus);
				break;
			}

			// Duplicate the boot entry list
			auto pDupBootEntryList = pBootEntryList;
			while (true)
			{
				auto pkBootEntry = &pDupBootEntryList->BootEntry;

				auto name = (PWSTR)((PBYTE)pkBootEntry + pkBootEntry->FriendlyNameOffset);
				
				// TODO: Check if the boot entry is a Windows boot entry > BOOTKIT_UNKNOWN_BOOT_ENTRY

				// Check another entry
				if (pDupBootEntryList->NextEntryOffset == 0)
					break;
				
				// Get the next entry
				pDupBootEntryList = (PBOOT_ENTRY_LIST)((PBYTE)pDupBootEntryList + pDupBootEntryList->NextEntryOffset);
			}

			bRet = true;
		} while (FALSE);

		if (pBootOptions)
		{
			CMemHelper::Free(pBootOptions);
			pBootOptions = nullptr;
		}
		if (pulOrder)
		{
			CMemHelper::Free(pulOrder);
			pulOrder = nullptr;
		}
		if (pBootEntryList)
		{
			CMemHelper::Free(pBootEntryList);
			pBootEntryList = nullptr;
		}
		
		return bRet;
	}

	bool IsBootSectorFileIntegrityValidated(LPDWORD pdwDetectType)
	{
		const auto wstRootDev = GetRootDevice();
		if (wstRootDev.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get root device");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
			return false;
		}
		auto wstBootSectorFile = fmt::format(xorstr_(L"{0}\\bootmgr"), wstRootDev);
		if (!g_winAPIs->PathFileExistsW(wstBootSectorFile.c_str()))
		{
			return true; // ignore, wtf?
//			APP_TRACE_LOG(LL_ERR, L"Failed to find boot sector file: %s", wstBootSectorFile.c_str());
//			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
//			return false;
		}

		WIN32_FILE_ATTRIBUTE_DATA wfad{};
		if (!g_winAPIs->GetFileAttributesExW(wstBootSectorFile.c_str(), GetFileExInfoStandard, &wfad))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get file attributes of boot sector file: %s (Error: %u)", wstBootSectorFile.c_str(), g_winAPIs->GetLastError());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
			return false;
		}
		
		const auto dwAttributes = wfad.dwFileAttributes;
		APP_TRACE_LOG(LL_SYS, L"Boot sector file attributes: 0x%p", dwAttributes);

		// Check if the file is not hidden
		if (!(dwAttributes & FILE_ATTRIBUTE_HIDDEN))
		{
			APP_TRACE_LOG(LL_ERR, L"Boot sector file is not hidden");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
			return false;
		}
		
		// Check if the file is system
		if (!(dwAttributes & FILE_ATTRIBUTE_SYSTEM))
		{
			APP_TRACE_LOG(LL_ERR, L"Boot sector file is not system");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
			return false;
		}

		// Check if the file is read-only
		if (!(dwAttributes & FILE_ATTRIBUTE_READONLY))
		{
			APP_TRACE_LOG(LL_ERR, L"Boot sector file is not read-only");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED;
			return false;
		}

		return true;
	}

	bool IsMBRSignatureValidated(LPDWORD pdwDetectType)
	{
		const auto c_wszDiskPath = xorstr_(L"\\\\.\\PhysicalDrive0");
		auto hDisk = g_winAPIs->CreateFileW(c_wszDiskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (!IS_VALID_HANDLE(hDisk))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to open disk: %s (Error: %u)", c_wszDiskPath, g_winAPIs->GetLastError());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_SIGN_INTEGRITY_CORRUPTED;
			return false;
		}
		
		const DWORD dwSectorSize = 512;
		char szBuffer[dwSectorSize]{ '\0' };
		DWORD dwReadByteCount = 0;

		if (!g_winAPIs->ReadFile(hDisk, szBuffer, dwSectorSize, &dwReadByteCount, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read disk: %s (Error: %u)", c_wszDiskPath, g_winAPIs->GetLastError());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_SIGN_INTEGRITY_CORRUPTED;
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		
		const uint8_t byExpectedSignature[2] = { 0x55, 0xAA };
		const auto bySectorData = reinterpret_cast<uint8_t*>(szBuffer);

		if (bySectorData[dwSectorSize - 2] != byExpectedSignature[0] ||
			bySectorData[dwSectorSize - 1] != byExpectedSignature[1])
		{
			APP_TRACE_LOG(LL_ERR, L"MBR signature is not valid! (0x%02X%02X)", bySectorData[dwSectorSize - 2], bySectorData[dwSectorSize - 1]);
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_SIGN_INTEGRITY_CORRUPTED;
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		
		g_winAPIs->CloseHandle(hDisk);
		return true;
	}

	bool IsMBRIntegrityValidated(LPDWORD pdwDetectType)
	{
		const auto c_wszDiskPath = xorstr_(L"\\\\.\\PhysicalDrive0");
		auto hDisk = g_winAPIs->CreateFileW(c_wszDiskPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (!IS_VALID_HANDLE(hDisk))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to open disk: %s (Error: %u)", c_wszDiskPath, g_winAPIs->GetLastError());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_INTEGRITY_CORRUPTED;
			return false;
		}

		const DWORD dwSectorSize = 512;
		char szBuffer[dwSectorSize]{ '\0' };
		DWORD dwReadByteCount = 0;

		if (!g_winAPIs->ReadFile(hDisk, szBuffer, dwSectorSize, &dwReadByteCount, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read disk: %s (Error: %u)", c_wszDiskPath, g_winAPIs->GetLastError());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_INTEGRITY_CORRUPTED;
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}

		std::stringstream buf;
		buf.write(reinterpret_cast<char*>(szBuffer), dwSectorSize);

		MBR mbr;
		try
		{
			mbr.Read(buf);
		}
		catch (const std::exception& e)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to parse MBR: %s", e.what());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_MBR_INTEGRITY_CORRUPTED;
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}

		auto cond1 = mbr.GetPartition(1).IsBootable();
		auto cond2 = !mbr.GetPartition(1).IsEmpty();
		auto cond3 = mbr.GetPartition(1).GetLBAStart() == 2048u;
		auto cond4 = mbr.GetPartition(1).GetLBALen() == 39892992u;

		auto cond5 = mbr.GetPartition(2).IsBootable() == false;
		auto cond6 = mbr.GetPartition(2).IsEmpty() == false;
		auto cond7 = mbr.GetPartition(2).GetLBAStart() == 39895040u;
		auto cond8 = mbr.GetPartition(2).GetLBALen() == 2048000u;

		auto cond9 = mbr.GetPartition(3).IsEmpty() == true;
		auto cond10 = mbr.GetPartition(4).IsEmpty() == true;
		
		g_winAPIs->CloseHandle(hDisk);
		return true;

#if 0
// #ifdef _RELEASE_DEBUG_MODE_
		if (!cond1)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 1 is not bootable");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond2)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 1 is not empty");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond3)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 1 LBA start is not 2048");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond4)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 1 LBA length is not 39892992");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		/*
		else if (!cond5)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 2 is bootable");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond6)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 2 is empty");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond7)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 2 LBA start is not 39895040");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond8)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 2 LBA length is not 2048000");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond9)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 3 is not empty");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		else if (!cond10)
		{
			APP_TRACE_LOG(LL_ERR, L"Partition 4 is not empty");
			g_winAPIs->CloseHandle(hDisk);
			return false;
		}
		*/

		g_winAPIs->CloseHandle(hDisk);
		return true;
#endif
	}

	bool IsNVRAMsIntegrityValidated(LPDWORD pdwDetectType)
	{
		auto fnGetNVRAMValue = [](const std::wstring& wstKey, const std::wstring& wstGUID) -> std::vector <uint8_t> {
			auto vecBuffer = std::vector <uint8_t>{};

			if (wstKey.empty() || wstGUID.empty())
				return vecBuffer;

			GUID kGUID{};
			if (!g_winAPIs->GUIDFromStringW(wstGUID.c_str(), &kGUID))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to convert GUID string to GUID (Error: %u)", g_winAPIs->GetLastError());
				return vecBuffer;
			}

			UNICODE_STRING uVarName;
			g_winAPIs->RtlInitUnicodeString(&uVarName, wstKey.c_str());

			ULONG ulLength = 0;
			ULONG ulAttr = 0;
			auto ntStatus = g_winAPIs->NtQuerySystemEnvironmentValueEx(&uVarName, &kGUID, 0, &ulLength, &ulAttr);
			if (ntStatus != STATUS_BUFFER_TOO_SMALL)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to query(1) NVRAM value (Error: %p)", ntStatus);
				return vecBuffer;
			}

			vecBuffer.resize(ulLength);

			ntStatus = g_winAPIs->NtQuerySystemEnvironmentValueEx(&uVarName, &kGUID, &vecBuffer[0], &ulLength, &ulAttr);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to query(2) NVRAM value (Error: %p)", ntStatus);
				return vecBuffer;
			}
			
			return vecBuffer;
		};

		// TODO https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/overview-of-boot-options-in-efi
		
#ifdef __EXPERIMENTAL__ // Too many people using
		const auto vecBootOrderValue = fnGetNVRAMValue(xorstr_(L"BootOrder"), xorstr_(L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"));
		if (vecBootOrderValue.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get BootOrder NVRAM value");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_NVRAM_INTEGRITY_CORRUPTED;
			return false;
		}
		else if (vecBootOrderValue.size() > 2)
		{
			APP_TRACE_LOG(LL_ERR, L"BootOrder NVRAM value(%u) is invalid, Multiple boot entries are not supported", vecBootOrderValue.size());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_NVRAM_INTEGRITY_CORRUPTED;
			return false;
		}
#endif
		
		/*
		const auto vecSecureBootValue = fnGetNVRAMValue(xorstr_(L"SecureBoot"), xorstr_(L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"));
		if (vecSecureBootValue.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get SecureBoot NVRAM value");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_NVRAM_INTEGRITY_CORRUPTED;
			return false;
		}
		else if (vecSecureBootValue.size() != 1)
		{
			APP_TRACE_LOG(LL_ERR, L"SecureBoot NVRAM value(%u) is invalid", vecSecureBootValue.size());
			if (pdwDetectType) *pdwDetectType = BOOTKIT_NVRAM_INTEGRITY_CORRUPTED;
			return false;
		}
		else if (vecSecureBootValue[0] != 0x01)
		{
			APP_TRACE_LOG(LL_ERR, L"SecureBoot NVRAM value is not enabled");
			if (pdwDetectType) *pdwDetectType = BOOTKIT_NVRAM_INTEGRITY_CORRUPTED;
			return false;
		}
		*/

		// TODO Alternative keys/methods for SecureFakePkg method

		return true;
	}

	bool IsDriversIntegrityValidated(LPDWORD pdwDetectType)
	{
		auto fnValidateDriverByPath = [](std::wstring wstDriverPath, bool bIsOptional) -> bool {
			if (wstDriverPath.empty())
				return false;

			if (wstDriverPath.find(xorstr_(L"%SystemRoot%")) != std::wstring::npos)
			{
				wstDriverPath = wstDriverPath.substr(wstDriverPath.find(xorstr_(L"%SystemRoot%")) + 12);

				const auto wstSystemPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
				wstDriverPath = wstSystemPath + wstDriverPath;
			}

			if (!bIsOptional && !g_winAPIs->PathFileExistsW(wstDriverPath.c_str()))
			{
				APP_TRACE_LOG(LL_ERR, L"Driver file(%s) is not exist, Error: %u", wstDriverPath.c_str(), g_winAPIs->GetLastError());
				return true;
			}

			if (!bIsOptional)
			{
				const auto obHasDriverCert = PeSignatureVerifier::HasValidFileCertificate(wstDriverPath);
				if (!obHasDriverCert.has_value())
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to check driver file(%s) has digital signature", wstDriverPath.c_str());
					return false;
				}
				else if (!obHasDriverCert.value())
				{
					APP_TRACE_LOG(LL_ERR, L"Driver file(%s) has no digital signature", wstDriverPath.c_str());
					return false;
				}

				const auto dwCheckSignRet = PeSignatureVerifier::CheckFileSignature(wstDriverPath, true); // TODO: convertSignInfo(lRetVal)
				if (dwCheckSignRet != ERROR_SUCCESS)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to check driver file(%s) signature (Error: %u)", wstDriverPath.c_str(), dwCheckSignRet);
					return false;
				}

				std::wstring wstProvider;
				CryptoApiWrapper::SignerInfoPtr si;
				const auto dwCertQueryRet = PeSignatureVerifier::GetCertificateInfo(wstDriverPath, si);
				if (dwCertQueryRet != ERROR_SUCCESS)
				{
					APP_TRACE_LOG(LL_ERR, L"Driver signature provider query failed! Error: %d", dwCertQueryRet);
					return false;
				}
				else if (!IS_VALID_SMART_PTR(si))
				{
					APP_TRACE_LOG(LL_ERR, L"Driver signature provider query failed! Error: %u", g_winAPIs->GetLastError());
					return false;
				}
				else
				{
					wstProvider = si->subjectName;
					APP_TRACE_LOG(LL_SYS, L"Driver signature provider query success! Provider: %ls", wstProvider.c_str());
				}

				const std::vector <std::wstring> vecKnownProviders = {
					xorstr_(L"Microsoft Windows"),
					xorstr_(L"Microsoft Windows Hardware Publisher"),
					xorstr_(L"Microsoft Windows Hardware Compatibility Publisher")
				};

				if (wstProvider.empty())
				{
					APP_TRACE_LOG(LL_ERR, L"Driver signature provider is empty");
					return false;
				}

				auto bIsKnownProvider = false;
				for (const auto& wstKnownProvider : vecKnownProviders)
				{
#ifdef _DEBUG
					APP_TRACE_LOG(LL_SYS, L"Checking driver signature provider(%ls[%u]) with known provider(%ls[%u])",
						wstProvider.c_str(), wstProvider.length(), wstKnownProvider.c_str(), wstKnownProvider.length()
					);
#endif
					if (wstProvider == wstKnownProvider)
					{
						bIsKnownProvider = true;
						break;
					}
				}
				if (!bIsKnownProvider)
				{
					APP_TRACE_LOG(LL_ERR, L"Driver signature provider (%s) is not known", wstProvider.c_str());
					return false;
				}
			}
			return true;
		};

		const auto lstTargetDrivers = std::map <std::wstring, bool>{
			{ xorstr_(L"%SystemRoot%\\Boot\\EFI\\bootmgr.efi"), false },
			{ xorstr_(L"%SystemRoot%\\Boot\\EFI\\bootmgfw.efi"), false },
			{ xorstr_(L"%SystemRoot%\\System32\\winload.exe"), false },
			{ xorstr_(L"%SystemRoot%\\System32\\winload.efi"), false },
			{ xorstr_(L"%SystemRoot%\\System32\\ntoskrnl.exe"), false },
			{ xorstr_(L"%SystemRoot%\\System32\\drivers\\beep.sys"), true },
			{ xorstr_(L"%SystemRoot%\\System32\\drivers\\null.sys"), true }
		};

		auto bRet = true;

		// Disables file system redirection for the calling thread.
		PVOID OldValue = nullptr;
		if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			for (const auto& [wstDriverPath, bIsOptional] : lstTargetDrivers)
			{
				if (!fnValidateDriverByPath(wstDriverPath, bIsOptional))
				{
					APP_TRACE_LOG(LL_ERR, L"Driver: %s validation failed!", wstDriverPath.c_str());
					if (pdwDetectType) *pdwDetectType = BOOTKIT_SYS_FILE_INTEGRITY_CORRUPTED;
					bRet = false;
					break;
				}

				g_winAPIs->Sleep(100);
			}

			// Restore file system redirection for the calling thread.
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
		}

		return bRet;
	}

	bool IsWindowsPatched(LPDWORD pdwDetectType)
	{

		return false;
	}
	
	bool CAntiDebug::AntiBootkit(LPDWORD pdwDetectType)
	{
		if (!pdwDetectType)
			return false;

		if (!ScanBCDEntries(pdwDetectType))
			return false;

		if (!IsEfiSupported())
			return true; // ignore other checks

		if (!IsBootSectorFileIntegrityValidated(pdwDetectType))
			return false;
		
		if (IsMBRSignatureValidated(pdwDetectType))
		{
			if (!IsMBRIntegrityValidated(pdwDetectType))
				return false;
		}

		if (!IsNVRAMsIntegrityValidated(pdwDetectType))
			return false;

		if (!IsDriversIntegrityValidated(pdwDetectType))
			return false;

		if (IsWindowsPatched(pdwDetectType))
			return false;
		
		return true;
	}
}
