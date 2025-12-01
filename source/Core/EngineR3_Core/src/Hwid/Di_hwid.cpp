#include "../../include/PCH.hpp"
#include "../../include/DI_hwid.hpp"
#include "../../include/MemAllocator.hpp"

namespace NoMercyCore
{
	CDIHwidHelper::CDIHwidHelper() :
		m_hDevInfo(nullptr)
	{
	}
	CDIHwidHelper::~CDIHwidHelper()
	{
	}

	bool CDIHwidHelper::Connect(const std::wstring& wstDevice)
	{
		if (wstDevice.empty())
			return false;
		m_stDeviceName = stdext::to_ansi(wstDevice);

		APP_TRACE_LOG(LL_SYS, L"SetupAPI Connect: Trying to connect to SetupAPI on device <%hs>...", m_stDeviceName.c_str());

		// Create a device information set that will be the container for  the device interfaces.
		m_hDevInfo = g_winAPIs->SetupDiCreateDeviceInfoListExA(nullptr, nullptr, m_stDeviceName.c_str(), nullptr);
		if (!IS_VALID_HANDLE(m_hDevInfo))
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiCreateDeviceInfoListExW failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		return true;
	}

	void CDIHwidHelper::Disconnect()
	{
		if (IS_VALID_HANDLE(m_hDevInfo))
		{
			g_winAPIs->SetupDiDestroyDeviceInfoList(m_hDevInfo);
		}
	}

	bool CDIHwidHelper::IsConnected() const
	{
		return IS_VALID_HANDLE(m_hDevInfo);
	}


	bool CDIHwidHelper::ParseEDID(LPBYTE lpByte, Standard_EDID& myEDID)
	{
		EDIDRecord tmpEDID{ 0 };
		memcpy(&tmpEDID, lpByte, sizeof(EDIDRecord));

		// Copy some well non data to EDID data structure
		myEDID.Checksum = tmpEDID.Checksum;

		// Chroma Information
		memcpy(&(myEDID.Chroma_Information_Green_X_Y_Red_X_Y), &(tmpEDID.Chroma_Information_Green_X_Y_Red_X_Y), 10 * sizeof(BYTE));

		// 4 Detailed_Timing_Descriptions
		memcpy(&(myEDID.Detailed_Timing_Description1), &(tmpEDID.Detailed_Timing_Description1), 72);

		// Get manufacturer ID
		const auto manufacturer_id = GetManufacturerID(tmpEDID.Manufacturer_ID);

		// Other values
		myEDID.DPMS_Flags = tmpEDID.DPMS_Flags;
		myEDID.EDID_ID_Code = tmpEDID.EDID_ID_Code;
		myEDID.EDID_Revision = tmpEDID.EDID_Revision;
		myEDID.EDID_Version = tmpEDID.EDID_Version;
		myEDID.Established_Timings_1 = tmpEDID.Established_Timings_1;
		myEDID.Established_Timings_2 = tmpEDID.Established_Timings_2;
		myEDID.Gamma_Factor = tmpEDID.Gamma_Factor;
		myEDID.Manufacture_Year = int(tmpEDID.Manufacture_Year) + 1990;
		strncpy(myEDID.Manufacturer_ID, manufacturer_id.c_str(), 4);
		myEDID.Manufacturer_Reserved_Timing = tmpEDID.Manufacturer_Reserved_Timing;
		myEDID.Maximum_Horizontal_Size = tmpEDID.Maximum_Horizontal_Size;
		myEDID.Maximum_Vertical_Size = tmpEDID.Maximum_Vertical_Size;
		myEDID.Serial_Number = tmpEDID.Serial_Number;
		myEDID.Video_Input_Type = tmpEDID.Video_Input_Type;
		myEDID.Week_Number_Manufacture = tmpEDID.Week_Number_Manufacture;

		return TRUE;
	}

	DetailTiming CDIHwidHelper::GetDetailledTimingDescriptionType(BYTE Detailed_Timing_Descript[])
	{
		if (Detailed_Timing_Descript[0] == 0 && Detailed_Timing_Descript[1] == 0 && Detailed_Timing_Descript[2] == 0)
		{
			switch (Detailed_Timing_Descript[3])
			{
			case 0xFF:
				return Serial_Number;
			case 0xFE:
				return Vendor_Name;
			case 0xFD:
				return Frequency_Range;
			case 0xFC:
				return Model_Name;
			}
		}

		return Detailed_Timing_Description;
	}

	std::string CDIHwidHelper::GetManufacturerID(BYTE ID[2])
	{
		int littleEndianID,
			i = ID[0];
		BYTE FirstLetter, SecondLetter, ThirdLetter;

		littleEndianID = ID[1];
		littleEndianID += i << 8;

		ThirdLetter = littleEndianID & (1 + 2 + 4 + 8 + 16);
		SecondLetter = (littleEndianID & (32 + 64 + 128 + 256 + 512)) / 32;
		FirstLetter = (littleEndianID & (1024 + 2048 + 4096 + 8192 + 16384)) / 1024;

		char szBuffer[32]{ 0 };
		snprintf(szBuffer, sizeof(szBuffer), xorstr_("%c%c%c"), 64 + FirstLetter, 64 + SecondLetter, 64 + ThirdLetter);
		return szBuffer;
	}

	std::string CDIHwidHelper::GetEdidText(BYTE lpByte[18])
	{
		char szResult[15]{ 0 };
		size_t i = 0;

		for (i = 0; i < 18; i++)
		{
			if (lpByte[i] == 0) lpByte[i] = ' ';
			if (lpByte[i] == 10) lpByte[i] = 0;
		}

		memset(szResult, 0, 15);
		strncpy(szResult, (LPCSTR)(lpByte + DESCRIPTOR_DATA_OFFSET), 14);

		// Ignore space characters at beginning
		for (i = 0; i < strlen(szResult) && szResult[i] == ' '; i++);

		char szBuffer[128]{ 0 };
		snprintf(szBuffer, sizeof(szBuffer), xorstr_("%s"), szResult + i);
		return szBuffer;
	}

	std::string CDIHwidHelper::DecodeDPMSFlag(BYTE Flag)
	{

		std::string stBuffer;


		return stBuffer;
	}

	bool CDIHwidHelper::GetDisplayEDID(HDEVINFO hDeviceInfoSet, SP_DEVINFO_DATA* pDevInfoData, Standard_EDID& myEDID)
	{
		const auto hKey = g_winAPIs->SetupDiOpenDevRegKey(hDeviceInfoSet, pDevInfoData, DICS_FLAG_GLOBAL, NULL, DIREG_DEV, KEY_QUERY_VALUE);
		if (!hKey)
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiOpenDevRegKey failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		LPBYTE lpByte = NULL;
		DWORD dwType, dwSize = 0;

		auto lStatus = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"EDID"), NULL, &dwType, lpByte, &dwSize);
		if (lStatus != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegQueryValueExW(1) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->RegCloseKey(hKey);
			return false;
		}

		const auto lpBuffer = (LPBYTE)CMemHelper::Allocate((dwSize + 1) * sizeof(BYTE));
		if (!lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"Buffer allocation failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->RegCloseKey(hKey);
			return false;
		}

		lStatus = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"EDID"), NULL, &dwType, lpByte, &dwSize);
		if (lStatus != ERROR_SUCCESS || !lpByte)
		{
			APP_TRACE_LOG(LL_ERR, L"RegQueryValueExW(2) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->RegCloseKey(hKey);
			CMemHelper::Free(lpBuffer);
			return false;
		} 
		
		lpByte[dwSize] = 0;
		ParseEDID(lpByte, myEDID);

		g_winAPIs->RegCloseKey(hKey);
		CMemHelper::Free(lpBuffer);
		return true;
	}

	bool CDIHwidHelper::AcerHack(std::string& stSerial, Standard_EDID* myRecord)
	{
		char szBuf1[32], szBuf2[32], szBuffer[32];

		if (_strnicmp(myRecord->Manufacturer_ID, xorstr_("ACR"), 3) == 0)
		{
			// This an Acer monitor
			strncpy(szBuf1, stSerial.c_str(), sizeof(szBuf1));
			if (strlen(szBuf1) == 12)
			{
				// Heuristic confirm for
				// AL1916 (0xAD49), AL1923 (0x0783) B223W (0x0018 et 0x0020)
				// P243W  (0xADAF), X233H  (0x00A8)
				sprintf(szBuf2, xorstr_("%08X"), myRecord->Serial_Number);
				strncpy(szBuffer, szBuf1, 9);
				strncpy(szBuffer + 8, szBuf2, 9);
				strncpy(szBuffer + 16, szBuf1 + 8, 5);
				stSerial = szBuffer;
				return TRUE;
			}
		}
		return FALSE;
	}

	std::string CDIHwidHelper::GetDescription(Standard_EDID* myRecord)
	{
		char szBuffer[256]{ 0 };
		snprintf(szBuffer, sizeof(szBuffer), xorstr_("%s.%04X.%08X (%d/%d)"),
			myRecord->Manufacturer_ID, (DWORD)myRecord->EDID_ID_Code, (DWORD)myRecord->Serial_Number,
			myRecord->Week_Number_Manufacture, myRecord->Manufacture_Year
		);

		return szBuffer;
	}

	bool CDIHwidHelper::GetMonitors(std::vector <SMonitorCtx>& vMonitors)
	{
#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Enumerating DISPLAY devices...");
#endif

		auto hDeviceInfoSet = g_winAPIs->SetupDiGetClassDevsExA(NULL, xorstr_("DISPLAY"), NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES, m_hDevInfo, NULL, NULL);
		if (!IS_VALID_HANDLE(hDeviceInfoSet))
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiGetClassDevsExW(1) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		DWORD dwIndex = 0;

		SP_DEVINFO_DATA spDeviceInfo{ 0 };
		spDeviceInfo.cbSize = sizeof(SP_DEVINFO_DATA);
		while (g_winAPIs->SetupDiEnumDeviceInfo(hDeviceInfoSet, dwIndex, &spDeviceInfo))
		{
			Standard_EDID myRecord;
			if (!GetDisplayEDID(hDeviceInfoSet, &spDeviceInfo, myRecord))
			{
				dwIndex++;
				continue;
			}

			SMonitorCtx ctx{ 0 };
			ctx.stManufacturer = myRecord.Manufacturer_ID;

			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description1))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description1);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description1);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description2))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description2);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description2);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description3))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description3);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description3);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description4))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description4);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description4);
				break;
			}

			ctx.stType = DecodeDPMSFlag(myRecord.DPMS_Flags);

			AcerHack(ctx.stSerial, &myRecord);

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Current MONITOR device: [%u] '%s' '%s' '%s' '%s' '%s'",
				dwIndex, ctx.stManufacturer.c_str(), ctx.stType.c_str(), ctx.stDescription.c_str(), ctx.stCaption.c_str(), ctx.stSerial.c_str()
			);
#endif

			vMonitors.push_back(ctx);
			dwIndex++;
		}

		if (g_winAPIs->GetLastError() != ERROR_NO_MORE_ITEMS)
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiEnumDeviceInterfaces(1) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
			return false;
		}

		if (IS_VALID_HANDLE(hDeviceInfoSet))
		{
			g_winAPIs->SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
		}

#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Enumerated DISPLAY devices finished (%u objects)...", dwIndex);
#endif


		dwIndex = 0;
#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Enumerating MONITOR devices...");
#endif

		hDeviceInfoSet = g_winAPIs->SetupDiGetClassDevsExA(NULL, xorstr_("MONITOR"), NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES, m_hDevInfo, m_stDeviceName.c_str(), NULL);
		if (!IS_VALID_HANDLE(hDeviceInfoSet))
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiGetClassDevsExW(2) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		spDeviceInfo.cbSize = sizeof(SP_DEVINFO_DATA);
		while (g_winAPIs->SetupDiEnumDeviceInfo(hDeviceInfoSet, dwIndex, &spDeviceInfo))
		{
			Standard_EDID myRecord;
			if (!GetDisplayEDID(hDeviceInfoSet, &spDeviceInfo, myRecord))
			{
				dwIndex++;
				continue;
			}

			SMonitorCtx ctx{ 0 };
			ctx.stManufacturer = myRecord.Manufacturer_ID;

			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description1))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description1);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description1);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description2))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description2);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description2);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description3))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description3);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description3);
				break;
			}
			switch (GetDetailledTimingDescriptionType(myRecord.Detailed_Timing_Description4))
			{
			case Serial_Number:
				ctx.stDescription = GetDescription(&myRecord);
				ctx.stSerial = GetEdidText(myRecord.Detailed_Timing_Description4);
				break;
			case Model_Name:
				ctx.stCaption = GetEdidText(myRecord.Detailed_Timing_Description4);
				break;
			}

			ctx.stType = DecodeDPMSFlag(myRecord.DPMS_Flags);

			AcerHack(ctx.stSerial, &myRecord);

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Current MONITOR device: [%u] '%s' '%s' '%s' '%s' '%s'",
				dwIndex, ctx.stManufacturer.c_str(), ctx.stType.c_str(), ctx.stDescription.c_str(), ctx.stCaption.c_str(), ctx.stSerial.c_str()
			);
#endif

			vMonitors.push_back(ctx);
			dwIndex++;
		}

		if (g_winAPIs->GetLastError() != ERROR_NO_MORE_ITEMS)
		{
			APP_TRACE_LOG(LL_ERR, L"SetupDiEnumDeviceInterfaces(2) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
			return false;
		}

		if (IS_VALID_HANDLE(hDeviceInfoSet))
		{
			g_winAPIs->SetupDiDestroyDeviceInfoList(hDeviceInfoSet);
		}

#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Enumerated MONITOR devices finished (%u objects)...", dwIndex);
#endif
		return true;
	}
};
