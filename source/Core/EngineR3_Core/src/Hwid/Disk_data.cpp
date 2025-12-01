#include "../../include/PCH.hpp"
#include "../../include/Disk_data.hpp"

namespace NoMercyCore
{
	CDiskData::CDiskData()
	{
		if (!ReadPhysicalDriveInNTWithAdminRights())
			ReadPhysicalDriveInNTUsingSmart();
	}
	CDiskData::~CDiskData()
	{
	}

	bool CDiskData::ReadPhysicalDriveInNTWithAdminRights()
	{
		bool bRet = false;

		constexpr auto MAX_IDE_DRIVES = 16;
		for (int drive = 0; drive < MAX_IDE_DRIVES; drive++)
		{
			wchar_t wszDriveName[256]{ L'\0' };
			_snwprintf(wszDriveName, 256, xorstr_(L"\\\\.\\PhysicalDrive%d"), drive);

			auto hPhysicalDriveIOCTL = g_winAPIs->CreateFileW(wszDriveName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (IS_VALID_HANDLE(hPhysicalDriveIOCTL))
			{
				GETVERSIONOUTPARAMS VersionParams{ 0 };
				DWORD cbBytesReturned = 0;

				// Get the version, etc of PhysicalDrive IOCTL
				if (!g_winAPIs->DeviceIoControl(hPhysicalDriveIOCTL, DFP_GET_VERSION, NULL, 0, &VersionParams, sizeof(VersionParams), &cbBytesReturned, NULL))
				{
					APP_TRACE_LOG(LL_ERR, L"DeviceIoControl (1) failed with error: %u", g_winAPIs->GetLastError());
					g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
					continue;
				}

				// If there is a IDE device at number "i" issue commands
				// to the device
				if (VersionParams.bIDEDeviceMap > 0)
				{
					// Now, get the ID sector for all IDE devices in the system.
					// If the device is ATAPI use the IDE_ATAPI_IDENTIFY command,
					// otherwise use the IDE_ATA_IDENTIFY command
					const auto bIDCmd = (VersionParams.bIDEDeviceMap >> drive & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;

					SENDCMDINPARAMS scip{ 0 };
					BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1]{ 0 };

					if (DoIDENTIFY(hPhysicalDriveIOCTL, &scip, (PSENDCMDOUTPARAMS)&IdOutCmd, (BYTE)bIDCmd, (BYTE)drive, &cbBytesReturned))
					{
						USHORT* pIdSector = (USHORT*)((PSENDCMDOUTPARAMS)IdOutCmd)->bBuffer;

						DWORD diskdata[256];
						for (auto ijk = 0; ijk < 256; ijk++)
							diskdata[ijk] = pIdSector[ijk];

						SetDiskData(diskdata);

						bRet = true;

						g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
						break;
					}
				}

				g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
			}
		}

		return bRet;
	}

	bool CDiskData::ReadPhysicalDriveInNTUsingSmart()
	{
		bool bRet = false;

		auto hPhysicalDriveIOCTL = g_winAPIs->CreateFileW(xorstr_(L"\\\\.\\PhysicalDrive0"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (!IS_VALID_HANDLE(hPhysicalDriveIOCTL))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileA failed with error: %u", g_winAPIs->GetLastError());
			return bRet;
		}

		DWORD cbBytesReturned = 0;
		GETVERSIONINPARAMS GetVersionParams = { 0 };
		if (!g_winAPIs->DeviceIoControl(hPhysicalDriveIOCTL, SMART_GET_VERSION, NULL, 0, &GetVersionParams, sizeof(GETVERSIONINPARAMS), &cbBytesReturned, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"DeviceIoControl (1) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
			return bRet;
		}

		ULONG CommandSize = sizeof(SENDCMDINPARAMS) + IDENTIFY_BUFFER_SIZE;
		PSENDCMDINPARAMS Command = (PSENDCMDINPARAMS)malloc(CommandSize);
		if (!Command)
		{
			APP_TRACE_LOG(LL_ERR, L"malloc failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
			return bRet;
		}
		Command->irDriveRegs.bCommandReg = ID_CMD;
		
		DWORD BytesReturned = 0;
		if (!g_winAPIs->DeviceIoControl(hPhysicalDriveIOCTL, SMART_RCV_DRIVE_DATA, Command, sizeof(SENDCMDINPARAMS), Command, CommandSize, &BytesReturned, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"DeviceIoControl (2) failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
			free(Command);
			return bRet;
		}

		DWORD diskdata[256]{ 0 };
		USHORT* pIdSector = (USHORT*)(PIDENTIFY_DATA)((PSENDCMDOUTPARAMS)Command)->bBuffer;

		for (int ijk = 0; ijk < 256; ijk++)
			diskdata[ijk] = pIdSector[ijk];

		SetDiskData(diskdata);
		bRet = true;

		// Done
		g_winAPIs->CloseHandle(hPhysicalDriveIOCTL);
		free(Command);
		return bRet;
	}

	std::wstring CDiskData::ReadPhysicalDriveStorageDeviceData()
	{
		auto hDrive = g_winAPIs->CreateFileW(xorstr_(L"\\\\.\\PhysicalDrive0"), 0, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!IS_VALID_HANDLE(hDrive))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		STORAGE_PROPERTY_QUERY inData;
		memset(&inData, 0, sizeof inData);
		inData.PropertyId = StorageDeviceProperty;
		inData.QueryType = PropertyStandardQuery;

		std::vector <BYTE> Buf(4096);
		DWORD bytesReturned = 0;
		const auto bResult = g_winAPIs->DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &inData, sizeof(inData), Buf.data(), Buf.size(), &bytesReturned, nullptr);
		if (!bResult)
		{
			APP_TRACE_LOG(LL_ERR, L"DeviceIoControl failed with error: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hDrive);
			return {};
		}

		const auto pHeader = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(Buf.data());

		stdext::json_data_container_t mapDataContainer;

		if (pHeader->VendorIdOffset != 0)
		{
			const auto data = stdext::to_wide(reinterpret_cast<LPCSTR>(Buf.data() + pHeader->VendorIdOffset));
			mapDataContainer.emplace(xorstr_(L"vendor_id"), data);
		}

		if (pHeader->ProductIdOffset != 0)
		{
			const auto data = stdext::to_wide(reinterpret_cast<LPCSTR>(Buf.data() + pHeader->ProductIdOffset));
			mapDataContainer.emplace(xorstr_(L"product_id"), data);
		}

		if (pHeader->ProductRevisionOffset != 0)
		{
			const auto data = stdext::to_wide(reinterpret_cast<LPCSTR>(Buf.data() + pHeader->ProductRevisionOffset));
			mapDataContainer.emplace(xorstr_(L"product_revision"), data);
		}

		if (pHeader->SerialNumberOffset != 0)
		{
			const auto data = stdext::to_wide(reinterpret_cast<LPCSTR>(Buf.data() + pHeader->SerialNumberOffset));
			mapDataContainer.emplace(xorstr_(L"serial_number"), data);
		}

		g_winAPIs->CloseHandle(hDrive);
		return stdext::dump_json(mapDataContainer);
	}

	// DoIDENTIFY FUNCTION: Send an IDENTIFY command to the drive bDriveNum = 0-3 bIDCmd = IDE_ATA_IDENTIFY or IDE_ATAPI_IDENTIFY
	bool CDiskData::DoIDENTIFY(HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP, PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd, BYTE bDriveNum, PDWORD lpcbBytesReturned)
	{
		pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE; // Set up data structures for IDENTIFY command.
		pSCIP->irDriveRegs.bFeaturesReg = 0;
		pSCIP->irDriveRegs.bSectorCountReg = 1;
		pSCIP->irDriveRegs.bCylLowReg = 0;
		pSCIP->irDriveRegs.bCylHighReg = 0;

		pSCIP->irDriveRegs.bDriveHeadReg = 0xA0 | ((bDriveNum & 1) << 4); 	// Compute the drive number.

		pSCIP->irDriveRegs.bCommandReg = bIDCmd; // The command can either be IDE identify or ATAPI identify.
		pSCIP->bDriveNumber = bDriveNum;
		pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

		return (g_winAPIs->DeviceIoControl(hPhysicalDriveIOCTL, DFP_RECEIVE_DRIVE_DATA, (LPVOID)pSCIP, sizeof(SENDCMDINPARAMS) - 1, (LPVOID)pSCOP, sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1, lpcbBytesReturned, NULL) != 0);
	}

	void CDiskData::SetDiskData(DWORD diskdata[256])
	{
		std::wstring serialNumber;
		std::wstring modelNumber;

		ConvertToString(diskdata, 10, 19, serialNumber); 	//  copy the hard drive serial number to the buffer
		ConvertToString(diskdata, 27, 46, modelNumber); 	//  copy the hard drive model number to the buffer

		SetDiskData(modelNumber, serialNumber);
	}

	void CDiskData::SetDiskData(std::wstring model, std::wstring serial)
	{
		if (m_HDDSerialNumber.empty() && (serial.size() >= 19 && (isalnum(serial[0]) || isalnum(serial[19]))))
		{
			CleanWhitespaces(model);
			CleanWhitespaces(serial);

			m_HDDModelNumber = model;
			m_HDDSerialNumber = serial;
		}
	}

	void CDiskData::ConvertToString(DWORD diskdata[256], int firstIndex, int lastIndex, std::wstring& buf)
	{
		std::wstringstream ss;
		for (int index = firstIndex; index <= lastIndex; index++)
		{
			ss.put((char)(diskdata[index] / 256)); //  get high byte for 1st character
			ss.put((char)(diskdata[index] % 256)); //  get low byte for 2nd character
		}
		buf = ss.str();
		CleanWhitespaces(buf);
	}

	void CDiskData::CleanWhitespaces(std::wstring& buf)
	{
		buf.erase(std::remove(buf.begin(), buf.end(), ' '), buf.end()); // remove whitespaces from everywhere
	}
};
