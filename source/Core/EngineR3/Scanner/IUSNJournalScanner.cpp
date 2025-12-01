#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

#define JOURNAL_BUFFER_SIZE (65536)
#define PATH_BUFFER_SIZE (65536)

namespace NoMercy
{
	static auto gs_bStoreVolumes = true;
	static std::map <HANDLE, wchar_t> gs_mapVolumes;

	void ProcessFullPath(HANDLE hDriver, USN nNextUsnID, DWORDLONG ldwParentFileReferenceNumber, std::vector <std::wstring>& vPaths)
	{
		auto lpPathBuffer = CMemHelper::Allocate(PATH_BUFFER_SIZE);
		if (!lpPathBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"lpPathBuffer allocation failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		MFT_ENUM_DATA_V0 mft_enum_data{ 0 };
		mft_enum_data.StartFileReferenceNumber = ldwParentFileReferenceNumber;
		mft_enum_data.LowUsn = 0;
		mft_enum_data.HighUsn = nNextUsnID;

		DWORD dwBytes = 0;
		if (!g_winAPIs->DeviceIoControl(hDriver, FSCTL_ENUM_USN_DATA, &mft_enum_data, sizeof(mft_enum_data), lpPathBuffer, PATH_BUFFER_SIZE, &dwBytes, NULL))
		{
			const auto dwErr = g_winAPIs->GetLastError();
			if (dwErr != ERROR_HANDLE_EOF)
			{
				APP_TRACE_LOG(LL_ERR, L"DeviceIoControl(FSCTL_ENUM_USN_DATA/parent) failed with error: %u", dwErr);
			}
			CMemHelper::Free(lpPathBuffer);
			return;
		}

		const auto parent_record_pointer = (USN_RECORD_V2*)((USN*)lpPathBuffer + 1);
		if (parent_record_pointer->FileReferenceNumber != ldwParentFileReferenceNumber)
		{
			CMemHelper::Free(lpPathBuffer);
			return;
		}
		vPaths.emplace_back(parent_record_pointer->FileName);

		ProcessFullPath(hDriver, nNextUsnID, parent_record_pointer->ParentFileReferenceNumber, vPaths);
		CMemHelper::Free(lpPathBuffer);
	}

	std::wstring GetFullPath(HANDLE hDriver, USN nNextUsnID, PUSN_RECORD record)
	{
		std::vector <std::wstring> vPaths;
		vPaths.emplace_back(record->FileName);

		ProcessFullPath(hDriver, nNextUsnID, record->ParentFileReferenceNumber, vPaths);

		auto driver_it = gs_mapVolumes.find(hDriver);
		auto path = fmt::format(xorstr_(L"{0}:"), driver_it->second);

		for (auto e = vPaths.rbegin(); e != vPaths.rend(); ++e)
		{
			path += xorstr_(L"\\");
			path += *e;
		}

		return path;
	}

	inline bool CheckUsnRecord(uint32_t idx, PUSN_RECORD record, const std::wstring& fullPath)
	{
		// TODO: check with quarentine

		/*
		todo
		// If the file has recently been closed, created, deleted, renamed , or overwritten/written to, we want to check that out.
		usn reason filter; USN_REASON_CLOSE | USN_REASON_STREAM_CHANGE | USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_RENAME_NEW_NAME | USN_REASON_RENAME_OLD_NAME | USN_REASON_FILE_DELETE | USN_REASON_FILE_CREATE | USN_REASON_NAMED_DATA_TRUNCATION | USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_OVERWRITE
		*/

		// Copy record->FileName to a std::wstring
		const auto wstFileName = std::wstring(record->FileName, record->FileNameLength / sizeof(WCHAR));

//		/*
		APP_TRACE_LOG(LL_SYS, L"Record: %u", idx);
		APP_TRACE_LOG(LL_SYS, L"USN: %I64x", record->Usn);
		APP_TRACE_LOG(LL_SYS, L"File name: %s", wstFileName.c_str());


		APP_TRACE_LOG(LL_SYS, L"Full path: %s", fullPath.c_str());
		APP_TRACE_LOG(LL_SYS, L"Reason: %x", record->Reason);

		SYSTEMTIME systemTime;
		FileTimeToSystemTime((FILETIME*)&record->TimeStamp, &systemTime);

		APP_TRACE_LOG(LL_SYS, L"Time stamp: %u.%u.%u %u:%u:%u.%u", systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);

		APP_TRACE_LOG(LL_SYS, L"\n");
//		*/

		return true;
	}

	void EnumerateUsnJournal(const std::wstring& wstPath)
	{
		const auto wstTargetDevice = fmt::format(xorstr_(L"\\\\?\\{}:"), wstPath.at(0));
		APP_TRACE_LOG(LL_SYS, L"Target device path: %ls", wstTargetDevice.c_str());

		auto hVolume = g_winAPIs->CreateFileW(wstTargetDevice.c_str(), GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING, NULL);
		if (!IS_VALID_HANDLE(hVolume))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", g_winAPIs->GetLastError());
			return;
		}
		if (gs_bStoreVolumes)
			gs_mapVolumes.emplace(hVolume, wstPath.at(0));

		DWORD dwBytes = 0;
		USN_JOURNAL_DATA_V0 JournalData{ 0 };
		if (!g_winAPIs->DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &JournalData, sizeof(JournalData), &dwBytes, NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"DeviceIoControl(FSCTL_QUERY_USN_JOURNAL) failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		READ_USN_JOURNAL_DATA_V0 ReadData = { 0, 0xFFFFFFFF, FALSE, 0, 0 };
		ReadData.UsnJournalID = JournalData.UsnJournalID;

		APP_TRACE_LOG(LL_SYS, L"Journal ID: %I64x", JournalData.UsnJournalID);
		APP_TRACE_LOG(LL_SYS, L"FirstUsn: %I64x", JournalData.FirstUsn);

		auto wszJournalBuffer = CMemHelper::Allocate(JOURNAL_BUFFER_SIZE);
		while (ReadData.StartUsn < JournalData.NextUsn)
		{
			if (!g_winAPIs->DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL, &ReadData, sizeof(ReadData), wszJournalBuffer, JOURNAL_BUFFER_SIZE, &dwBytes, NULL))
			{
				APP_TRACE_LOG(LL_ERR, L"DeviceIoControl(FSCTL_READ_USN_JOURNAL) failed with error: %u", g_winAPIs->GetLastError());
				CMemHelper::Free(wszJournalBuffer);
				return;
			}

			auto counter = 0ULL;
			auto record = (PUSN_RECORD)(((PUCHAR)wszJournalBuffer) + sizeof(USN));

			DWORD dwRetBytes = dwBytes - sizeof(USN);
			while (dwRetBytes > 0)
			{		
				// TODO: Disable or move to another thread
				if (counter++ > 100)
				{
					CMemHelper::Free(wszJournalBuffer);
					return;
				}			

				auto fullPath = GetFullPath(hVolume, JournalData.NextUsn, record);
				if (CheckUsnRecord(counter, record, fullPath))
				{
					// TODO: throw
				}

				dwRetBytes -= record->RecordLength;

				// Find the next record
				record = (PUSN_RECORD)(((PCHAR)record) + record->RecordLength);
			}
			// Update starting USN for next call
			ReadData.StartUsn = *(USN*)wszJournalBuffer;
		}

		CMemHelper::Free(wszJournalBuffer);
		return;
	}

	std::string GetVolumePath(PCHAR VolumeName)
	{
		std::string stName;
		BOOL Success = FALSE;
		PCHAR Names = NULL;
		DWORD CharCount = MAX_PATH + 1;

		for (;;)
		{
			Names = (PCHAR)new (std::nothrow) BYTE[CharCount * sizeof(CHAR)];
			if (!Names)
				return stName;

			Success = g_winAPIs->GetVolumePathNamesForVolumeNameA(VolumeName, Names, CharCount, &CharCount);
			if (Success)
				break;

			if (g_winAPIs->GetLastError() != ERROR_MORE_DATA)
				break;

			delete[] Names;
			Names = NULL;
		}

		stName = std::string(Names);

		if (Names != NULL)
		{
			delete[] Names;
			Names = NULL;
		}

		return stName;
	}

	bool IScanner::EnumerateSystemVolumes(std::function<void(std::wstring)> cb, bool bFilterNTFS)
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

			APP_TRACE_LOG(LL_SYS, L"Found a device: %s", wszDeviceName);
			APP_TRACE_LOG(LL_SYS, L"Volume name: %s", wszVolumeName);

			const auto stVolumeName = stdext::to_ansi(wszVolumeName);
			const auto wstPath = stdext::to_wide(GetVolumePath(const_cast<char*>(stVolumeName.c_str())));
			if (!wstPath.empty() && wstPath.size() < 5) // Ignore 5 < volumes(unaccesible windows sandbox paths)
			{
				APP_TRACE_LOG(LL_SYS, L"Path: %s", wstPath.c_str());

				if (bFilterNTFS)
				{
					wchar_t wszFS[MAX_PATH]{ L'\0' };
					if (!g_winAPIs->GetVolumeInformationW(wstPath.c_str(), NULL, 0, NULL, NULL, NULL, wszFS, MAX_PATH))
					{
						APP_TRACE_LOG(LL_ERR, L"GetVolumeInformationA failed with error: %u", g_winAPIs->GetLastError());
						continue;
					}
					auto stLowerFS = stdext::to_lower_ansi(wszFS);
					APP_TRACE_LOG(LL_SYS, L"FS: %s", stLowerFS.c_str());

					if (stLowerFS == xorstr_("ntfs"))
					{
						cb(wstPath);
						bRet = true;
					}
				}
				else
				{
					cb(wstPath);
					bRet = true;
				}
			}
		} while (g_winAPIs->FindNextVolumeW(FindHandle, wszVolumeName, ARRAYSIZE(wszVolumeName)));

		g_winAPIs->FindVolumeClose(FindHandle);
		return bRet;
	}

	void IScanner::CheckUsnJournal()
	{
		APP_TRACE_LOG(LL_SYS, L"USN journal scan has been started!");

		EnumerateSystemVolumes([](std::wstring path) {
			EnumerateUsnJournal(path);
		}, true);

		gs_bStoreVolumes = false;

		for (const auto& [hVolume, wszVolume] : gs_mapVolumes)
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hVolume);
		gs_mapVolumes.clear();

		APP_TRACE_LOG(LL_SYS, L"USN journal scan completed!");
	}
};
