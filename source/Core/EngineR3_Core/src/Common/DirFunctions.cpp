#include "../../include/PCH.hpp"
#include "../../include/DirFunctions.hpp"
#include "../../include/WinAPIManager.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/Defines.hpp"

namespace NoMercyCore
{
	std::wstring CDirFunctions::ExpandEnvPath(const std::wstring& stPath)
	{
		const auto cch = g_winAPIs->ExpandEnvironmentStringsW(stPath.c_str(), nullptr, 0);
		if (!cch)
			return stPath;

		std::wstring stBuffer;
		stBuffer.reserve(cch);
		stBuffer.resize(cch - 1);
		g_winAPIs->ExpandEnvironmentStringsW(stPath.c_str(), &stBuffer[0], cch);

		return stBuffer;
	}

	bool CDirFunctions::IsFileExist(const std::wstring& stFileName)
	{
		const auto dwAttrib = g_winAPIs->GetFileAttributesW(stFileName.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}
	bool CDirFunctions::IsDirExist(const std::wstring& stFileName)
	{
		const auto dwAttrib = g_winAPIs->GetFileAttributesW(stFileName.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	std::wstring CDirFunctions::ReadFileContent(const std::wstring& stFileName)
	{
		std::wstring stContent;
		
		try
		{
			std::ifstream in(stFileName.c_str(), std::ios_base::binary);
			if (in.is_open())
			{
				in.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
				stContent = std::wstring(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
			}
		}
		catch (const std::bad_alloc&)
		{
			stContent.clear();
		}
		catch (const std::ios_base::failure&)
		{
			stContent.clear();
		}
		catch (...)
		{
			stContent.clear();
		}
		
		return stContent;
	}
	void CDirFunctions::WriteFileContent(const std::wstring& szFileName, const std::wstring& szText)
	{
		std::ofstream f(szFileName.c_str(), std::ofstream::out | std::ofstream::app);
		if (f)
		{
			f << szText.c_str() << std::endl;
			f.close();
		}
	}

	DWORD CDirFunctions::GetFileSize(const std::wstring& stFileName)
	{
		if (stFileName.empty())
			return INVALID_FILE_SIZE;

		WIN32_FILE_ATTRIBUTE_DATA fileInfo{};
		if (!g_winAPIs->GetFileAttributesExW(stFileName.c_str(), GetFileExInfoStandard, &fileInfo))
			return INVALID_FILE_SIZE;

		return fileInfo.nFileSizeLow;
	}

	bool CDirFunctions::DeleteDirectory(const std::wstring& refcstrRootDirectory, bool bDeleteSubdirectories)
	{
		bool        bSubdirectory	= false;
		std::wstring wstrFilePath		= L"";

		const auto strPattern = refcstrRootDirectory + xorstr_(L"\\*.*");

		WIN32_FIND_DATAW FileInformation{ 0 };
		auto hFile = g_winAPIs->FindFirstFileW(strPattern.c_str(), &FileInformation);
		if (IS_VALID_HANDLE(hFile))
		{
			do
			{
				if (FileInformation.cFileName[0] != '.')
				{
					wstrFilePath.erase();
					wstrFilePath = refcstrRootDirectory + xorstr_(L"\\") + FileInformation.cFileName;

					if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						if (bDeleteSubdirectories)
						{
							// Delete subdirectory
							const auto iRC = DeleteDirectory(wstrFilePath, bDeleteSubdirectories);
							if (iRC)
								return iRC;
						}
						else
							bSubdirectory = true;
					}
					else
					{
						// Set file attributes
						if (g_winAPIs->SetFileAttributesW(wstrFilePath.c_str(), FILE_ATTRIBUTE_NORMAL))
							g_winAPIs->DeleteFileW(wstrFilePath.c_str());
					}
				}
			} while (g_winAPIs->FindNextFileW(hFile, &FileInformation));

			// Close handle
			g_winAPIs->FindClose(hFile);
		}
		
		const auto dwError = g_winAPIs->GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return false;

		if (!bSubdirectory)
		{
			// Set directory attributes
			if (!g_winAPIs->SetFileAttributesW(refcstrRootDirectory.c_str(), FILE_ATTRIBUTE_NORMAL))
				return false;

			// Delete directory
			if (!g_winAPIs->RemoveDirectoryW(refcstrRootDirectory.c_str()))
				return false;
		}

		return true;
	}

	std::wstring CDirFunctions::CurrentPath()
	{
		/*
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetCurrentDirectoryW(MAX_PATH, buffer);
		return buffer;
		*/
		return std::filesystem::current_path().wstring();
	}

	std::wstring CDirFunctions::WinPath()
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetWindowsDirectoryW(buffer, MAX_PATH);
		return buffer;
	}

	std::wstring CDirFunctions::SystemPath()
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetSystemDirectoryW(buffer, MAX_PATH);
		return buffer;
	}

	std::wstring CDirFunctions::SystemPath2()
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetSystemWow64DirectoryW(buffer, MAX_PATH);
		return buffer;
	}

	std::wstring CDirFunctions::TempPath()
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetTempPathW(MAX_PATH, buffer);
		return buffer;
	}

	std::wstring CDirFunctions::GetSpecialDirectory(int csidl)
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->SHGetSpecialFolderPathW(NULL, buffer, csidl, TRUE);
		return buffer;
	}

	std::wstring CDirFunctions::ExeNameWithPath()
	{
		wchar_t buffer[MAX_PATH]{ L'\0' };
		g_winAPIs->GetModuleFileNameW(nullptr, buffer, MAX_PATH);
		return buffer;
	}

	std::wstring CDirFunctions::ExeName()
	{
		const auto szExeNameWithPath = ExeNameWithPath();
		const auto szExeNameWithoutPath = GetNameFromPath(szExeNameWithPath);
		return szExeNameWithoutPath;
	}

	std::wstring CDirFunctions::ExePath()
	{
		const auto szBuffer = ExeNameWithPath();
		return GetPathFromProcessName(szBuffer);
	}

	bool CDirFunctions::IsFromWindowsPath(const std::wstring& szPath)
	{
		auto szLowerWinPath = WinPath();
		std::transform(szLowerWinPath.begin(), szLowerWinPath.end(), szLowerWinPath.begin(), tolower);

		return (szPath.find(szLowerWinPath) != std::wstring::npos);
	}

	bool CDirFunctions::IsFromCurrentPath(const std::wstring& szPath)
	{
		auto szLowerExePath = ExePath();
		std::transform(szLowerExePath.begin(), szLowerExePath.end(), szLowerExePath.begin(), tolower);

		return (szPath.find(szLowerExePath) != std::wstring::npos);
	}

	std::wstring CDirFunctions::GetNameFromPath(std::wstring __wszFileName)
	{
		auto wszFileName = __wszFileName;
		const auto iLastSlash = wszFileName.find_last_of(xorstr_(L"\\/"));
		wszFileName = wszFileName.substr(iLastSlash + 1, wszFileName.length() - iLastSlash);
		return wszFileName;
	}

	std::wstring CDirFunctions::GetPathFromProcessName(std::wstring szBuffer)
	{
		const auto szCopyBuffer = szBuffer;
		const auto pos = szCopyBuffer.find_last_of(xorstr_(L"\\/"));
		return szCopyBuffer.substr(0, pos);
	}

	bool CDirFunctions::IsPackedExecutable(const std::wstring& szName)
	{
		auto __GetEntropy = [](BYTE* byBuffer, DWORD dwLength) {
			DWORD dwSize = 0;
			long lBuff[0xFF + 1] = { 0 };
			float fTemp, fEntropy = 0;

			for (DWORD i = 0; i < dwLength; i++)
			{
				lBuff[byBuffer[i]]++;
				dwSize++;
			}

			for (DWORD i = 0; i < 256; i++)
			{
				if (lBuff[i])
				{
					fTemp = (float)lBuff[i] / (float)dwSize;
					fEntropy += (-fTemp * log2(fTemp));
				}
			}

			return fEntropy;
		};

		auto bIsPacked = false;

		if (szName.empty())
			return bIsPacked;

		const auto hFile = g_winAPIs->CreateFileW(szName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, nullptr);
		if (!IS_VALID_HANDLE(hFile))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileA fail! Error code: %u", g_winAPIs->GetLastError());
			return bIsPacked;
		}

		const auto dwFileLen = g_winAPIs->GetFileSize(hFile, nullptr);
		if (!dwFileLen || dwFileLen == INVALID_FILE_SIZE)
		{
			APP_TRACE_LOG(LL_ERR, L"GetFileSize fail! Error code: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hFile);
			return bIsPacked;
		}

		const auto pImage = reinterpret_cast<BYTE*>(CMemHelper::Allocate(dwFileLen));
		if (!pImage)
		{
			APP_TRACE_LOG(LL_ERR, L"Image allocation fail!");
			g_winAPIs->CloseHandle(hFile);
			return bIsPacked;
		}

		DWORD dwReadedBytes;
		const auto readRet = g_winAPIs->ReadFile(hFile, pImage, dwFileLen, &dwReadedBytes, nullptr);
		if (!readRet || dwReadedBytes != dwFileLen)
		{
			APP_TRACE_LOG(LL_ERR, L"ReadFile fail! Error code: %u", g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hFile);
			CMemHelper::Free(pImage);
			return bIsPacked;
		}
		g_winAPIs->CloseHandle(hFile);

		const auto fEntropy = __GetEntropy(pImage, dwFileLen);

		CMemHelper::Free(pImage);
		return (fEntropy > 7.5f);
	}

	std::wstring CDirFunctions::CreateTempFileName(const std::wstring& stPrefix)
	{
		wchar_t wszTempPath[MAX_PATH + 1]{ L'\0' };
		if (g_winAPIs->GetTempPathW(MAX_PATH, wszTempPath))
		{
			wchar_t wszTempName[MAX_PATH + 1]{ L'\0' };
			if (g_winAPIs->GetTempFileNameW(wszTempPath, !stPrefix.empty() ? stPrefix.c_str() : xorstr_(L"nmf"), 0, wszTempName))
			{
				return wszTempName;
			}
		}
		return {};
	}

	bool CDirFunctions::ForceDeleteFile(const std::wstring& stFileName, bool bSilent)
	{
		auto force_delete_method_1 = [stFileName, bSilent] {
			auto bRet = false;

			PSID all = nullptr;
			PSID admin = nullptr;
			PACL acl = nullptr;
			
			do
			{
				SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
				if (!g_winAPIs->AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &all))
				{
					APP_TRACE_LOG(LL_ERR, L"AllocateAndInitializeSid(all) failed for path: %s with error: %u", stFileName.c_str(), g_winAPIs->GetLastError());
					break;
				}

				SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
				if (!g_winAPIs->AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin))
				{
					APP_TRACE_LOG(LL_ERR, L"AllocateAndInitializeSid(admin) failed for path: %s with error: %u", stFileName.c_str(), g_winAPIs->GetLastError());
					break;
				}

				EXPLICIT_ACCESSW access[2] = { 0 };

				access[0].grfAccessPermissions = GENERIC_ALL;
				access[0].grfAccessMode = SET_ACCESS;
				access[0].grfInheritance = NO_INHERITANCE;
				access[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
				access[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
				access[0].Trustee.ptstrName = (LPWCH)all;

				access[1].grfAccessPermissions = GENERIC_ALL;
				access[1].grfAccessMode = SET_ACCESS;
				access[1].grfInheritance = NO_INHERITANCE;
				access[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
				access[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
				access[1].Trustee.ptstrName = (LPWCH)admin;

				auto dwErrCode = g_winAPIs->SetEntriesInAclW(2, access, 0, &acl);
				if (ERROR_SUCCESS != dwErrCode)
				{
					APP_TRACE_LOG(LL_ERR, L"SetEntriesInAclA failed for path: %s with status: %u", stFileName.c_str(), dwErrCode);
					break;
				}

				dwErrCode = g_winAPIs->SetNamedSecurityInfoW(const_cast<wchar_t*>(stFileName.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, admin, 0, 0, 0);
				if (ERROR_SUCCESS != dwErrCode)
				{
					APP_TRACE_LOG(LL_ERR, L"SetNamedSecurityInfoA(owner sec) failed for path: %s with status: %u", stFileName.c_str(), dwErrCode);
					break;
				}

				dwErrCode = g_winAPIs->SetNamedSecurityInfoW(const_cast<wchar_t*>(stFileName.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, acl, 0);
				if (ERROR_SUCCESS != dwErrCode)
				{
					APP_TRACE_LOG(LL_ERR, L"SetNamedSecurityInfoA(dacl sec) failed for path: %s with status: %u", stFileName.c_str(), dwErrCode);
					break;
				}

				g_winAPIs->SetFileAttributesW(stFileName.c_str(), FILE_ATTRIBUTE_NORMAL);

				SHFILEOPSTRUCTW op = { 0 };
				op.wFunc = FO_DELETE;
				op.pFrom = stFileName.c_str();
				op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;

				const auto nRet = g_winAPIs->SHFileOperationW(&op);
				if (nRet)
				{
					APP_TRACE_LOG(bSilent ? LL_TRACE : LL_ERR, L"SHFileOperationA failed for path: %s with status: %d error: %u", stFileName.c_str(), nRet, g_winAPIs->GetLastError());
					break;
				}

				bRet = true;
			} while (FALSE);

			if (all)
			{
				g_winAPIs->FreeSid(all);
				all = nullptr;
			}
			if (admin)
			{
				g_winAPIs->FreeSid(admin);
				admin = nullptr;
			}
			if (acl)
			{
				g_winAPIs->LocalFree(acl);
				acl = nullptr;
			}
			return bRet;
		};

		auto force_delete_method_2 = [stFileName] {
			auto open_handle = [] (const std::wstring& c_wstFileName) {
				return g_winAPIs->CreateFileW(c_wstFileName.c_str(), DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			};
			static auto rename_handle = [](HANDLE hHandle) {
				FILE_RENAME_INFO fRename;
				RtlSecureZeroMemory(&fRename, sizeof(fRename));

				LPWSTR lpwStream = xorstr_(L":qwezxc");
				fRename.FileNameLength = sizeof(lpwStream);
				RtlCopyMemory(fRename.FileName, lpwStream, sizeof(lpwStream));

				return g_winAPIs->SetFileInformationByHandle(hHandle, FileRenameInfo, &fRename, sizeof(fRename) + sizeof(lpwStream));
			};
			static auto deposite_handle = [](HANDLE hHandle) {
				FILE_DISPOSITION_INFO fDelete;
				RtlSecureZeroMemory(&fDelete, sizeof(fDelete));

				fDelete.DeleteFile = TRUE;

				return g_winAPIs->SetFileInformationByHandle(hHandle, FileDispositionInfo, &fDelete, sizeof(fDelete));
			};

			auto hCurrent = open_handle(stFileName.c_str());
			if (!hCurrent || hCurrent == INVALID_HANDLE_VALUE)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileA (1) failed for path: %s with status: %u", stFileName.c_str(), g_winAPIs->GetLastError());
				return false;
			}

			if (!rename_handle(hCurrent))
			{
				APP_TRACE_LOG(LL_ERR, L"SetFileInformationByHandle (1) failed for path: %s with status: %u", stFileName.c_str(), g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hCurrent);
				return false;
			}

			g_winAPIs->CloseHandle(hCurrent);

			hCurrent = open_handle(stFileName.c_str());
			if (hCurrent == INVALID_HANDLE_VALUE)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileA (2) failed for path: %s with status: %u", stFileName.c_str(), g_winAPIs->GetLastError());
				return false;
			}

			if (!deposite_handle(hCurrent))
			{
				APP_TRACE_LOG(LL_ERR, L"SetFileInformationByHandle (2) failed for path: %s with status: %u", stFileName.c_str(), g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hCurrent);
				return false;
			}

			g_winAPIs->CloseHandle(hCurrent);

			if (g_winAPIs->PathFileExistsW(stFileName.c_str()))
			{
				APP_TRACE_LOG(LL_ERR, L"PathFileExistsA failed for path: %s with status: %u", stFileName.c_str(), g_winAPIs->GetLastError());
				return false;
			}

			return true;
		};


		if (!this->IsFileExist(stFileName))
			return false;

		if (!g_winAPIs->DeleteFileW(stFileName.c_str()))
		{
			APP_TRACE_LOG(bSilent ? LL_TRACE : LL_ERR, L"DeleteFileA failed for path: %s with error: %u", stFileName.c_str(), g_winAPIs->GetLastError());

			if (!force_delete_method_1())
			{
				APP_TRACE_LOG(bSilent ? LL_TRACE : LL_ERR, L"force_delete_method_1 failed for path: %s with error: %u", stFileName.c_str(), g_winAPIs->GetLastError());

				return false;
				/*
				if (!force_delete_method_2())
				{
					APP_TRACE_LOG(LL_ERR, L"force_delete_method_2 failed for path: %s with error: %u", stFileName.c_str(), g_winAPIs->GetLastError());
					return false;
				}
				*/
			}
		}
		
		return true;
	}

	bool CDirFunctions::HideFile(const std::wstring& stFileName)
	{
		return g_winAPIs->SetFileAttributesW(stFileName.c_str(), FILE_ATTRIBUTE_HIDDEN);
	}
};
