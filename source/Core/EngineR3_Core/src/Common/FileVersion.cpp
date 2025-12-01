#include "../../include/PCH.hpp"
#include "../../include/FileVersion.hpp"
#include "../../include/MemAllocator.hpp"

namespace NoMercyCore
{
	CFileVersion::CFileVersion() :
		m_wstTargetFile(L""), m_nLocaleTableSize(0), m_dwLangCharset(0), m_pVerInfo(nullptr)
	{
	}
	CFileVersion::~CFileVersion()
	{
		if (m_pVerInfo)
		{
			CMemHelper::Free(m_pVerInfo);
			m_pVerInfo = nullptr;
		}
	}

	bool CFileVersion::QueryFile(std::wstring filename)
	{
		auto bRet = false;

		do
		{
			if (filename.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Target file param is null!");
				break;
			}

			if (filename.compare(0, 4, xorstr_(L"\\??\\")) == 0)
				filename.erase(0, 4);

			/*
			if (!CApplication::Instance().DirFunctionsInstance()->IsFileExist(filename))
			{
				APP_TRACE_LOG(LL_ERR, L"Target file: %s does not exist!", filename.c_str());
				break;
			}
			*/

			wchar_t wszDrive[MAX_PATH]{ L'\0' };
			wchar_t wszFolder[MAX_PATH]{ L'\0' };
			wchar_t wszName[MAX_PATH]{ L'\0' };
			wchar_t wszExtension[MAX_PATH]{ L'\0' };

			const auto err = _wsplitpath_s(
				filename.c_str(),
				wszDrive, MAX_PATH,
				wszFolder, MAX_PATH,
				wszName, MAX_PATH,
				wszExtension, MAX_PATH
			);
			if (err != ERROR_SUCCESS)
			{
				APP_TRACE_LOG(LL_ERR, L"_splitpath_s (%s) failed with error: %d", filename.c_str(), err);
				break;
			}

			DWORD dwHandle = 0;
			const auto dwSize = g_winAPIs->GetFileVersionInfoSizeW(filename.c_str(), &dwHandle);
			if (!dwSize)
			{
				const auto dwError = g_winAPIs->GetLastError();
				if (dwError != ERROR_RESOURCE_TYPE_NOT_FOUND)
				{
					APP_TRACE_LOG(LL_ERR, L"GetFileVersionInfoSizeA (%s) failed with error: %u", filename.c_str(), dwError);
				}
				break;
			}

			m_pVerInfo = reinterpret_cast<char*>(CMemHelper::Allocate(dwSize));
			if (!m_pVerInfo)
			{
				APP_TRACE_LOG(LL_ERR, L"%u bytes memory allocation failed! Last error: %u", dwSize, g_winAPIs->GetLastError());
				break;
			}

			if (!g_winAPIs->GetFileVersionInfoW(filename.c_str(), dwHandle, dwSize, m_pVerInfo))
			{
				APP_TRACE_LOG(LL_ERR, L"GetFileVersionInfoA (%s) failed with error: %u", filename.c_str(), g_winAPIs->GetLastError());
				break;
			}

			UINT cbQuerySize = 0;
			DWORD* pTransTable = nullptr;
			if (!g_winAPIs->VerQueryValueW(m_pVerInfo, xorstr_(L"\\VarFileInfo\\Translation"), (void**)&pTransTable, &cbQuerySize))
			{
				APP_TRACE_LOG(LL_ERR, L"VerQueryValueA (%s) failed with error: %u", filename.c_str(), g_winAPIs->GetLastError());
				break;
			}

			m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
			m_nLocaleTableSize = cbQuerySize / sizeof(LANGANDCODEPAGE);
			m_wstTargetFile = filename;

			__GetAndSaveValue(xorstr_(L"Comments"), m_wstComments);
			__GetAndSaveValue(xorstr_(L"CompanyName"), m_wstCompanyName);
			__GetAndSaveValue(xorstr_(L"FileDescription"), m_wstFileDescription);
			__GetAndSaveValue(xorstr_(L"FileVersion"), m_wstFileVersion);
			__GetAndSaveValue(xorstr_(L"InternalName"), m_wstInternalName);
			__GetAndSaveValue(xorstr_(L"LegalCopyright"), m_wstLegalCopyright);
			__GetAndSaveValue(xorstr_(L"LegalTrademarks"), m_wstLegalTrademarks);
			__GetAndSaveValue(xorstr_(L"OriginalFilename"), m_wstOriginalFilename);
			__GetAndSaveValue(xorstr_(L"ProductName"), m_wstProductName);
			__GetAndSaveValue(xorstr_(L"ProductVersion"), m_wstProductVersion);
			__GetAndSaveValue(xorstr_(L"PrivateBuild"), m_wstPrivateBuild);
			__GetAndSaveValue(xorstr_(L"SpecialBuild"), m_wstSpecialBuild);

			bRet = true;
		} while (FALSE);

		return bRet;
	}

	bool CFileVersion::__GetAndSaveValue(const std::wstring& keyword, std::wstring& ref_value, DWORD lang_char_set) const
	{
		if (!m_pVerInfo)
			return false;

		if (lang_char_set == 0)
			lang_char_set = m_dwLangCharset;

		wchar_t wszBuffer[256]{ L'\0' };
		_snwprintf_s(wszBuffer, sizeof(wszBuffer), xorstr_(L"\\StringFileInfo\\%08lx\\%s"), lang_char_set, keyword.c_str());

		UINT cbQuerySize = 0;
		LPVOID lpData = nullptr;
		if (!g_winAPIs->VerQueryValueW((void**)m_pVerInfo, wszBuffer, &lpData, &cbQuerySize))
		{
			const auto dwError = g_winAPIs->GetLastError();
			if (dwError != ERROR_RESOURCE_TYPE_NOT_FOUND)
			{
				APP_TRACE_LOG(LL_ERR, L"VerQueryValueA (%s) failed with error: %u", wszBuffer, dwError);
			}
			return false;
		}

		ref_value = std::wstring((LPCWSTR)lpData, cbQuerySize);
		if (!ref_value.empty() && ref_value.back() == L'\0')
			ref_value.pop_back();
		return true;
	}

	bool CFileVersion::GetFixedInfo(VS_FIXEDFILEINFO& vsffi)
	{
		if (!m_pVerInfo)
			return false;

		UINT nQuerySize = 0;
		VS_FIXEDFILEINFO* pVsffi = nullptr;

		if (!g_winAPIs->VerQueryValueW((void**)m_pVerInfo, xorstr_(L"\\"), (void**)&pVsffi, &nQuerySize))
		{
			APP_TRACE_LOG(LL_ERR, L"VerQueryValueA failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		vsffi = *pVsffi;
		return true;
	}

	std::wstring CFileVersion::GetFixedFileVersion()
	{
		std::wstring strVersion;

		VS_FIXEDFILEINFO vsffi{ 0 };
		if (GetFixedInfo(vsffi))
		{
			wchar_t wszBuffer[128]{ L'\0' };
			_snwprintf(wszBuffer, 128,
				xorstr_(L"%u.%u.%u.%u"),
				HIWORD(vsffi.dwFileVersionMS),
				LOWORD(vsffi.dwFileVersionMS),
				HIWORD(vsffi.dwFileVersionLS),
				LOWORD(vsffi.dwFileVersionLS)
			);

			strVersion = wszBuffer;
		}
		return strVersion;
	}

	std::wstring CFileVersion::GetFixedProductVersion()
	{
		std::wstring strVersion;

		VS_FIXEDFILEINFO vsffi{ 0 };
		if (GetFixedInfo(vsffi))
		{
			wchar_t wszBuffer[128]{ L'\0' };
			_snwprintf(wszBuffer, 128,
				xorstr_(L"%u.%u.%u.%u"),
				HIWORD(vsffi.dwProductVersionMS),
				LOWORD(vsffi.dwProductVersionMS),
				HIWORD(vsffi.dwProductVersionLS),
				LOWORD(vsffi.dwProductVersionLS)
			);

			strVersion = wszBuffer;
		}
		return strVersion;
	}

	std::wstring CFileVersion::GetProductLanguage()
	{
		std::wstring wstrLanguage;
		DWORD cbSize = 256;
		wchar_t lpData[256]{ L'\0' };

		const auto nResult = g_winAPIs->VerLanguageNameW(m_dwLangCharset, lpData, cbSize);
		if (nResult != 0 && nResult < cbSize - 1)
			wstrLanguage = std::wstring((LPCWSTR)lpData, cbSize);

		return wstrLanguage;
	}

	std::wstring CFileVersion::GetTimestamp()
	{
		std::wstring str;

		HANDLE hFile = INVALID_HANDLE_VALUE;
		do
		{
			hFile = g_winAPIs->CreateFileW(m_wstTargetFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (!IS_VALID_HANDLE(hFile))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			
			ULONG len = sizeof(IMAGE_DOS_HEADER);
			IMAGE_DOS_HEADER dos_header = {};
			if (!g_winAPIs->ReadFile(hFile, &dos_header, len, &len, NULL))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadFile (DOS) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			
			if (len != sizeof(IMAGE_DOS_HEADER))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadFile (DOS) length mismatch (expected: %u, actual: %u)", sizeof(IMAGE_DOS_HEADER), len);
				break;
			}
			
			if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Invalid DOS signature (expected: %u, actual: %u)", IMAGE_DOS_SIGNATURE, dos_header.e_magic);
				break;
			}
			
			g_winAPIs->SetFilePointer(hFile, dos_header.e_lfanew, NULL, FILE_BEGIN);

			len = sizeof(IMAGE_NT_HEADERS);
			IMAGE_NT_HEADERS nt_header = { 0 };

			if (!g_winAPIs->ReadFile(hFile, &nt_header, len, &len, NULL))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadFile (NT) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			if (len != sizeof(IMAGE_NT_HEADERS))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadFile (NT) length mismatch (expected: %u, actual: %u)", sizeof(IMAGE_NT_HEADERS), len);
				break;
			}

			if (nt_header.Signature != IMAGE_NT_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Invalid NT signature (expected: %u, actual: %u)", IMAGE_NT_SIGNATURE, nt_header.Signature);
				break;
			}

			const auto timestamp = Int32x32To64(nt_header.FileHeader.TimeDateStamp, 10000000) + 116444736000000000;

			SYSTEMTIME time;
			g_winAPIs->FileTimeToSystemTime((FILETIME*)&timestamp, &time);

			wchar_t wszBuffer[128]{ L'\0' };
			_snwprintf(wszBuffer, sizeof(wszBuffer),
				xorstr_(L"%04u-%02u-%02u %02u:%02u:%02u"),
				time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
			);
			str = wszBuffer;
		} while (FALSE);

		if (IS_VALID_HANDLE(hFile))
		{
			g_winAPIs->CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
		
		return str;
	}
}
