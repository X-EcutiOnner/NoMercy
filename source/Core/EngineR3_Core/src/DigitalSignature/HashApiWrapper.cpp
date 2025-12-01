#include "../../include/PCH.hpp"
#include "../../include/HashApiWrapper.hpp"
#include "../../include/WinVerHelper.hpp"

namespace NoMercyCore
{
	DWORD HashApiWrapper::CalculateFileHash(std::wstring aFileName, std::wstring aHashType, std::wstring& aHashWstr)
	{
		if (!IsWindows8OrGreater())
			return ERROR_NOT_SUPPORTED;

		GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		auto hFile = g_winAPIs->CreateFileW(aFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!IS_VALID_HANDLE(hFile))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		HCATADMIN hCatAdmin = nullptr;
		GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
		if (!g_winAPIs->CryptCATAdminAcquireContext2(&hCatAdmin, &DriverActionGuid, aHashType.c_str(), NULL, 0))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptCATAdminAcquireContext2 failed with error: %u", dwErrorCode);
			g_winAPIs->CloseHandle(hFile);
			return dwErrorCode;
		}

		BYTE bHash[100]{ 0x0 };
		DWORD dwHash = sizeof(bHash);
		if (!g_winAPIs->CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &dwHash, bHash, 0))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptCATAdminCalcHashFromFileHandle2 failed with error: %u", dwErrorCode);
			g_winAPIs->CryptCATAdminReleaseCatalogContext(hCatAdmin, nullptr, 0);
			g_winAPIs->CloseHandle(hFile);
			return dwErrorCode;
		}

		g_winAPIs->CryptCATAdminReleaseCatalogContext(hCatAdmin, nullptr, 0);
		g_winAPIs->CryptCATAdminReleaseContext(hCatAdmin, 0);
		g_winAPIs->CloseHandle(hFile);

		aHashWstr = HashApiWrapper::ByteHashIntoWstring(bHash, dwHash);
		return ERROR_SUCCESS;
	}

	std::wstring HashApiWrapper::ByteHashIntoWstring(BYTE* aHash, size_t aHashLen)
	{
		if (!aHash || !aHashLen)
			return L"";

		auto lHashString = new (std::nothrow) WCHAR[aHashLen * 2 + 1];
		if (!lHashString)
			return L"";
		
		memset(lHashString, 0x0, aHashLen * 2 + 1);
		
		for (DWORD dw = 0; dw < aHashLen; ++dw)
		{
			wsprintfW(&lHashString[dw * 2], xorstr_(L"%02X"), aHash[dw]);
		}

		std::wstring lHashWstr(lHashString);

		delete[] lHashString;
		return lHashWstr;
	}
};
