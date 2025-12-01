#include "../../include/PCH.hpp"
#include "../../include/TrustVerifyWrapper.hpp"
#include "../../include/HashApiWrapper.hpp"
#include "../../include/WinVerHelper.hpp"

#define SHA256 xorstr_(L"SHA256")

namespace NoMercyCore
{
	static std::map <std::wstring, DWORD> gs_mapCertRetCache;

	SignStatus TrustVerifyWrapper::convertSignInfo(LONG winStatus)
	{
		if (winStatus == ERROR_SUCCESS || winStatus == CERT_E_EXPIRED)
			return SignStatus::Valid;
		if (winStatus == TRUST_E_NOSIGNATURE)
			return SignStatus::Unsigned;
		if (winStatus == CERT_E_UNTRUSTEDROOT)
			return SignStatus::Untrusted;
		if (winStatus == CRYPT_E_FILE_ERROR)
			return SignStatus::Undefined;
		return SignStatus::Invalid;
	}

	std::wstring TrustVerifyWrapper::getCertificateProvider(HANDLE hWVTStateData)
	{
		const auto pCryptProvData = g_winAPIs->WTHelperProvDataFromStateData(hWVTStateData);
		if (!pCryptProvData)
		{
			const auto dwError = g_winAPIs->GetLastError();
			if (dwError != TRUST_E_SUBJECT_NOT_TRUSTED)
			{
				APP_TRACE_LOG(LL_WARN, L"WTHelperProvDataFromStateData (1) failed with error: %u (%p)", hWVTStateData, dwError, dwError);
			}
			return {};
		}

		const auto pSigner = g_winAPIs->WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
		if (!pSigner)
		{
			APP_TRACE_LOG(LL_ERR, L"WTHelperGetProvSignerFromChain failed with error: %u (%p)", g_winAPIs->GetLastError(), g_winAPIs->GetLastError());
			return {};
		}

		const auto pCert = g_winAPIs->WTHelperGetProvCertFromChain(pSigner, 0);
		if (!pCert)
		{
			APP_TRACE_LOG(LL_ERR, L"WTHelperGetProvCertFromChain failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		const auto dwRequiredSize = g_winAPIs->CertGetNameStringW(pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
		if (dwRequiredSize == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW (1) failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		std::wstring wstProvider = std::wstring(dwRequiredSize, L'\0');
		if (!g_winAPIs->CertGetNameStringW(pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, wstProvider.data(), (DWORD)wstProvider.size()))
		{
			APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW (2) failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		wstProvider.resize(wstProvider.size() - 1);
		return wstProvider;
	}

	bool CertChainMicrosoftRootVerify(PCCERT_CHAIN_CONTEXT pChainContext)
	{
		CERT_CHAIN_POLICY_PARA ccpp;
		memset(&ccpp, 0, sizeof(ccpp));
		ccpp.cbSize = sizeof(ccpp);
		ccpp.dwFlags = 0;
		
		CERT_CHAIN_POLICY_STATUS ccps;
		memset(&ccps, 0, sizeof(ccps));
		ccps.cbSize = sizeof(ccps);

		auto bMicrosoftRoot = false;

		if (g_winAPIs->CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, pChainContext, &ccpp, &ccps) == TRUE)
		{
			// CertVerifyCertificateChainPolicy was able to check the policy
			// *Must* check ChainPolicyStatus.dwError to determine if the policy check was actually satisfied
			bMicrosoftRoot = (ccps.dwError == 0);
		}

		if (!bMicrosoftRoot)
		{
			// If Microsoft Product Root verification was unsuccessful, check for the Microsoft Application Root
			// via: MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG

			CERT_CHAIN_POLICY_PARA AppRootChainPolicyPara;
			memset(&AppRootChainPolicyPara, 0, sizeof(CERT_CHAIN_POLICY_PARA));
			AppRootChainPolicyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
			AppRootChainPolicyPara.dwFlags = MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG;
			
			CERT_CHAIN_POLICY_STATUS AppRootChainPolicyStatus;
			memset(&AppRootChainPolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
			AppRootChainPolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);

			if (g_winAPIs->CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, pChainContext, &AppRootChainPolicyPara, &AppRootChainPolicyStatus) == TRUE)
			{
				// CertVerifyCertificateChainPolicy was able to check the policy
				// *Must* check AppRootChainPolicyStatus.dwError to determine if the policy check was actually satisfied
				bMicrosoftRoot = (AppRootChainPolicyStatus.dwError == 0);
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"CertVerifyCertificateChainPolicy failed with error: %u", g_winAPIs->GetLastError());
			}
		}

		return bMicrosoftRoot;
	}
	
	bool TrustVerifyWrapper::verifyMicrosoftRoot(HANDLE hWVTStateData)
	{
		auto pCryptProvData = g_winAPIs->WTHelperProvDataFromStateData(hWVTStateData);
		if (!pCryptProvData)
		{
			APP_TRACE_LOG(LL_WARN, L"WTHelperProvDataFromStateData2 (%p) failed with error: %u (%p)", hWVTStateData, g_winAPIs->GetLastError(), g_winAPIs->GetLastError());
			return false;
		}
		
		auto pSigner = g_winAPIs->WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
		if (!pSigner)
		{
			APP_TRACE_LOG(LL_ERR, L"WTHelperGetProvSignerFromChain failed with error: %u (%p)", g_winAPIs->GetLastError(), g_winAPIs->GetLastError());
			return false;
		}

		return CertChainMicrosoftRootVerify(pSigner->pChainContext);
	}

	DWORD TrustVerifyWrapper::CheckFileSignature(const std::wstring& wstFile, bool bDisableNetworkAccess)
	{
		auto it = gs_mapCertRetCache.find(wstFile);
		if (it != gs_mapCertRetCache.end())
			return it->second;

		// Whitelisted by name (c:\programdata\kaspersky lab\avp21.20\bases\sw2\cache\klswapiproxy.kdl.f2957acacbfcff9703828b3f8055c90a.0075d943-8d7d-418b-ba7d-de2e604476fc)
		if (wstFile.find(xorstr_(L"c:\\programdata\\kaspersky lab\\")) != std::wstring::npos)
		{
			gs_mapCertRetCache.emplace(wstFile, ERROR_SUCCESS);
			return ERROR_SUCCESS;
		}

		// Try to find embeeded signature in the given PE.
		auto bVerifiedMSRoot = false;
		std::wstring wstCertProvider;
		if (verifyFromFile(wstFile, bDisableNetworkAccess, wstCertProvider, bVerifiedMSRoot) == ERROR_SUCCESS)
		{
			gs_mapCertRetCache.emplace(wstFile, ERROR_SUCCESS);
			return ERROR_SUCCESS;
		}

		// Calculate the hash for the given PE and look for in Windows catalogs.
		const auto dwResult = verifyFromCatalog(wstFile, SHA256, bDisableNetworkAccess, wstCertProvider, bVerifiedMSRoot);
		gs_mapCertRetCache.emplace(wstFile, dwResult);

		return dwResult;
	}

	DWORD TrustVerifyWrapper::verifyFromFile(std::wstring wstFile, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot)
	{
		////set up structs to verify files with cert signatures
		WINTRUST_FILE_INFO wfi{ 0 };
		memset(&wfi, 0, sizeof(wfi));
		wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
		wfi.pcwszFilePath = wstFile.c_str();
		wfi.hFile = NULL;
		wfi.pgKnownSubject = NULL;

		WINTRUST_DATA wd{ 0 };
		memset(&wd, 0, sizeof(wd));
		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.pPolicyCallbackData = NULL;
		wd.pSIPClientData = NULL;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.dwUnionChoice = WTD_CHOICE_FILE;
		wd.dwStateAction = WTD_STATEACTION_VERIFY; // WTD_STATEACTION_IGNORE;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
		wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
		wd.pFile = &wfi;

		wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		wd.dwProvFlags = WTD_SAFER_FLAG | WTD_DISABLE_MD2_MD4;
		if (bDisableNetworkAccess)
		{
			wd.fdwRevocationChecks = WTD_REVOKE_NONE;
			wd.dwProvFlags |= WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
		}

		GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		auto lStatus = g_winAPIs->WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

		if (lStatus != ERROR_SUCCESS)
		{
			auto bShouldIgnore = false;
			if (wstFile.find(xorstr_(L"NoMercy_Module")) != std::wstring::npos && (lStatus == CERT_E_CHAINING || lStatus == CERT_E_UNTRUSTEDROOT))
				bShouldIgnore = true;
			
			if (bShouldIgnore)
			{
				lStatus = ERROR_SUCCESS;
			}
			else
			{
				const auto dwErrorCode = g_winAPIs->GetLastError();
				APP_TRACE_LOG(LL_WARN, L"WinVerifyTrust failed with error: %u (%p) status: %u (%p)", dwErrorCode, dwErrorCode, lStatus, lStatus);
				return lStatus;
			}
		}
		wstCertProvider = getCertificateProvider(wd.hWVTStateData);
		bVerifiedMSRoot = verifyMicrosoftRoot(wd.hWVTStateData);

		wd.dwStateAction = WTD_STATEACTION_CLOSE;
		g_winAPIs->WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

		return lStatus;
	}

	DWORD TrustVerifyWrapper::verifyFromCatalog(std::wstring wstFile, std::wstring wstCatalogHashAlgo, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot)
	{
		if (!IsWindows8OrGreater())
			return ERROR_NOT_SUPPORTED;
		
		auto hFile = g_winAPIs->CreateFileW(wstFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!IS_VALID_HANDLE(hFile))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		HCATADMIN hCatAdmin = nullptr;
		GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
		if (!g_winAPIs->CryptCATAdminAcquireContext2(&hCatAdmin, &DriverActionGuid, wstCatalogHashAlgo.c_str(), NULL, 0))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptCATAdminAcquireContext2 failed with error: %u", dwErrorCode);
			g_winAPIs->CloseHandle(hFile);
			return dwErrorCode;
		}

		BYTE bHash[100];
		DWORD dwHash = sizeof(bHash);
		if (!g_winAPIs->CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &dwHash, bHash, 0))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptCATAdminCalcHashFromFileHandle2 failed with error: %u", dwErrorCode);
			g_winAPIs->CloseHandle(hFile);
			return dwErrorCode;
		}

		auto lHashWstr = HashApiWrapper::ByteHashIntoWstring(bHash, dwHash);

		/*
		* Find the calalogue that contains hash of our file.
		* Note that CryptCATAdminEnumCatalogFromHash gives you
		* the ability to iterate over all the catalogues that are
		* containing your hash.
		*/
		auto hCatInfo = g_winAPIs->CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);
		if (!hCatInfo)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_WARN, L"CryptCATAdminEnumCatalogFromHash failed with error: %u", dwErrorCode);
			g_winAPIs->CryptCATAdminReleaseContext(hCatAdmin, 0);
			g_winAPIs->CloseHandle(hFile);
			return dwErrorCode;
		}

		auto lStatus = TrustVerifyWrapper::verifyTrustFromCatObject(hCatInfo, wstFile, lHashWstr, bDisableNetworkAccess, wstCertProvider, bVerifiedMSRoot);

		g_winAPIs->CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
		g_winAPIs->CryptCATAdminReleaseContext(hCatAdmin, 0);
		g_winAPIs->CloseHandle(hFile);
		return lStatus;
	}

	DWORD TrustVerifyWrapper::verifyTrustFromCatObject(HCATINFO hCatInfo, std::wstring wstFileName, std::wstring wstHash, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot)
	{
		CATALOG_INFO ci{ 0 };
		const auto bCatRet = g_winAPIs->CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0);
		if (!bCatRet)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptCATCatalogInfoFromContext failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}
		
		WINTRUST_CATALOG_INFO wci{ 0 };
		memset(&wci, 0, sizeof(wci));
		wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		wci.pcwszCatalogFilePath = ci.wszCatalogFile;
		wci.pcwszMemberFilePath = wstFileName.c_str();
		wci.pcwszMemberTag = wstHash.c_str();

		WINTRUST_DATA wd{ 0 };
		memset(&wd, 0, sizeof(wd));
		wd.cbStruct = sizeof(WINTRUST_DATA);
		wd.pPolicyCallbackData = NULL;
		wd.pSIPClientData = NULL;
		wd.dwUIChoice = WTD_UI_NONE;
		wd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wd.dwStateAction = WTD_STATEACTION_VERIFY; // WTD_STATEACTION_IGNORE;
		wd.hWVTStateData = NULL;
		wd.pwszURLReference = NULL;
		wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
		wd.pCatalog = &wci;

		wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		wd.dwProvFlags = WTD_SAFER_FLAG | WTD_DISABLE_MD2_MD4;
		if (bDisableNetworkAccess)
		{
			wd.fdwRevocationChecks = WTD_REVOKE_NONE;
			wd.dwProvFlags |= WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
		}

		GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		const auto lStatus = g_winAPIs->WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

		if (lStatus != ERROR_SUCCESS)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"WinVerifyTrust failed with error: %u (%p) status: %u (%p)", dwErrorCode, dwErrorCode, lStatus, lStatus);
			return dwErrorCode;
		}
		wstCertProvider = getCertificateProvider(wd.hWVTStateData);
		bVerifiedMSRoot = verifyMicrosoftRoot(wd.hWVTStateData);

		wd.dwStateAction = WTD_STATEACTION_CLOSE;
		g_winAPIs->WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

		return lStatus;
	}
};
