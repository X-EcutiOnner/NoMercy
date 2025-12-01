#pragma once

namespace NoMercyCore
{
	enum class SignStatus
	{
		Valid = 0,
		Invalid = 1,
		Unsigned = 2,
		Untrusted = 3,
		Undefined = 4
	};

	class TrustVerifyWrapper
	{		
	public:
		static SignStatus convertSignInfo(LONG winStatus);

		static DWORD CheckFileSignature(const std::wstring& aPePath, bool bDisableNetworkAccess);

	private:		
		static bool verifyMicrosoftRoot(HANDLE hWVTStateData);

		static std::wstring getCertificateProvider(HANDLE hWVTStateData);

		static DWORD verifyFromFile(std::wstring aPePath, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot);

		static DWORD verifyFromCatalog(std::wstring aPePath, std::wstring aCatalogHashAlgo, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot);

		static DWORD verifyTrustFromCatObject(HCATINFO aCatInfo, std::wstring aFileName, std::wstring aHash, bool bDisableNetworkAccess, std::wstring& wstCertProvider, bool& bVerifiedMSRoot);
	};
};
