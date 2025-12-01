#include "../../include/PCH.hpp"
#include "../../include/PeSignatureVerifier.hpp"

namespace NoMercyCore
{
	DWORD PeSignatureVerifier::CheckFileSignature(std::wstring aPePath, bool bDisableNetworkAccess)
	{
		return TrustVerifyWrapper::CheckFileSignature(aPePath, bDisableNetworkAccess);
	}

	DWORD PeSignatureVerifier::GetCertificateInfo(std::wstring aFileName, SignerInfoPtr& aCertInfo)
	{
		return CryptoApiWrapper::GetCertificateInfo(aFileName, aCertInfo);
	}

	DWORD PeSignatureVerifier::GetTimestampCertificateInfo(std::wstring aFileName, TimeStampCertInfoPtr& aCertInfo)
	{
		return CryptoApiWrapper::GetTimestampCertificateInfo(aFileName, aCertInfo);
	}

	DWORD PeSignatureVerifier::CalculateFileHash(std::wstring aFileName, std::wstring aHashType, std::wstring& aHashWstr)
	{
		return HashApiWrapper::CalculateFileHash(aFileName, aHashType, aHashWstr);
	}
};
