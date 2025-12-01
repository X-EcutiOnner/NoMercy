#pragma once
#include "SignerInfo.hpp"
#include "TimestampCertificateInfo.hpp"

namespace NoMercyCore
{
	class CryptoApiWrapper
	{
	public:
		using SignerInfoPtr = SignerInfo::SignerInfoPtr;
		using TimeStampCertInfoPtr = TimestampCertificateInfo::TimmeStampCertPtr;

		static DWORD GetCertificateInfo(const std::wstring& wstFileName, SignerInfoPtr& pkRefCertInfo);

		static DWORD GetTimestampCertificateInfo(const std::wstring& wstFileName, TimeStampCertInfoPtr& pkRefCertInfo);

		static PCCERT_CHAIN_CONTEXT GetCertChainContext(BYTE* signatureBuffer, ULONG cbSignatureBuffer);

		static bool IsCertificateSelfSigned(PCCERT_CONTEXT pContext, DWORD dwEncoding);

		static bool IsCACert(PCCERT_CONTEXT pCertContext);

		static bool IsCertificateRevoked(PCCERT_CONTEXT pContext);

		static PCCERT_CONTEXT GetCertContext(BYTE* signatureBuffer, ULONG cbSignatureBuffer, bool allowSelfSignedCert);

	private:
		static bool IsMicrosoftTrustedChainForLegacySystems(PCCERT_CHAIN_CONTEXT certChainContext);

		static bool IsMicrosoftTrustedChain(PCCERT_CHAIN_CONTEXT certChainContext);

		static bool IsAuthenticodeTrustedChain(PCCERT_CHAIN_CONTEXT certChainContext);
		
		static bool validateCertTime(PCCERT_CONTEXT pTargetCert, const std::wstring& wstFilename = L"");

		static DWORD queryCertificateInfo(PCCERT_CONTEXT aCertContext, DWORD aType, std::wstring& aOutputName);

		static DWORD queryProgAndPublisher(PCMSG_SIGNER_INFO pSignerInfo, std::wstring& aProgName, std::wstring& aPublisherLink, std::wstring& aMoreInfoLink);

		static DWORD getSignatureAlgoWstring(CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo, std::wstring& signatureAlgo);

		static DWORD getCertificateContext(std::shared_ptr <CMSG_SIGNER_INFO> aSignerInfo, HCERTSTORE aCertStore, PCCERT_CONTEXT& aCertContextPtr);

		static DWORD getTimeStampSignerInfo(std::shared_ptr <CMSG_SIGNER_INFO>& aSignerInfo, std::shared_ptr <CMSG_SIGNER_INFO>& aCounterSignerInfo);

		static DWORD getCertificateSerialNumber(PCCERT_CONTEXT aCertContext, std::wstring& aSerialNumberWstr);

		static DWORD getSignerInfo(std::wstring aFileName, std::shared_ptr <CMSG_SIGNER_INFO>& aSignerInfo, HCERTSTORE& aCertStore);

		static bool getDateOfTimeStamp(std::shared_ptr <CMSG_SIGNER_INFO>& aSignerInfo, std::shared_ptr <SYSTEMTIME>& aSysTime);
	};
};
