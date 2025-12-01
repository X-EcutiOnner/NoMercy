#pragma once
#include "SignerInfo.hpp"
#include "CryptoApiWrapper.hpp"
#include "HashApiWrapper.hpp"
#include "TrustVerifyWrapper.hpp"
#include "FileVerifier.hpp"

namespace NoMercyCore
{
	typedef struct {
		int id;
		std::vector <std::wstring> data;
	} FindData;

	typedef struct {
		std::wstring type;
		std::wstring data;
	}FailInfo;

	typedef struct _CERT_SEARCH_DATA {
		int iocId;
		int type;
		std::wstring data;
		bool found;
	} CERT_SEARCH_DATA;

	typedef struct _ENUM_ARG {
		DWORD       dwFlags;
		const void* pvStoreLocationPara;
		std::vector <CERT_SEARCH_DATA> searchData;
		std::vector <FindData>* found;
		std::vector <FailInfo>* fails;
	} ENUM_ARG, *PENUM_ARG;

	class PeSignatureVerifier
	{
	public:
		using SignerInfoPtr = CryptoApiWrapper::SignerInfoPtr;
		using TimeStampCertInfoPtr = CryptoApiWrapper::TimeStampCertInfoPtr;

		static DWORD CheckFileSignature(std::wstring aPePath, bool bDisableNetworkAccess);

		static DWORD CalculateFileHash(std::wstring aFileName, std::wstring aHashType, std::wstring& aHashWstr);

		static DWORD GetCertificateInfo(std::wstring aFileName, SignerInfoPtr& aCertInfo);

		static DWORD GetTimestampCertificateInfo(std::wstring aFileName, TimeStampCertInfoPtr& aCertInfo);

		// true: valid, false: invalid, null: error on verification
		static std::optional <bool> HasValidFileCertificate(const std::wstring& wstFileName, bool bDisableNetworkAccess = true);

		static bool VerifyRootCAChainThumbPrint(PCCERT_CONTEXT& pCertContext);

		static void checkCertificates(std::vector <CERT_SEARCH_DATA> searchData, std::vector <FindData>* found, std::vector <FailInfo>* fails);
	};
};
