#include "../../include/PCH.hpp"
#include "../../include/PeSignatureVerifier.hpp"
#include "../../include/TrustVerifyWrapper.hpp"
#include "../../include/AutoFSRedirection.hpp"
#include "../../include/WinVerHelper.hpp"

namespace NoMercyCore
{
	std::optional <bool> PeSignatureVerifier::HasValidFileCertificate(const std::wstring& wstFileName, bool bDisableNetworkAccess)
	{
		if (wstFileName.empty())
			return std::nullopt;

		std::vector <SCertContext> vecCerts;
		const auto obHasEmbeddedSign = FileVerifier::GetEmbeddedCertificates(wstFileName, vecCerts);
		if (!obHasEmbeddedSign.has_value())
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls embedded signature check failed!", wstFileName.c_str());
			
			const auto dwSignRet = TrustVerifyWrapper::CheckFileSignature(wstFileName, true);
			const auto dwSignStatus = TrustVerifyWrapper::convertSignInfo(dwSignRet);
			const auto bIsSigned = (dwSignRet == ERROR_SUCCESS);
			APP_TRACE_LOG(bIsSigned ? LL_SYS : LL_ERR, L"File: %ls signature status: %s (%u)",
				wstFileName.c_str(), bIsSigned ? xorstr_(L"signed") : xorstr_(L"unsigned"), (uint32_t)dwSignStatus
			);

			return std::make_optional<bool>(bIsSigned);
		}
		if (!obHasEmbeddedSign.value())
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls has no embedded signature!", wstFileName.c_str());
			return std::make_optional<bool>(false);
		}
		
		auto lRetVal = PeSignatureVerifier::CheckFileSignature(wstFileName, bDisableNetworkAccess); // TODO: convertSignInfo(lRetVal)
		if (lRetVal != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls check signature failed with error: %p", wstFileName.c_str(), lRetVal);
			return std::make_optional<bool>(false);
		}

		PeSignatureVerifier::SignerInfoPtr lCertInfo = NULL;
		lRetVal = PeSignatureVerifier::GetCertificateInfo(wstFileName, lCertInfo);
		if (lRetVal != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls certificate query failed with error: %p", wstFileName.c_str(), lRetVal);
			return std::make_optional<bool>(false);
		}

		/*
		if (!lCertInfo->timeValid)
		{
			if (IsWindows10OrGreater()) // unsupported os can contain expired cert
			{
				APP_TRACE_LOG(LL_ERR, L"File: %ls certificate time is NOT valid!", wstFileName.c_str());
				return std::make_optional<bool>(false);
			}
		}
		*/

		return std::make_optional<bool>(true);
	}


	bool __CompareCertThumbPrint(PCCERT_CONTEXT certContext, const BYTE* thumbprintToVerify)
	{
		bool result = false;

		DWORD thumbPrintSize = 0;
		if (g_winAPIs->CryptHashCertificate(0, CALG_SHA1, 0, certContext->pbCertEncoded, certContext->cbCertEncoded, NULL, &thumbPrintSize))
		{
			auto thumbPrint = (BYTE*)std::calloc(thumbPrintSize, sizeof(BYTE));
			if (thumbPrint)
			{
				if (g_winAPIs->CryptHashCertificate(0, CALG_SHA1, 0, certContext->pbCertEncoded, certContext->cbCertEncoded, thumbPrint, &thumbPrintSize))
				{
					if (!memcmp(thumbprintToVerify, thumbPrint, thumbPrintSize))
					{
						result = true;
					}
				}

				free(thumbPrint);
				thumbPrint = nullptr;
			}
		}

		return result;
	}

#pragma warning(push) 
#pragma warning(disable: 4245)
	bool PeSignatureVerifier::VerifyRootCAChainThumbPrint(PCCERT_CONTEXT& pCertContext)
	{
		static constexpr std::uint8_t VERISIGN_CERT_THUMBPRINT[] = {
			0x4E, 0xB6, 0xD5, 0x78, 0x49, 0x9B, 0x1C, 0xCF, 0x5F, 0x58, 0x1E, 0xAD, 0x56, 0xBE, 0x3D, 0x9B, 0x67, 0x44, 0xA5, 0xE5
		};
		static constexpr std::uint8_t ADDTRUST_CERT_THUMBPRINT[] = {
			0x02, 0xFA, 0xF3, 0xE2, 0x91, 0x43, 0x54, 0x68, 0x60, 0x78, 0x57, 0x69, 0x4D, 0xF5, 0xE4, 0x5B, 0x68, 0x85, 0x18, 0x68
		};
		static constexpr std::uint8_t INTEL_SHA256_CERT_THUMBPRINT[] = {
			0x30, 0xa1, 0xa6, 0xc9, 0xbc, 0x92, 0x0e, 0x60, 0x1a, 0x44, 0xa3, 0x05, 0x4e, 0x77, 0xf4, 0x0b, 0xd3, 0x1b, 0xe6, 0x39
		};

		auto ret = false;

		if (!pCertContext)
			return ret;

		CERT_CHAIN_PARA chainPara{ 0 };
		DWORD dwFlags = ~(CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_END_CERT);
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		if (g_winAPIs->CertGetCertificateChain(NULL, pCertContext, NULL, pCertContext->hCertStore, &chainPara, dwFlags, NULL, &pChainContext))
		{
			auto pSimpleChain = pChainContext->rgpChain[0];

			//Check revocation
			HRESULT hResult = S_OK;
			DWORD dwTrustErrorMask = ~(CERT_TRUST_IS_NOT_TIME_NESTED | CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_REVOCATION_STATUS_UNKNOWN);
			dwTrustErrorMask &= pSimpleChain->TrustStatus.dwErrorStatus;
			if (dwTrustErrorMask)
			{
				if (dwTrustErrorMask & CERT_TRUST_IS_OFFLINE_REVOCATION)
				{
					hResult = S_OK;
				}
				else if (dwTrustErrorMask & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_UNTRUSTED_ROOT))
				{
					hResult = SEC_E_UNTRUSTED_ROOT;
				}
				else
				{
					hResult = SEC_E_CERT_UNKNOWN;
				}
			}

			if (hResult == S_OK)
			{
				auto numCerts = pSimpleChain->cElement;
				if (numCerts > 0)
				{
					PCERT_CHAIN_ELEMENT* certPtr = pSimpleChain->rgpElement;

					for (auto i = 0u; i < numCerts; ++i)
					{
						PCCERT_CONTEXT rootCAContext = certPtr[i]->pCertContext;
						bool isValidChainRootCA =
							__CompareCertThumbPrint(rootCAContext, INTEL_SHA256_CERT_THUMBPRINT) ||
							__CompareCertThumbPrint(rootCAContext, VERISIGN_CERT_THUMBPRINT) ||
							__CompareCertThumbPrint(rootCAContext, ADDTRUST_CERT_THUMBPRINT);

						if (isValidChainRootCA)
						{
							ret = true;
							break;
						}
					}
				}
			}
		}

		return ret;
	}
};
#pragma warning(pop) 
