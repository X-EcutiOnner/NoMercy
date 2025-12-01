#include "../../include/PCH.hpp"
#include "../../include/CryptoApiWrapper.hpp"
#include "../../../../Common/HandleGuard.hpp"

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define PKCS7_SIGNER_INFO_WC ((LPCSTR)500)

namespace NoMercyCore
{
	DWORD CryptoApiWrapper::GetCertificateInfo(const std::wstring& wstFileName, CryptoApiWrapper::SignerInfoPtr& pkRefCertInfo)
	{
		DWORD dwRetVal = ERROR_SUCCESS;
		std::shared_ptr <CMSG_SIGNER_INFO> spSignerInfo;
		HCERTSTORE hCertStore = nullptr;
		PCCERT_CONTEXT pCertContextPtr = nullptr;

		do
		{
			dwRetVal = CryptoApiWrapper::getSignerInfo(wstFileName, spSignerInfo, hCertStore);
			if (dwRetVal != ERROR_SUCCESS)
				break;

			dwRetVal = CryptoApiWrapper::getCertificateContext(spSignerInfo, hCertStore, pCertContextPtr);
			if (dwRetVal != ERROR_SUCCESS)
				break;

			pkRefCertInfo = stdext::make_shared_nothrow<SignerInfo>();
			if (!IS_VALID_SMART_PTR(pkRefCertInfo))
			{
				dwRetVal = ERROR_OUTOFMEMORY;
				break;
			}

			pkRefCertInfo->timeValid = validateCertTime(pCertContextPtr, wstFileName);

			std::wstring lProgName, lPublisherLink, lMoreInfoLink;
			dwRetVal = queryProgAndPublisher(spSignerInfo.get(), lProgName, lPublisherLink, lMoreInfoLink);
			if (dwRetVal == ERROR_SUCCESS)
			{
				pkRefCertInfo->programName = lProgName;
				pkRefCertInfo->publisherLink = lPublisherLink;
				pkRefCertInfo->moreInfoLink = lMoreInfoLink;
			}

			std::wstring lSerialNumber;
			dwRetVal = CryptoApiWrapper::getCertificateSerialNumber(pCertContextPtr, lSerialNumber);
			if (dwRetVal == ERROR_SUCCESS)
			{
				pkRefCertInfo->serialNumber = lSerialNumber;
			}

			std::wstring lIssuerName;
			dwRetVal = CryptoApiWrapper::queryCertificateInfo(pCertContextPtr, CERT_NAME_ISSUER_FLAG, lIssuerName);
			if (dwRetVal == ERROR_SUCCESS)
			{
				pkRefCertInfo->issuerName = lIssuerName;
			}

			std::wstring lSubjectName;
			dwRetVal = CryptoApiWrapper::queryCertificateInfo(pCertContextPtr, 0, lSubjectName);
			if (dwRetVal == ERROR_SUCCESS)
			{
				pkRefCertInfo->subjectName = lSubjectName;
			}

			std::wstring lSignAlgorithm;
			dwRetVal = CryptoApiWrapper::getSignatureAlgoWstring(&pCertContextPtr->pCertInfo->SignatureAlgorithm, lSignAlgorithm);
			if (dwRetVal == ERROR_SUCCESS)
			{
				pkRefCertInfo->signAlgorithm = lSignAlgorithm;
			}

			if (CryptoApiWrapper::IsCertificateSelfSigned(pCertContextPtr, pCertContextPtr->dwCertEncodingType))
				pkRefCertInfo->selfSigned = true;

			if (CryptoApiWrapper::IsCACert(pCertContextPtr))
				pkRefCertInfo->caCert = true;

			if (CryptoApiWrapper::IsCertificateRevoked(pCertContextPtr))
				pkRefCertInfo->revoked = true;

			dwRetVal = ERROR_SUCCESS;
		} while (FALSE);

		if (pCertContextPtr)
		{
			g_winAPIs->CertFreeCertificateContext(pCertContextPtr);
			pCertContextPtr = nullptr;
		}
		if (hCertStore)
		{
			g_winAPIs->CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
			hCertStore = nullptr;
		}

		return dwRetVal;
	}

	bool CryptoApiWrapper::validateCertTime(PCCERT_CONTEXT pTargetCert, const std::wstring& wstFilename)
	{
		auto bRet = false;

		const auto pTargetCertInfo = pTargetCert->pCertInfo;
		const auto ret = g_winAPIs->CertVerifyTimeValidity(nullptr, pTargetCertInfo);
		switch (ret)
		{
		case -1:
		{
			APP_TRACE_LOG(LL_ERR, L"File: %s certificate is not valid yet!", wstFilename.c_str());
			break;
		}
		case 1:
		{
			APP_TRACE_LOG(LL_WARN, L"File: %s certificate is expired!", wstFilename.c_str());
			break;
		}
		case 0:
		{
			APP_TRACE_LOG(LL_TRACE, L"Certificate is valid!");
			bRet = true;
			break;
		}

		default:
		{
			APP_TRACE_LOG(LL_ERR, L"CertVerifyTimeValidity returned unknown value: %ld last error: %u", ret, g_winAPIs->GetLastError());
			break;
		}
		};

		return bRet;
	}

	DWORD CryptoApiWrapper::GetTimestampCertificateInfo(const std::wstring& wstFileName, CryptoApiWrapper::TimeStampCertInfoPtr& aCertInfo)
	{
		DWORD lRetVal = ERROR_SUCCESS;

		HCERTSTORE lCertStore = nullptr;
		std::shared_ptr <CMSG_SIGNER_INFO> lSignerInfo;
		lRetVal = CryptoApiWrapper::getSignerInfo(wstFileName, lSignerInfo, lCertStore);
		if (lRetVal != ERROR_SUCCESS)
		{
			return lRetVal;
		}

		PCCERT_CONTEXT lCertContexPtr = nullptr;
		lRetVal = CryptoApiWrapper::getCertificateContext(lSignerInfo, lCertStore, lCertContexPtr);
		if (lRetVal != ERROR_SUCCESS)
		{
			return lRetVal;
		}

		std::shared_ptr <CMSG_SIGNER_INFO> lTimeStammpSignerInfo;
		lRetVal = CryptoApiWrapper::getTimeStampSignerInfo(lSignerInfo, lTimeStammpSignerInfo);
		if (lRetVal != ERROR_SUCCESS)
		{
			return lRetVal;
		}

		lRetVal = CryptoApiWrapper::getCertificateContext(lTimeStammpSignerInfo, lCertStore, lCertContexPtr);
		if (lRetVal != ERROR_SUCCESS)
		{
			return lRetVal;
		}

		aCertInfo = std::make_shared<TimestampCertificateInfo>();

		std::wstring lSerialNumber;
		lRetVal = CryptoApiWrapper::getCertificateSerialNumber(lCertContexPtr, lSerialNumber);
		if (lRetVal == ERROR_SUCCESS)
		{
			aCertInfo->serialNumber = lSerialNumber;
		}

		std::wstring lIssuerName;
		lRetVal = CryptoApiWrapper::queryCertificateInfo(lCertContexPtr, CERT_NAME_ISSUER_FLAG, lIssuerName);
		if (lRetVal == ERROR_SUCCESS)
		{
			aCertInfo->issuerName = lIssuerName;
		}

		std::wstring lSubjectName;
		lRetVal = CryptoApiWrapper::queryCertificateInfo(lCertContexPtr, 0, lSubjectName);
		if (lRetVal == ERROR_SUCCESS)
		{
			aCertInfo->subjectName = lSubjectName;
		}

		std::wstring lSignAlgorithm;
		lRetVal = CryptoApiWrapper::getSignatureAlgoWstring(&lCertContexPtr->pCertInfo->SignatureAlgorithm, lSignAlgorithm);
		if (lRetVal == ERROR_SUCCESS)
		{
			aCertInfo->signAlgorithm = lSignAlgorithm;
		}

		std::shared_ptr <SYSTEMTIME> lSysTime;
		auto lBoolRetVal = CryptoApiWrapper::getDateOfTimeStamp(lTimeStammpSignerInfo, lSysTime);
		if (lBoolRetVal == true)
		{
			aCertInfo->dateOfTimeStamp = lSysTime;
		}

		if (lCertContexPtr)
		{
			g_winAPIs->CertFreeCertificateContext(lCertContexPtr);
			lCertContexPtr = nullptr;
		}

		if (lCertStore)
		{
			g_winAPIs->CertCloseStore(lCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
			lCertStore = nullptr;
		}

		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::getSignerInfo(std::wstring aFileName, std::shared_ptr <CMSG_SIGNER_INFO>& aSignerInfo, HCERTSTORE& aCertStore)
	{
		BOOL lRetVal = TRUE;

		DWORD lEncoding = 0;
		DWORD lContentType = 0;
		DWORD lFormatType = 0;
		HCERTSTORE lStoreHandle = nullptr;
		HCRYPTMSG lCryptMsgHandle = nullptr;
		lRetVal = g_winAPIs->CryptQueryObject(
			CERT_QUERY_OBJECT_FILE, aFileName.data(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
			&lEncoding, &lContentType, &lFormatType, &lStoreHandle, &lCryptMsgHandle, NULL
		);
		if (!lRetVal)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptQueryObject failed with error: %u/%p", dwErrorCode, dwErrorCode);
			return dwErrorCode;
		}

		DWORD lSignerInfoSize = 0;
		lRetVal = g_winAPIs->CryptMsgGetParam(lCryptMsgHandle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &lSignerInfoSize);
		if (!lRetVal)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(1) failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		auto lSignerInfoPtr = (PCMSG_SIGNER_INFO)new BYTE[lSignerInfoSize];
		if (!lSignerInfoPtr)
		{
			const auto dwErrorCode = errno;
			APP_TRACE_LOG(LL_ERR, L"Memory allocation failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		// Get Signer Information.
		lRetVal = g_winAPIs->CryptMsgGetParam(lCryptMsgHandle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)lSignerInfoPtr, &lSignerInfoSize);
		if (!lRetVal)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(2) failed with error: %u", dwErrorCode);
			delete[] lSignerInfoPtr;
			return dwErrorCode;
		}

		aSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>( lSignerInfoPtr, [](PCMSG_SIGNER_INFO p) { delete[] p; } );
		aCertStore = lStoreHandle;

		return ERROR_SUCCESS;
	}

	PCCERT_CHAIN_CONTEXT CryptoApiWrapper::GetCertChainContext(BYTE* signatureBuffer, ULONG cbSignatureBuffer)
	{
		CRYPT_DATA_BLOB signatureBlob = { 0 };
		signatureBlob.cbData = cbSignatureBuffer;
		signatureBlob.pbData = signatureBuffer;

		// Get the cert content
		HCERTSTORE certStoreT = nullptr;
		HCRYPTMSG signedMessageT = nullptr;
		if (!g_winAPIs->CryptQueryObject(
			CERT_QUERY_OBJECT_BLOB,
			&signatureBlob,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,      // Reserved parameter
			NULL,   // No encoding info needed
			NULL,
			NULL,
			&certStoreT,
			&signedMessageT,
			NULL))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptQueryObject failed with error: %u/%p", dwErrorCode, dwErrorCode);
			return nullptr;
		}

		SafeCertStore certStore(certStoreT);
		SafeCryptMsg signedMessage(signedMessageT);

		// Get the signer size and information from the signed data message
		// The properties of the signer info will be used to uniquely identify the signing certificate in the certificate store
		CMSG_SIGNER_INFO* signerInfo = NULL;
		DWORD signerInfoSize = 0;
		if (!g_winAPIs->CryptMsgGetParam(signedMessage.get(), CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(1) failed with error: %u", dwErrorCode);
			return nullptr;
		}

		// Check that the signer info size is within reasonable bounds; under the max length of a string for the issuer field
		if (signerInfoSize == 0 || signerInfoSize >= STRSAFE_MAX_CCH)
		{
			APP_TRACE_LOG(LL_ERR, L"Signer info size is invalid: %u", signerInfoSize);
			return nullptr;
		}

		std::vector <BYTE> signerInfoBuffer(signerInfoSize);
		signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuffer.data());
		if (!g_winAPIs->CryptMsgGetParam(signedMessage.get(), CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(2) failed with error: %u", dwErrorCode);
			return nullptr;
		}

		// Get the signing certificate from the certificate store based on the issuer and serial number of the signer info
		CERT_INFO certInfo;
		certInfo.Issuer = signerInfo->Issuer;
		certInfo.SerialNumber = signerInfo->SerialNumber;

		SafeCertContext signingCertContext(g_winAPIs->CertGetSubjectCertificateFromStore(certStore.get(), ENCODING, &certInfo));
		if (signingCertContext.get() == NULL)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertGetSubjectCertificateFromStore failed with error: %u", dwErrorCode);
			return nullptr;
		}

		// Get the signing certificate chain context.  Do not connect online for URL
		// retrievals. If CertVerifyCertificateChainPolicy fails to validate the certificates
		//  we call WinVerifyTrust, which also checks if a package was timestamped while the cert was valid.
		// If it returns ERROR_SUCCESS or "0" the signature is valid.
		CERT_CHAIN_PARA certChainParameters = { 0 };
		certChainParameters.cbSize = sizeof(CERT_CHAIN_PARA);
		certChainParameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
		DWORD certChainFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
		PCCERT_CHAIN_CONTEXT certChainContext;

		if (!g_winAPIs->CertGetCertificateChain(
			HCCE_LOCAL_MACHINE,
			signingCertContext.get(),
			NULL,   // Use the current system time for CRL validation
			certStore.get(),
			&certChainParameters,
			certChainFlags,
			NULL,   // Reserved parameter; must be NULL
			&certChainContext))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertGetCertificateChain failed with error: %u", dwErrorCode);
			return nullptr;
		}

		return certChainContext;
	}

	bool CryptoApiWrapper::IsMicrosoftTrustedChainForLegacySystems(PCCERT_CHAIN_CONTEXT certChainContext)
	{
		static constexpr unsigned HASH_BYTES = 32;
		const BYTE MicrosoftApplicationRootList[HASH_BYTES] = {
			// The following is the SHA256 of PublicKey for the Microsoft Application
			// Root:
			//      CN=Microsoft Root Certificate Authority 2011
			//      O=Microsoft Corporation
			//      L=Redmond
			//      S=Washington
			//      C=US
			//
			//  NotBefore:: Tue Mar 22 15:05:28 2011
			//  NotAfter:: Sat Mar 22 15:13:04 2036
			0x4A, 0xBB, 0x05, 0x94, 0xD3, 0x03, 0xEF, 0x70, 0x77, 0x13,
			0x88, 0x34, 0xAB, 0x31, 0x5E, 0x94, 0x1E, 0x96, 0x30, 0x93,
			0xE0, 0x5B, 0x4B, 0x14, 0xAF, 0x5D, 0xCB, 0x52, 0x77, 0x12,
			0xC0, 0x0A
		};

		PCERT_SIMPLE_CHAIN chain = certChainContext->rgpChain[0];
		DWORD chainElement = chain->cElement;;
		PCCERT_CONTEXT cert = chain->rgpElement[chainElement - 1]->pCertContext;
		BYTE keyId[HASH_BYTES]{ 0x0 };
		DWORD keyIdLength = HASH_BYTES;

		if (!g_winAPIs->CryptHashCertificate2(
			BCRYPT_SHA256_ALGORITHM,
			0,
			nullptr,
			cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
			cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
			keyId,
			&keyIdLength) ||
			HASH_BYTES != keyIdLength)
		{
			APP_TRACE_LOG(LL_ERR, L"CryptHashCertificate2 failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		return (0 == memcmp(MicrosoftApplicationRootList, keyId, HASH_BYTES));
	}

	bool CryptoApiWrapper::IsMicrosoftTrustedChain(PCCERT_CHAIN_CONTEXT certChainContext)
	{
		// Validate that the certificate chain is rooted in one of the well-known MS root certs
		CERT_CHAIN_POLICY_PARA policyParameters = { 0 };
		policyParameters.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
		CERT_CHAIN_POLICY_STATUS policyStatus = { 0 };
		policyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
		policyParameters.dwFlags = MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG;

		if (!g_winAPIs->CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, certChainContext, &policyParameters, &policyStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"CertVerifyCertificateChainPolicy failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		bool chainsToTrustedRoot = (policyStatus.dwError == ERROR_SUCCESS);
		if (!chainsToTrustedRoot && policyStatus.dwError == CERT_E_UNTRUSTEDROOT)
		{   // CertVerifyCertificateChainPolicy fails with CERT_E_UNTRUSTEDROOT on Win7.
			chainsToTrustedRoot = IsMicrosoftTrustedChainForLegacySystems(certChainContext);
		}
		return chainsToTrustedRoot;
	}

	bool CryptoApiWrapper::IsAuthenticodeTrustedChain(PCCERT_CHAIN_CONTEXT certChainContext)
	{
		CERT_CHAIN_POLICY_PARA policyParameters = { 0 };
		policyParameters.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
		CERT_CHAIN_POLICY_STATUS policyStatus = { 0 };
		policyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);

		//policyParameters.dwFlags = MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG;
		if (!g_winAPIs->CertVerifyCertificateChainPolicy(
			CERT_CHAIN_POLICY_AUTHENTICODE,
			certChainContext,
			&policyParameters,
			&policyStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"CertVerifyCertificateChainPolicy failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		bool isAuthenticode = (ERROR_SUCCESS == policyStatus.dwError);

		policyParameters = { 0 };
		policyParameters.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
		policyStatus = { 0 };
		policyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
		if (!g_winAPIs->CertVerifyCertificateChainPolicy(
			CERT_CHAIN_POLICY_BASE,
			certChainContext,
			&policyParameters,
			&policyStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"CertVerifyCertificateChainPolicy failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		bool chainsToTrustedRoot = (ERROR_SUCCESS == policyStatus.dwError);
		return isAuthenticode && chainsToTrustedRoot;
	}

	bool CryptoApiWrapper::IsCertificateSelfSigned(PCCERT_CONTEXT pContext, DWORD dwEncoding)
	{
		if (!pContext || !pContext->pCertInfo)
			return false;

		if (!g_winAPIs->CertCompareCertificateName(dwEncoding, &pContext->pCertInfo->Issuer, &pContext->pCertInfo->Subject))
		{
//			const auto dwErrorCode = g_winAPIs->GetLastError();
//			APP_TRACE_LOG(LL_ERR, L"CertFindCertificateInStore failed with error: %u", dwErrorCode);
			return false;
		}

		DWORD dwFlag = CERT_STORE_SIGNATURE_FLAG;
		if (!g_winAPIs->CertVerifySubjectCertificateContext(pContext, pContext, &dwFlag) || dwFlag & CERT_STORE_SIGNATURE_FLAG)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertVerifySubjectCertificateContext failed with error: %u", dwErrorCode);
			return false;
		}

		return true;
	}

	bool CryptoApiWrapper::IsCertificateRevoked(PCCERT_CONTEXT pContext)
	{
		if (!pContext || !pContext->pCertInfo)
			return false;

		CERT_ENHKEY_USAGE EnhkeyUsage{};
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier = NULL;

		CERT_USAGE_MATCH CertUsage{};
		CertUsage.dwType = USAGE_MATCH_TYPE_AND;
		CertUsage.Usage = EnhkeyUsage;

		CERT_CHAIN_PARA ChainPara{};
		ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
		ChainPara.RequestedUsage = CertUsage;

		PCCERT_CHAIN_CONTEXT pChainContext;
		if (!g_winAPIs->CertGetCertificateChain(NULL, pContext, NULL, NULL, &ChainPara, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, &pChainContext))
		{
			APP_TRACE_LOG(LL_ERR, L"CertGetCertificateChain failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		CERT_CHAIN_POLICY_PARA ChainPolicy = { 0 };
		ChainPolicy.cbSize = sizeof(ChainPolicy);

		CERT_CHAIN_POLICY_STATUS PolicyStatus = { 0 };
		PolicyStatus.cbSize = sizeof(PolicyStatus);

		if (!g_winAPIs->CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, &ChainPolicy, &PolicyStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"CertVerifyCertificateChainPolicy failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		CERT_REVOCATION_STATUS revocationStatus;
		revocationStatus.cbSize = sizeof(CERT_REVOCATION_STATUS);

		auto pCerts = new (std::nothrow) PCERT_CONTEXT[pChainContext->cChain];
		if (!pCerts)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for certificates");
			return false;
		}

		for (DWORD i = 0; i < pChainContext->cChain; i++)
		{
			pCerts[i] = (PCERT_CONTEXT)(pChainContext->rgpChain[i]->rgpElement[0]->pCertContext);
		}

		DWORD revocationCheckType = CERT_VERIFY_REV_CHAIN_FLAG;
		if (!g_winAPIs->CertVerifyRevocation(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE, pChainContext->cChain, (void**)pCerts, revocationCheckType, NULL, &revocationStatus))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			const auto dwErrorLevel = dwErrorCode == CRYPT_E_REVOCATION_OFFLINE ? LL_TRACE : LL_ERR;
			APP_TRACE_LOG(dwErrorLevel, L"CertVerifyRevocation failed with error: %u (%p)", dwErrorCode, dwErrorCode);
			delete[] pCerts;
			return false;
		}
		
		delete[] pCerts;

		const auto bRevoked = pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR;
		if (bRevoked)
		{
			APP_TRACE_LOG(LL_WARN, L"Revocation status: %u, %u, %u", revocationStatus.dwError, pChainContext->TrustStatus.dwErrorStatus, pChainContext->TrustStatus.dwInfoStatus);
		}
		return bRevoked;
	}

	bool CryptoApiWrapper::IsCACert(PCCERT_CONTEXT pCertContext)
	{
		PCERT_EXTENSION certExtension = g_winAPIs->CertFindExtension(
			szOID_BASIC_CONSTRAINTS2,
			pCertContext->pCertInfo->cExtension,
			pCertContext->pCertInfo->rgExtension
		);

		CERT_BASIC_CONSTRAINTS2_INFO* basicConstraintsT = NULL;
		DWORD cbDecoded = 0;
		if (certExtension && g_winAPIs->CryptDecodeObjectEx(
			X509_ASN_ENCODING,
			X509_BASIC_CONSTRAINTS2,
			certExtension->Value.pbData,
			certExtension->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG,
			NULL/*pDecodePara*/,
			(LPVOID*)&basicConstraintsT,
			&cbDecoded))
		{
			SafeLocal basicConstraints(basicConstraintsT);
			return basicConstraintsT->fCA ? true : false;
		}
		return false;
	}

	PCCERT_CONTEXT CryptoApiWrapper::GetCertContext(BYTE* signatureBuffer, ULONG cbSignatureBuffer, bool allowSelfSignedCert)
	{
		CERT_BLOB blob;
		blob.pbData = signatureBuffer;
		blob.cbData = cbSignatureBuffer;

		DWORD dwExpectedContentType = CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED;
		HCERTSTORE certStoreHandleT = NULL;
		DWORD dwContentType = 0;
		if (!g_winAPIs->CryptQueryObject(
			CERT_QUERY_OBJECT_BLOB,
			&blob,
			dwExpectedContentType,
			CERT_QUERY_FORMAT_FLAG_ALL,
			0,
			NULL,
			&dwContentType,
			NULL,
			&certStoreHandleT,
			NULL,
			NULL))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptQueryObject failed with error: %u/%p", dwErrorCode, dwErrorCode);
			return NULL;
		}
		SafeCertStore certStoreHandle(certStoreHandleT);

		if (dwContentType == CERT_QUERY_CONTENT_CERT)
		{
			return g_winAPIs->CertEnumCertificatesInStore(certStoreHandle.get(), NULL);
		}
		else
		{
			PCCERT_CONTEXT pCertContext = NULL;
			while (NULL != (pCertContext = g_winAPIs->CertEnumCertificatesInStore(certStoreHandle.get(), pCertContext)))
			{
				if (IsCertificateSelfSigned(pCertContext, pCertContext->dwCertEncodingType))
				{
					if (allowSelfSignedCert)
						return pCertContext;
					continue;
				}
				if (IsCACert(pCertContext))
				{
					continue;
				}
				else
				{
					return pCertContext;
				}
			}
			return NULL;
		}
	}

	DWORD CryptoApiWrapper::getCertificateContext(std::shared_ptr <CMSG_SIGNER_INFO> aSignerInfo, HCERTSTORE aCertStore, PCCERT_CONTEXT& aCertContextPtr)
	{
		CERT_INFO CertInfo = { 0 };
		CertInfo.Issuer = aSignerInfo->Issuer;
		CertInfo.SerialNumber = aSignerInfo->SerialNumber;

		auto pCertContext = g_winAPIs->CertFindCertificateInStore(aCertStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
		if (!pCertContext)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertFindCertificateInStore failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		aCertContextPtr = pCertContext;
		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::queryCertificateInfo(PCCERT_CONTEXT aCertContext, DWORD aType, std::wstring& aOutputName)
	{
		auto lNameLength = g_winAPIs->CertGetNameStringW(aCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, aType, NULL, NULL, 0);
		if (!lNameLength)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(1) failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		std::vector <wchar_t> lNameVector;
		lNameVector.reserve(lNameLength);

		// Get Issuer name.
		lNameLength = g_winAPIs->CertGetNameStringW(aCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, aType, NULL, lNameVector.data(), lNameLength);
		if (!lNameLength)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(2) failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		// aOutputName.assign(lNameVector.data(), lNameLength);
		aOutputName = lNameVector.data();
		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::queryProgAndPublisher(PCMSG_SIGNER_INFO pSignerInfo, std::wstring& aProgName, std::wstring& aPublisherLink, std::wstring& aMoreInfoLink)
	{
		struct SProgPublisherInfo
		{
			std::wstring lpszProgramName;
			std::wstring lpszPublisherLink;
			std::wstring lpszMoreInfoLink;
		};

		auto GetProgAndPublisherInfo = [](PCMSG_SIGNER_INFO pSignerInfo, SProgPublisherInfo* Info, DWORD& pdwErrCode)
		{
			BOOL fReturn = FALSE;
			PSPC_SP_OPUS_INFO OpusInfo = NULL;

			// Loop through authenticated attributes and find
			// SPC_SP_OPUS_INFO_OBJID OID.
			for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
			{
				if (!g_winAPIs->lstrcmpA(SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].pszObjId))
				{
					// Get Size of SPC_SP_OPUS_INFO structure.
					DWORD dwData = 0;
					auto fResult = g_winAPIs->CryptDecodeObject(ENCODING, SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
						pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData, 0, NULL, &dwData
					);
					if (!fResult)
					{
						pdwErrCode = g_winAPIs->GetLastError();
						APP_TRACE_LOG(LL_ERR, L"CryptDecodeObject(1) failed with error: %u", pdwErrCode);
						break;
					}

					// Allocate memory for SPC_SP_OPUS_INFO structure.
					OpusInfo = (PSPC_SP_OPUS_INFO)g_winAPIs->LocalAlloc(LPTR, dwData);
					if (!OpusInfo)
					{
						pdwErrCode = g_winAPIs->GetLastError();
						APP_TRACE_LOG(LL_ERR, L"LocalAlloc failed with error: %u", pdwErrCode);
						break;
					}

					// Decode and get SPC_SP_OPUS_INFO structure.
					fResult = g_winAPIs->CryptDecodeObject(ENCODING, SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
						pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData, 0, OpusInfo, &dwData
					);
					if (!fResult)
					{
						pdwErrCode = g_winAPIs->GetLastError();
						APP_TRACE_LOG(LL_ERR, L"CryptDecodeObject(2) failed with error: %u", pdwErrCode);
						break;
					}

					// Fill in Program Name if present.
					if (OpusInfo->pwszProgramName)
						Info->lpszProgramName = OpusInfo->pwszProgramName;

					// Fill in Publisher Information if present.
					if (OpusInfo->pPublisherInfo)
					{
						switch (OpusInfo->pPublisherInfo->dwLinkChoice)
						{
						case SPC_URL_LINK_CHOICE:
							Info->lpszPublisherLink = OpusInfo->pPublisherInfo->pwszUrl;
							break;

						case SPC_FILE_LINK_CHOICE:
							Info->lpszPublisherLink = OpusInfo->pPublisherInfo->pwszFile;
							break;

						default:
							break;
						}
					}

					// Fill in More Info if present.
					if (OpusInfo->pMoreInfo)
					{
						switch (OpusInfo->pMoreInfo->dwLinkChoice)
						{
						case SPC_URL_LINK_CHOICE:
							Info->lpszMoreInfoLink = OpusInfo->pMoreInfo->pwszUrl;
							break;

						case SPC_FILE_LINK_CHOICE:
							Info->lpszMoreInfoLink = OpusInfo->pMoreInfo->pwszFile;
							break;

						default:
							break;
						}
					}

					fReturn = TRUE;
					break;
				}
			}

			if (OpusInfo)
			{
				g_winAPIs->LocalFree(OpusInfo);
				OpusInfo = NULL;
			}

			return fReturn;
		};

		DWORD dwErrCode = ERROR_SUCCESS;
		SProgPublisherInfo info;
		auto bRet = GetProgAndPublisherInfo(pSignerInfo, &info, dwErrCode);
		if (!bRet)
		{
			APP_TRACE_LOG(dwErrCode ? LL_ERR : LL_WARN, L"GetProgAndPublisherInfo failed with error: %u", dwErrCode);
			return dwErrCode;
		}

		aProgName = info.lpszProgramName;
		aPublisherLink = info.lpszPublisherLink;
		aMoreInfoLink = info.lpszMoreInfoLink;
		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::getSignatureAlgoWstring(CRYPT_ALGORITHM_IDENTIFIER* pSigAlgo, std::wstring& signatureAlgo)
	{
		if (!pSigAlgo || !pSigAlgo->pszObjId)
			return ERROR_INVALID_PARAMETER;

		auto pCOI = g_winAPIs->CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pSigAlgo->pszObjId, 0);
		if (!pCOI)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptFindOIDInfo failed with error: %u", dwErrorCode);
			return dwErrorCode;
		}

		if (pCOI && pCOI->pwszName)
			// signatureAlgo.assign(pCOI->pwszName);
			signatureAlgo = pCOI->pwszName;
		else
			// signatureAlgo.assign(stdext::to_wide(pSigAlgo->pszObjId));
			signatureAlgo = stdext::to_wide(pSigAlgo->pszObjId);
		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::getTimeStampSignerInfo(std::shared_ptr<CMSG_SIGNER_INFO>& aSignerInfo, std::shared_ptr<CMSG_SIGNER_INFO>& aCounterSignerInfo)
	{
		aCounterSignerInfo = nullptr;

		bool lFoundCounterSign = false;
		PCMSG_SIGNER_INFO pCounterSignerInfo = nullptr;

		// Loop through unathenticated attributes for
		// szOID_RSA_counterSign OID.
		for (DWORD n = 0; n < aSignerInfo->UnauthAttrs.cAttr; n++)
		{
			if (g_winAPIs->lstrcmpA(aSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign) == 0)
			{
				// Get size of CMSG_SIGNER_INFO structure.
				DWORD dwSize = 0;
				auto lRetValBool = g_winAPIs->CryptDecodeObject(
					ENCODING, PKCS7_SIGNER_INFO_WC, aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData, aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData, 0, NULL, &dwSize
				);
				if (!lRetValBool)
				{
					const auto dwErrorCode = g_winAPIs->GetLastError();
					APP_TRACE_LOG(LL_ERR, L"CryptDecodeObject(1) failed with error: %u", dwErrorCode);
					return dwErrorCode;
				}

				// Allocate memory for CMSG_SIGNER_INFO.
				pCounterSignerInfo = (PCMSG_SIGNER_INFO)new BYTE[dwSize];
				if (!pCounterSignerInfo)
				{
					const auto dwErrorCode = errno;
					APP_TRACE_LOG(LL_ERR, L"Memory allocation failed with error: %u", dwErrorCode);
					return dwErrorCode;
				}

				// Decode and get CMSG_SIGNER_INFO structure
				// for timestamp certificate.
				lRetValBool = g_winAPIs->CryptDecodeObject(
					ENCODING, PKCS7_SIGNER_INFO_WC, aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData, aSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0, (PVOID)pCounterSignerInfo, &dwSize
				);
				if (!lRetValBool)
				{
					const auto dwErrorCode = g_winAPIs->GetLastError();
					APP_TRACE_LOG(LL_ERR, L"CryptDecodeObject(2) failed with error: %u", dwErrorCode);
					delete[] pCounterSignerInfo;
					return dwErrorCode;
				}

				lFoundCounterSign = true;
				break;
			}
		}

		if (!lFoundCounterSign)
			return ERROR_GEN_FAILURE;

		aCounterSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>(pCounterSignerInfo);
		return ERROR_SUCCESS;
	}

	DWORD CryptoApiWrapper::getCertificateSerialNumber(PCCERT_CONTEXT aCertContext, std::wstring& aSerialNumberWstr)
	{
		if (!aCertContext)
			return ERROR_INVALID_PARAMETER;

		aSerialNumberWstr = L"";

		const int lBufferSize = 3;
		wchar_t lTempBuffer[lBufferSize * 2]{ L'\0' };

		auto lDataBytesCount = aCertContext->pCertInfo->SerialNumber.cbData;
		for (DWORD n = 0; n < lDataBytesCount; n++)
		{
			auto lSerialByte = aCertContext->pCertInfo->SerialNumber.pbData[lDataBytesCount - (n + 1)];

			swprintf(lTempBuffer, lBufferSize * 2, xorstr_(L"%02x"), lSerialByte);

			aSerialNumberWstr += std::wstring(lTempBuffer, 2);
		}

		return ERROR_SUCCESS;
	}

	bool CryptoApiWrapper::getDateOfTimeStamp(std::shared_ptr<CMSG_SIGNER_INFO>& aSignerInfo, std::shared_ptr<SYSTEMTIME>& aSysTime)
	{
		aSysTime = std::make_shared<SYSTEMTIME>();

		bool bRetVal = false;
		FILETIME lft, ft;

		// Loop through authenticated attributes and find
		// szOID_RSA_signingTime OID.
		for (DWORD n = 0; n < aSignerInfo->AuthAttrs.cAttr; n++)
		{
			if (g_winAPIs->lstrcmpA(szOID_RSA_signingTime, aSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
			{
				// Decode and get FILETIME structure.
				DWORD dwData = sizeof(ft);
				bRetVal = !!g_winAPIs->CryptDecodeObject(
					ENCODING, szOID_RSA_signingTime, aSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					aSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData, 0, (PVOID)&ft, &dwData
				);
				if (!bRetVal)
				{
					const auto dwErrorCode = g_winAPIs->GetLastError();
					APP_TRACE_LOG(LL_ERR, L"CryptDecodeObject(3) failed with error: %u", dwErrorCode);
					return false;
				}

				// Convert to local time.
				g_winAPIs->FileTimeToLocalFileTime(&ft, &lft);
				g_winAPIs->FileTimeToSystemTime(&lft, aSysTime.get());

				bRetVal = true;
				break;
			}
		}

		return bRetVal;
	}
};
