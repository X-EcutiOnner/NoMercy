#include "../../include/PCH.hpp"
#include "../../include/FileVerifier.hpp"

namespace NoMercyCore
{	
	std::string GetCertificateType(WORD CertificateType)
	{
		std::string CertificateTypeStr;

		switch (CertificateType)
		{
		case WIN_CERT_TYPE_X509:
			CertificateTypeStr = xorstr_("X509");
			break;
		case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			CertificateTypeStr = xorstr_("PKCS Signed Data");
			break;
		case WIN_CERT_TYPE_RESERVED_1:
			CertificateTypeStr = xorstr_("Reserved 1");
			break;
		case WIN_CERT_TYPE_TS_STACK_SIGNED:
			CertificateTypeStr = xorstr_("Stack Signed");
			break;
		default:
			CertificateTypeStr = fmt::format(xorstr_("Unknown: {0}"), CertificateType);
			break;
		}

		return CertificateTypeStr;
	}
	std::string GetCertRevision(WORD wRevision)
	{
		std::string CertificateRevStr;

		switch (wRevision)
		{
		case WIN_CERT_REVISION_1_0:
			CertificateRevStr = xorstr_("1.0");
			break;
		case WIN_CERT_REVISION_2_0:
			CertificateRevStr = xorstr_("2.0");
			break;
		default:
			CertificateRevStr = fmt::format(xorstr_("Unknown: {0}"), wRevision);
			break;
		}

		return CertificateRevStr;
	}
	
	bool __FileTimeToLocalTimeW(PFILETIME ft, wchar_t* time)
	{
		FILETIME lft;
		auto ret = g_winAPIs->FileTimeToLocalFileTime(ft, &lft);
		if (!ret)
			return false;

		SYSTEMTIME st;
		ret = g_winAPIs->FileTimeToSystemTime(&lft, &st);
		if (!ret)
			return false;

		swprintf_s(
			time,
			MAX_PATH,
			xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
			st.wYear,
			st.wMonth,
			st.wDay,
			st.wHour,
			st.wMinute,
			st.wSecond
		);
		return true;
	}

	void DumpCertInfo(PCERT_INFO CertInfo, SCertContext& cert)
	{
		cert.dwVersion = CertInfo->dwVersion + 1;
		cert.wstObjectID = stdext::to_wide(CertInfo->SignatureAlgorithm.pszObjId);
		cert.wstPubKeyParam = stdext::dump_hex(CertInfo->SignatureAlgorithm.Parameters.pbData, CertInfo->SignatureAlgorithm.Parameters.cbData);
		cert.wstSerialNum = stdext::dump_hex(CertInfo->SerialNumber.pbData, CertInfo->SerialNumber.cbData);
		
		wchar_t NotBefore[MAX_PATH]{ L'\0' };
		__FileTimeToLocalTimeW(&CertInfo->NotBefore, NotBefore);
		cert.wstNotBefore = NotBefore;

		wchar_t NotAfter[MAX_PATH]{ L'\0' };
		__FileTimeToLocalTimeW(&CertInfo->NotAfter, NotAfter);
		cert.wstNotAfter = NotAfter;

		cert.wstPubKeyAlgoObjID = stdext::to_wide(CertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
		cert.wstPubKeyAlgoParam = stdext::dump_hex(CertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData, CertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData);

		cert.dwUnusedBits = CertInfo->SubjectPublicKeyInfo.PublicKey.cUnusedBits;
		cert.dwExtension = CertInfo->cExtension;

		cert.wstPubKey = stdext::dump_hex(CertInfo->SubjectPublicKeyInfo.PublicKey.pbData, CertInfo->SubjectPublicKeyInfo.PublicKey.cbData);
	}

#pragma warning(push) 
#pragma warning(disable: 4706)
	bool ExtractCertificateContext(PCCERT_CONTEXT pCertContext, std::vector <SCertContext>& vecCerts)
	{
		bool bRet = false;
		SCertContext ctx{};
		LPWSTR wszIssuer = NULL;
		LPWSTR wszSubject = NULL;
		LPWSTR wszSubjectRDN = NULL;
		DWORD dwData = 0;

		do
		{
			// APP_TRACE_LOG(LL_SYS, L"Cert encoding: %u", pCertContext->dwCertEncodingType);
			ctx.dwEncodingType = pCertContext->dwCertEncodingType;

			DumpCertInfo(pCertContext->pCertInfo, ctx);

			// Get Issuer name size.
			if (!(dwData = g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0)))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(1) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Allocate memory for Issuer name.
			wszIssuer = (LPWSTR)g_winAPIs->LocalAlloc(LPTR, dwData * sizeof(wchar_t));
			if (!wszIssuer)
			{
				APP_TRACE_LOG(LL_ERR, L"LocalAlloc(1) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Get Issuer name.
			if (!(g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, wszIssuer, dwData)))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(2) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			ctx.wstIssuer = wszIssuer;

			// Get Subject name size.
			if (!(dwData = g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(3) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Allocate memory for subject name.
			wszSubject = (LPWSTR)g_winAPIs->LocalAlloc(LPTR, dwData * sizeof(wchar_t));
			if (!wszSubject)
			{
				APP_TRACE_LOG(LL_ERR, L"LocalAlloc(2) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Get subject name.
			if (!(g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, wszSubject, dwData)))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(4) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			ctx.wstSubject = wszSubject;

			DWORD dwStrType = CERT_X500_NAME_STR;
			if (!(dwData = g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, NULL, 0)))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(5) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			
			wszSubjectRDN = (LPWSTR)g_winAPIs->LocalAlloc(0, dwData * sizeof(wchar_t));
			if (!wszSubjectRDN)
			{
				APP_TRACE_LOG(LL_ERR, L"LocalAlloc(3) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			if (!g_winAPIs->CertGetNameStringW(pCertContext, CERT_NAME_RDN_TYPE, 0, &dwStrType, wszSubjectRDN, dwData))
			{
				APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW(6) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}
			ctx.wstSubjectRDN = wszSubjectRDN;

			vecCerts.push_back(ctx);
			bRet = true;
		} while (false);
		
		if (wszIssuer)
		{
			g_winAPIs->LocalFree(wszIssuer);
			wszIssuer = nullptr;
		}
		if (wszSubject)
		{
			g_winAPIs->LocalFree(wszSubject);
			wszSubject = nullptr;
		}
		if (wszSubjectRDN)
		{
			g_winAPIs->LocalFree(wszSubjectRDN);
			wszSubjectRDN = nullptr;
		}

		return bRet;
	}
	
	bool DecodeCertificate(PBYTE Certificate, DWORD Length, std::wstring& stRefObjID, std::vector <SCertContext>& vecCerts)
	{
		CERT_BLOB data_blob;
		data_blob.cbData = Length;
		data_blob.pbData = Certificate;

		DWORD expected_types =
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
			CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED;

		DWORD dwEncoding, dwContentType, dwFormatType;
		HCERTSTORE CertStore = NULL;
		HCRYPTMSG Msg = NULL;
		if (!g_winAPIs->CryptQueryObject(
			CERT_QUERY_OBJECT_BLOB, &data_blob, expected_types, CERT_QUERY_FORMAT_FLAG_ALL,
			0, &dwEncoding, &dwContentType, &dwFormatType, &CertStore, &Msg, NULL
		))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptQueryObject failed with error: %u (%p)", dwErrorCode, dwErrorCode);
			return false;
		}
		
		PCCERT_CONTEXT PrevCertContext = NULL;
		while ((PrevCertContext = g_winAPIs->CertEnumCertificatesInStore(CertStore, PrevCertContext)))
		{
			ExtractCertificateContext(PrevCertContext, vecCerts);
		}

		g_winAPIs->CertCloseStore(CertStore, 0);
		g_winAPIs->CryptMsgClose(Msg);
		return true;
	}
#pragma warning(pop) 
	
	std::optional <bool> FileVerifier::GetEmbeddedCertificates(const std::wstring& wstFileName, std::wstring& stRefObjID, std::vector <SCertContext>& vecCerts)
	{
		if (wstFileName.empty())
			return std::nullopt;

		std::error_code ec{};
		if (!std::filesystem::exists(wstFileName, ec))
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls does not exist", wstFileName.c_str());
			return std::nullopt;
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls exist check failed with error: %hs", wstFileName.c_str(), ec.message().c_str());
			return std::nullopt;
		}
		
		auto fp = msl::file_ptr(wstFileName, xorstr_(L"rb"));
		if (!fp)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls open failed with error: %hs", wstFileName.c_str(), strerror(errno));
			return std::nullopt;
		}

		const auto nFileSize = fp.size();
		if (!nFileSize)
		{		
			APP_TRACE_LOG(LL_ERR, L"File %ls is empty", wstFileName.c_str());
			return std::nullopt;
		}

		std::vector <uint8_t> vBuffer(nFileSize);
		fp.read(vBuffer.data(), nFileSize);
		
		if (vBuffer.size() != nFileSize)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls read failed with error: %hs Read size: %u File size: %u", wstFileName.c_str(), strerror(errno), vBuffer.size(), nFileSize);
			return std::nullopt;
		}

		const auto pIDH = reinterpret_cast<IMAGE_DOS_HEADER*>(vBuffer.data());
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (1)", wstFileName.c_str());
			return std::nullopt;
		}

		const auto pINH = reinterpret_cast<IMAGE_NT_HEADERS32*>(vBuffer.data() + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (2)", wstFileName.c_str());
			return std::nullopt;
		}

		if (pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (3)", wstFileName.c_str());
			return std::nullopt;
		}
		
		const auto pIDD = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
		if (!pIDD || !pIDD->Size || !pIDD->VirtualAddress)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls does not contain security directory", wstFileName.c_str());
			return std::nullopt;
		}

		// tf? TODO
		if (pIDD->Size > nFileSize || pIDD->VirtualAddress > nFileSize)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls contains invalid security directory", wstFileName.c_str());
			return std::nullopt;
		}

		uint32_t pSignHdr[2]{ 0 };
		memcpy(pSignHdr, (LPCVOID)(vBuffer.data() + pIDD->VirtualAddress), sizeof(pSignHdr));

		if (pSignHdr[1] != 0x00020200)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (4)", wstFileName.c_str());
			return std::nullopt;
		}

		const auto SecurityDirectory = (LPWIN_CERTIFICATE)(vBuffer.data() + pIDD->VirtualAddress);
		APP_TRACE_LOG(LL_SYS, L"Length: %u, Revision: %d(%s), CertType: %d(%s)",
			SecurityDirectory->dwLength,
			SecurityDirectory->wRevision, GetCertRevision(SecurityDirectory->wRevision).c_str(),
			SecurityDirectory->wCertificateType, GetCertificateType(SecurityDirectory->wCertificateType).c_str()
		);

		if (SecurityDirectory->wRevision != WIN_CERT_REVISION_1_0 && SecurityDirectory->wRevision != WIN_CERT_REVISION_2_0)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (5)", wstFileName.c_str());
			return std::nullopt;
		}

		if (SecurityDirectory->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls is not a valid PE file (6)", wstFileName.c_str());
			return std::nullopt;
		}

		DWORD dwReqSize = 0;
		g_winAPIs->CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_CONTENT_INFO, SecurityDirectory->bCertificate, SecurityDirectory->dwLength, CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &dwReqSize);
		if (!dwReqSize)
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptDecodeObjectEx(1) failed with error: %u (%p)", dwErrorCode, dwErrorCode);
			return std::nullopt;
		}

		auto pbDecoded = (BYTE*)malloc(dwReqSize);
		if (!pbDecoded)
		{
			APP_TRACE_LOG(LL_ERR, L"malloc failed with error: %u", errno);
			return std::nullopt;
		}

		if (!g_winAPIs->CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_CONTENT_INFO, SecurityDirectory->bCertificate, SecurityDirectory->dwLength, CRYPT_DECODE_NOCOPY_FLAG, NULL, pbDecoded, &dwReqSize))
		{
			const auto dwErrorCode = g_winAPIs->GetLastError();
			APP_TRACE_LOG(LL_ERR, L"CryptDecodeObjectEx(2) failed with error: %u (%p)", dwErrorCode, dwErrorCode);
			free(pbDecoded);
			return std::nullopt;
		}
		
		auto content_info = (CRYPT_CONTENT_INFO*)pbDecoded;
		if (!content_info)
		{
			APP_TRACE_LOG(LL_ERR, L"content_info is null");
			free(pbDecoded);
			return std::nullopt;
		}

		auto bHasDecodedCert = false;
		switch (SecurityDirectory->wCertificateType)
		{
			case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
			{
				if (DecodeCertificate(content_info->Content.pbData, content_info->Content.cbData, stRefObjID, vecCerts))
					bHasDecodedCert = true;
			} break;
			
			case WIN_CERT_TYPE_X509:
			case WIN_CERT_TYPE_RESERVED_1:
			case WIN_CERT_TYPE_TS_STACK_SIGNED:
			default:
				free(pbDecoded);
				return false;
		}

		free(pbDecoded);
	
		return std::make_optional<bool>(bHasDecodedCert);
	}

	bool FileVerifier::ExtractEmbeddedSignatures(HANDLE hFileHandle, std::vector <SCertArray>& vCertificates)
	{
		DWORD dwCount = 0;
		DWORD indexes[128]{ 0 };
		if (!g_winAPIs->ImageEnumerateCertificates(hFileHandle, CERT_SECTION_TYPE_ANY, &dwCount, indexes, 128))
		{
			APP_TRACE_LOG(LL_ERR, L"ImageEnumerateCertificates failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		else if (!dwCount)
		{
			APP_TRACE_LOG(LL_WARN, L"Any embedded signature does not exist in file!");
			return false;
		}

		for (std::size_t i = 0; i < dwCount; i++)
		{
			DWORD dwSize = 0;
			g_winAPIs->ImageGetCertificateData(hFileHandle, indexes[i], NULL, &dwSize);
			if (!dwSize)
			{
				APP_TRACE_LOG(LL_ERR, L"ImageGetCertificateData (1) failed with error: %u", g_winAPIs->GetLastError());
				continue;
			}

			auto pCertificate = reinterpret_cast<LPWIN_CERTIFICATE>(g_winAPIs->HeapAlloc(g_winAPIs->GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1));
			if (!pCertificate)
			{
				APP_TRACE_LOG(LL_ERR, L"HeapAlloc failed with error: %u", g_winAPIs->GetLastError());
				continue;
			}
			
			if (g_winAPIs->ImageGetCertificateData(hFileHandle, indexes[i], pCertificate, &dwSize))
			{
				// extract the PKCS7 signed data     
				CRYPT_VERIFY_MESSAGE_PARA cvmp{ 0 };
				cvmp.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
				cvmp.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

				PCCERT_CONTEXT pCertContext = nullptr;
				if (!g_winAPIs->CryptVerifyMessageSignature(&cvmp, dwCount, pCertificate->bCertificate, pCertificate->dwLength, NULL, NULL, &pCertContext))
				{
					const auto dwErrorCode = g_winAPIs->GetLastError();
					APP_TRACE_LOG(
						dwErrorCode != CRYPT_E_NO_SIGNER ? LL_WARN : LL_TRACE,
						L"CryptVerifyMessageSignature failed with error: %u (%p)", 
						dwErrorCode, dwErrorCode
					);
				}

				vCertificates.push_back({ pCertificate, dwSize, pCertContext });
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"ImageGetCertificateData (2) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->HeapFree(g_winAPIs->GetProcessHeap(), 0, pCertificate);
			}
		}

		return true;
	}

	std::optional <bool> FileVerifier::GetEmbeddedCertificates(const std::wstring& wstFileName, std::vector <SCertContext>& vCertificates)
	{
		if (wstFileName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File name is empty");
			return std::nullopt;
		}

		std::error_code ec{};
		if (!std::filesystem::exists(wstFileName, ec))
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls does not exist", wstFileName.c_str());
			return std::nullopt;
		}
		else if (ec)
		{
			APP_TRACE_LOG(LL_ERR, L"File %ls exist check failed with error: %hs", wstFileName.c_str(), ec.message().c_str());
			return std::nullopt;
		}

		SafeHandle pkFileHandle = g_winAPIs->CreateFileW(wstFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!pkFileHandle.IsValid())
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileW failed with error: %u", g_winAPIs->GetLastError());
			return std::nullopt;
		}
		
		std::vector <SCertArray> vCertificatesTemp;
		if (!ExtractEmbeddedSignatures(pkFileHandle.get(), vCertificatesTemp))
		{
			APP_TRACE_LOG(LL_WARN, L"ExtractEmbeddedSignatures failed for file %ls", wstFileName.c_str());
			return std::nullopt;
		}

		auto bHasValidCert = false;
		for (std::size_t i = 0; i < vCertificatesTemp.size(); ++i)
		{
			const auto& pCert = vCertificatesTemp[i];

			if (pCert.pCertificate->wCertificateType & WIN_CERT_TYPE_X509)
			{
				APP_TRACE_LOG(LL_TRACE, L"Found X.509 certificate in file %ls", wstFileName.c_str());
				bHasValidCert = true;
			}
			else if (pCert.pCertificate->wCertificateType & WIN_CERT_TYPE_PKCS_SIGNED_DATA)
			{
				APP_TRACE_LOG(LL_TRACE, L"Found PKCS certificate in file %ls", wstFileName.c_str());
				bHasValidCert = true;
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Found unknown certificate: %u in file %ls", pCert.pCertificate->wCertificateType, wstFileName.c_str());

				for (const auto& cert : vCertificatesTemp)
				{
					g_winAPIs->HeapFree(g_winAPIs->GetProcessHeap(), 0, cert.pCertificate);
					g_winAPIs->CertFreeCertificateContext(cert.pCertContext);
				}
				return std::nullopt;
			}

			CRYPT_DATA_BLOB p7Data{};
			p7Data.cbData = pCert.dwLength - sizeof(DWORD) - sizeof(WORD) - sizeof(WORD);
			p7Data.pbData = pCert.pCertificate->bCertificate;

			auto store = g_winAPIs->CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, &p7Data);
			if (!store)
			{
				const auto dwErrorCode = g_winAPIs->GetLastError();
				APP_TRACE_LOG(LL_ERR, L"CertOpenStore failed with error: %u (%p)", dwErrorCode, dwErrorCode);

				for (const auto& cert : vCertificatesTemp)
				{
					g_winAPIs->HeapFree(g_winAPIs->GetProcessHeap(), 0, cert.pCertificate);
					g_winAPIs->CertFreeCertificateContext(cert.pCertContext);
				}
				return std::nullopt;
			}

			int count = 0;
			char signingOID[] = szOID_PKIX_KP_CODE_SIGNING;

			CERT_ENHKEY_USAGE keyUsage;
			keyUsage.cUsageIdentifier = 1;
			keyUsage.rgpszUsageIdentifier = (LPSTR*)g_winAPIs->LocalAlloc(LPTR, sizeof(LPSTR));
			keyUsage.rgpszUsageIdentifier[0] = &signingOID[0];

			PCCERT_CONTEXT certContext = NULL;
			do
			{
				certContext = g_winAPIs->CertFindCertificateInStore(store,
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
					CERT_FIND_ENHKEY_USAGE,
					&keyUsage,
					certContext
				);

				if (certContext)
				{
					ExtractCertificateContext(certContext, vCertificates);
				}
			} while (certContext);

			g_winAPIs->LocalFree(keyUsage.rgpszUsageIdentifier);
			g_winAPIs->CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG);

			g_winAPIs->HeapFree(g_winAPIs->GetProcessHeap(), 0, pCert.pCertificate);
			g_winAPIs->CertFreeCertificateContext(pCert.pCertContext);
		}

		if (!bHasValidCert)
		{
			APP_TRACE_LOG(LL_ERR, L"No valid certificate found in file %ls", wstFileName.c_str());
			return std::nullopt;
		}

		return std::make_optional<bool>(!vCertificates.empty());
	}
};
