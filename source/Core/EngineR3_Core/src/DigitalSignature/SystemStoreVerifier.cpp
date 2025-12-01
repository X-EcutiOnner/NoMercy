#include "../../include/PCH.hpp"
#include "../../include/PeSignatureVerifier.hpp"
#include "../../include/MemAllocator.hpp"

#define CERT_DOMAIN_DATA 1
#define CERT_ISSUER_DATA 2

namespace NoMercyCore
{
#pragma warning(push) 
#pragma warning(disable: 4706)
	BOOL WINAPI checkSystemStore(const void* pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void* pvReserved, void* pvArg)
	{
		PENUM_ARG enumArg = (PENUM_ARG)pvArg;
		std::vector <CERT_SEARCH_DATA> searchData = enumArg->searchData;
		std::vector <FindData>* found = enumArg->found;
		std::vector <FailInfo>* fails = enumArg->fails;

		DWORD flags = (dwFlags & CERT_SYSTEM_STORE_LOCATION_MASK);
#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Target flags: %u", flags);
#endif

		LPCWSTR storeName = nullptr;
		if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG)
		{
			const auto pRelPara = (const CERT_SYSTEM_STORE_RELOCATE_PARA*)pvSystemStore;
			storeName = pRelPara->pwszSystemStore;
		}
		else
		{
			storeName = (LPCWSTR)pvSystemStore;
		}

#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Target store name: %ls", storeName ? storeName : xorstr_(L"<null>"));
#endif

		auto hStore = g_winAPIs->CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM, 0, NULL, flags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, storeName);
		if (!hStore)
		{
			APP_TRACE_LOG(LL_ERR, L"CertOpenStore failed with error: %u", g_winAPIs->GetLastError());

			FailInfo fi;
			fi.type = xorstr_(L"CertOpenStore");
			fi.data = storeName;
			fails->push_back(fi);

			return TRUE;
		}

		PCCERT_CONTEXT pCertContext = nullptr;
		while ((pCertContext = g_winAPIs->CertEnumCertificatesInStore(hStore, pCertContext)))
		{
			if (pCertContext->pCertInfo)
			{
				const auto dwReqSize = g_winAPIs->CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Issuer), CERT_X500_NAME_STR, NULL, 0);
				if (!dwReqSize)
				{
					APP_TRACE_LOG(LL_ERR, L"CertNameToStrW size query failed with error: %u", g_winAPIs->GetLastError());

					FailInfo fi;
					fi.type = xorstr_(L"CertNameToStrW_1");
					fi.data = std::to_wstring(g_winAPIs->GetLastError());
					fails->push_back(fi);

					continue;
				}

				auto spwszCertBuffer = std::unique_ptr<wchar_t>(new (std::nothrow) wchar_t[dwReqSize]);
				if (!spwszCertBuffer || !spwszCertBuffer.get())
				{
					APP_TRACE_LOG(LL_ERR, L"Memory allocation with size: %u failed with error: %d", dwReqSize, errno);

					FailInfo fi;
					fi.type = xorstr_(L"spwszCertBuffer");
					fi.data = std::to_wstring(g_winAPIs->GetLastError());
					fails->push_back(fi);

					continue;
				}

				if (!g_winAPIs->CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Issuer), CERT_X500_NAME_STR, spwszCertBuffer.get(), dwReqSize))
				{
					APP_TRACE_LOG(LL_ERR, L"CertNameToStrW failed with error: %u", g_winAPIs->GetLastError());

					FailInfo fi;
					fi.type = xorstr_(L"CertNameToStrW_2");
					fi.data = std::to_wstring(g_winAPIs->GetLastError());
					fails->push_back(fi);

					continue;
				}

				for (auto i = 0u; i < searchData.size(); ++i)
				{
					if (wcsstr(spwszCertBuffer.get(), searchData[i].data.c_str()))
					{
						FindData fd;
						fd.id = i;
						std::wstring ws(spwszCertBuffer.get());
						fd.data.push_back(ws);
						found->push_back(fd);
					}
				}

				if (pCertContext->pCertInfo->rgExtension)
				{
					if ((strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_SUBJECT_ALT_NAME) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_SUBJECT_ALT_NAME2) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_ISSUER_ALT_NAME) == 0) ||
						(strcmp(pCertContext->pCertInfo->rgExtension->pszObjId, szOID_ISSUER_ALT_NAME2) == 0))
					{
						DWORD dwSize = 0;
						g_winAPIs->CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							szOID_SUBJECT_ALT_NAME,
							pCertContext->pCertInfo->rgExtension->Value.pbData,
							pCertContext->pCertInfo->rgExtension->Value.cbData,
							CRYPT_DECODE_NOCOPY_FLAG,
							NULL,
							nullptr,
							&dwSize
						);
						if (!dwSize)
						{
							APP_TRACE_LOG(LL_ERR, L"CryptDecodeObjectEx size query failed with error: %u", g_winAPIs->GetLastError());

							FailInfo fi;
							fi.type = xorstr_(L"CryptDecodeObjectEx_1");
							fi.data = std::to_wstring(g_winAPIs->GetLastError());
							fails->push_back(fi);

							continue;
						}

						auto pCertAltNameInfo = (CERT_ALT_NAME_INFO*)CMemHelper::Allocate(dwSize);
						if (!pCertAltNameInfo)
						{
							APP_TRACE_LOG(LL_ERR, L"Memory allocation with size: %u failed with error: %d", dwSize, g_winAPIs->GetLastError());

							FailInfo fi;
							fi.type = xorstr_(L"CERT_ALT_NAME_INFO");
							fi.data = std::to_wstring(g_winAPIs->GetLastError());
							fails->push_back(fi);

							continue;
						}

						const auto bDecodeRet = g_winAPIs->CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							szOID_SUBJECT_ALT_NAME,
							pCertContext->pCertInfo->rgExtension->Value.pbData,
							pCertContext->pCertInfo->rgExtension->Value.cbData,
							CRYPT_DECODE_NOCOPY_FLAG,
							NULL,
							pCertAltNameInfo,
							&dwSize
						);
						if (!bDecodeRet)
						{
							APP_TRACE_LOG(LL_ERR, L"CryptDecodeObjectEx failed with error: %u", g_winAPIs->GetLastError());

							FailInfo fi;
							fi.type = xorstr_(L"CryptDecodeObjectEx_2");
							fi.data = std::to_wstring(g_winAPIs->GetLastError());
							fails->push_back(fi);

							CMemHelper::Free(pCertAltNameInfo);
							continue;
						}

						for (auto i = 0u; i < pCertAltNameInfo->cAltEntry; ++i)
						{
							if (pCertAltNameInfo->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME)
							{
								for (auto j = 0u; j < searchData.size(); ++j)
								{
									if (searchData[j].type == CERT_DOMAIN_DATA)
									{
										if (searchData[j].data.compare(pCertAltNameInfo->rgAltEntry[i].pwszDNSName) == 0)
										{
											FindData fd;
											fd.id = j;
											std::wstring ws(spwszCertBuffer.get());
											fd.data.push_back(ws);
											ws = pCertAltNameInfo->rgAltEntry[i].pwszDNSName;
											fd.data.push_back(ws);
											found->push_back(fd);
										}
									}
								}
							}
						}

						CMemHelper::Free(pCertAltNameInfo);
					}
				}
			}
		}

		g_winAPIs->CertCloseStore(hStore, CERT_CLOSE_STORE_CHECK_FLAG);
		return TRUE;
	}
#pragma warning(pop) 

	BOOL WINAPI LocationCallBack(LPCWSTR pwszStoreLocation, DWORD dwFlags, void* pvReserved, void* pvArg)
	{
		PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;

		dwFlags &= CERT_SYSTEM_STORE_MASK;
		dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;

		if (!g_winAPIs->CertEnumSystemStore(dwFlags, (void*)pEnumArg->pvStoreLocationPara, pEnumArg, &checkSystemStore))
		{
			APP_TRACE_LOG(LL_ERR, L"CertEnumSystemStore failed with error: %u", g_winAPIs->GetLastError());
			return FALSE;
		}
		return TRUE;
	}

	void PeSignatureVerifier::checkCertificates(std::vector <CERT_SEARCH_DATA> searchData, std::vector <FindData>* found, std::vector <FailInfo>* fails)
	{
		ENUM_ARG EnumArg{ 0 };
		EnumArg.dwFlags = 0;
		EnumArg.searchData = searchData;
		EnumArg.found = found;
		EnumArg.fails = fails;
		EnumArg.pvStoreLocationPara = NULL;

		if (!g_winAPIs->CertEnumSystemStoreLocation(0, &EnumArg, &LocationCallBack))
		{
			APP_TRACE_LOG(LL_ERR, L"CertEnumSystemStoreLocation failed with error: %u", g_winAPIs->GetLastError());
		}
	}
};
