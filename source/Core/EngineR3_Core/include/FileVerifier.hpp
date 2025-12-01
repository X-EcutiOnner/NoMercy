#pragma once

namespace NoMercyCore
{
	struct SCertContext
	{
		DWORD dwEncodingType{ 0 };
		DWORD dwVersion{ 0 };
		std::wstring wstObjectID;
		std::wstring wstPubKeyParam;
		std::wstring wstSerialNum;
		std::wstring wstNotBefore;
		std::wstring wstNotAfter;
		std::wstring wstPubKeyAlgoObjID;
		std::wstring wstPubKeyAlgoParam;
		DWORD dwUnusedBits{ 0 };
		DWORD dwExtension{ 0 };
		std::wstring wstPubKey;
		std::wstring wstIssuer;
		std::wstring wstSubject;
		std::wstring wstSubjectRDN;
	};
	struct SCertArray
	{
		WIN_CERTIFICATE* pCertificate{ nullptr };
		DWORD dwLength{ 0 };
		PCCERT_CONTEXT pCertContext{ nullptr }; // clear with CertFreeCertificateContext
	};
	
	class FileVerifier
	{
	public:
		static bool ExtractEmbeddedSignatures(HANDLE hFileHandle, std::vector <SCertArray>& vCertificates);
		
		static std::optional <bool> GetEmbeddedCertificates(const std::wstring& wstFileName, std::wstring& stRefObjID, std::vector <SCertContext>& vecCerts);
		static std::optional <bool> GetEmbeddedCertificates(const std::wstring& wstFileName, std::vector <SCertContext>& vCertificates);
	};
};