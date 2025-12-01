#pragma once
#include <string>

namespace NoMercyCore
{
	class CertificateInfoBase
	{
	public:
		CertificateInfoBase() {};
		virtual ~CertificateInfoBase() {};

	public:
		bool timeValid{ false };
		bool selfSigned{ false };
		bool caCert{ false };
		bool revoked{ false };
		
		std::wstring serialNumber;
		std::wstring subjectName;
		std::wstring issuerName;
		std::wstring signAlgorithm;
		
		std::wstring programName;
		std::wstring publisherLink;
		std::wstring moreInfoLink;
	};
};
