#pragma once
#include "CertificateInfoBase.hpp"
#include <memory>

namespace NoMercyCore
{
	class TimestampCertificateInfo : public CertificateInfoBase
	{
	public:
		using TimmeStampCertPtr = std::shared_ptr <TimestampCertificateInfo>;

		TimestampCertificateInfo();
		virtual ~TimestampCertificateInfo();

		std::wstring GetDateAsWstr();

	public:
		std::shared_ptr <SYSTEMTIME> dateOfTimeStamp;
	};
};
