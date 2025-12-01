#include "../../include/PCH.hpp"
#include "../../include/TimestampCertificateInfo.hpp"

namespace NoMercyCore
{
	TimestampCertificateInfo::TimestampCertificateInfo()
	{
	}
	TimestampCertificateInfo::~TimestampCertificateInfo()
	{
	}

	std::wstring TimestampCertificateInfo::GetDateAsWstr()
	{
		if (!dateOfTimeStamp)
			return L"";

		const int lBufSize = 100;
		wchar_t lStrBuf[lBufSize]{ L'\0' };

		int lDateStrLen = swprintf_s(
			lStrBuf,
			lBufSize,
			xorstr_(L"%02d/%02d/%04d %02d:%02d"),
			dateOfTimeStamp->wDay,
			dateOfTimeStamp->wMonth,
			dateOfTimeStamp->wYear,
			dateOfTimeStamp->wHour,
			dateOfTimeStamp->wMinute
		);

		return std::wstring(lStrBuf, lDateStrLen);
	}
};
