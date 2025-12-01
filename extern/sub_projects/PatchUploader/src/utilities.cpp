#include "../include/main.hpp"
#include "../include/BasicLog.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

std::string __GetNoMercyPath()
{
	auto IsSysWow64 = [] {
#ifdef _WIN64
		return false;
#else
		return ((DWORD)__readfsdword(0xC0) != 0);
#endif
	};

	char buffer[MAX_PATH]{ '\0' };
	if (!ExpandEnvironmentStringsA(IsSysWow64() ? "%ProgramW6432%" : "%ProgramFiles%", buffer, sizeof(buffer)))
	{
		LogfA(LOG_FILENAME, "ExpandEnvironmentStringsA(wow64:%d) failed with error: %u", IsSysWow64() ? 1 : 0, GetLastError());
		return {};
	}

	if (buffer[0] == '\0' || !std::filesystem::exists(buffer))
	{
		LogfA(LOG_FILENAME, "Program files: %s path is not correct!", buffer);
		return {};
	}

	return fmt::format("{0}\\NoMercy", buffer);
}

std::string __GetMd5(const std::string& filename)
{
	std::string out;
	try
	{
		CryptoPP::Weak1::MD5 md5;
		CryptoPP::HashFilter hashfilter(md5);
		hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));

		const auto fileSource = new CryptoPP::FileSource(filename.c_str(), true, &hashfilter);
	}
	catch (const CryptoPP::Exception& exception)
	{
		LogfA(LOG_FILENAME, "Cryptopp exception: %u (%s)", exception.GetErrorType(), exception.GetWhat().c_str());
	}
	return out;
};
std::string __GetSHA1(const std::string& filename)
{
	std::string out;
	try
	{
		CryptoPP::SHA1 sha1;
		CryptoPP::HashFilter hashfilter(sha1);
		hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));

		const auto fileSource = new CryptoPP::FileSource(filename.c_str(), true, &hashfilter);
	}
	catch (const CryptoPP::Exception& exception)
	{
		LogfA(LOG_FILENAME, "Cryptopp exception: %u (%s)", exception.GetErrorType(), exception.GetWhat().c_str());
	}
	return out;
}
std::string __GetSHA256(const std::string& filename)
{
	std::string out;
	try
	{
		CryptoPP::SHA256 sha256;
		CryptoPP::HashFilter hashfilter(sha256);
		hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));

		const auto fileSource = new CryptoPP::FileSource(filename.c_str(), true, &hashfilter);
	}
	catch (const CryptoPP::Exception& exception)
	{
		LogfA(LOG_FILENAME, "Cryptopp exception: %u (%s)", exception.GetErrorType(), exception.GetWhat().c_str());
	}
	return out;
}

bool __WildcardMatch(const std::string& str, const std::string& match)
{
	const char* pMatch = match.c_str(), * pString = str.c_str();
	while (*pMatch)
	{
		if (*pMatch == '?')
		{
			if (!*pString)
			{
				return false;
			}
			++pString;
			++pMatch;
		}
		else if (*pMatch == '*')
		{
			if (__WildcardMatch(pString, pMatch + 1) || (*pString && __WildcardMatch(pString + 1, pMatch)))
			{
				return true;
			}
			return false;
		}
		else
		{
			if (*pString++ != *pMatch++)
			{
				return false;
			}
		}
	}
	return !*pString && !*pMatch;
}

std::string __ReadFileContent(const std::string& stFileName)
{
	std::ifstream in(stFileName.c_str(), std::ios_base::binary);
	if (in)
	{
		in.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
		return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	}
	return "";
}
