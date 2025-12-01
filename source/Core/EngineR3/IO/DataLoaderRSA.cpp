#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "DataLoader.hpp"
#include "../../../Common/FilePtr.hpp"
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pem.h>
#include <cryptopp/osrng.h>

namespace NoMercy
{
	bool CDataLoader::LoadRsaPublicComponents(const std::string& stContent, uint8_t& pFailStep)
	{
		m_spRsaPublicKey = stdext::make_shared_nothrow<CryptoPP::RSA::PublicKey>();
		try
		{
			CryptoPP::StringSource source(stContent, true);
			CryptoPP::PEM_Load(source, *m_spRsaPublicKey.get());
		}
		catch (const CryptoPP::Exception& ex)
		{
			APP_TRACE_LOG(LL_ERR, L"PEM could not load, Error: %hs", ex.what());
			pFailStep = 3;
			return false;
		}

		CryptoPP::AutoSeededRandomPool rnd;
		const auto valid = m_spRsaPublicKey->Validate(rnd, 3);
		if (!valid)
		{
			APP_TRACE_LOG(LL_ERR, L"Key not valid");
			pFailStep = 4;
			return false;
		}

		return true;
	}

	bool CDataLoader::LoadRsaPublicKeyFile(const std::wstring& stFileName, uint8_t& pFailStep)
	{
		const auto buffer = LoadCryptedFile(stFileName, pFailStep);
		if (buffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Public RSA key file: %s could not load! Fail step: %u", stFileName.c_str(), pFailStep);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Public RSA key succesfully loaded:\n%s", buffer.c_str());
		return LoadRsaPublicComponents(stdext::to_ansi(buffer), pFailStep);
	}
}
