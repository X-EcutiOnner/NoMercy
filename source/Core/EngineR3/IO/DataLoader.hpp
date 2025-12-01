#pragma once
#include <cryptopp/rsa.h>

namespace NoMercy
{
	class CDataLoader : public std::enable_shared_from_this <CDataLoader>
	{
	public:
		CDataLoader() = default;
		virtual ~CDataLoader() = default;

		std::wstring LoadCryptedFile(const std::wstring& stFileName, uint8_t& pFailStep);
		bool LoadPackedGameData(const std::wstring& stFileName, uint8_t& pFailStep);
		bool LoadRsaPublicKeyFile(const std::wstring& stFileName, uint8_t& pFailStep);

		auto GetGameDataContent() const		{ return m_mapGameDataContent; };
		auto GetRSAPublicKey()				{ return m_spRsaPublicKey; };

	protected:
		bool ProcessNoMercyData(const std::wstring& stContent, uint8_t& pFailStep);
		bool ProcessGameData(const std::wstring& stContent, uint8_t& pFailStep);
		bool LoadRsaPublicComponents(const std::string& stContent, uint8_t& pFailStep);

	private:
		std::map <std::wstring, std::wstring> m_mapGameDataContent;
		std::shared_ptr <CryptoPP::RSA::PublicKey> m_spRsaPublicKey;
	};
};
