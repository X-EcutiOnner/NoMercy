#include "../PCH.hpp"
#include "../Application.hpp"
#include "SealedBox.hpp"
#include "Base64.hpp"
#include <sodium.h>

namespace NoMercy
{
	SKeyPair::SKeyPair()
	{
		generate();
	}
	SKeyPair::~SKeyPair()
	{
		if (public_key)
			std::memset(public_key.get(), 0, crypto_box_PUBLICKEYBYTES);
	
		if (private_key)
			std::memset(private_key.get(), 0, crypto_box_SECRETKEYBYTES);
	}

	bool SKeyPair::create_keys(std::string& stRefPubKey, std::string& stRefPrivKey)
	{
		const auto ret = crypto_box_keypair(public_key.get(), private_key.get());
		if (ret != -1)
		{
			stRefPubKey = CBase64::encode(public_key.get(), crypto_box_PUBLICKEYBYTES);
			stRefPrivKey = CBase64::encode(private_key.get(), crypto_box_SECRETKEYBYTES);

			return !stRefPubKey.empty() && !stRefPrivKey.empty();
		}
		return false;
	}
	void SKeyPair::generate()
	{
		if (!public_key)
			public_key = std::make_unique<std::uint8_t[]>(crypto_box_PUBLICKEYBYTES);
		
		if (!private_key)
			private_key = std::make_unique<std::uint8_t[]>(crypto_box_SECRETKEYBYTES);
	}

	void SKeyPair::load_public_key(const std::string& key) const
	{
		if (!key.empty() && public_key)
		{
			auto tmp = CBase64::base64_to_array<std::array<std::uint8_t, crypto_box_PUBLICKEYBYTES>>(key.data());

			std::memcpy(public_key.get(), tmp.data(), tmp.size());
			std::memset(tmp.data(), 0, tmp.size());
		}
	}
	void SKeyPair::load_private_key(const std::string& key) const
	{
		if (!key.empty() && private_key)
		{
			auto tmp = CBase64::base64_to_array<std::array<std::uint8_t, crypto_box_SECRETKEYBYTES>>(key.data());

			std::memcpy(private_key.get(), tmp.data(), tmp.size());
			std::memset(tmp.data(), 0, tmp.size());
		}
	}

	std::string SKeyPair::get_public_key() const
	{
		return CBase64::encode(public_key.get(), crypto_box_PUBLICKEYBYTES);
	}
	std::string SKeyPair::get_private_key() const
	{
		return CBase64::encode(private_key.get(), crypto_box_SECRETKEYBYTES);
	}


	std::string Encrypt(const std::string& plain, const std::shared_ptr <SKeyPair>& kp)
	{
		if (plain.empty() || !kp || !kp->public_key)
			return {};

		try
		{
			std::string cipher(plain.length() + crypto_box_SEALBYTES, 0);
			crypto_box_seal(
				reinterpret_cast<std::uint8_t*>(cipher.data()),
				reinterpret_cast<const std::uint8_t*>(plain.data()),
				plain.length(),
				kp->public_key.get()
			);

			return CBase64::encode(cipher);
		}
		catch (...)
		{
			return {};
		}
	}
	std::string Decrypt(const std::string& cipher, const std::shared_ptr <SKeyPair>& kp)
	{
		if (cipher.empty() || !kp || !kp->public_key || !kp->private_key)
			return {};

		try
		{
			const auto cipher_decoded = CBase64::decode(cipher.data());

			std::string plain(cipher_decoded.length() - crypto_box_SEALBYTES, 0);
			crypto_box_seal_open(
				reinterpret_cast<std::uint8_t*>(plain.data()),
				reinterpret_cast<const std::uint8_t*>(cipher_decoded.data()),
				cipher_decoded.size(),
				kp->public_key.get(),
				kp->private_key.get()
			);

			return plain;
		}
		catch (...)
		{
			return {};
		}
	}
}
