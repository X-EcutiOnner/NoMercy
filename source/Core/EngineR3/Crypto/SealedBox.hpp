#pragma once
#include <memory>
#include "Base64.hpp"

namespace NoMercy
{
	struct SKeyPair
	{
		using key_type = std::unique_ptr <std::uint8_t[]>;

		SKeyPair();
		~SKeyPair();

		bool create_keys(std::string& stRefPubKey, std::string& stRefPrivKey);
		void generate();

		void load_public_key(const std::string& key) const;
		void load_private_key(const std::string& key) const;

		[[nodiscard]] std::string get_public_key() const;
		[[nodiscard]] std::string get_private_key() const;

		key_type public_key = nullptr;
		key_type private_key = nullptr;
	};

	extern std::string Encrypt(const std::string& plain, const std::shared_ptr <SKeyPair>& kp);
	extern std::string Decrypt(const std::string& cipher, const std::shared_ptr <SKeyPair>& kp);
}