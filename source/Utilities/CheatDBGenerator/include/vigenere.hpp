#include <string>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <xorstr.hpp>

namespace VigenereCrypt
{
	static std::string STRING_CRYPT_KEY = xorstr_("super_safe_key");
	static std::string AVAILABLE_CHARS = xorstr_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ");

	namespace base64
	{
		static std::string encode(const std::string& in)
		{
			std::string out;
			try
			{
				CryptoPP::StringSource ss(in, true,
					new CryptoPP::Base64Encoder(
						new CryptoPP::StringSink(out),
						false /* Newline */
					) // Base64Encoder
				); // StringSource
			}
			catch (const CryptoPP::Exception& exception)
			{
				std::cerr << "Caught exception on base64 encoding: " << exception.what() << std::endl;
			}
			return out;
		}

		static std::string decode(const std::string& in)
		{
			std::string out;
			try
			{
				CryptoPP::StringSource ss(in, true,
					new CryptoPP::Base64Decoder(
						new CryptoPP::StringSink(out)
					) // Base64Decoder
				); // StringSource
			}
			catch (const CryptoPP::Exception& exception)
			{
				std::cerr << "Caught exception on base64 decoding: " << exception.what() << std::endl;
			}
			return out;
		}
	};

	namespace vigenere
	{
		static std::string to_ansi(const std::wstring& in)
		{
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
			auto out = std::string(in.begin(), in.end());
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32

			return out;
		}
		static std::wstring to_wide(const std::string& in)
		{
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
			auto out = std::wstring(in.begin(), in.end());
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32
		}

		static int index(char c)
		{
			for (const auto& i : AVAILABLE_CHARS)
			{
				if (i == c)
				{
					return AVAILABLE_CHARS.find(i);
				}
			}
			return -1;
		}

		static std::string extend_key(const std::string& msg, const std::string& key)
		{
			std::string newKey;
			newKey.reserve(msg.size());

			auto idx = 0u;
			for (auto& c : msg)
			{
				if (idx == key.size())
					idx = 0;

				newKey += key[idx++];
			}

			return newKey;
		}

		static std::string encrypt(const std::string& msg, const std::string& key)
		{
			std::string encryptedMsg;
			encryptedMsg.reserve(msg.size());

			auto idx = 0;
			std::string newKey = extend_key(msg, key);
			for (const auto& c : msg)
			{
				if (isalnum(c) || c == ' ')
				{
					auto newIdx = index(c) + index(newKey[idx]);
					auto charIdx = newIdx % AVAILABLE_CHARS.size();
					auto encryptedChar = AVAILABLE_CHARS[charIdx];

					encryptedMsg.push_back(encryptedChar);
				}
				else
				{
					encryptedMsg.push_back(c);
				}
			}

			return encryptedMsg;
		}

		static std::string decrypt(const std::string& msg, const std::string& newKey)
		{
			std::string decryptedMsg;
			decryptedMsg.reserve(msg.size());

			auto idx = 0;
			for (const auto& c : msg)
			{
				if (isalnum(c) || c == ' ')
				{
					auto newIdx = index(c) - index(newKey[idx]);
					auto newIdx2 = newIdx + AVAILABLE_CHARS.size();
					auto charIdx = newIdx2 % AVAILABLE_CHARS.size();
					auto decryptedChar = AVAILABLE_CHARS[charIdx];

					decryptedMsg.push_back(decryptedChar);
				}
				else
				{
					decryptedMsg.push_back(c);
				}
			}

			return decryptedMsg;
		}
	};

	static std::string encrypt(const std::string& c_stMessage, const std::string& c_stKey)
	{
		if (c_stMessage.empty() || c_stKey.empty())
			return {};

		auto stOut = base64::encode(c_stMessage);
		if (stOut.empty())
			return {};

		stOut = vigenere::encrypt(stOut, c_stKey);
		if (stOut.empty())
			return {};

		return stOut;
	}
	static std::wstring encrypt(const std::wstring& c_wstMessage, const std::string& c_stKey)
	{
		if (c_wstMessage.empty())
			return {};

		const auto c_stMessage = vigenere::to_ansi(c_wstMessage);
		return vigenere::to_wide(encrypt(c_stMessage, c_stKey));
	}

	static std::string decrypt(const std::string& c_stMessage, const std::string& c_stKey)
	{
		if (c_stMessage.empty() || c_stKey.empty())
			return {};

		const auto c_stNewKey = vigenere::extend_key(c_stMessage, c_stKey);
		if (c_stNewKey.empty())
			return {};

		auto stOut = vigenere::decrypt(c_stMessage, c_stNewKey);
		if (stOut.empty())
			return {};

		stOut = base64::decode(stOut);
		if (stOut.empty())
			return {};

		return stOut;
	}
	static std::wstring decrypt(const std::wstring& c_wstMessage, const std::string& c_stKey)
	{
		if (c_wstMessage.empty())
			return {};

		const auto c_stMessage = vigenere::to_ansi(c_wstMessage);
		return vigenere::to_wide(decrypt(c_stMessage, c_stKey));
	}
}
