#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "DataLoader.hpp"
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"

namespace NoMercy
{
	std::wstring CDataLoader::LoadCryptedFile(const std::wstring& stFileName, uint8_t& pFailStep)
	{
		std::wstring out;

		// Open file
		msl::file_ptr file(stFileName, xorstr_(L"rb"));
		if (!file)
		{
			APP_TRACE_LOG(LL_ERR, L"Crypted file: %s could not open, error: %d", stFileName.c_str(), errno);
			pFailStep = 1;
			return out;
		}

		// Read file info
		uint32_t magic = 0;
		file.read(&magic, sizeof(magic));
		if (magic != NM_CREATEMAGIC('N', 'M', 'C', 'F'))
		{
			APP_TRACE_LOG(LL_ERR, L"Crypted file magic is not valid: %p", magic);
			pFailStep = 2;
			return out;
		}

		uint32_t version = 0;
		file.read(&version, sizeof(version));
		if (version != NOMERCY_FILE_CRYPT_VERSION)
		{
			APP_TRACE_LOG(LL_ERR, L"Crypted file version is not valid: %u", version);
			pFailStep = 3;
			return out;
		}

		uint32_t raw_size = 0;
		file.read(&raw_size, sizeof(raw_size));
		if (!raw_size)
		{
			pFailStep = 4;
			return out;
		}

		uint32_t raw_hash = 0;
		file.read(&raw_hash, sizeof(raw_hash));
		if (!raw_hash)
		{
			pFailStep = 5;
			return out;
		}

		uint32_t final_size = 0;
		file.read(&final_size, sizeof(final_size));
		if (!final_size)
		{
			pFailStep = 6;
			return out;
		}

		uint32_t final_hash = 0;
		file.read(&final_hash, sizeof(final_hash));
		if (!final_hash)
		{
			pFailStep = 7;
			return out;
		}

		// Alloc & read
		std::unique_ptr <uint8_t[]> buf(new uint8_t[final_size]);
		if (!buf)
		{
			APP_TRACE_LOG(LL_ERR, L"Crypted file read buffer could not allocated");
			pFailStep = 8;
			return out;
		}
		file.read(buf.get(), final_size);

		// Validate
		const auto current_hash = XXH32(buf.get(), final_size, 0);
		if (current_hash != final_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Crypted file final hash mismatch, corrupted data.");
			pFailStep = 9;
			return out;
		}

		// Decrypt
		std::vector <uint8_t> decrypted_buf(final_size);
		try
		{
			CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
			dec.ProcessData(&decrypted_buf[0], reinterpret_cast<const uint8_t*>(buf.get()), final_size);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Caught exception on decryption: %hs", exception.what());
			pFailStep = 10;
			return out;
		}
	
		// Decompress
		std::vector <char> decompressed_buf(raw_size);

		const auto decompressedsize = LZ4_decompress_safe(
			reinterpret_cast<const char*>(decrypted_buf.data()), reinterpret_cast<char*>(&decompressed_buf[0]),
			decrypted_buf.size(), decompressed_buf.size()
		);
		if (decompressedsize != (int32_t)raw_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed size mismatch: %d-%u", decompressedsize, raw_size);
			pFailStep = 11;
			return out;
		}

		// Validate
		const auto decompressed_hash = XXH32(decompressed_buf.data(), decompressed_buf.size(), 0);
		if (raw_hash != decompressed_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed hash mismatch: %p-%p", decompressed_hash, raw_hash);
			pFailStep = 12;
			return out;
		}

		const auto stBuffer = std::string(decompressed_buf.data(), decompressed_buf.size());
		out = stdext::to_wide(stBuffer);
		return out;
	}
}
