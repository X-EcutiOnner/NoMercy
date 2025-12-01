#include <iostream>
#include <cstdlib>
#include <chrono>
#include <array>
#include <lz4/lz4.h>
#include <lz4/lz4hc.h>
#include <xxhash.h>
#include <filesystem>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"
#include "../../../Core/EngineR3_Core/include/BasicLog.hpp"
using namespace NoMercyCore;

#define NM_CREATEMAGIC(b0, b1, b2, b3) \
	(uint32_t(uint8_t(b0)) | (uint32_t(uint8_t(b1)) << 8) | \
	(uint32_t(uint8_t(b2)) << 16) | (uint32_t(uint8_t(b3)) << 24))

#define LOG_FILENAME "file_encryptor.log"

int32_t main(int32_t argc, char *argv[])
{
	if (argc != 2)
	{
		LogfA(LOG_FILENAME, "Usage: %s <target_file>", argv[0]);
		return EXIT_FAILURE;
	}
	const std::string target_file = argv[1];

	// Open files
	msl::file_ptr in_file(target_file, "rb");
	if (!in_file)
	{
		LogfA(LOG_FILENAME, "In %s could not open! Error: %u", target_file.c_str(), errno);
		return EXIT_FAILURE;
	}

	// Get common data
	const auto in_data = in_file.string_read();
	const uint32_t in_size = in_file.size();

	in_file.close();

	std::filesystem::rename(target_file, target_file + ".backup");

	msl::file_ptr out_file(target_file, "wb");
	if (!out_file)
	{
		LogfA(LOG_FILENAME, "Out %s could not open! Error: %u", target_file.c_str(), errno);
		return EXIT_FAILURE;
	}

	// Compress
	const auto bound = LZ4_compressBound(in_size);
	std::vector <uint8_t> compressed(bound);

	const auto compressedsize = LZ4_compress_HC(
		reinterpret_cast<const char*>(in_data.data()), reinterpret_cast<char*>(&compressed[0]),
		in_size, bound, LZ4HC_CLEVEL_MAX
	);
	if (compressedsize >= bound || compressedsize == 0)
	{
		LogfA(LOG_FILENAME, "Compression fail! Raw: %u Compressed: %u Capacity: %u", in_size, compressedsize, bound);
		return EXIT_FAILURE;
	}

	// Crypt
	std::vector <uint8_t> crypted(compressedsize);

	try
	{
		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
		enc.ProcessData(&crypted[0], reinterpret_cast<const uint8_t*>(compressed.data()), compressedsize);
	}
	catch (const CryptoPP::Exception& exception)
	{
		LogfA(LOG_FILENAME, "Caught exception on encryption: %s", exception.what());
		return EXIT_FAILURE;
	}

	/// Write basic data
	// Magic
	const uint32_t magic = NM_CREATEMAGIC('N', 'M', 'C', 'F');
	out_file.write(&magic, sizeof(magic));

	// Version
	const uint32_t version = NOMERCY_FILE_CRYPT_VERSION;
	out_file.write(&version, sizeof(version));

	// Raw size
	out_file.write(&in_size, sizeof(in_size));

	// Raw hash
	const uint32_t in_raw_hash = XXH32(in_data.data(), in_size, 0);
	out_file.write(&in_raw_hash, sizeof(in_raw_hash));

	// Final size
	const uint32_t final_size = crypted.size();
	out_file.write(&final_size, sizeof(final_size));

	// Final hash
	const uint32_t final_hash = XXH32(crypted.data(), crypted.size(), 0);
	out_file.write(&final_hash, sizeof(final_hash));

	// Write final data
	out_file.write(crypted.data(), crypted.size());

	// Close output file
	out_file.close();

	return EXIT_SUCCESS;
}
