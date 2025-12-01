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
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"
#include "../../../Common/StdExtended.hpp"
#include "../../../Core/EngineR3_Core/include/BasicLog.hpp"
using namespace rapidjson;
using namespace NoMercyCore;

#define NM_CREATEMAGIC(b0, b1, b2, b3) \
	(uint32_t(uint8_t(b0)) | (uint32_t(uint8_t(b1)) << 8) | \
	(uint32_t(uint8_t(b2)) << 16) | (uint32_t(uint8_t(b3)) << 24))

#define LOG_FILENAME "nmd_generator.log"

int32_t main(int32_t argc, char* argv[])
{
	std::string stTargetFile = "../document/internal/NoMercy_data.json";
	if (argc >= 2)
		stTargetFile = argv[1];

	// Open files
	msl::file_ptr in_file(stTargetFile, "rb");
	if (!in_file)
	{
		LogfA(LOG_FILENAME, "NoMercy_data.json could not open!");
		return EXIT_FAILURE;
	}

	msl::file_ptr out_file("NoMercy.dat", "wb");
	if (!out_file)
	{
		LogfA(LOG_FILENAME, "NoMercy.dat could not open!");
		return EXIT_FAILURE;
	}

	// Get common data
	const auto in_data = in_file.string_read();
	const uint32_t in_size = in_file.size();

	// Validate file integrity
	auto document = rapidjson::Document{};
	document.Parse<kParseCommentsFlag>(in_data.data());
	if (document.HasParseError())
	{
		LogfA(LOG_FILENAME, "NoMercy game data could NOT parsed! Error: %s offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
		return false;
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
	const uint32_t version = NOMERCY_DATA_VERSION;
	out_file.write(&version, sizeof(version));

	// Raw size
	out_file.write(&in_size, sizeof(in_size));

	// Raw hash
	const uint32_t in_raw_hash = XXH32(in_data.data(), in_file.size(), 0);
	out_file.write(&in_raw_hash, sizeof(in_raw_hash));

	// Final size
	const uint32_t final_size = crypted.size();
	out_file.write(&final_size, sizeof(final_size));

	// Final hash
	const uint32_t final_hash = XXH32(crypted.data(), crypted.size(), 0);
	out_file.write(&final_hash, sizeof(final_hash));

	/// Write final data
	out_file.write(crypted.data(), crypted.size());

	return EXIT_SUCCESS;
}
