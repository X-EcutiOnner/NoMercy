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
#include "../../../Common/BasicCrypt.hpp"
#include "../../../Common/StdExtended.hpp"
#include "../../../Core/EngineR3_Core/include/BasicLog.hpp"
#include "../../../Core/EngineR3_Core/include/MiniDump.hpp"
#include "../include/vigenere.hpp"
using namespace rapidjson;
using namespace NoMercyCore;

extern bool DecommentMain(const char* c_szInFile, const char* c_szOutFile);

#define NM_CREATEMAGIC(b0, b1, b2, b3) \
	(uint32_t(uint8_t(b0)) | (uint32_t(uint8_t(b1)) << 8) | \
	(uint32_t(uint8_t(b2)) << 16) | (uint32_t(uint8_t(b3)) << 24))

#undef GetObject
#define LOG_FILENAME "db_generator.log"

bool __ProcessJSON(rapidjson::GenericDocument<UTF16<>>& document)
{
	// Sanity check the document
	if (document.IsObject() == false)
	{
		LogfA(LOG_FILENAME, "Document is not an object\n");
		return false;
	}

	const auto lstTargetLists = {
		L"blacklist",
		L"whitelist"
	};
	for (const auto& c_szTargetList : lstTargetLists)
	{
		// Get the target list
		if (!document.HasMember(c_szTargetList))
		{
			LogfA(LOG_FILENAME, "Document has no %ls member\n", c_szTargetList);
			return false;
		}		

		auto& targetList = document[c_szTargetList];
		if (targetList.IsArray() == false)
		{
			LogfA(LOG_FILENAME, "%ls is not an array\n", c_szTargetList);
			return false;
		}

		// Process the targetList
		for (SizeType i = 0; i < targetList.Size(); i++)
		{
			auto& item = targetList[i];
			if (item.IsObject() == false)
			{
				LogfA(LOG_FILENAME, "%ls item %d is not a object. Type: %d\n", c_szTargetList, i, item.GetType());
				return false;
			}

			for (auto& member : item.GetObject())
			{
				// Clear description value
				if (member.name == L"description")
				{
					if (member.value.IsString() == false)
					{
						LogfA(LOG_FILENAME, "%ls item %d description is not a string\n", c_szTargetList, i);
						return false;
					}

					LogfA(LOG_FILENAME, "%ls item %d description: %ls\n", c_szTargetList, i, member.value.GetString());
					member.value.SetString(L"");
				}

				// Encrypt params array strings
				if (member.name == L"params")
				{
					if (member.value.IsArray() == false)
					{
						LogfA(LOG_FILENAME, "%ls item %d params is not an array\n", c_szTargetList, i);
						return false;
					}

					for (SizeType j = 0; j < member.value.Size(); j++)
					{
						auto& param = member.value[j];
						if (param.IsString() == false)
						{
							LogfA(LOG_FILENAME, "%ls item %d params item %d is not a string\n", c_szTargetList, i, j);
							return false;
						}

						auto wstParam = std::wstring(param.GetString(), param.GetStringLength());
						auto stParam = stdext::to_ansi(wstParam);
						auto stEncrypted = VigenereCrypt::encrypt(stParam, VigenereCrypt::STRING_CRYPT_KEY);
						auto stDecrypted = VigenereCrypt::decrypt(stEncrypted, VigenereCrypt::STRING_CRYPT_KEY);

						if (stParam != stDecrypted)
						{
							LogfA(LOG_FILENAME, "%ls item %d params item %d encryption failed\n", c_szTargetList, i, j);
							return false;
						}

						LogfA(LOG_FILENAME, "Param: %s encrypted: %s decrypted: %s\n", stParam.c_str(), stEncrypted.c_str(), stDecrypted.c_str());

						const auto wstEncrypted = stdext::to_wide(stEncrypted);
						param.SetString(wstEncrypted.c_str(), wstEncrypted.length(), document.GetAllocator());
					}
				}
			}
		}
	}
	
	// Get the single objects
	auto& objects = document[L"single"];
	if (objects.IsArray() == false)
	{
		LogfA(LOG_FILENAME, "single is not an array\n");
		return false;
	}

	// Process the single objects
	for (SizeType i = 0; i < objects.Size(); i++)
	{
		auto& item = objects[i];
		if (item.IsObject() == false)
		{
			LogfA(LOG_FILENAME, "single item %d is not a object. Type: %d\n", i, item.GetType());
			return false;
		}

		for (auto& member : item.GetObject())
		{
			// Check member name ending with _value or detection_name
			const auto c_wstMemberName = std::wstring(member.name.GetString(), member.name.GetStringLength());
			const auto c_bIsParamValue = c_wstMemberName.length() > 6 && c_wstMemberName.substr(c_wstMemberName.length() - 6) == L"_value";
			
			if (c_bIsParamValue || c_wstMemberName == L"detection_name" || c_wstMemberName == L"id")
			{
				// Check value type
				if (member.value.IsString() == false)
				{
					LogfA(LOG_FILENAME, "single item %d %ls is not a string\n", i, c_wstMemberName.c_str());
					return false;
				}

				// Encrypt value string
				auto wstValue = std::wstring(member.value.GetString(), member.value.GetStringLength());
				auto stValue = stdext::to_ansi(wstValue);
				auto stEncrypted = VigenereCrypt::encrypt(stValue, VigenereCrypt::STRING_CRYPT_KEY);
				auto stDecrypted = VigenereCrypt::decrypt(stEncrypted, VigenereCrypt::STRING_CRYPT_KEY);
				
				if (stValue != stDecrypted)
				{
					LogfA(LOG_FILENAME, "single item %d %ls encryption failed\n", i, c_wstMemberName.c_str());
					return false;
				}

				LogfA(LOG_FILENAME, "single item %d %ls encrypted: %s decrypted: %s\n", i, c_wstMemberName.c_str(), stEncrypted.c_str(), stDecrypted.c_str());

				const auto wstEncrypted = stdext::to_wide(stEncrypted);
				member.value.SetString(wstEncrypted.c_str(), wstEncrypted.length(), document.GetAllocator());
			}
		}
	}
	return true;
}

int32_t main(int32_t argc, char *argv[])
{
	CMiniDump::InitMiniDumpHandler();

	const auto stOutputFileName = "NoMercy.cdb";

	// Declare DB file name
	std::string stTargetFileName = "Cheat_db.json";
	if (argc >= 2)
		stTargetFileName = argv[1];
	
	if (!std::filesystem::exists(stTargetFileName))
	{
		LogfA(LOG_FILENAME, "File not found: %s", stTargetFileName.c_str());

		stTargetFileName = "../document/internal/Cheat_db.json";
		if (!std::filesystem::exists(stTargetFileName))
		{
			LogfA(LOG_FILENAME, "Internal file not found: %s", stTargetFileName.c_str());
			return EXIT_FAILURE;
		}
	}
	
	// Delete old decomment file, if exists
	std::string stDecommentFile = "Cheat_db_decomment.json";
	if (std::filesystem::exists(stDecommentFile))
		std::filesystem::remove(stDecommentFile);

	// Decomment comments from DB file
	if (!DecommentMain(stTargetFileName.c_str(), stDecommentFile.c_str()))
	{
		LogfA(LOG_FILENAME, "Decomment file failed: %s -> %s", stTargetFileName.c_str(), stDecommentFile.c_str());
		return EXIT_FAILURE;
	}

	// Open files
	msl::file_ptr in_file(stDecommentFile, "rb");
	if (!in_file)
	{
		LogfA(LOG_FILENAME, "%s could not open! Error: %u", stDecommentFile.c_str(), errno);
		return EXIT_FAILURE;
	}

	msl::file_ptr out_file(stOutputFileName, "wb");
	if (!out_file)
	{
		LogfA(LOG_FILENAME, "%s could not open! Error: %u", stOutputFileName, errno);
		return EXIT_FAILURE;
	}

	// Get common data
	const auto in_data = stdext::to_wide(in_file.string_read());
	const uint32_t in_data_size = in_file.size();

	if (!in_data_size)
	{
		LogfA(LOG_FILENAME, "File: %s is empty", stDecommentFile.c_str());
		return EXIT_FAILURE;
	}

	// Validate file integrity
	auto document = rapidjson::GenericDocument<UTF16<>>{};
	document.Parse<kParseCommentsFlag>(in_data.data());
	if (document.HasParseError())
	{
		LogfA(LOG_FILENAME, "Cheat DB could NOT parsed! Error: %s offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
		return EXIT_FAILURE;
	}
	
	// Process JSON data
	const auto process_ret = __ProcessJSON(document);
	if (!process_ret)
	{
		LogfA(LOG_FILENAME, "Cheat DB could NOT processed!");
		return EXIT_FAILURE;
	}

	// Serialize processed JSON
	const auto out_data_w = stdext::dump_json_document(document);
	const auto out_data = stdext::to_ansi(out_data_w);
	const auto out_data_size = out_data.size();

	// Compress
	const auto bound = LZ4_compressBound(out_data_size);
	std::vector <uint8_t> compressed(bound);

	const auto compressedsize = LZ4_compress_HC(
		reinterpret_cast<const char*>(out_data.data()), reinterpret_cast<char*>(&compressed[0]),
		out_data_size, bound, LZ4HC_CLEVEL_MAX
	);
	if (compressedsize >= bound || compressedsize == 0)
	{
		LogfA(LOG_FILENAME, "Compression fail! Raw: %u Compressed: %u Capacity: %u", out_data_size, compressedsize, bound);
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
	const uint32_t magic = NM_CREATEMAGIC('N', 'M', 'D', 'B');
	out_file.write(&magic, sizeof(magic));

	// Version
	const uint32_t version = NOMERCY_CDB_VERSION;
	out_file.write(&version, sizeof(version));

	// Raw size
	out_file.write(&out_data_size, sizeof(out_data_size));

	// Raw hash
	const uint32_t in_raw_hash = XXH32(out_data.data(), out_data_size, 0);
	out_file.write(&in_raw_hash, sizeof(in_raw_hash));

	// Final size
	const uint32_t final_size = crypted.size();
	out_file.write(&final_size, sizeof(final_size));

	// Final hash
	const uint32_t final_hash = XXH32(crypted.data(), crypted.size(), 0);
	out_file.write(&final_hash, sizeof(final_hash));

	// Crypt buffer
	BasicCrypt::EncryptBuffer(crypted.data(), crypted.size(), 0x69);

	// Reverse buffer
	std::reverse(crypted.begin(), crypted.end());

	// Write final data
	out_file.write(crypted.data(), crypted.size());

	// Close output file handle
	out_file.close();

	// Copy created file to debug workspace
	if (std::filesystem::exists("../Bin_public/.debug/Data"))
		std::filesystem::copy_file(stOutputFileName, "../Bin_public/.debug/Data/NoMercy.cdb", std::filesystem::copy_options::update_existing);

	return EXIT_SUCCESS;
}
