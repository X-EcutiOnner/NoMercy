#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "GameIntegrationCheck.hpp"
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"

namespace NoMercy
{
	bool CGameIntegrationManager::LoadPackedBundleFile(const std::wstring& stFileName, uint8_t& pFailStep)
	{
		// Open file
		msl::file_ptr file(stFileName, xorstr_(L"rb"));
		if (!file)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file: %s could not open", stFileName.c_str());
			pFailStep = 1;
			return false;
		}

		// Read file info
		uint32_t magic = 0;
		file.read(&magic, sizeof(magic));
		if (magic != NM_CREATEMAGIC('N', 'M', 'G', 'B'))
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file magic is not valid: %p", magic);
			pFailStep = 2;
			return false;
		}

		uint32_t version = 0;
		file.read(&version, sizeof(version));
		if (version != NOMERCY_GAME_INTEGRATION_VERSION)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file version is not valid: %u", version);
			pFailStep = 3;
			return false;
		}

		uint32_t raw_size = 0;
		file.read(&raw_size, sizeof(raw_size));
		if (!raw_size)
		{
			pFailStep = 4;
			return false;
		}

		uint32_t raw_hash = 0;
		file.read(&raw_hash, sizeof(raw_hash));
		if (!raw_hash)
		{
			pFailStep = 5;
			return false;
		}

		uint32_t final_size = 0;
		file.read(&final_size, sizeof(final_size));
		if (!final_size)
		{
			pFailStep = 6;
			return false;
		}

		uint32_t final_hash = 0;
		file.read(&final_hash, sizeof(final_hash));
		if (!final_hash)
		{
			pFailStep = 7;
			return false;
		}

		// Alloc & read
		std::unique_ptr <uint8_t[]> buf(new uint8_t[final_size]);
		if (!buf)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file read buffer could not allocated");
			pFailStep = 8;
			return false;
		}
		file.read(buf.get(), final_size);

		// Validate
		const auto current_hash = XXH32(buf.get(), final_size, 0);
		if (current_hash != final_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file final hash mismatch, corrupted data.");
			pFailStep = 9;
			return false;
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
			return false;
		}

		// Decompress
		std::vector <char> decompressed_buf(raw_size);

		auto decompressedsize = LZ4_decompress_safe(
			reinterpret_cast<const char*>(decrypted_buf.data()), reinterpret_cast<char*>(&decompressed_buf[0]),
			decrypted_buf.size(), decompressed_buf.size()
		);
		if (decompressedsize != (int32_t)raw_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed size mismatch: %d-%u", decompressedsize, raw_size);
			pFailStep = 11;
			return false;
		}

		// Validate
		const auto decompressed_hash = XXH32(decompressed_buf.data(), decompressed_buf.size(), 0);
		if (raw_hash != decompressed_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed hash mismatch: %p-%p", decompressed_hash, raw_hash);
			pFailStep = 12;
			return false;
		}

		// Process
		const auto stBuffer = std::string(decompressed_buf.data(), decompressed_buf.size());
		return this->ProcessBundleFileData(stdext::to_wide(stBuffer), pFailStep);
	}

	bool CGameIntegrationManager::ProcessBundleFileData(const std::wstring& stContent, uint8_t& pFailStep)
	{
		if (stContent.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file content is null");
			pFailStep = 13;
			return false;
		}

		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse(stContent.c_str());
		if (document.HasParseError())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file could NOT parsed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			pFailStep = 14;
			return false;
		}
		if (!document.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game integrity file base is not an object! Type: %u", document.GetType());
			pFailStep = 15;
			return false;
		}

		if (!document.HasMember(L"version"))
		{
			APP_TRACE_LOG(LL_ERR, L"'version' member does not exist!");
			pFailStep = 16;
			return false;
		}
		const auto& pkVersion = document[L"version"];
		if (!pkVersion.IsNumber())
		{
			APP_TRACE_LOG(LL_ERR, L"'version' member is not an number!");
			pFailStep = 17;
			return false;
		}

		if (!document.HasMember(L"enabled"))
		{
			APP_TRACE_LOG(LL_ERR, L"'enabled' enabled does not exist!");
			pFailStep = 18;
			return false;
		}
		const auto& pkEnabled = document[L"enabled"];
		if (!pkEnabled.IsBool())
		{
			APP_TRACE_LOG(LL_ERR, L"'enabled' member is not an boolean!");
			pFailStep = 19;
			return false;
		}

		if (!document.HasMember(L"files"))
		{
			APP_TRACE_LOG(LL_ERR, L"'files' enabled does not exist!");
			pFailStep = 20;
			return false;
		}
		const auto& pkFiles = document[L"files"];
		if (!pkFiles.IsArray())
		{
			APP_TRACE_LOG(LL_ERR, L"'files' member is not an array!");
			pFailStep = 21;
			return false;
		}

		size_t idx = 0;
		for (const auto& pkFile : pkFiles.GetArray())
		{
			idx++;

			if (!pkFile.IsObject())
			{
				APP_TRACE_LOG(LL_ERR, L"[%u] 'file' member is not an object!", idx);
				pFailStep = 22;
				return false;
			}

			if (!pkFile.HasMember(L"name"))
			{
				APP_TRACE_LOG(LL_ERR, L"'name' enabled does not exist!");
				pFailStep = 23;
				return false;
			}
			const auto& pkName = pkFile[L"name"];
			if (!pkName.IsString())
			{
				APP_TRACE_LOG(LL_ERR, L"'name' member is not an string!");
				pFailStep = 24;
				return false;
			}

			if (!pkFile.HasMember(L"hash"))
			{
				APP_TRACE_LOG(LL_ERR, L"'hash' enabled does not exist!");
				pFailStep = 25;
				return false;
			}
			const auto& pkHash = pkFile[L"hash"];
			if (!pkHash.IsString())
			{
				APP_TRACE_LOG(LL_ERR, L"'hash' member is not an string!");
				pFailStep = 26;
				return false;
			}

			if (!pkFile.HasMember(L"optional"))
			{
				APP_TRACE_LOG(LL_ERR, L"'optional' enabled does not exist!");
				pFailStep = 27;
				return false;
			}
			const auto& pkOptional = pkFile[L"optional"];
			if (!pkOptional.IsBool())
			{
				APP_TRACE_LOG(LL_ERR, L"'optional' member is not an boolean!");
				pFailStep = 28;
				return false;
			}

			if (!pkFile.HasMember(L"virtual"))
			{
				APP_TRACE_LOG(LL_ERR, L"'virtual' enabled does not exist!");
				pFailStep = 29;
				return false;
			}
			const auto& pkVirtual = pkFile[L"virtual"];
			if (!pkVirtual.IsBool())
			{
				APP_TRACE_LOG(LL_ERR, L"'virtual' member is not an boolean!");
				pFailStep = 30;
				return false;
			}

			const auto file_name = std::wstring(pkName.GetString(), pkName.GetStringLength());
			const auto file_hash = std::wstring(pkHash.GetString(), pkHash.GetStringLength());
			const auto is_optional = pkOptional.GetBool();
			const auto is_virtual = pkVirtual.GetBool();

			if (is_virtual)
			{
				m_mapVirtualFileHashList.emplace(file_name, file_hash);
				continue;
			}

			if (is_optional && (!std::filesystem::exists(file_name) || !std::filesystem::is_regular_file(file_name)))
			{
				APP_TRACE_LOG(LL_ERR, L"[%u] File: %ls does not exists!", idx, file_name.c_str());
				continue;
			}

			const auto current_filehash = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(file_name));
			if (current_filehash.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"[%u] File: %ls hash calculate failed!", idx, file_name.c_str());
				continue;
			}

			APP_TRACE_LOG(LL_ERR, L"[%u] '%ls' >> '%ls'/'%ls' EQ:%d -- O:%d V:%d",
				idx, file_name.c_str(), file_hash.c_str(), current_filehash.c_str(), file_hash == current_filehash, is_optional, is_virtual
			);

			if (current_filehash != file_hash)
			{
				APP_TRACE_LOG(LL_ERR, L"[%u] File: %s hash mismatch!", idx, file_name.c_str());
				pFailStep = 31;
				return false;
			}
		}

		return true;
	}
};
