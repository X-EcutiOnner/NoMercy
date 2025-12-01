#include <iostream>
#include <cstdlib>
#include <chrono>
#include <array>
#include <filesystem>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include <lz4/lz4.h>
#include <lz4/lz4hc.h>
#include <xxhash.h>
#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"
#include "../../../Common/StdExtended.hpp"
#include "../../../Core/EngineR3_Core/include/BasicLog.hpp"
using namespace rapidjson;
using namespace NoMercyCore;

#undef GetObject
#define NM_CREATEMAGIC(b0, b1, b2, b3) \
	(uint32_t(uint8_t(b0)) | (uint32_t(uint8_t(b1)) << 8) | \
	(uint32_t(uint8_t(b2)) << 16) | (uint32_t(uint8_t(b3)) << 24))

#define LOG_FILENAME "nmgf_generator.log"

#define IS_VALID_SMART_PTR(ptr)		(ptr && ptr.get())

std::string get_file_sha1(const std::string& filename)
{
	std::string out;
	try
	{
		CryptoPP::SHA1 sha1;

		CryptoPP::FileSource(filename.c_str(), true,
			new CryptoPP::HashFilter(sha1,
				new CryptoPP::HexEncoder(
					new CryptoPP::StringSink(out)
				)
			)
		);
	}
	catch (const CryptoPP::Exception& exception)
	{
		LogfA(LOG_FILENAME, "Cryptopp exception: %u (%s)\n", exception.GetErrorType(), exception.GetWhat().c_str());
	}
	return out;
}

static bool WildcardMatch(const std::wstring& str, const std::wstring& match)
{
	const wchar_t* pMatch = match.c_str();
	const wchar_t* pString = str.c_str();

	while (*pMatch)
	{
		if (*pMatch == L'?')
		{
			if (!*pString)
			{
				return false;
			}
			++pString;
			++pMatch;
		}
		else if (*pMatch == L'*')
		{
			if (WildcardMatch(pString, pMatch + 1) || (*pString && WildcardMatch(pString + 1, pMatch)))
			{
				return true;
			}
			return false;
		}
		else
		{
			if (*pString++ != *pMatch++)
			{
				return false;
			}
		}
	}
	return !*pString && !*pMatch;
}

int32_t create_hash_list(const std::string& config, const std::string& out)
{
	struct SPathContext
	{
		bool optional{ false };
		std::wstring path;
		std::vector <std::wstring> ignores;
		std::map <std::wstring, std::wstring> aliases;
		std::vector <std::wstring> ignored_sub_paths;
		bool recursive_visit{ false };
		bool ignore_files_without_extension{ false };
	};
	struct SConfigV1Context
	{
		bool enabled{ true };
		uint32_t size_threshold{ 0 };
		std::vector <std::wstring> files;
		std::vector <std::wstring> virtual_files;
		std::map <std::wstring, std::wstring> virtual_file_aliases;
		std::vector <std::shared_ptr <SPathContext>> paths;
	};
	struct SConfigContext
	{
		uint32_t version{ 0 };
		std::shared_ptr <SConfigV1Context> v1_ctx;
	};	
	
	Document config_content{};
	bool enabled{};
	uint32_t version{};
	std::shared_ptr <SConfigContext> ctx;
	std::vector <std::tuple <std::wstring, std::wstring, bool>> raw_hash_list;
	std::map <std::wstring, std::wstring> virtual_hash_list;
	std::wstring hash_stream;

	const auto read_config_file = [&](const std::string& filename) {
		try
		{
			const auto fp = msl::file_ptr(filename);
			if (!fp)
			{
				LogfA(LOG_FILENAME, "Config file could not open!\n");
				return false;
			}

			const auto buffer = fp.read();
			if (buffer.empty())
			{
				LogfA(LOG_FILENAME, "Config file could not read!\n");
				return false;
			}

			config_content.Parse(reinterpret_cast<const char*>(buffer.data()));
			if (config_content.HasParseError())
			{
				LogfA(LOG_FILENAME, "Config file could not parsed! Error: %s offset: %u\n", GetParseError_En(config_content.GetParseError()), config_content.GetErrorOffset());
				return false;
			}
		}
		catch (const std::exception& e)
		{
			LogfA(LOG_FILENAME, "Exception handled on read_config_file Error: %s\n", e.what());
			return false;
		}

		return true;
	};
	if (!read_config_file(config))
	{
		LogfA(LOG_FILENAME, "read_config_file has been failed!\n");
		return EXIT_FAILURE;
	}

	const auto process_config_file = [&]() {
		try
		{
			if (!config_content.IsObject())
			{
				LogfA(LOG_FILENAME, "Config file base must be object!\n");
				return false;
			}

			if (!config_content.HasMember("version"))
			{
				LogfA(LOG_FILENAME, "'version' key must be exist in config!\n");
				return false;
			}
			const auto& pkVersion = config_content["version"];
			if (!pkVersion.IsNumber())
			{
				LogfA(LOG_FILENAME, "'version' key must defined as number!\n");
				return false;
			}
			version = pkVersion.GetUint();
			if (version != 1)
			{
				LogfA(LOG_FILENAME, "Unknown 'version' value: %u\n", version);
				return false;
			}

			ctx = std::make_shared<SConfigContext>();
			if (!IS_VALID_SMART_PTR(ctx))
			{
				LogfA(LOG_FILENAME, "SConfigContext allocation failed! Error: %u\n", errno);
				return false;
			}

			if (version == 1)
			{
				ctx->version = version;
				auto v1_ctx = std::make_shared<SConfigV1Context>();
				if (!IS_VALID_SMART_PTR(v1_ctx))
				{
					LogfA(LOG_FILENAME, "SConfigV1Context allocation failed! Error: %u\n", errno);
					return false;
				}

				if (!config_content.HasMember("enabled"))
				{
					LogfA(LOG_FILENAME, "'enabled' key must be exist in config!\n");
					return false;
				}
				const auto& pkEnabled = config_content["enabled"];
				if (!pkEnabled.IsBool())
				{
					LogfA(LOG_FILENAME, "'enabled' key must defined as boolean!\n");
					return false;
				}
				enabled = pkEnabled.GetBool();
				v1_ctx->enabled = enabled;

				if (!config_content.HasMember("exclude_size_threshold"))
				{
					LogfA(LOG_FILENAME, "'exclude_size_threshold' key must be exist in config!\n");
					return false;
				}
				const auto& pkSizeThreshoold = config_content["exclude_size_threshold"];
				if (!pkSizeThreshoold.IsNumber())
				{
					LogfA(LOG_FILENAME, "'exclude_size_threshold' key must defined as number!\n");
					return false;
				}
				v1_ctx->size_threshold = pkSizeThreshoold.GetUint();

				if (config_content.HasMember("files"))
				{
					const auto& pkFiles = config_content["files"];
					if (!pkFiles.IsArray())
					{
						LogfA(LOG_FILENAME, "'files' key must defined as array!\n");
						return false;
					}
					uint32_t idx = 0;
					const auto files = pkFiles.GetArray();
					for (const auto& file : files)
					{
						idx++;

						if (!file.IsString())
						{
							LogfA(LOG_FILENAME, "[%u] 'file' key must defined as string!\n", idx);
							return false;
						}

						const auto file_str = std::string(file.GetString(), file.GetStringLength());
						v1_ctx->files.emplace_back(stdext::utf8_to_wchar(file_str));
					}
				}
				if (config_content.HasMember("virtual_files"))
				{
					const auto& pkVirtualFiles = config_content["virtual_files"];
					if (!pkVirtualFiles.IsArray())
					{
						LogfA(LOG_FILENAME, "'virtual_files' key must defined as array!\n");
						return false;
					}
					uint32_t idx = 0;
					const auto v_files = pkVirtualFiles.GetArray();
					for (const auto& file : v_files)
					{
						idx++;

						if (!file.IsString())
						{
							LogfA(LOG_FILENAME, "[%u] 'virtual_file' key must defined as string!\n", idx);
							return false;
						}

						const auto file_str = std::string(file.GetString(), file.GetStringLength());
						v1_ctx->virtual_files.emplace_back(stdext::utf8_to_wchar(file_str));
					}

					if (config_content.HasMember("virtual_file_aliases"))
					{
						const auto& pkVirtualFileAliases = config_content["virtual_file_aliases"];
						if (!pkVirtualFileAliases.IsObject())
						{
							LogfA(LOG_FILENAME, "'virtual_file_aliases' key must defined as array!\n");
							return false;
						}

						uint32_t sub_idx = 0;
						const auto& aliasesObject = pkVirtualFileAliases.GetObject();
						for (auto it = aliasesObject.begin(); it != aliasesObject.end(); ++it)
						{
							sub_idx++;

							if (it->name.IsString() && it->value.IsString())
							{
								const auto alias_key = std::string(it->name.GetString(), it->name.GetStringLength());
								const auto alias_value = std::string(it->value.GetString(), it->value.GetStringLength());
								v1_ctx->virtual_file_aliases.emplace(stdext::utf8_to_wchar(alias_key), stdext::utf8_to_wchar(alias_value));
							}
							else
							{
								LogfA(LOG_FILENAME, "[%u][%u] 'virtual_file_aliase' value is not an string!\n", idx, sub_idx);
								return false;
							}
						}
					}
					else
					{
						LogfA(LOG_FILENAME, "'virtual_file_aliases' is not defnied!\n");
						return false;
					}
				}
				if (config_content.HasMember("paths"))
				{
					const auto& pkPaths = config_content["paths"];
					if (!pkPaths.IsArray())
					{
						LogfA(LOG_FILENAME, "'paths' key must be defined as an array!\n");
						return false;
					}

					uint32_t idx = 0;
					for (const auto& pathObj : pkPaths.GetArray())
					{
						idx++;

						if (!pathObj.IsObject())
						{
							LogfA(LOG_FILENAME, "[%u] 'path' key must defined as object!\n", idx);
							return false;
						}

						auto pathContext = std::make_shared<SPathContext>();
						if (!IS_VALID_SMART_PTR(pathContext))
						{
							LogfA(LOG_FILENAME, "[%u] SPathContext allocation failed! Error: %u\n", idx, errno);
							return false;
						}

						if (pathObj.HasMember("optional") && pathObj["optional"].IsBool())
						{
							pathContext->optional = pathObj["optional"].GetBool();
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'optional' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("path") && pathObj["path"].IsString())
						{
							const auto path_str = std::string(pathObj["path"].GetString(), pathObj["path"].GetStringLength());
							pathContext->path = stdext::utf8_to_wchar(path_str);
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'path' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("ignores") && pathObj["ignores"].IsArray())
						{
							uint32_t sub_idx = 0;
							const auto& ignoresArray = pathObj["ignores"].GetArray();
							for (const auto& ignore : ignoresArray)
							{
								sub_idx++;
								
								if (ignore.IsString())
								{
									const auto ignore_str = std::string(ignore.GetString(), ignore.GetStringLength());
									pathContext->ignores.emplace_back(stdext::utf8_to_wchar(ignore_str));
								}
								else
								{
									LogfA(LOG_FILENAME, "[%u][%u] 'ignore' value is not an string!\n", idx, sub_idx);
									return false;
								}
							}
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'ignores' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("aliases") && pathObj["aliases"].IsObject())
						{
							uint32_t sub_idx = 0;
							const auto& aliasesObject = pathObj["aliases"].GetObject();
							for (auto it = aliasesObject.begin(); it != aliasesObject.end(); ++it)
							{
								sub_idx++;
								
								if (it->name.IsString() && it->value.IsString())
								{
									const auto alias_key = std::string(it->name.GetString(), it->name.GetStringLength());
									const auto alias_value = std::string(it->value.GetString(), it->value.GetStringLength());
									pathContext->aliases.emplace(stdext::utf8_to_wchar(alias_key), stdext::utf8_to_wchar(alias_value));
								}
								else
								{
									LogfA(LOG_FILENAME, "[%u][%u] 'alias' value is not an string!\n", idx, sub_idx);
									return false;
								}
							}
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'aliases' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("ignored_sub_paths") && pathObj["ignored_sub_paths"].IsArray())
						{
							uint32_t sub_idx = 0;
							const auto& ignoredSubPathsArray = pathObj["ignored_sub_paths"].GetArray();
							for (const auto& ignored_sub_path : ignoredSubPathsArray)
							{
								sub_idx++;

								if (ignored_sub_path.IsString())
								{
									const auto sub_path_str = std::string(ignored_sub_path.GetString(), ignored_sub_path.GetStringLength());
									pathContext->ignored_sub_paths.emplace_back(stdext::utf8_to_wchar(sub_path_str));
								}
								else
								{
									LogfA(LOG_FILENAME, "[%u][%u] 'ignored_sub_path' value is not an string!\n", idx, sub_idx);
									return false;
								}
							}
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'ignored_sub_paths' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("recursive_visit") && pathObj["recursive_visit"].IsBool())
						{
							pathContext->recursive_visit = pathObj["recursive_visit"].GetBool();
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'recursive_visit' value does not exist or is not valid!\n", idx);
							return false;
						}

						if (pathObj.HasMember("ignore_files_without_extension") && pathObj["ignore_files_without_extension"].IsBool())
						{
							pathContext->ignore_files_without_extension = pathObj["ignore_files_without_extension"].GetBool();
						}
						else
						{
							LogfA(LOG_FILENAME, "[%u] 'ignore_files_without_extension' value does not exist or is not valid!\n", idx);
							return false;
						}

						v1_ctx->paths.emplace_back(pathContext);
					}
				}

				if (enabled && v1_ctx->files.empty() && v1_ctx->virtual_files.empty() && v1_ctx->paths.empty())
				{
					LogfA(LOG_FILENAME, "No file or path has been added!\n");
					return false;
				}

				ctx->v1_ctx = v1_ctx;
			}

			return true;
		}
		catch (const std::exception& e)
		{
			LogfA(LOG_FILENAME, "Exception handled on process_config_file, Error: %s\n", e.what());
			return false;
		}
	};
	if (!process_config_file())
	{
		LogfA(LOG_FILENAME, "process_config_file has been failed!\n");
		return EXIT_FAILURE;
	}
	const auto process_hash_list = [&]() {
		try
		{
			LogfA(LOG_FILENAME, "Processing hash list for version: %u\n", version);

			if (version == 1)
			{
				LogfA(LOG_FILENAME, "File list check started!\n");

				// Files
				for (const auto& file : ctx->v1_ctx->files)
				{
					LogfA(LOG_FILENAME, "Current file: %ls\n", file.c_str());

					std::error_code ec{};
					if (!std::filesystem::exists(file, ec) || ec)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls does not exist! Error: %u(%s)\n", file.c_str(), ec.value(), ec.message().c_str());
						continue;
					}

					const auto filesize = std::filesystem::file_size(file, ec);
					if (ec)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls size check failed! Error: %u(%s)\n", file.c_str(), ec.value(), ec.message().c_str());
						continue;
					}
					else if (!filesize)
					{
						LogfA(LOG_FILENAME, "[WARNING] Skipped empty file: %ls\n", file.c_str());
						continue;
					}
					else if (ctx->v1_ctx->size_threshold > filesize)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls reached size limit: %u with filesize: %llu\n", file.c_str(), ctx->v1_ctx->size_threshold, filesize);
						continue;
					}

					const auto filehash = get_file_sha1(stdext::wchar_to_utf8(file));
					if (filehash.empty())
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls hash could not calculated!\n", file.c_str());
						continue;
					}

					LogfA(LOG_FILENAME, "%ls >> %s", file.c_str(), filehash.c_str());
					raw_hash_list.push_back(std::make_tuple(file, stdext::to_lower_wide(filehash), false));
				}

				LogfA(LOG_FILENAME, "Virtual file list check started!\n");
				
				// Virtual Files
				for (const auto& file : ctx->v1_ctx->virtual_files)
				{
					LogfA(LOG_FILENAME, "Current file: %ls", file.c_str());

					std::error_code ec{};
					if (!std::filesystem::exists(file, ec) || ec)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls does not exist! Error: %u(%s)\n", file.c_str(), ec.value(), ec.message().c_str());
						continue;
					}

					const auto filesize = std::filesystem::file_size(file, ec);
					if (ec)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls size check failed! Error: %u(%s)\n", file.c_str(), ec.value(), ec.message().c_str());
						continue;
					}
					else if (!filesize)
					{
						LogfA(LOG_FILENAME, "[WARNING] Skipped empty file: %ls\n", file.c_str());
						continue;
					}
					else if (ctx->v1_ctx->size_threshold > filesize)
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls reached size limit: %u with filesize: %llu\n", file.c_str(), ctx->v1_ctx->size_threshold, filesize);
						continue;
					}

					const auto filehash = get_file_sha1(stdext::wchar_to_utf8(file));
					if (filehash.empty())
					{
						LogfA(LOG_FILENAME, "[WARNING] File: %ls hash could not calculated!\n", file.c_str());
						continue;
					}

					auto new_filename = file;
					for (const auto& [alias_old, alias_new] : ctx->v1_ctx->virtual_file_aliases)
					{
						if (new_filename.find(alias_old) != std::wstring::npos)
						{
							new_filename = stdext::replace(new_filename, alias_old, alias_new);
						}
					}

					LogfA(LOG_FILENAME, "%ls (%ls) >> %s\n", new_filename.c_str(), file.c_str(), filehash.c_str());
					virtual_hash_list.emplace(new_filename, stdext::to_lower_wide(filehash));
				}

				LogfA(LOG_FILENAME, "Path list check started!\n");

				// Paths
				uint32_t idx = 0;
				for (const auto& path : ctx->v1_ctx->paths)
				{
					idx++;

					auto path_name = path->path;
					if (path_name.empty())
					{
						LogfA(LOG_FILENAME, "[WARNING] [%u] Path name empty!\n", idx);
						continue;
					}
					else if (path_name == L"." || path_name == L"*")
					{
						LogfA(LOG_FILENAME, "[WARNING] [%u] Path name replaced with current path!\n", idx);
						path_name = std::filesystem::current_path().wstring();
					}
					else
					{
						path_name = fmt::format(L"{0}\\{1}", std::filesystem::current_path().wstring(), path_name);
						LogfA(LOG_FILENAME, "[%u] Path: %ls >> %ls\n", idx, path->path.c_str(), path_name.c_str());
					}

					LogfA(LOG_FILENAME, "Current path: %ls\n", path_name.c_str());

					std::error_code ec{};
					if (!std::filesystem::exists(path_name, ec) || ec)
					{
						LogfA(LOG_FILENAME, "[WARNING] [%u] Path: %ls does not exist! Error: %u(%s)\n", idx, path_name.c_str(), ec.value(), ec.message().c_str());
						continue;
					}

					auto fnOnDirectoryFileVisit = [&](bool recursive, const std::filesystem::directory_entry& entry) -> bool {
						auto filename = entry.path().filename().wstring();
						LogfA(LOG_FILENAME, "Current file: %ls", filename.c_str());

						if (entry.is_directory() && stdext::in_vector(path->ignored_sub_paths, filename))
						{
							LogfA(LOG_FILENAME, "[WARNING] Ignored sub path found in '%ls' and skipped...\n", filename.c_str());
							return true;
						}
						if (!entry.is_regular_file())
						{
							LogfA(LOG_FILENAME, "[WARNING] Non raw file entry found in '%ls' and skipped...\n", filename.c_str());
							return true;
						}

						std::error_code ec{};
						if (!std::filesystem::exists(filename, ec) || ec)
						{
							LogfA(LOG_FILENAME, "[WARNING] Non-exist file: '%ls' skiiped Error: %u(%s)\n", filename.c_str(), ec.value(), ec.message().c_str());
							return true;
						}

						const auto filesize = std::filesystem::file_size(filename, ec);
						if (ec)
						{
							LogfA(LOG_FILENAME, "[WARNING] File: %ls size check failed! Error: %u(%s)\n", filename.c_str(), ec.value(), ec.message().c_str());
							return true;
						}
						else if (!filesize)
						{
							LogfA(LOG_FILENAME, "[WARNING] Skipped empty file: %ls\n", filename.c_str());
							return true;
						}
						else if (ctx->v1_ctx->size_threshold > filesize)
						{
							LogfA(LOG_FILENAME, "[WARNING] File: %ls reached size limit: %u with filesize: %llu\n", filename.c_str(), ctx->v1_ctx->size_threshold, filesize);
							return true;
						}

						if (path->ignore_files_without_extension && !entry.path().has_extension())
						{
							LogfA(LOG_FILENAME, "[WARNING] File: %ls have not an extension, skipped!\n", filename.c_str());
							return true;
						}

						for (const auto& ignore : path->ignores)
						{
							if (WildcardMatch(filename.c_str(), ignore.c_str()))
							{
								LogfA(LOG_FILENAME, "[WARNING] File: %ls skipped by filter: %ls\n", filename.c_str(), ignore.c_str());
								return true;
							}
						}

						const auto filehash = get_file_sha1(stdext::wchar_to_utf8(filename));
						if (filehash.empty())
						{
							LogfA(LOG_FILENAME, "[WARNING] File: %ls hash could not calculated!\n", filename.c_str());
							return true;
						}

						for (const auto& [alias_old, alias_new] : path->aliases)
						{
							if (filename.find(alias_old) != std::wstring::npos)
							{
								filename = stdext::replace(filename, alias_old, alias_new);
								LogfA(LOG_FILENAME, "File: %ls replaced with: %ls by alias: %ls\n", entry.path().filename().wstring().c_str(), filename.c_str(), alias_new.c_str());
							}
						}

						LogfA(LOG_FILENAME, "%ls >> %s\n", filename.c_str(), filehash.c_str());
						raw_hash_list.push_back(std::make_tuple(filename, stdext::to_lower_wide(filehash), path->optional));
						return true;
					};
					
					if (path->recursive_visit)
					{
						for (const auto& entry : std::filesystem::recursive_directory_iterator(path_name, ec))
						{
							if (!fnOnDirectoryFileVisit(true, entry))
								break;
						}
					}
					else
					{
						for (const auto& entry : std::filesystem::directory_iterator(path_name, ec))
						{
							if (!fnOnDirectoryFileVisit(false, entry))
								break;
						}
					}
				}

				LogfA(LOG_FILENAME, "Hash list processed. Raw file count: %u Virtual file count: %u\n", raw_hash_list.size(), virtual_hash_list.size());
			
				if (enabled && raw_hash_list.empty() && virtual_hash_list.empty())
				{
					LogfA(LOG_FILENAME, "No files could be processed for the hash check.\n");
					return false;
				}
			}
			else
			{
				LogfA(LOG_FILENAME, "Undefined version: %u\n", version);
				return false;
			}

			return true;
		}
		catch (const std::exception& e)
		{
			LogfA(LOG_FILENAME, "Exception handled on process_hash_list, Error: %s\n", e.what());
			return false;
		}
	};
	if (!process_hash_list())
	{
		LogfA(LOG_FILENAME, "process_hash_list has been failed!\n");
		return EXIT_FAILURE;
	}
	const auto create_json_stream = [&]() {
		try
		{
			GenericStringBuffer <UTF16 <>> s;
			PrettyWriter <GenericStringBuffer <UTF16<>>, UTF16<>, UTF16<>> writer(s);

			writer.StartObject();
			{
				writer.Key(L"version");
				writer.Uint(version);

				writer.Key(L"enabled");
				writer.Bool(enabled);

				writer.Key(L"files");
				writer.StartArray();
				{
					for (const auto& [name, hash, optional] : raw_hash_list)
					{
						writer.StartObject();
						{
							writer.Key(L"name");
							writer.String(name.c_str());

							writer.Key(L"hash");
							writer.String(hash.c_str());

							writer.Key(L"optional");
							writer.Bool(optional);

							writer.Key(L"virtual");
							writer.Bool(false);
						}
						writer.EndObject();
					}
					for (const auto& [name, hash] : virtual_hash_list)
					{
						writer.StartObject();
						{
							writer.Key(L"name");
							writer.String(name.c_str());

							writer.Key(L"hash");
							writer.String(hash.c_str());

							writer.Key(L"optional");
							writer.Bool(false);

							writer.Key(L"virtual");
							writer.Bool(true);
						}
						writer.EndObject();
					}
				}
				writer.EndArray();
			}
			writer.EndObject();

			std::wostringstream woss;
			woss << std::setw(4) << s.GetString() << std::endl;
			hash_stream = woss.str();

#ifdef _DEBUG
			msl::file_ptr out_file("hash.json", "wb");
			if (!out_file)
			{
				LogfA(LOG_FILENAME, "%s could not open!\n", out.c_str());
				return false;
			}
			out_file.string_write(hash_stream);
#endif
		}
		catch (const std::exception& e)
		{
			LogfA(LOG_FILENAME, "Exception handled on create_json_stream, Error: %s\n", e.what());
			return false;
		}

		return true;
	};
	if (!create_json_stream())
	{
		LogfA(LOG_FILENAME, "create_json_stream has been failed!\n");
		return EXIT_FAILURE;
	}

	const auto write_to_packed_file = [&](const std::wstring& stream, const std::string& out) {

		// Open files
		msl::file_ptr out_file(out, "wb");
		if (!out_file)
		{
			LogfA(LOG_FILENAME, "%s could not open!\n", out.c_str());
			return false;
		}

		// Get common data
		const auto in_data = stdext::wchar_to_utf8(stream);
		const uint32_t in_size = stream.size();

		// TODO: Validate

		// Compress
		const auto bound = LZ4_compressBound(in_size);
		std::vector <uint8_t> compressed(bound);

		const auto compressedsize = LZ4_compress_HC(
			reinterpret_cast<const char*>(in_data.data()), reinterpret_cast<char*>(&compressed[0]),
			in_size, bound, LZ4HC_CLEVEL_MAX
		);
		if (compressedsize >= bound || compressedsize == 0)
		{
			LogfA(LOG_FILENAME, "Compression fail! Raw: %u Compressed: %u Capacity: %u\n", in_size, compressedsize, bound);
			return false;
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
			LogfA(LOG_FILENAME, "Caught exception on encryption: %s\n", exception.what());
			return false;
		}

		/// Write basic data
		// Magic
		const uint32_t magic = NM_CREATEMAGIC('N', 'M', 'G', 'B');
		out_file.write(&magic, sizeof(magic));

		// Version
		const uint32_t version = NOMERCY_GAME_INTEGRATION_VERSION;
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

		/// Write final data
		out_file.write(crypted.data(), crypted.size());

		return true;
	};
	if (!write_to_packed_file(hash_stream, out))
	{
		LogfA(LOG_FILENAME, "write_to_packed_file has been failed!\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
std::wstring dump_bundle_file(const std::string& filename)
{
	// Open files
	msl::file_ptr file(filename, "rb");
	if (!file)
	{
		LogfA(LOG_FILENAME, "File: %s could not open\n", filename.c_str());
		return {};
	}

	// Read file info
	uint32_t magic = 0;
	file.read(&magic, sizeof(magic));
	if (magic != NM_CREATEMAGIC('N', 'M', 'G', 'B'))
	{
		LogfA(LOG_FILENAME, "File magic is not valid: %p\n", magic);
		return {};
	}

	uint32_t version = 0;
	file.read(&version, sizeof(version));
	if (version != NOMERCY_GAME_INTEGRATION_VERSION)
	{
		LogfA(LOG_FILENAME, "File version is not valid: %u\n", version);
		return {};
	}

	uint32_t raw_size = 0;
	file.read(&raw_size, sizeof(raw_size));
	if (!raw_size)
	{
		LogfA(LOG_FILENAME, "File size could not determined\n");
		return {};
	}

	uint32_t raw_hash = 0;
	file.read(&raw_hash, sizeof(raw_hash));
	if (!raw_hash)
	{
		LogfA(LOG_FILENAME, "File hash could not determined\n");
		return {};
	}

	uint32_t final_size = 0;
	file.read(&final_size, sizeof(final_size));
	if (!final_size)
	{
		LogfA(LOG_FILENAME, "File size2 could not determined\n");
		return {};
	}

	uint32_t final_hash = 0;
	file.read(&final_hash, sizeof(final_hash));
	if (!final_hash)
	{
		LogfA(LOG_FILENAME, "File hash2 could not determined\n");
		return {};
	}

	// Alloc & read
	std::unique_ptr <uint8_t[]> buf(new uint8_t[final_size]);
	if (!buf)
	{
		LogfA(LOG_FILENAME, "File read buffer could not allocated\n");
		return {};
	}
	file.read(buf.get(), final_size);

	// Validate
	const auto current_hash = XXH32(buf.get(), final_size, 0);
	if (current_hash != final_hash)
	{
		LogfA(LOG_FILENAME, "File final hash mismatch, corrupted data.\n");
		return{};
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
		LogfA(LOG_FILENAME, "Caught exception on decryption: %s\n", exception.what());
		return {};
	}

	// Decompress
	std::vector <char> decompressed_buf(raw_size);

	const uint32_t decompressedsize = LZ4_decompress_safe(
		reinterpret_cast<const char*>(decrypted_buf.data()), reinterpret_cast<char*>(&decompressed_buf[0]),
		decrypted_buf.size(), decompressed_buf.size()
	);
	if (decompressedsize != raw_size)
	{
		LogfA(LOG_FILENAME, "Decomperssed size mismatch: %d-%u\n", decompressedsize, raw_size);
		return {};
	}

	// Validate
	const auto decompressed_hash = XXH32(decompressed_buf.data(), decompressed_buf.size(), 0);
	if (raw_hash != decompressed_hash)
	{
		LogfA(LOG_FILENAME, "Decomperssed hash mismatch: %p-%p\n", decompressed_hash, raw_hash);
		return {};
	}

	const auto final_data = std::string(decompressed_buf.data(), decompressed_buf.size());
	return stdext::to_wide(final_data);
}
int32_t dump_hashs(const std::string& filename, const std::string& out)
{
	msl::file_ptr out_file(out, "wb");
	if (!out_file)
	{
		LogfA(LOG_FILENAME, "File: %s could not open!\n", out.c_str());
		return EXIT_FAILURE;
	}

	const auto content = dump_bundle_file(filename);
	out_file.string_write(content);
	return EXIT_SUCCESS;
}
int32_t test_run(const std::string& in, const std::string& out)
{
	msl::file_ptr out_file(out, "wb");
	if (!out_file)
	{
		LogfA(LOG_FILENAME, "File: %s could not open!\n", out.c_str());
		return EXIT_FAILURE;
	}

	const auto content = dump_bundle_file(in);

	auto document = rapidjson::GenericDocument<UTF16<>>{};
	document.Parse(content.c_str());
	if (document.HasParseError())
	{
		LogfA(LOG_FILENAME, "File: %s could not parsed! Error: %s offset: %u\n", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
		return EXIT_FAILURE;
	}
	if (!document.IsObject())
	{
		LogfA(LOG_FILENAME, "File base is not an object! Type: %u\n", document.GetType());
		return EXIT_FAILURE;
	}

	if (!document.HasMember(L"version"))
	{
		LogfA(LOG_FILENAME, "'version' member does not exist!\n");
		return EXIT_FAILURE;
	}
	const auto& pkVersion = document[L"version"];
	if (!pkVersion.IsNumber())
	{
		LogfA(LOG_FILENAME, "'version' member is not an number!\n");
		return EXIT_FAILURE;
	}

	if (!document.HasMember(L"enabled"))
	{
		LogfA(LOG_FILENAME, "'enabled' enabled does not exist!\n");
		return EXIT_FAILURE;
	}
	const auto& pkEnabled = document[L"enabled"];
	if (!pkEnabled.IsBool())
	{
		LogfA(LOG_FILENAME, "'enabled' member is not an boolean!\n");
		return EXIT_FAILURE;
	}

	if (!document.HasMember(L"files"))
	{
		LogfA(LOG_FILENAME, "'files' enabled does not exist!\n");
		return EXIT_FAILURE;
	}
	const auto& pkFiles = document[L"files"];
	if (!pkFiles.IsArray())
	{
		LogfA(LOG_FILENAME, "'files' member is not an array!\n");
		return EXIT_FAILURE;
	}

	size_t idx = 0;
	for (const auto& pkFile : pkFiles.GetArray())
	{
		idx++;

		if (!pkFile.IsObject())
		{
			LogfA(LOG_FILENAME, "[%u] 'file' member is not an object!\n", idx);
			return EXIT_FAILURE;
		}

		if (!pkFile.HasMember(L"name"))
		{
			LogfA(LOG_FILENAME, "'name' enabled does not exist!\n");
			return EXIT_FAILURE;
		}
		const auto& pkName = pkFile[L"name"];
		if (!pkName.IsString())
		{
			LogfA(LOG_FILENAME, "'name' member is not an string!\n");
			return EXIT_FAILURE;
		}

		if (!pkFile.HasMember(L"hash"))
		{
			LogfA(LOG_FILENAME, "'hash' enabled does not exist!\n");
			return EXIT_FAILURE;
		}
		const auto& pkHash = pkFile[L"hash"];
		if (!pkHash.IsString())
		{
			LogfA(LOG_FILENAME, "'hash' member is not an string!\n");
			return EXIT_FAILURE;
		}

		if (!pkFile.HasMember(L"optional"))
		{
			LogfA(LOG_FILENAME, "'optional' enabled does not exist!\n");
			return EXIT_FAILURE;
		}
		const auto& pkOptional = pkFile[L"optional"];
		if (!pkOptional.IsBool())
		{
			LogfA(LOG_FILENAME, "'optional' member is not an boolean!\n");
			return EXIT_FAILURE;
		}

		if (!pkFile.HasMember(L"virtual"))
		{
			LogfA(LOG_FILENAME, "'virtual' enabled does not exist!\n");
			return EXIT_FAILURE;
		}
		const auto& pkVirtual = pkFile[L"virtual"];
		if (!pkVirtual.IsBool())
		{
			LogfA(LOG_FILENAME, "'virtual' member is not an boolean!\n");
			return EXIT_FAILURE;
		}

		const auto file_name = std::wstring(pkName.GetString(), pkName.GetStringLength());
		const auto file_hash = std::wstring(pkHash.GetString(), pkHash.GetStringLength());
		const auto is_optional = pkOptional.GetBool();
		const auto is_virtual = pkVirtual.GetBool();

		if (!is_virtual && (!std::filesystem::exists(file_name) || !std::filesystem::is_regular_file(file_name)))
		{
			LogfA(LOG_FILENAME, "File: %ls does not exists!\n", file_name.c_str());
			continue;
		}

		const auto current_filehash = stdext::to_lower_wide(get_file_sha1(stdext::wchar_to_utf8(file_name)));
		if (current_filehash.empty())
		{
			LogfA(LOG_FILENAME, "File: %ls hash calculate failed!\n", file_name.c_str());
			continue;
		}
		
		LogfA(LOG_FILENAME, "[%u] '%ls' >> '%ls'/'%ls' EQ:%d -- O:%d V:%d\n",
			idx, file_name.c_str(), file_hash.c_str(), current_filehash.c_str(), file_hash == current_filehash, is_optional, is_virtual
		);
	}

	return EXIT_SUCCESS;
}


int32_t main(int32_t argc, char* argv[])
{
#ifdef _DEBUG
	std::string type = "create_hash_list", in = "../document/internal/NoMercy_game_integration_config.json", out = "NoMercy_Game.fdb";
//	std::string type = "dump_hashs", in = "NoMercy_Game.fdb", out = "NoMercy_Game_bundle_dump.json";
//	std::string type = "test_run", in = "NoMercy_Game.fdb", out = "NoMercy_Game_validation.log";
#else
	static const auto known_types = { "create_hash_list", "dump_hashs", "test_run" };
	static const auto required_keys = { "type", "in", "out" };

	cxxopts::Options options(argv[0], "");

	options.add_options()
		("t,type", "Work type", cxxopts::value<std::string>())
		("i,in", "Input(Config/Packed) file name", cxxopts::value<std::string>())
		("o,out", "Output file name", cxxopts::value<std::string>())
		("h,help", "Print usage")
	;

	std::string type, in, out;
	try
	{
		auto result = options.parse(argc, argv);
		if (argc < 2 || result.count("help"))
		{
			LogfA(LOG_FILENAME, options.help().c_str());
			LogfA(LOG_FILENAME, "Known types:\n");
			for (const auto& known_type : known_types)
			{
				LogfA(LOG_FILENAME, "\t - %s\n", known_type);
			}
			return EXIT_FAILURE;
		}

		for (const auto& req_key : required_keys)
		{
			if (!result.count(req_key))
			{
				LogfA(LOG_FILENAME, "'%s' key must be exist\n", req_key);
				return EXIT_FAILURE;
			}
		}

		type = result["type"].as<std::string>();
		if (type.empty() || std::find(known_types.begin(), known_types.end(), type) == known_types.end())
		{
			LogfA(LOG_FILENAME, "Unknown type: %s\n", type.c_str());
			return EXIT_FAILURE;
		}

		in = result["in"].as<std::string>();
		if (in.empty() || !std::filesystem::exists(in))
		{
			LogfA(LOG_FILENAME, "Input file: %s does not exist\n", in.c_str());
			return EXIT_FAILURE;
		}

		out = result["out"].as<std::string>();
		if (out.empty() || std::filesystem::exists(out))
		{
			LogfA(LOG_FILENAME, "Output file: %s is null or already exist\n", out.c_str());
			return EXIT_FAILURE;
		}
	}
	catch (const cxxopts::exceptions::exception& ex)
	{
		LogfA(LOG_FILENAME, "Console parse exception: %s\n", ex.what());
		return EXIT_FAILURE;
	}
	catch (const std::exception& ex)
	{
		LogfA(LOG_FILENAME, "System exception: %s\n", ex.what());
		return EXIT_FAILURE;
	}
	catch (...)
	{
		LogfA(LOG_FILENAME, "Unhandled exception\n");
		return EXIT_FAILURE;
	}
#endif

	switch (stdext::hash(type.c_str()))
	{
		case stdext::hash("create_hash_list"):
			return create_hash_list(in, out);
		case stdext::hash("dump_hashs"):
			return dump_hashs(in, out);
		case stdext::hash("test_run"):
			return test_run(in, out);
		default:
			return EXIT_SUCCESS;
	}
}
