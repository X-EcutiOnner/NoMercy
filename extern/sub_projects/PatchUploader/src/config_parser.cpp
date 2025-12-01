#include "../include/main.hpp"
#include "../include/config_parser.hpp"
#include "../include/worker.hpp"

CConfigParser::CConfigParser() :
	m_bParsed(false)
{
}
CConfigParser::~CConfigParser()
{
}

bool CConfigParser::ParseConfigFile(const std::string& c_stConfigFile)
{	
	try
	{
		LogfA(LOG_FILENAME, "Parsing config file: %s", c_stConfigFile.c_str());

		if (!std::filesystem::exists(c_stConfigFile))
		{
			LogfA(LOG_FILENAME, "Config file does not exist!");
			return false;
		}

		const auto fp = msl::file_ptr(c_stConfigFile, "rb");
		if (!fp)
		{
			LogfA(LOG_FILENAME, "Config file could not open! Error: %d", errno);
			return false;
		}

		const auto buffer = fp.string_read();
		if (buffer.empty())
		{
			LogfA(LOG_FILENAME, "Config file could not read! Error: %d", errno);
			return false;
		}

		doc.Parse<kParseCommentsFlag>(reinterpret_cast<const char*>(buffer.data()));
		if (doc.HasParseError())
		{
			LogfA(LOG_FILENAME, "Config file could not parsed! Error: %s offset: %u", GetParseError_En(doc.GetParseError()), doc.GetErrorOffset());
			return false;
		}
		else if (!doc.IsObject())
		{
			LogfA(LOG_FILENAME, "Config file base is not an object! Type: %u", doc.GetType());
			return false;
		}
		
		if (!doc.HasMember("hosts"))
		{
			LogfA(LOG_FILENAME, "Config 'hosts' key does not exist!");
			return false;
		}
		else if (!doc.HasMember("ftp_hosts"))
		{
			LogfA(LOG_FILENAME, "Config 'ftp_hosts' key does not exist!");
			return false;
		}
		else if (!doc.HasMember("version"))
		{
			LogfA(LOG_FILENAME, "Config 'version' key does not exist!");
			return false;
		}
		else if (!doc.HasMember("sdk_files"))
		{
			LogfA(LOG_FILENAME, "Config 'sdk_files' key does not exist!");
			return false;
		}
		else if (!doc.HasMember("game_files"))
		{
			LogfA(LOG_FILENAME, "Config 'game_files' key does not exist!");
			return false;
		}
		else if (!doc.HasMember("ac_files"))
		{
			LogfA(LOG_FILENAME, "Config 'ac_files' key does not exist!");
			return false;
		}

		if (!doc["hosts"].IsObject())
		{
			LogfA(LOG_FILENAME, "Config 'hosts' key is not object!");
			return false;
		}
		else if (doc["hosts"].ObjectEmpty())
		{
			LogfA(LOG_FILENAME, "Config 'hosts' value is not valid!");
			return false;
		}

		if (!doc["ftp_hosts"].IsObject())
		{
			LogfA(LOG_FILENAME, "Config 'ftp_hosts' key is not object!");
			return false;
		}
		/*
		else if (doc["ftp_hosts"].ObjectEmpty())
		{
			LogfA(LOG_FILENAME, "Config 'ftp_hosts' value is not valid!");
			return false;
		}
		*/

		if (!doc["version"].IsNumber())
		{
			LogfA(LOG_FILENAME, "Config 'version' key is not number!");
			return false;
		}
		else if (!doc["version"].GetInt())
		{
			LogfA(LOG_FILENAME, "Config 'version' value is not valid!");
			return false;
		}

		if (!doc["sdk_files"].IsObject())
		{
			LogfA(LOG_FILENAME, "Config 'sdk_files' key is not object!");
			return false;
		}
		else if (doc["sdk_files"].ObjectEmpty())
		{
			LogfA(LOG_FILENAME, "Config 'sdk_files' value is null!");
			return false;
		}

		if (!doc["game_files"].IsObject())
		{
			LogfA(LOG_FILENAME, "Config 'game_files' key is not object!");
			return false;
		}
		else if (doc["game_files"].ObjectEmpty())
		{
			LogfA(LOG_FILENAME, "Config 'game_files' value is null!");
			return false;
		}

		if (!doc["ac_files"].IsObject())
		{
			LogfA(LOG_FILENAME, "Config 'ac_files' key is not object!");
			return false;
		}
		else if (doc["ac_files"].ObjectEmpty())
		{
			LogfA(LOG_FILENAME, "Config 'ac_files' value is null!");
			return false;
		}

		m_bParsed = true;
		LogfA(LOG_FILENAME, "Config file parsed successfully, processing parsed data...");
		return __ProcessConfigFile(CWorker::Instance().GetParams()->u32PatchVersion);
	}
	catch (const std::exception& e)
	{
		LogfA(LOG_FILENAME, "Exception handled on read_config_file Error: %s", e.what());
		return false;
	}
}

bool CConfigParser::__ProcessConfigFile(uint32_t nVersion)
{
	m_spConfigCtx = std::make_shared<SConfigCtx>();
	if (!m_spConfigCtx)
	{
		LogfA(LOG_FILENAME, "Config context could not be created!");
		return false;
	}

	// S3 config
	if (!doc.HasMember("hosts") || !doc["hosts"].IsObject())
	{
		LogfA(LOG_FILENAME, "hosts key is not valid!");
		return false;
	}

	const auto& hosts = doc["hosts"];
	for (auto it = hosts.MemberBegin(); it != hosts.MemberEnd(); ++it)
	{
		SHostCtx hostCtx;

		if (!it->name.IsString())
		{
			LogfA(LOG_FILENAME, "hosts key is not valid!");
			return false;
		}
		hostCtx.hostname = std::string(it->name.GetString(), it->name.GetStringLength());

		if (!it->value.IsObject())
		{
			LogfA(LOG_FILENAME, "hosts value is not valid!");
			return false;
		}

		const auto& host = it->value;
		if (!host.HasMember("endpoint") || !host["endpoint"].IsString() || !host["endpoint"].GetStringLength())
		{
			LogfA(LOG_FILENAME, "host:endpoint key is not valid!");
			return false;
		}
		hostCtx.endpoint = host["endpoint"].GetString();

		if (!host.HasMember("access_key") || !host["access_key"].IsString() || !host["access_key"].GetStringLength())
		{
			LogfA(LOG_FILENAME, "host:access_key key is not valid!");
			return false;
		}
		hostCtx.access_key = host["access_key"].GetString();

		if (!host.HasMember("secret_key") || !host["secret_key"].IsString() || !host["secret_key"].GetStringLength())
		{
			LogfA(LOG_FILENAME, "host:secret_key key is not valid!");
			return false;
		}
		hostCtx.secret_key = host["secret_key"].GetString();

		m_spConfigCtx->hosts.emplace_back(hostCtx);
	}

	// SFTP config
	if (!doc.HasMember("ftp_hosts") || !doc["ftp_hosts"].IsObject())
	{
		LogfA(LOG_FILENAME, "ftp_hosts key is not valid!");
		return false;
	}

	if (!doc["ftp_hosts"].ObjectEmpty())
	{
		const auto& sftp_hosts = doc["ftp_hosts"];
		for (auto it = sftp_hosts.MemberBegin(); it != sftp_hosts.MemberEnd(); ++it)
		{
			SSFTPHostCtx hostCtx;

			if (!it->name.IsString())
			{
				LogfA(LOG_FILENAME, "ftp_hosts key is not valid!");
				return false;
			}
			hostCtx.hostname = std::string(it->name.GetString(), it->name.GetStringLength());

			if (!it->value.IsObject())
			{
				LogfA(LOG_FILENAME, "ftp_hosts value is not valid!");
				return false;
			}

			const auto& host = it->value;

			if (!host.HasMember("endpoint") || !host["endpoint"].IsString() || !host["endpoint"].GetStringLength())
			{
				LogfA(LOG_FILENAME, "host:endpoint key is not valid!");
				return false;
			}
			hostCtx.endpoint = host["endpoint"].GetString();

			if (!host.HasMember("port") || !host["port"].IsNumber())
			{
				LogfA(LOG_FILENAME, "host:port key is not valid!");
				return false;
			}
			hostCtx.port = host["port"].GetUint();

			if (!host.HasMember("username") || !host["username"].IsString() || !host["username"].GetStringLength())
			{
				LogfA(LOG_FILENAME, "host:username key is not valid!");
				return false;
			}
			hostCtx.username = host["username"].GetString();

			if (!host.HasMember("password") || !host["password"].IsString() || !host["password"].GetStringLength())
			{
				LogfA(LOG_FILENAME, "host:password key is not valid!");
				return false;
			}
			hostCtx.password = host["password"].GetString();

			m_spConfigCtx->sftp_hosts.emplace_back(hostCtx);
		}
	}
	
	// Config version
	m_spConfigCtx->version = doc["version"].GetInt();
	LogfA(LOG_FILENAME, "Version: %d", m_spConfigCtx->version);

	if (m_spConfigCtx->version != 1)
	{
		LogfA(LOG_FILENAME, "Version is not allowed!");
		return false;
	}

	// Root path
	m_spConfigCtx->target_path = fmt::format("{0}\\1.{1}", CWorker::Instance().GetParams()->stRootPath, nVersion);
	LogfA(LOG_FILENAME, "Target path: %s", m_spConfigCtx->target_path.c_str());

	if (!std::filesystem::exists(m_spConfigCtx->target_path))
	{
		LogfA(LOG_FILENAME, "Target path does not exist!");
		return false;
	}

	// Single file
	const auto stUpdateFile = CWorker::Instance().GetParams()->stUpdateFile;
	if (!stUpdateFile.empty())
	{
		const auto stFileNameWithPath = fmt::format("{0}\\{1}", m_spConfigCtx->target_path, stUpdateFile);
		LogfA(LOG_FILENAME, "Single target: %s (%s)", stUpdateFile.c_str(), stFileNameWithPath.c_str());

		if (!std::filesystem::exists(stFileNameWithPath))
		{
			LogfA(LOG_FILENAME, "Target file: %s does not exist!", stFileNameWithPath.c_str());
			return false;
		}

		if (stUpdateFile == "NoMercy_SystemModule_x64.sys")
		{
			auto spFileContainerCtx = std::make_shared<SFileContainerCtx>();
			spFileContainerCtx->id = "ac_files";
			spFileContainerCtx->method = "md5";

			auto spFileCtx = std::make_shared<SFileCtx>();
			spFileCtx->name = stUpdateFile.c_str();
			spFileCtx->local_path = "";
			spFileCtx->attr = NoMercySetup::EFileAttributes::FILE_ATTR_PATH_SYSTEM;
			spFileCtx->optional = false;
			spFileContainerCtx->files.emplace_back(spFileCtx);

			m_spConfigCtx->file_containers.emplace_back(spFileContainerCtx);
			return true;
		}
		else
		{
			LogfA(LOG_FILENAME, "Target file: %s is not a known file!", stFileNameWithPath.c_str());
			return false;
		}
	}

	// Files
	size_t idx = 0;
	for (const auto& objFiles : { doc["sdk_files"].GetObject(), doc["game_files"].GetObject(), doc["ac_files"].GetObject() })
	{
		idx++;

		auto spFileContainerCtx = std::make_shared<SFileContainerCtx>();
		if (idx == 1)
		{
			spFileContainerCtx->id = "sdk_files";
		}
		else if (idx == 2)
		{
			spFileContainerCtx->id = "game_files";
		}
		else if (idx == 3)
		{
			spFileContainerCtx->id = "ac_files";
		}
		else
		{
			LogfA(LOG_FILENAME, "Unknown index: %u", idx);
			return false;
		}

		LogfA(LOG_FILENAME, "Checking object: %d (%s)", idx, spFileContainerCtx->id.c_str());

		size_t file_idx = 0;
		for (auto node = objFiles.MemberBegin(); node != objFiles.MemberEnd(); ++node)
		{
			if (!node->name.IsString())
			{
				LogfA(LOG_FILENAME, "Node: %u key is not an string! Key: %s Type: %u", file_idx, node->name.IsString() ? node->name.GetString() : "<not_string>", node->name.GetType());
				return false;
			}

			const std::string id = node->name.GetString();
			LogfA(LOG_FILENAME, "\t[%u] Node: %s", file_idx, id.c_str());

			if (id == "check_method")
			{
				spFileContainerCtx->method = node->value.GetString();
				LogfA(LOG_FILENAME, "\t\tCheck method: %s", spFileContainerCtx->method.c_str());
				continue;
			}
			else if (id == "files")
			{
				size_t child_idx = 0;
				auto objGameFilesContext = node->value.GetObject();
				for (auto childNode = objGameFilesContext.MemberBegin(); childNode != objGameFilesContext.MemberEnd(); ++childNode)
				{
					child_idx++;

					auto spFileCtx = std::make_shared<SFileCtx>();
					spFileCtx->name = childNode->name.GetString();
					LogfA(LOG_FILENAME, "\t\t[%u] File: %s", child_idx, spFileCtx->name.c_str());

					auto objFileContext = childNode->value.GetObject();
					for (auto fileCtxNode = objFileContext.MemberBegin(); fileCtxNode != objFileContext.MemberEnd(); ++fileCtxNode)
					{
						std::string stFileCtxKey = fileCtxNode->name.GetString();
						if (stFileCtxKey == "local_path")
						{
							spFileCtx->local_path = fileCtxNode->value.GetString();
							LogfA(LOG_FILENAME, "\t\t\tPath: %s", spFileCtx->local_path.c_str());
						}
						else if (stFileCtxKey == "attr")
						{
							for (const auto& pkAttr : fileCtxNode->value.GetArray())
							{
								const auto stAttr = std::string(pkAttr.GetString());
								if (stAttr == "system")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_PATH_SYSTEM;
								}
								else if (stAttr == "game")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_PATH_GAME;
								}
								else if (stAttr == "local")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_PATH_LOCAL;
								}
								else if (stAttr == "hidden")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_HIDDEN;
								}
								else if (stAttr == "crypted_1")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_CRYPTED_1;
								}
								else if (stAttr == "compressed_1")
								{
									spFileCtx->attr |= NoMercySetup::EFileAttributes::FILE_ATTR_COMPRESSED_1;
								}
								else
								{
									LogfA(LOG_FILENAME, "Unknown dependency attribute: %s", stAttr.c_str());
									return false;
								}
								LogfA(LOG_FILENAME, "\t\t\tAttr: %u", spFileCtx->attr);
							}
						}
						else if (stFileCtxKey == "preprocess")
						{
							spFileCtx->preprocess = fileCtxNode->value.GetString();
							LogfA(LOG_FILENAME, "\t\t\tPreprocess: %s", spFileCtx->preprocess.c_str());
						}
						else if (stFileCtxKey == "optional")
						{
							spFileCtx->optional = fileCtxNode->value.GetBool();
							LogfA(LOG_FILENAME, "\t\t\tOptional: %d", spFileCtx->optional ? 1 : 0);
						}
						else if (stFileCtxKey == "skip_pdb")
						{
							spFileCtx->skip_pdb = fileCtxNode->value.GetBool();
							LogfA(LOG_FILENAME, "\t\t\tSkip PDB: %d", spFileCtx->skip_pdb ? 1 : 0);
						}
						else if (stFileCtxKey == "rename")
						{
							spFileCtx->new_name = fileCtxNode->value.GetString();
							LogfA(LOG_FILENAME, "\t\t\tNew name: %s", spFileCtx->new_name.c_str());
						}
						else if (stFileCtxKey == "file_path")
						{
							spFileCtx->local_source_file = fmt::format("{0}\\{1}{2}", m_spConfigCtx->target_path, fileCtxNode->value.GetString(), spFileCtx->name);
							LogfA(LOG_FILENAME, "\t\t\tFile path: %s (%s)", fileCtxNode->value.GetString(), spFileCtx->local_source_file.c_str());
						}
						else
						{
							LogfA(LOG_FILENAME, "Unknown file key: %s", stFileCtxKey.c_str());
							return false;
						}
					}

					spFileContainerCtx->files.emplace_back(spFileCtx);
				}
			}
			else
			{
				LogfA(LOG_FILENAME, "Unknown id: %s", id.c_str());
				return false;
			}

			m_spConfigCtx->file_containers.emplace_back(spFileContainerCtx);
		}
	}

	return true;
};
