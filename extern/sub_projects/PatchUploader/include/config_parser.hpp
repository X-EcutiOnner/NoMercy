#pragma once
#include "../../source/Common/AbstractSingleton.hpp"
#include "storage_helper.hpp"
#include <optional>

#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>

struct SFileCtx
{
	std::string name;
	std::string new_name;
	std::string local_source_file;
	std::string local_debug_symbol_file;
	std::string local_path;
	uint32_t attr;
	std::string preprocess;
	uint32_t size;
	std::string hash;
	std::string egg_hash;
	bool optional;
	bool skip_pdb;
	bool processed{ false };
	std::vector <SObjectDetails> binary_metadata;
	std::vector <SObjectDetails> symbol_metadata;
};
struct SFileContainerCtx
{
	std::string id;
	std::string method;
	std::vector <std::shared_ptr <SFileCtx>> files;
	std::string archive_file;
	std::string archive_metadata;
};
struct SHostCtx
{
	std::string hostname;
	std::string endpoint;
	std::string access_key;
	std::string secret_key;
};
struct SSFTPHostCtx
{
	std::string hostname;
	std::string endpoint;
	uint16_t port;
	std::string username;
	std::string password;
};
struct SConfigCtx
{
	std::vector <SHostCtx> hosts;
	std::vector <SSFTPHostCtx> sftp_hosts;
	int32_t version;
	std::string target_path;
	std::vector <std::shared_ptr <SFileContainerCtx>> file_containers;
};

class CConfigParser : public CSingleton <CConfigParser>
{
public:
	CConfigParser();
	virtual ~CConfigParser();

	bool ParseConfigFile(const std::string& c_stConfigFile);

	auto GetConfig() const { return m_spConfigCtx; };

protected:
	bool __ProcessConfigFile(uint32_t nVersion);

private:
	bool m_bParsed;
	std::shared_ptr <SConfigCtx> m_spConfigCtx;
	Document doc;
};
