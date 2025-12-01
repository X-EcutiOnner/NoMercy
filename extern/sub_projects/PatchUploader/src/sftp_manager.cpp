#include "../include/sftp_manager.hpp"
#include "../include/BasicLog.hpp"
#include "../include/config_parser.hpp"
#include <fcntl.h>
#include <array>

// https://curl.se/libcurl/c/ftpupload.html

namespace
{
	static constexpr mode_t DEFAULT_FILE_PERMISSION = 0755;
	static constexpr mode_t DEFAULT_DIR_PERMISSION = 0755;
	static constexpr unsigned long long MAX_TRANSFER_SIZE = 65536;

	struct sshKeyPtr
	{
		ssh_key sshKey{ nullptr };
		
		~sshKeyPtr()
		{
			ssh_key_free(sshKey);
		}
	};
	struct hashPtr
	{
		unsigned char* hash{ nullptr };
		
		~hashPtr()
		{
			ssh_clean_pubkey_hash(&hash);
		}
	};
	struct hexHashPtr
	{
		char* hexHash = nullptr;
		
		~hexHashPtr()
		{
			ssh_string_free_char(hexHash);
		}
	};
}

CSFTPManager::CSFTPManager() :
	m_pSSHSession(nullptr), m_pSFTPSession(nullptr)
{
}
CSFTPManager::~CSFTPManager()
{
	this->Close();
}

void CSFTPManager::Close()
{
	if (m_pSFTPSession)
	{
		sftp_free(m_pSFTPSession);
		m_pSFTPSession = nullptr;
	}

	if (m_pSSHSession)
	{
		ssh_disconnect(m_pSSHSession);
		ssh_free(m_pSSHSession);
		m_pSSHSession = nullptr;
	}
}

bool CSFTPManager::Connect(
	const std::string& ip,
	const uint16_t port,
	const std::string& username,
	const std::string& password,
	const std::string& pubKey,
	const std::string& privKey,
	const std::function <std::string()>& getPrivKeyPassPhraseFn,
	const std::vector <std::string>& serverFingerPrints)
{
	if (ip.empty() || !port)
	{
		LogfA(LOG_FILENAME, "Invalid ip or port: %s:%u", ip.c_str(), port);
		this->Close();
		return false;
	}
	if (username.empty())
	{
		LogfA(LOG_FILENAME, "Invalid username: %s", username.c_str());
		this->Close();
		return false;
	}
	if ((password.empty()) && (pubKey.empty() || privKey.empty() || !getPrivKeyPassPhraseFn))
	{
		LogfA(LOG_FILENAME, "Invalid password and keys");
		this->Close();
		return false;
	}

	if (!this->SSHConnect(ip, port, username, password))
	{
		LogfA(LOG_FILENAME, "SSHConnect(%s:%u) failed!", ip.c_str(), port);
		this->Close();
		return false;
	}
	
	if (!serverFingerPrints.empty())
	{
		if (!this->VerifySFTPServerIdentity(serverFingerPrints))
		{
			LogfA(LOG_FILENAME, "VerifySFTPServerIdentity failed!");
			this->Close();
			return false;
		}
	}

	if (!pubKey.empty() && !privKey.empty())
	{
		if (!this->SSHAuthorize(username, pubKey, privKey, getPrivKeyPassPhraseFn()))
		{
			LogfA(LOG_FILENAME, "SSHAuthorize(%s / %s / %s) failed!", username.c_str(), pubKey.c_str(), privKey.c_str());
			this->Close();
			return false;
		}
	}
	
	if (!this->SFTPConnect())
	{
		LogfA(LOG_FILENAME, "SFTPConnect failed!");
		this->Close();
		return false;
	}

	LogfA(LOG_FILENAME, "Connected to SFTP!");
	return true;
}

bool CSFTPManager::SSHConnect(const std::string& ip, const uint16_t port, const std::string& username, const std::string& password)
{
	auto ret = ssh_init();
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_init() failed with: %d", ret);
		return false;
	}

	m_pSSHSession = ssh_new();
	if (!m_pSSHSession)
	{
		LogfA(LOG_FILENAME, "SSH session cannot started!");
		return false;
	}
	
	ret = ssh_set_log_callback([](int priority, const char* function, const char* buffer, void* userdata) {
		LogfA(LOG_FILENAME, "[SSH] [%d] %s :: %s", priority, function, buffer);
	});
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_set_log_callback failed with: %d", ret);
		return false;
	}
	
	ret = ssh_set_log_level(SSH_LOG_DEBUG);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_set_log_level failed with: %d", ret);
		return false;
	}

	auto verbosity = SSH_LOG_PROTOCOL;
	ret = ssh_options_set(m_pSSHSession, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_options_set(SSH_OPTIONS_LOG_VERBOSITY) failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}

	auto pIpPtr = ip.c_str();
	ret = ssh_options_set(m_pSSHSession, SSH_OPTIONS_HOST, pIpPtr);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_options_set(SSH_OPTIONS_HOST) failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}

	auto pPortPtr = &port;
	ret = ssh_options_set(m_pSSHSession, SSH_OPTIONS_PORT, pPortPtr);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_options_set(SSH_OPTIONS_PORT) failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}

	auto pUserPtr = username.c_str();
	ret = ssh_options_set(m_pSSHSession, SSH_OPTIONS_USER, pUserPtr);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_options_set(SSH_OPTIONS_USER) failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}

	ret = ssh_connect(m_pSSHSession);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_connect failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}

	ret = ssh_userauth_password(m_pSSHSession, nullptr, password.c_str());
	if (ret != SSH_AUTH_SUCCESS)
	{
		LogfA(LOG_FILENAME, "ssh_userauth_password failed with: %d / %s", ret, ssh_get_error(m_pSSHSession));
		return false;
	}
	
	return true;
}
bool CSFTPManager::SSHAuthorize(const std::string& username, const std::string& pubKey, const std::string& privKey, const std::string& privKeyPassPhrase)
{
	sshKeyPtr publickey;
	sshKeyPtr privatekey;

	auto ret = ssh_pki_import_pubkey_base64(pubKey.c_str(), SSH_KEYTYPE_RSA, &publickey.sshKey);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_pki_import_pubkey_base64 failed with: %d", ret);
		return false;
	}

	ret = ssh_userauth_try_publickey(m_pSSHSession, username.c_str(), publickey.sshKey);
	if (ret != SSH_AUTH_SUCCESS)
	{
		LogfA(LOG_FILENAME, "ssh_userauth_try_publickey failed with: %d", ret);
		return false;
	}

	ret = ssh_pki_import_privkey_base64(privKey.c_str(), privKeyPassPhrase.c_str(), NULL, NULL, &privatekey.sshKey);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_pki_import_privkey_base64 failed with: %d", ret);
		return false;
	}

	ret = ssh_userauth_publickey(m_pSSHSession, username.c_str(), privatekey.sshKey);
	if (ret != SSH_AUTH_SUCCESS)
	{
		LogfA(LOG_FILENAME, "ssh_userauth_publickey failed with: %d", ret);
		return false;
	}

	return true;
}
bool CSFTPManager::VerifySFTPServerIdentity(const std::vector <std::string>& serverFingerPrints)
{
	sshKeyPtr srv_pubkey;
	hashPtr hash_ptr;
	hexHashPtr hexHash_ptr;

	auto ret = ssh_get_server_publickey(m_pSSHSession, &srv_pubkey.sshKey);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_get_server_publickey failed with: %d", ret);
		return false;
	}

	size_t hlen;
	ret = ssh_get_publickey_hash(srv_pubkey.sshKey, SSH_PUBLICKEY_HASH_SHA256, &hash_ptr.hash, &hlen);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "ssh_get_publickey_hash failed with: %d", ret);
		return false;
	}

	hexHash_ptr.hexHash = ssh_get_hexa(hash_ptr.hash, hlen);
	if (std::find(serverFingerPrints.begin(), serverFingerPrints.end(), hexHash_ptr.hexHash) == serverFingerPrints.end())
	{
		LogfA(LOG_FILENAME, "Server fingerprint is not accepted!");
		return false;
	}

	return true;
}
bool CSFTPManager::SFTPConnect()
{
	m_pSFTPSession = sftp_new(m_pSSHSession);
	if (!m_pSFTPSession)
	{
		LogfA(LOG_FILENAME, "SFTP session cannot started!");
		return false;
	}

	const auto ret = sftp_init(m_pSFTPSession);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_init failed with: %d", ret);
		return false;
	}

	return true;
}

bool CSFTPManager::Upload(const std::string& srcFile, const std::string& dstFile)
{
	bool bRet = false;
	sftp_file serverFile = nullptr;
	char* srcFileBuffer = nullptr;
	std::ifstream srcFileStream;
	
	do
	{
		if (!this->IsConnected())
		{
			LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
			break;
		}

		std::error_code ec{};
		if (!std::filesystem::exists(srcFile, ec))
		{
			LogfA(LOG_FILENAME, "File %s does not exist!", srcFile.c_str());
			break;
		}
		if (ec)
		{
			LogfA(LOG_FILENAME, "File exist check error: %s", ec.message().c_str());
			break;
		}

		auto srcFileSize = std::filesystem::file_size(srcFile, ec);
		if (!srcFileSize)
		{
			LogfA(LOG_FILENAME, "File %s size is 0!", srcFile.c_str());
			break;
		}
		if (ec)
		{
			LogfA(LOG_FILENAME, "File size check error: %s", ec.message().c_str());
			break;
		}

		LogfA(LOG_FILENAME, "File %s size is %llu", srcFile.c_str(), srcFileSize);

		srcFileStream = std::ifstream(srcFile, std::ios::binary);
		if (!srcFileStream.is_open())
		{
			LogfA(LOG_FILENAME, "File %s cannot be opened! Error: %d", srcFile.c_str(), errno);
			break;
		}

		srcFileBuffer = (char*)std::calloc(srcFileSize, sizeof(char));
		if (!srcFileBuffer)
		{
			LogfA(LOG_FILENAME, "File %s cannot be allocated! Error: %d", srcFile.c_str(), errno);
			break;
		}
		
		srcFileStream.read(srcFileBuffer, srcFileSize);

		const auto nReadSize = srcFileStream.gcount();
		if (nReadSize != srcFileSize)
		{
			LogfA(LOG_FILENAME, "File %s cannot be read! Read size: %lld File size: %llu", srcFile.c_str(), nReadSize, srcFileSize);
			break;
		}

		serverFile = sftp_open(m_pSFTPSession, dstFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_FILE_PERMISSION);
		if (!serverFile)
		{
			LogfA(LOG_FILENAME, "sftp_open failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
			break;
		}

		// Write file content with chunk size of 1MB
		size_t nWrittenSize = 0;
		while (nWrittenSize < srcFileSize)
		{
			unsigned long long nWriteSize = srcFileSize > MAX_TRANSFER_SIZE ? std::min(MAX_TRANSFER_SIZE, srcFileSize - nWrittenSize) : srcFileSize;
			
			const auto nWriteRet = sftp_write(serverFile, srcFileBuffer + nWrittenSize, nWriteSize);
			if (nWriteRet != nWriteSize)
			{
				LogfA(LOG_FILENAME, "sftp_write failed with: %s / %d - Write size: %llu Written size: %llu",
					ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession), nWriteSize, nWriteRet
				);
				break;
			}
			nWrittenSize += nWriteSize;
		}

		bRet = true;
	} while (false);

	if (serverFile)
	{
		sftp_close(serverFile);
		serverFile = nullptr;
	}
	if (srcFileBuffer)
	{
		std::free(srcFileBuffer);
		srcFileBuffer = nullptr;
	}
	if (srcFileStream.is_open())
	{
		srcFileStream.close();
	}
	if (!bRet)
	{
		sftp_unlink(m_pSFTPSession, dstFile.c_str());
	}

	return bRet;
}

bool CSFTPManager::Download(const std::string& srcFile, const std::string& dstFile)
{
	bool bRet = false;
	sftp_file serverFile = nullptr;
	std::ofstream dstFileStream;

	do
	{
		if (!this->IsConnected())
		{
			LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
			break;
		}

		std::error_code ec{};
		if (std::filesystem::exists(dstFile, ec))
		{
			LogfA(LOG_FILENAME, "File %s already exist!", dstFile.c_str());
			break;
		}
		if (ec)
		{
			LogfA(LOG_FILENAME, "File exist check error: %s", ec.message().c_str());
			break;
		}

		dstFileStream = std::ofstream(dstFile, std::ios::binary);
		if (!dstFileStream.is_open())
		{
			LogfA(LOG_FILENAME, "File %s cannot be opened! Error: %d", dstFile.c_str(), errno);
			break;
		}
	
		auto serverFile = sftp_open(m_pSFTPSession, srcFile.c_str(), O_RDONLY, 0);
		if (!serverFile)
		{
			LogfA(LOG_FILENAME, "sftp_open failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
			return false;
		}
	
		while (true)
		{
			char szBuffer[MAX_TRANSFER_SIZE]{ '\0' };
			const auto nread = sftp_read(serverFile, szBuffer, sizeof(szBuffer));
			
			if (nread > 0)
			{
				dstFileStream.write(szBuffer, nread);
			}
			else if (nread == 0)
			{
				break;
			}
			else
			{
				LogfA(LOG_FILENAME, "sftp_read failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
				break;
			}
		}
		
		bRet = true;
	} while (false);

	if (serverFile)
	{
		sftp_close(serverFile);
		serverFile = nullptr;
	}
	if (dstFileStream.is_open())
	{
		dstFileStream.close();
	}
	
	return bRet;
}

bool CSFTPManager::Rename(const std::string& srcFile, const std::string& dstFile)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}

	const auto ret = sftp_rename(m_pSFTPSession, srcFile.c_str(), dstFile.c_str());
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_rename failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}

	return true;
}

bool CSFTPManager::Delete(const std::string& file)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}

	const auto ret = sftp_unlink(m_pSFTPSession, file.c_str());
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_unlink failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}

	return true;
}

bool CSFTPManager::CreateDirectory(const std::string& dir)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto ret = sftp_mkdir(m_pSFTPSession, dir.c_str(), DEFAULT_DIR_PERMISSION);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_mkdir failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	return true;
}

bool CSFTPManager::RemoveDirectory(const std::string& dir)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto ret = sftp_rmdir(m_pSFTPSession, dir.c_str());
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_rmdir failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	return true;
}

bool CSFTPManager::ChangePermission(const std::string& file, const uint32_t mode)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto ret = sftp_chmod(m_pSFTPSession, file.c_str(), mode);
	if (ret != SSH_OK)
	{
		LogfA(LOG_FILENAME, "sftp_chmod failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	return true;
}

bool CSFTPManager::ListDirectory(const std::string& dir, std::vector <SSFTPFileContext>& files)
{
	files.clear();
	
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	auto pDir = sftp_opendir(m_pSFTPSession, dir.c_str());
	if (!pDir)
	{
		LogfA(LOG_FILENAME, "sftp_opendir failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	while (true)
	{
		const auto pEntry = sftp_readdir(m_pSFTPSession, pDir);
		if (!pEntry)
		{
			if (sftp_dir_eof(pDir))
			{
				break;
			}
			else
			{
				LogfA(LOG_FILENAME, "sftp_readdir failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
				sftp_closedir(pDir);
				return false;
			}
		}

		SSFTPFileContext fileContext;
		fileContext.name = pEntry->name;
		fileContext.flags = pEntry->flags;
		fileContext.type = pEntry->type;
		fileContext.size = pEntry->size;
		fileContext.permissions = pEntry->permissions;

		files.push_back(fileContext);
	}
	
	sftp_closedir(pDir);
	return true;
}

bool CSFTPManager::IsExistDirectory(const std::string& dir)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto pDir = sftp_opendir(m_pSFTPSession, dir.c_str());
	if (!pDir)
	{
		const auto err = sftp_get_error(m_pSFTPSession);
		if (err != SSH_FX_NO_SUCH_FILE && err != SSH_FX_NO_SUCH_PATH)
		{
			LogfA(LOG_FILENAME, "sftp_opendir failed with: %s / %d", ssh_get_error(m_pSSHSession), err);
		}
		return false;
	}
	
	sftp_closedir(pDir);
	return true;
}

bool CSFTPManager::GetDetails(const std::string& file, SSFTPFileDetails& details)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto pDetails = sftp_stat(m_pSFTPSession, file.c_str());
	if (!pDetails)
	{
		LogfA(LOG_FILENAME, "sftp_stat failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	details.size = pDetails->size;
	details.permissions = pDetails->permissions;
	details.uid = pDetails->uid;
	details.gid = pDetails->gid;
	details.atime = pDetails->atime;
	details.mtime = pDetails->mtime;
	details.type = pDetails->type;
	return true;
}

bool CSFTPManager::ReadLink(const std::string& file, std::string& link)
{
	if (!this->IsConnected())
	{
		LogfA(LOG_FILENAME, "SFTP connection is not yet initialized!");
		return false;
	}
	
	const auto pLink = sftp_readlink(m_pSFTPSession, file.c_str());
	if (!pLink)
	{
		LogfA(LOG_FILENAME, "sftp_readlink failed with: %s / %d", ssh_get_error(m_pSSHSession), sftp_get_error(m_pSFTPSession));
		return false;
	}
	
	link = pLink;
	return true;
}
