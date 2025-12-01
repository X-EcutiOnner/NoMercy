#pragma once
#include "../../../../source/Common/AbstractSingleton.hpp"
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/sftp.h>

#undef CreateDirectory
#undef RemoveDirectory

struct SSFTPFileContext
{
	std::string name;
	uint32_t flags;
	uint8_t type;
	uint64_t size;
	uint32_t permissions;
};

struct SSFTPFileDetails
{
	uint64_t size;
	uint32_t permissions;
	uint32_t uid;
	uint32_t gid;
	uint32_t atime;
	uint32_t mtime;
	uint8_t type;
};

class CSFTPManager : std::enable_shared_from_this <CSFTPManager>
{
public:
	CSFTPManager();
	virtual ~CSFTPManager();

	bool IsConnected() const { return !!m_pSFTPSession; };

	bool Connect(
		const std::string& ip,
		const uint16_t port,
		const std::string& username,
		const std::string& password,
		const std::string& pubKey,
		const std::string& privKey,
		const std::function <std::string()>& getPrivKeyPassPhraseFn,
		const std::vector <std::string>& serverFingerPrints
	);
	void Close();

	bool Upload(const std::string& srcFile, const std::string& dstFile);
	bool Download(const std::string& srcFile, const std::string& dstFile);
	bool Rename(const std::string& srcFile, const std::string& dstFile);
	bool Delete(const std::string& file);
	bool ChangePermission(const std::string& file, const uint32_t mode);
	bool GetDetails(const std::string& file, SSFTPFileDetails& details);
	bool ReadLink(const std::string& file, std::string& link);

	bool CreateDirectory(const std::string& dir);
	bool RemoveDirectory(const std::string& dir);
	bool ListDirectory(const std::string& dir, std::vector <SSFTPFileContext>& files);
	bool IsExistDirectory(const std::string& dir);

protected:
	bool SSHConnect(const std::string& ip, const uint16_t port, const std::string& username, const std::string& password);
	bool SSHAuthorize(const std::string& username, const std::string& pubKeyFile, const std::string& privKeyFile, const std::string& privKeyPassPhrase);
	bool VerifySFTPServerIdentity(const std::vector <std::string>& serverFingerPrints);
	bool SFTPConnect();
	
private:
	ssh_session m_pSSHSession;
	sftp_session m_pSFTPSession;
};
