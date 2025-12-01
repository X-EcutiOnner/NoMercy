#pragma once
#include "../../../../source/Common/AbstractSingleton.hpp"
#include "sftp_manager.hpp"

class CSFTPHelper : public CSingleton <CSFTPHelper>
{
public:
	CSFTPHelper();
	virtual ~CSFTPHelper();

	bool Initialize();
	void Release();

	auto IsInitialized() const { return m_bInitialized; };

	bool HasDirectory(const std::string& strDirectory);
	bool CreateDirectory(const std::string& strDirectory);
	bool UploadFile(const std::string& strLocalFile, const std::string& strRemoteFile);
	
private:
	bool m_bInitialized;
	std::shared_ptr <CSFTPManager> m_spSFTPManager;
};
