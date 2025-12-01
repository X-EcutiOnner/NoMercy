#include "../include/sftp_helper.hpp"
#include "../include/BasicLog.hpp"
#include "../include/config_parser.hpp"

CSFTPHelper::CSFTPHelper() :
	m_bInitialized(false)
{
	m_spSFTPManager = std::make_shared<CSFTPManager>();
}
CSFTPHelper::~CSFTPHelper()
{
	m_spSFTPManager.reset();
}

bool CSFTPHelper::Initialize()
{
	if (m_bInitialized)
		return false;

	const auto vecHosts = CConfigParser::Instance().GetConfig()->sftp_hosts;
	for (const auto& pkHost : vecHosts)
	{
		LogfA(LOG_FILENAME, "Connecting to SFTP host: %s", pkHost.hostname.c_str());
		
		if (!m_spSFTPManager->Connect(pkHost.endpoint, pkHost.port, pkHost.username, pkHost.password, "", "", nullptr, {}))
		{
			LogfA(LOG_FILENAME, "SFTPManager connect failed");
			return false;
		}

		LogfA(LOG_FILENAME, "Connected to SFTP host: %s", pkHost.hostname.c_str());
		m_bInitialized = true;
	}
	
	return true;
}

void CSFTPHelper::Release()
{
	if (!m_bInitialized)
		return;
	
	m_bInitialized = false;
	
	m_spSFTPManager->Close();
}

bool CSFTPHelper::HasDirectory(const std::string& strDirectory)
{
	if (!m_bInitialized)
		return false;
	
	return m_spSFTPManager->IsExistDirectory(strDirectory);
}

bool CSFTPHelper::CreateDirectory(const std::string& strDirectory)
{
	if (!m_bInitialized)
		return false;
	
	return m_spSFTPManager->CreateDirectory(strDirectory);
}

bool CSFTPHelper::UploadFile(const std::string& strLocalFile, const std::string& strRemoteFile)
{
	if (!m_bInitialized)
		return false;
	
	return m_spSFTPManager->Upload(strLocalFile, strRemoteFile);
}
