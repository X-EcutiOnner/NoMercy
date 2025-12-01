#pragma once
#include "../../source/Common/AbstractSingleton.hpp"

struct SWorkerParams
{
	bool bActivateRelease { false };
	std::string stBranchName;
	std::string stConfigFileName;
	std::uint32_t u32PatchVersion{ 0 };
	std::string stRootPath;
	bool bSkipIfNotExist{ false };
	std::string stUpdateFile;
};

class CWorker : public CSingleton <CWorker>
{
public:
	CWorker();
	virtual ~CWorker();
	
	void RegisterParams(std::shared_ptr <SWorkerParams> spParams) { m_spParams = std::move(spParams); }
	auto GetParams() const { return m_spParams; }

	bool LoadWorker();
	bool ActivateRelease();

protected:
	bool __ProcessFileList();
	bool __CreateZipArchive();
	bool __CreateFileIndex();
	bool __UploadFilesToMinio();
	bool __UploadFileListToPatchServer();

private:
	std::shared_ptr <SWorkerParams> m_spParams;
};
