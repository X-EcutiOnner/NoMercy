#pragma once
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/ListObjectVersionsRequest.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/transfer/TransferManager.h>
#include <aws/transfer/TransferHandle.h>
#include "../../../../source/Common/AbstractSingleton.hpp"

struct SObjectDetails
{
	std::string hostname;
	std::string metadata;
};
struct SObjectVersionDetails
{
	std::string hostname;
	std::string version_id;
};
	
class CStorageHelper : public CSingleton <CStorageHelper>
{
	struct SStorageCtx
	{
		std::string hostname;
		std::shared_ptr <Aws::S3::S3Client> client;
		std::shared_ptr <Aws::Utils::Threading::PooledThreadExecutor> executor;
		std::shared_ptr <Aws::Transfer::TransferManager> transfer_manager;
	};

public:
	CStorageHelper();
	virtual ~CStorageHelper();

	bool Initialize();
	void Release();

	auto IsInitialized() const { return m_bInitialized; };
	auto GetStorageSize() const { return m_storages.size(); };
	auto GetUploadJobCount() const { return m_job_counter; };

	bool InitializeTransferManager();

	uint8_t HasBucket(const std::string& stBucketName);
	uint8_t CreateBucket(const std::string& stBucketName);
	
	uint8_t PutObject(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName,
		const uint32_t nVersion, const std::string& stContainer, std::vector <SObjectDetails>& vectRefMetadata, const std::string& stFileHash = ""
	);
	uint8_t PutObjectAsync(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName,
		const uint32_t nVersion, const std::string& stContainer, std::vector <SObjectDetails>& vectRefMetadata, const std::string& stFileHash = ""
	);
	
	uint8_t UploadFile(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName,
		const uint32_t nVersion, const std::string& stContainer, std::vector <SObjectDetails>& vecRefMetadata, const std::string& stFileHash = ""
	);

	uint8_t FindObjectLatestVersionID(const std::string& stBucketName, const std::string& stObjectName, std::vector <SObjectVersionDetails>& vecRefVersionID);

private:
	bool m_bInitialized;
	Aws::SDKOptions m_options;
	std::vector <SStorageCtx> m_storages;
	std::size_t m_job_counter;
};
