#include "../include/storage_helper.hpp"
#include "../include/BasicLog.hpp"
#include "../include/config_parser.hpp"

static constexpr auto ALLOC_TAG = "StorageHelper";

#undef GetMessage

CStorageHelper::CStorageHelper() :
	m_bInitialized(false), m_job_counter(0)
{
}
CStorageHelper::~CStorageHelper()
{
}

bool CStorageHelper::Initialize()
{
	if (m_bInitialized)
		return false;
	
	// Initialize SDK
	m_options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Trace; // Aws::Utils::Logging::LogLevel::Debug;
	Aws::InitAPI(m_options);
	
	for (const auto& host : CConfigParser::Instance().GetConfig()->hosts)
	{
		LogfA(LOG_FILENAME, "Initializing host: %s", host.hostname.c_str());

		SStorageCtx ctx;
		ctx.hostname = host.hostname;

		const auto stEndpoint = host.endpoint;
		if (stEndpoint.empty())
		{
			LogfA(LOG_FILENAME, "host_endpoint key not found in config file");
			return false;
		}

		const auto stAccessKey = host.access_key;
		if (stAccessKey.empty())
		{
			LogfA(LOG_FILENAME, "host_access_key key not found in config file");
			return false;
		}

		const auto stSecretKey = host.secret_key;
		if (stSecretKey.empty())
		{
			LogfA(LOG_FILENAME, "host_secret_key key not found in config file");
			return false;
		}

		// Create credinitals object
		Aws::Auth::AWSCredentials credentials;
		credentials.SetAWSAccessKeyId(stAccessKey.c_str());
		credentials.SetAWSSecretKey(stSecretKey.c_str());

		// Create configration object
		Aws::Client::ClientConfiguration config;
		config.endpointOverride = Aws::String(stEndpoint.c_str());
		config.scheme = Aws::Http::Scheme::HTTPS;
		config.region = Aws::Region::EU_CENTRAL_1;
		config.verifySSL = false;
		config.connectTimeoutMs = 60000;
		config.requestTimeoutMs = 10000;

		// Create AWS client
		ctx.client = Aws::MakeShared<Aws::S3::S3Client>(
			ALLOC_TAG,
			credentials,
			config,
			Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never,
			false
		);
		if (!ctx.client)
		{
			LogfA(LOG_FILENAME, "S3 client allocation failed!");
			return false;
		}

		// Create thread executor
		ctx.executor = Aws::MakeShared<Aws::Utils::Threading::PooledThreadExecutor>(ALLOC_TAG, 4);
		if (!ctx.executor)
		{
			LogfA(LOG_FILENAME, "Thread executor allocation failed!");
			return false;
		}

		// Test request
		const auto listBucketsOutcome = ctx.client->ListBuckets();
		if (!listBucketsOutcome.IsSuccess())
		{
			LogfA(LOG_FILENAME, "S3 list buckets failed! Error:  '%s' :: '%s'", listBucketsOutcome.GetError().GetExceptionName().c_str(), listBucketsOutcome.GetError().GetMessage().c_str());
			return false;
		}

		// Add to list
		m_storages.push_back(ctx);

		LogfA(LOG_FILENAME, "%s S3 client initialized!", host.hostname.c_str());
	}
	
	LogfA(LOG_FILENAME, "S3 client initialized!");
	m_bInitialized = true;
	return true;
}

void CStorageHelper::Release()
{
	if (!m_bInitialized)
		return;
	m_bInitialized = false;

	for (auto& storage : m_storages)
	{
		storage.executor.reset();
	}
	Aws::ShutdownAPI(m_options);
	return;
}

bool CStorageHelper::InitializeTransferManager()
{
	for (auto& storage : m_storages)
	{
		auto transferConfig = Aws::Transfer::TransferManagerConfiguration(storage.executor.get());
		transferConfig.s3Client = storage.client;

		transferConfig.transferInitiatedCallback = [&](const Aws::Transfer::TransferManager*, const std::shared_ptr <const Aws::Transfer::TransferHandle>& handle) {
			LogfA(LOG_FILENAME, "Transfer initialized for: '%s'", handle->GetTargetFilePath().c_str());
		};

		transferConfig.transferStatusUpdatedCallback = [&](const Aws::Transfer::TransferManager*, const std::shared_ptr <const Aws::Transfer::TransferHandle>& handle) {
			LogfA(LOG_FILENAME, "Transfer status updated for: '%s' with: %d", handle->GetTargetFilePath().c_str(), static_cast<int>(handle->GetStatus()));
		};
		/*
		transferConfig.uploadProgressCallback = [&](const Aws::Transfer::TransferManager*, const std::shared_ptr <const Aws::Transfer::TransferHandle>& handle) {
			LogfA(LOG_FILENAME, "Upload progress for: '%s' with: %llu/%llu", handle->GetTargetFilePath().c_str(), handle->GetBytesTransferred(), handle->GetBytesTotalSize());
		};
		*/
		transferConfig.errorCallback = [&](const Aws::Transfer::TransferManager*, const std::shared_ptr <const Aws::Transfer::TransferHandle>& handle, const Aws::Client::AWSError <Aws::S3::S3Errors>& error) {
			LogfA(LOG_FILENAME, "Transfer error for: '%s' with: %s (%s)", handle->GetTargetFilePath().c_str(), error.GetMessage().c_str(), error.GetExceptionName().c_str());
		};

		storage.transfer_manager = Aws::Transfer::TransferManager::Create(transferConfig);
		if (!storage.transfer_manager)
		{
			LogfA(LOG_FILENAME, "Transfer manager allocation failed!");
			return false;
		}

		LogfA(LOG_FILENAME, "Transfer manager initialized!");
		return true;
	}
	return false;
}

uint8_t CStorageHelper::HasBucket(const std::string& stBucketName)
{
	if (!m_bInitialized)
		return 0;

	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		const auto response = storage.client->ListBuckets();
		if (response.IsSuccess())
		{
			const auto buckets = response.GetResult().GetBuckets();
			for (const auto& bucket : buckets)
			{
				if (bucket.GetName() == stBucketName)
					nSuccessSize++;
			}
		}
		else
		{
			LogfA(LOG_FILENAME, "ListBuckets failed! Error: '%s' :: '%s'", response.GetError().GetExceptionName().c_str(), response.GetError().GetMessage().c_str());
		}
	}
	return nSuccessSize;
}
uint8_t CStorageHelper::CreateBucket(const std::string& stBucketName)
{
	if (!m_bInitialized)
		return 0;

	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		Aws::S3::Model::CreateBucketRequest request;
		request.SetBucket(stBucketName.c_str());

		const auto response = storage.client->CreateBucket(request);
		if (response.IsSuccess())
		{
			LogfA(LOG_FILENAME, "Bucket: %s succesfully created!", stBucketName.c_str());
			nSuccessSize++;
		}
		else
		{
			LogfA(LOG_FILENAME, "CreateBucket failed! Error: '%s' :: '%s'", response.GetError().GetExceptionName().c_str(), response.GetError().GetMessage().c_str());
		}
	}
	return nSuccessSize;
}

uint8_t CStorageHelper::PutObject(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName, const uint32_t nVersion,
	const std::string& stContainer, std::vector <SObjectDetails>& vectRefMetadata, const std::string& stFileHash)
{
	if (!m_bInitialized)
		return 0;

	if (stFileName.find(".dll.bak") != std::string::npos && stFileName.find("rtti") == std::string::npos)
	{	
		LogfA(LOG_FILENAME, "Skipping backup file: %s", stFileName.c_str());
		return static_cast<uint8_t>(m_storages.size());
	}
	
	std::error_code ec{};
	const auto nFileSize = std::filesystem::file_size(stFileName, ec);

	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		Aws::S3::Model::PutObjectRequest request;
		request.SetBucket(stBucketName.c_str());
		request.SetKey(stObjectName.c_str());

		auto stTagList = fmt::format("version={0}&container={1}", nVersion, stContainer);
		if (!stFileHash.empty())
			stTagList += fmt::format("&hash={0}", stFileHash);
		if (nFileSize)
			stTagList += fmt::format("&size={0}", nFileSize);
		request.SetTagging(stTagList);

		auto spInputData = Aws::MakeShared<Aws::FStream>("PutObjectInputStream", stFileName, std::ios_base::in | std::ios_base::binary);
		if (!spInputData)
		{
			LogfA(LOG_FILENAME, "Input data allocation failed!");
			return nSuccessSize;
		}
		request.SetBody(spInputData);

		const auto response = storage.client->PutObject(request);
		if (response.IsSuccess())
		{
			SObjectDetails objectDetails;
			objectDetails.hostname = storage.hostname;

			// objectDetails.metadata = response.GetResult().GetETag();
			objectDetails.metadata = response.GetResult().GetVersionId();
			LogfA(LOG_FILENAME, "Object: %s (%s) succesfully stored! Metadata: %s", stObjectName.c_str(), stFileName.c_str(), objectDetails.metadata.c_str());

			vectRefMetadata.push_back(objectDetails);
			nSuccessSize++;
		}
		else
		{
			LogfA(LOG_FILENAME, "PutObject failed! Error: '%s' :: '%s'", response.GetError().GetExceptionName().c_str(), response.GetError().GetMessage().c_str());
		}
	}
	return nSuccessSize;
}

uint8_t CStorageHelper::PutObjectAsync(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName,
	const uint32_t nVersion, const std::string& stContainer, std::vector <SObjectDetails>& vectRefMetadata, const std::string& stFileHash)
{
	if (!m_bInitialized)
		return 0;

	if (stFileName.find(".dll.bak") != std::string::npos && stFileName.find("rtti") == std::string::npos)
	{
		LogfA(LOG_FILENAME, "Skipping backup file: %s", stFileName.c_str());
		return static_cast<uint8_t>(m_storages.size());
	}

	std::error_code ec{};
	const auto nFileSize = std::filesystem::file_size(stFileName, ec);

	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		Aws::S3::Model::PutObjectRequest request;
		request.SetBucket(stBucketName.c_str());
		request.SetKey(stObjectName.c_str());

		auto stTagList = fmt::format("version={0}&container={1}", nVersion, stContainer);
		if (!stFileHash.empty())
			stTagList += fmt::format("&hash={0}", stFileHash);
		if (nFileSize)
			stTagList += fmt::format("&size={0}", nFileSize);
		request.SetTagging(stTagList);

		auto spInputData = Aws::MakeShared<Aws::FStream>("PutObjectInputStream", stFileName, std::ios_base::in | std::ios_base::binary);
		if (!spInputData)
		{
			LogfA(LOG_FILENAME, "Input data allocation failed!");
			return nSuccessSize;
		}
		request.SetBody(spInputData);

		m_job_counter++;

		// Use PutObjectAsync to avoid blocking the main thread
		storage.client->PutObjectAsync(request, [this, stObjectName, stFileName, &vectRefMetadata, &nSuccessSize](const Aws::S3::S3Client* client, const Aws::S3::Model::PutObjectRequest& request, const Aws::S3::Model::PutObjectOutcome& outcome, const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context)
		{
			if (outcome.IsSuccess())
			{
				SObjectDetails objectDetails;
				objectDetails.hostname = context->GetUUID();

				// objectDetails.metadata = outcome.GetResult().GetETag();
				objectDetails.metadata = outcome.GetResult().GetVersionId();
				LogfA(LOG_FILENAME, "Object: %s (%s) succesfully stored! Metadata: %s", stObjectName.c_str(), stFileName.c_str(), objectDetails.metadata.c_str());

				vectRefMetadata.push_back(objectDetails);
				nSuccessSize++;

				m_job_counter--;
			}
			else
			{
				LogfA(LOG_FILENAME, "PutObjectAsync failed! Error: '%s' :: '%s'", outcome.GetError().GetExceptionName().c_str(), outcome.GetError().GetMessage().c_str());
			}
		});
	}

	return nSuccessSize;
}

uint8_t CStorageHelper::UploadFile(const std::string& stBucketName, const std::string& stObjectName, const std::string& stFileName, const uint32_t nVersion,
	const std::string& stContainer, std::vector <SObjectDetails>& vectRefMetadata, const std::string& stFileHash)
{
	if (!m_bInitialized)
		return 0;
	
	if (stFileName.find(".dll.bak") != std::string::npos && stFileName.find("rtti") == std::string::npos)
	{
		LogfA(LOG_FILENAME, "Skipping backup file: %s", stFileName.c_str());
		return static_cast<uint8_t>(m_storages.size());
	}

	std::error_code ec{};
	const auto nFileSize = std::filesystem::file_size(stFileName, ec);

	auto mapMetaData = Aws::Map<Aws::String, Aws::String>();
	mapMetaData["version"] = fmt::format("{0}", nVersion);
	mapMetaData["container"] = stContainer;
	mapMetaData["hash"] = stFileHash;
	mapMetaData["size"] = std::to_string(nFileSize);
	
	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		const auto spTransferHandle = storage.transfer_manager->UploadFile(stFileName, stBucketName, stObjectName, "application/octet-stream", mapMetaData);
		if (spTransferHandle)
		{
			spTransferHandle->WaitUntilFinished();

			const auto success = spTransferHandle->GetStatus() == Aws::Transfer::TransferStatus::COMPLETED;
			if (success)
			{
				if (spTransferHandle->GetBytesTransferred() == spTransferHandle->GetBytesTotalSize())
				{
					// Try to find uploaded object with iteration and get its metadata, TransferManager doesn't support it yet(just for downloading)
					std::vector <SObjectVersionDetails> vecRefVersionID;
					if (this->FindObjectLatestVersionID(stBucketName, stObjectName, vecRefVersionID))
					{
						std::string stMetadata;
						for (const auto& version : vecRefVersionID)
						{
							if (version.hostname == storage.hostname)
							{
								stMetadata = version.version_id;
								break;
							}
						}
						if (!stMetadata.empty())
						{
							LogfA(LOG_FILENAME, "File: %s (%s) succesfully stored! Metadata: %s", stObjectName.c_str(), stFileName.c_str(), stMetadata.c_str());

							SObjectDetails objectDetails;
							objectDetails.hostname = storage.hostname;
							objectDetails.metadata = stMetadata;
							vectRefMetadata.push_back(objectDetails);
							
							nSuccessSize++;
						}
						else
						{
							LogfA(LOG_FILENAME, "File: %s (%s) Metadata: %s does not exist in: %s!", stObjectName.c_str(), stFileName.c_str(), stMetadata.c_str(), storage.hostname.c_str());
						}
					}
					else
					{
						LogfA(LOG_FILENAME, "UploadFile (%s) failed to find object metadata!", stFileName.c_str());
					}
				}
				else
				{
					LogfA(LOG_FILENAME, "UploadFile (%s) incomplete: %llu/%llu",
						stFileName.c_str(), spTransferHandle->GetBytesTransferred(), spTransferHandle->GetBytesTotalSize()
					);
				}
			}
			else
			{
				const auto err = spTransferHandle->GetLastError();
				LogfA(LOG_FILENAME, "UploadFile (%s) failed with status: %d error: %s (%s)",
					stFileName.c_str(), static_cast<int>(spTransferHandle->GetStatus()), err.GetMessage().c_str(), err.GetExceptionName().c_str()
				);
			}
		}
		else
		{
			LogfA(LOG_FILENAME, "UploadFile (%s) failed!", stFileName.c_str());
		}
	}
	return nSuccessSize;
}

uint8_t CStorageHelper::FindObjectLatestVersionID(const std::string& stBucketName, const std::string& stObjectName, std::vector <SObjectVersionDetails>& vecRefVersionID)
{
	if (!m_bInitialized)
		return 0;
	
	auto nSuccessSize = 0;
	for (const auto& storage : m_storages)
	{
		Aws::S3::Model::ListObjectVersionsRequest request;
		request.SetBucket(stBucketName);

		const auto outcome = storage.client->ListObjectVersions(request);
		if (outcome.IsSuccess())
		{
			const auto versions = outcome.GetResult().GetVersions();
			if (!versions.empty())
			{
				bool bObjFound = false;
				auto vecObjects = std::vector <std::tuple <uint64_t, std::string>>();
				for (const auto& object : versions)
				{
					if (bObjFound)
						continue;
					
					if (object.GetKey() != stObjectName)
						continue;

					if (!object.IsLatestHasBeenSet())
					{
						LogfA(LOG_FILENAME, "GetVersions for: %s object latest has not been set! Will try to find with manual iterate by datetime", stObjectName.c_str());

						const auto datetime = object.GetLastModified().UnderlyingTimestamp();
						const auto datetime_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(datetime);
						const auto datetime_ms_epoch = datetime_ms.time_since_epoch();
						const auto datetime_ms_epoch_value = std::chrono::duration_cast<std::chrono::milliseconds>(datetime_ms_epoch);
						vecObjects.emplace_back(std::make_tuple(datetime_ms_epoch_value.count(), object.GetVersionId()));
					}
					else if (object.GetIsLatest())
					{
						LogfA(LOG_FILENAME, "GetVersions for: %s object latest is true! Version ID: %s", stObjectName.c_str(), object.GetVersionId().c_str());
						
						SObjectVersionDetails objectDetails;
						objectDetails.hostname = storage.hostname;
						objectDetails.version_id = object.GetVersionId();
						vecRefVersionID.push_back(objectDetails);

						nSuccessSize++;
						bObjFound = true;
					}
				}

				// Find latest version by last modified date
				if (!vecObjects.empty())
				{
					std::sort(vecObjects.begin(), vecObjects.end(), [](const std::tuple <uint64_t, std::string>& a, const std::tuple <uint64_t, std::string>& b) {
						return std::get<0>(a) > std::get<0>(b);
					});
										
					SObjectVersionDetails objectDetails;
					objectDetails.hostname = storage.hostname;
					objectDetails.version_id = std::get<1>(vecObjects.front());
					vecRefVersionID.push_back(objectDetails);
					
					LogfA(LOG_FILENAME, "GetVersions for: %s latest version ID: %s", stObjectName.c_str(), objectDetails.version_id.c_str());
					nSuccessSize++;
				}
				else
				{
					LogfA(LOG_FILENAME, "GetVersions for: %s no objects found!", stObjectName.c_str());
				}
			}
			else
			{
				LogfA(LOG_FILENAME, "GetVersions for: %s response null!", stObjectName.c_str());
			}
		}
		else
		{
			LogfA(LOG_FILENAME, "ListObjectVersions failed! Error: '%s' :: '%s'", outcome.GetError().GetExceptionName().c_str(), outcome.GetError().GetMessage().c_str());
		}
	}
	return nSuccessSize;
}
