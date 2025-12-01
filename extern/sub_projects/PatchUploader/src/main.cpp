#include <iostream>
#include <thread>
#include <chrono>
#include <cassert>
#include <filesystem>
#include <cxxopts.hpp>
#include <fmt/format.h>
#include "../include/main.hpp"
#include "../include/worker.hpp"
#include "../include/BasicLog.hpp"
#include "../include/storage_helper.hpp"
#include "../include/config_parser.hpp"
#include "../include/sftp_helper.hpp"
#include "../include/MD5.hpp"

// --branch=dev --config=C:\\Users\\PC\\NoMercy_git\\document\\internal\\patch_uploader_config.json --version=513 --root_path=C:\\Users\\PC\\NoMercy_git\\Bin_public

bool __ParseCommandLine(int argc, char* argv[])
{
	cxxopts::Options options(argv[0], "");
	options.allow_unrecognised_options();

	options.add_options()
		("a,activate_release", "Activate uploaded release", cxxopts::value<std::uint8_t>())
		("b,branch", "Env branch name", cxxopts::value<std::string>())
		("c,config", "PatchUpdater config file name", cxxopts::value<std::string>())
		("v,version", "Patch version number", cxxopts::value<std::uint32_t>())
		("r,root_path", "Bin_public path", cxxopts::value<std::string>())
		("s,skip_if_not_exist", "Skip file if not exist", cxxopts::value<std::uint8_t>())
		("u,update_file", "Update single file", cxxopts::value<std::string>())
	;

	if (argc < 2)
	{
		LogfA(LOG_FILENAME, "No arg given...");
		return false;
	}

	try
	{
		auto result = options.parse(argc, argv);

		if (!result.count("branch"))
		{
			LogfA(LOG_FILENAME, "'branch' parameter does not exist");
			return false;
		}
		else if (!result.count("config"))
		{
			LogfA(LOG_FILENAME, "'config' parameter does not exist");
			return false;
		}
		else if (!result.count("version"))
		{
			LogfA(LOG_FILENAME, "'version' parameter does not exist");
			return false;
		}
		else if (!result.count("root_path"))
		{
			LogfA(LOG_FILENAME, "'root_path' parameter does not exist");
			return false;
		}

		auto spWorkerParams = std::make_shared<SWorkerParams>();
		if (!spWorkerParams || !spWorkerParams.get())
		{
			LogfA(LOG_FILENAME, "Failed to create worker params");
			return false;
		}
		
		auto stBranchName = result["branch"].as<std::string>();
		if (stBranchName.empty())
		{
			LogfA(LOG_FILENAME, "Branch name is empty");
			return false;
		}

		if (stBranchName == "master")
			stBranchName = "release";
		else if (stBranchName == "develop")
			stBranchName = "dev";
		else if (stBranchName == "staging")
			stBranchName = "beta";
		else if (stBranchName != "local") // ignore local branch name
		{
			LogfA(LOG_FILENAME, "Invalid branch name");
			return false;
		}

		spWorkerParams->bActivateRelease = result.count("activate_release") ? result["activate_release"].as<std::uint8_t>() == 1 : false;
		spWorkerParams->stBranchName = stBranchName;
		spWorkerParams->stConfigFileName = result["config"].as<std::string>();
		spWorkerParams->u32PatchVersion = result["version"].as<std::uint32_t>();
		spWorkerParams->stRootPath = result["root_path"].as<std::string>();
		if (result.count("skip_if_not_exist"))
			spWorkerParams->bSkipIfNotExist = result["skip_if_not_exist"].as<std::uint8_t>();
		if (result.count("update_file"))
			spWorkerParams->stUpdateFile = result["update_file"].as<std::string>();

		LogfA(LOG_FILENAME, "Branch: '%s', Config: '%s', Version: '%u', Root path: '%s', Skip opt: '%d' Update file: '%s'",
			spWorkerParams->stBranchName.c_str(), spWorkerParams->stConfigFileName.c_str(), spWorkerParams->u32PatchVersion,
			spWorkerParams->stRootPath.c_str(), spWorkerParams->bSkipIfNotExist ? 1 : 0, spWorkerParams->stUpdateFile.c_str()
		);
		
		CWorker::Instance().RegisterParams(spWorkerParams);
		return true;
	}
	catch (const cxxopts::exceptions::exception& ex)
	{
		const auto msg = fmt::format("IO Console parse exception: {}", ex.what());
		LogfA(LOG_FILENAME, msg.c_str());
		return false;
	}
	catch (const std::exception& ex)
	{
		const auto msg = fmt::format("IO System exception: {}", ex.what());
		LogfA(LOG_FILENAME, msg.c_str());
		return false;
	}
	catch (...)
	{
		LogfA(LOG_FILENAME, "IO Unhandled exception");
		return false;
	}
}

int main(int argc, char* argv[])
{
	int ret = EXIT_FAILURE;

	static CConfigParser s_kConfigParser;
	static CStorageHelper s_kStorageHelper;
	static CSFTPHelper s_kSFTPHelper;
	static CWorker s_kWorker;

	do
	{
		if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST))
		{
			LogfA(LOG_FILENAME, "Thread priority change failed with error: %u", GetLastError());
		}
		else
		{
			LogfA(LOG_FILENAME, "Thread priority succesfully changed!");
		}
		
		if (!SetupCrashHandler())
		{
			LogfA(LOG_FILENAME, "Crash handler setup failed!");
			break;
		}

		if (!__ParseCommandLine(argc, argv))
		{
			LogfA(LOG_FILENAME, "Commandline parse failed!");
			break;
		}
		const auto spParams = CWorker::Instance().GetParams();
		
		if (spParams->stBranchName != "dev" && spParams->stBranchName != "beta" && spParams->stBranchName != "release" && spParams->stBranchName != "local")
		{
			LogfA(LOG_FILENAME, "Invalid branch name: %s", spParams->stBranchName.c_str());
			break;
		}
		else if (spParams->stConfigFileName.empty())
		{
			LogfA(LOG_FILENAME, "Config file name is empty!");
			break;
		}
		else if (!std::filesystem::exists(spParams->stConfigFileName))
		{
			LogfA(LOG_FILENAME, "Config file: %s does not exist!", spParams->stConfigFileName.c_str());
			break;
		}
		else if (!spParams->u32PatchVersion || spParams->u32PatchVersion > 100000)
		{
			LogfA(LOG_FILENAME, "Patch version: %u is not correct!", spParams->u32PatchVersion);
			break;
		}
		else if (spParams->stRootPath.empty())
		{
			LogfA(LOG_FILENAME, "Root path is empty!");
			break;
		}
		else if (!std::filesystem::exists(spParams->stRootPath))
		{
			LogfA(LOG_FILENAME, "Root path: %s does not exist!", spParams->stRootPath.c_str());
			break;
		}

		if (spParams->bActivateRelease)
		{
			if (!CWorker::Instance().ActivateRelease())
			{
				LogfA(LOG_FILENAME, "Release activation failed!");
				break;
			}
			else
			{
				ret = EXIT_SUCCESS;
				break;
			}
		}

		if (!CConfigParser::Instance().ParseConfigFile(spParams->stConfigFileName))
		{
			LogfA(LOG_FILENAME, "Config file parse failed!");
			break;
		}
		
		if (!CStorageHelper::Instance().Initialize())
		{
			LogfA(LOG_FILENAME, "CStorageHelper initilization failed!");
			break;
		}

		if (!CStorageHelper::Instance().InitializeTransferManager())
		{
			LogfA(LOG_FILENAME, "CStorageHelper transfer manager initilization failed!");
			break;
		}

		if (!CSFTPHelper::Instance().Initialize())
		{
			LogfA(LOG_FILENAME, "CSFTPHelper initilization failed!");
			break;
		}
		
		if (!CWorker::Instance().LoadWorker())
		{
			LogfA(LOG_FILENAME, "Worker load failed!");
			break;
		}

		LogfA(LOG_FILENAME, "PatchUpdater successfuly completed!");
		ret = EXIT_SUCCESS;
	} while (FALSE);

	if (s_kStorageHelper.IsInitialized())
		s_kStorageHelper.Release();

	if (ret != EXIT_SUCCESS)
	{
		MD5 md5;
		const auto c_szLogHash = md5.digestFile(LOG_FILENAME);
		LogfA(LOG_FILENAME, "Log hash: %s", c_szLogHash);

		const auto stRequestFileShareURL = "https://api-beta.nomercy.ac/request_share_file";
		const auto stReqURL = fmt::format(xorstr_("{0}?file_name={1}&file_hash={2}"), stRequestFileShareURL, LOG_FILENAME, c_szLogHash);
		LogfA(LOG_FILENAME, "Request URL: %s", stReqURL.c_str());

		const auto res1 = cpr::Get(
			cpr::Url{ stReqURL },
			cpr::ConnectTimeout{ 3000 },
			cpr::Timeout{ 30000 }, 
			cpr::Ssl(
				cpr::ssl::TLSv1_3{},
				cpr::ssl::VerifyPeer{ false }
			)
		);

		if (res1.error.code != cpr::ErrorCode::OK)
		{
			LogfA(LOG_FILENAME, "CPR internal error: %u", (uint32_t)res1.error.code);
		}
		else if (res1.status_code != 200)
		{
			LogfA(LOG_FILENAME, "HTTP status: %d is not OK", res1.status_code);
		}
		else if (res1.text.empty())
		{
			LogfA(LOG_FILENAME, "Response text is empty!");
		}
		else
		{
			const auto stShareID = res1.text;
			LogfA(LOG_FILENAME, "Share ID: %s", stShareID.c_str());
			
			const auto stFileShareURL = "https://api-beta.nomercy.ac/share_file";
			const auto stShareURL = fmt::format(xorstr_("{0}?share_id={1}&type=1"), stFileShareURL, stShareID);
			LogfA(LOG_FILENAME, "Share URL: %s", stShareURL.c_str());

			auto data_list = cpr::Multipart{};
			data_list.parts.push_back({ "upload", cpr::File{ LOG_FILENAME } });

			const auto res2 = cpr::Post(
				cpr::ConnectTimeout{ 3000 },
				cpr::Timeout{ 30000 },
				cpr::Url{ stShareURL },
				cpr::Ssl(
					cpr::ssl::TLSv1_3{},
					cpr::ssl::VerifyPeer{ false }
				),
				data_list
			);

			if (res2.error.code != cpr::ErrorCode::OK)
			{
				LogfA(LOG_FILENAME,  "#1 Upload failed: %s(%d)", res2.error.message.c_str(), res2.error.code);
			}
			else if (res2.status_code != 200)
			{
				LogfA(LOG_FILENAME, "#2 Upload failed: %d", res2.status_code);
			}
			else if (res2.text.empty())
			{
				LogfA(LOG_FILENAME,  "#3 Upload failed: empty response");
			}
			else
			{
				LogfA(LOG_FILENAME,  "Uploaded: %s", res2.text.c_str());
			}
		}
	}

	LogfA(LOG_FILENAME, "PatchUpdater finished!");
	return ret;
}
