#include "../include/main.hpp"
#include "../include/worker.hpp"
#include "../include/config_parser.hpp"
#include "../include/storage_helper.hpp"
#include "../include/sftp_helper.hpp"
#include <ZipLib/ZipFile.h>
#include <ZipLib/streams/memstream.h>
#include <ZipLib/methods/Bzip2Method.h>

static constexpr auto sc_szPatchURL = "https://api-beta.nomercy.ac/v1/upload_patch_list";
static constexpr auto sc_szPatchActivateURL = "https://api-beta.nomercy.ac/v1/active_patch_version";

CWorker::CWorker()
{
}
CWorker::~CWorker()
{
}

bool CWorker::LoadWorker()
{
	if (!__ProcessFileList())
	{
		LogfA(LOG_FILENAME, "__ProcessFileList has been failed!");
		return false;
	}
	else if (!__CreateZipArchive())
	{
		LogfA(LOG_FILENAME, "__CreateZipArchive has been failed!");
		return false;
	}
	else if (!__CreateFileIndex())
	{
		LogfA(LOG_FILENAME, "__CreateFileIndex (1) has been failed!");
		return false;
	}
	else if (!__UploadFilesToMinio())
	{
		LogfA(LOG_FILENAME, "__UploadFilesToMinio has been failed!");
		return false; 
	}
	else if (!__CreateFileIndex())
	{
		LogfA(LOG_FILENAME, "__CreateFileIndex (2) has been failed!");
		return false;
	}
	else if (!__UploadFileListToPatchServer())
	{
		LogfA(LOG_FILENAME, "__UploadFileListToPatchServer has been failed!");
		return false;
	}
	
	return true;
}

bool CWorker::ActivateRelease()
{
	LogfA(LOG_FILENAME, "Activating release...");

	const auto res = cpr::Post(
		cpr::Url{ sc_szPatchActivateURL },
		cpr::Body{ fmt::format("{{\"branch_name\":\"{}\",\"patch_version\":{}}}", m_spParams->stBranchName, m_spParams->u32PatchVersion) },
		cpr::Timeout{ 5000 }
	);

	const auto err_code = res.error.code;
	const auto status_code = res.status_code;
	const auto res_text = res.text;

	LogfA(LOG_FILENAME, "\tConnection result: err: %d status: %d response: %s", err_code, status_code, res_text.c_str());

	if (err_code != cpr::ErrorCode::OK)
	{
		LogfA(LOG_FILENAME, "\tCPR internal error: %u", (uint32_t)err_code);
		return false;
	}
	else if (status_code != 200)
	{
		LogfA(LOG_FILENAME, "\tCPR status is not ok: %d", status_code);
		return false;
	}
	else if (res_text != "1")
	{
		LogfA(LOG_FILENAME, "\tCPR result text: '%s' is not valid", res_text.c_str());
		return false;
	}

	LogfA(LOG_FILENAME, "\tRelease has been activated!");
	return true;
}

bool CWorker::__ProcessFileList()
{
	const auto spConfigCtx = CConfigParser::Instance().GetConfig();
	const auto stUpdateFile = m_spParams->stUpdateFile;

	LogfA(LOG_FILENAME, "Version: %d", spConfigCtx->version);

	if (spConfigCtx->version == 1)
	{
		LogfA(LOG_FILENAME, "Current local file path %s", spConfigCtx->target_path.c_str());

		for (const auto spFileContainer : spConfigCtx->file_containers)
		{
			LogfA(LOG_FILENAME, "Current container: %s", spFileContainer->id.c_str());

			for (const auto spFile : spFileContainer->files)
			{
				LogfA(LOG_FILENAME, "\tCurrent file: %s (%s) path: %s", spFile->name.c_str(), spFile->local_source_file.c_str(), spConfigCtx->target_path.c_str());

				auto bOptional = false;
				if (spFile->name.find("non_rtti") != std::string::npos && m_spParams->u32PatchVersion < 10000)
					bOptional = true;
				if (spFile->name.find("non_rtti") != std::string::npos && m_spParams->stBranchName != "release")
					bOptional = true;
				
				auto stFullPath = spConfigCtx->target_path;
				if (stFullPath.empty())
				{
					stFullPath = std::filesystem::current_path().string();
					LogfA(LOG_FILENAME, "\t\tTarget path is not defined! Adjusted with current working directory: %s", stFullPath.c_str());
				}
				
				auto stFullName = spFile->local_source_file;
				if (!stFullName.empty())
				{
					stFullPath = stFullName.substr(0, stFullName.find_last_of("\\"));
					LogfA(LOG_FILENAME, "\t\tTarget source file is defined, Target path will be adjusted to file source path: %s", stFullPath.c_str());
				}
				else
				{
					LogfA(LOG_FILENAME, "\t\tSpecific file is not defined!");

					// Apply path by attributes
					if (spFile->local_path == "I18n")
						stFullPath = fmt::format("{0}\\..\\..\\document\\i18n_files", stFullPath);
					else if (spFile->local_path == "License")
						stFullPath = fmt::format("{0}\\..\\..\\document\\license_files", stFullPath);

					if (stFullPath.empty())
					{
						LogfA(LOG_FILENAME, "\t\tUnsupported path attribute!");
						return false;
					}

					// Check path
					LogfA(LOG_FILENAME, "\t\tCurrent file target path: %s", stFullPath.c_str());

					if (!std::filesystem::exists(stFullPath))
					{
						LogfA(LOG_FILENAME, "\t\tTarget path: %s does not exist!", stFullPath.c_str());
						return false;
					}

					stFullName = fmt::format("{0}\\{1}", stFullPath, spFile->name);
					LogfA(LOG_FILENAME, "\t\tCurrent file path: %s", stFullName.c_str());
				}

				// Apply wildcard
				auto bHasBinaryWildcard = spFile->name.find("*") != std::string::npos, bFoundBinaryWildcard = false;
				auto bHasSymbolWildcard = spFile->local_debug_symbol_file.find("*") != std::string::npos, bFoundSymbolWildcard = false;

				LogfA(LOG_FILENAME, "\t\tWildcard result: %d / %d", bHasBinaryWildcard, bHasSymbolWildcard);

				if (bHasBinaryWildcard || bHasSymbolWildcard)
				{
					std::error_code ec{};
					for (const auto& entry : std::filesystem::recursive_directory_iterator(stFullPath, ec))
					{
						if (!entry.is_regular_file())
							continue;

						const auto& stFileName = entry.path().filename().string();
						const auto& stExtension = entry.path().extension().string();

						LogfA(LOG_FILENAME, "\t\t\tChecking %s with %s/%s", stFileName.c_str(), spFile->name.c_str(), spFile->local_debug_symbol_file.c_str());

						auto bSkipFile = false;
						if (stExtension != ".json")
						{
							if (m_spParams->stBranchName == "local")
							{
								if (stFileName.find("_d") == std::string::npos)
								{
									bSkipFile = true;
								}
							}
							else
							{
								if (stFileName.find("_d") != std::string::npos)
								{
									bSkipFile = true;
								}
							}
						}
						if (bSkipFile)
						{
							LogfA(LOG_FILENAME, "\t\t\t\tSkipped file for current branch policies");
							continue;
						}

						if (bHasBinaryWildcard && __WildcardMatch(stFileName, spFile->name))
						{
							LogfA(LOG_FILENAME, "\t\tBinary Wildcard matched; %s -> %s Already found: %d", spFile->name.c_str(), stFileName.c_str(), bFoundBinaryWildcard);
							if (!bFoundBinaryWildcard)
							{
								spFile->name = stFileName;
								bFoundBinaryWildcard = true;
							}
						}

						if (bHasSymbolWildcard && __WildcardMatch(stFileName, spFile->local_debug_symbol_file))
						{
							LogfA(LOG_FILENAME, "\t\tSymbol Wildcard matched; %s -> %s Already found: %d", spFile->local_debug_symbol_file.c_str(), stFileName.c_str(), bFoundSymbolWildcard);
							if (!bFoundSymbolWildcard)
							{
								spFile->local_debug_symbol_file = stFileName;
								bFoundSymbolWildcard = true;
							}
						}

						if ((!bHasBinaryWildcard || (bHasBinaryWildcard && bFoundBinaryWildcard)) &&
							(!bHasSymbolWildcard || (bHasSymbolWildcard && bFoundSymbolWildcard)))
						{
							LogfA(LOG_FILENAME, "\t\tFound wildcard matches!");
							break;
						}
					}

					if (ec)
					{
						LogfA(LOG_FILENAME, "\t\tDirectory iterator failed with error: %d (%s)", ec.value(), ec.message().c_str());
						return false;
					}
					
					if (bHasBinaryWildcard && !bFoundBinaryWildcard)
					{
						LogfA(LOG_FILENAME, "\t\tBinary Wildcard not found!");
						
						if (bOptional)
							continue;
						else
							return false;
					}
					if (bHasSymbolWildcard && !bFoundSymbolWildcard)
					{
						LogfA(LOG_FILENAME, "\t\tSymbol Wildcard not found!");
						return false;
					}
					
					stFullName = fmt::format("{0}\\{1}", stFullPath, spFile->name);
					LogfA(LOG_FILENAME, "\t\tCurrent file wildcard adjusted path: %s", stFullName.c_str());
				}

				// Rename
				if (!spFile->new_name.empty())
				{
					const auto stNewName = fmt::format("{0}\\{1}", stFullPath, spFile->new_name);

					if (std::filesystem::exists(stNewName))
					{
						LogfA(LOG_FILENAME, "\t\tNew name: %s already exists!", stNewName.c_str());
						// return false;
					}
					else
					{
						std::error_code ec{};
						std::filesystem::rename(stFullName, stNewName, ec);
						if (ec)
						{
							LogfA(LOG_FILENAME, "\t\tFailed to rename(%s -> %s) with error: %s", stFullName.c_str(), stNewName.c_str(), ec.message().c_str());
							return false;
						}

						LogfA(LOG_FILENAME, "\t\tFile renamed: %s(%s) -> %s(%s)", stFullName.c_str(), spFile->name.c_str(), stNewName.c_str(), spFile->new_name.c_str());
					}
					
					spFile->name = spFile->new_name;
					stFullName = stNewName;
				}

				// Debug symbol
				const auto vSplittedName = stdext::split_string<std::string>(spFile->name, ".");
				if (!vSplittedName.empty())
				{
					const auto stExtension = vSplittedName.at(1);
					if (stExtension == "exe" || stExtension == "dll" || stExtension == "sys")
					{
						const auto stDebugSymbolName = fmt::format("{0}.pdb", vSplittedName.at(0));
						spFile->local_debug_symbol_file = fmt::format("{0}\\Pdb\\{1}", stFullPath, stDebugSymbolName);
						LogfA(LOG_FILENAME, "\t\tCurrent file debug symbol file: %s", spFile->local_debug_symbol_file.c_str());

						if (stUpdateFile.empty() || (!stUpdateFile.empty() && spFile->name != stUpdateFile))
						{
							if (!std::filesystem::exists(spFile->local_debug_symbol_file))
							{
								LogfA(LOG_FILENAME, "\t\t[WARN] Debug symbol file: %s does not exist!", spFile->local_debug_symbol_file.c_str());
								
								if (!m_spParams->bSkipIfNotExist &&
									!spFile->optional &&
									!spFile->skip_pdb)
								{
									LogfA(LOG_FILENAME, "\t\t[ERROR] Debug symbol file is NOT optional, aborting!");
									return false;
								}
							}
						}
					}
				}

				// Preprocess
				if (!spFile->preprocess.empty())
				{
					std::string stFinalParam = "";

					const auto stBinRoot = fmt::format("{0}\\..\\..\\Bin", spConfigCtx->target_path);
					LogfA(LOG_FILENAME, "\t\tBin output root path: %s", stBinRoot.c_str());

					if (!std::filesystem::exists(stBinRoot))
					{
						LogfA(LOG_FILENAME, "\t\tBin output root path: %s does not exist", stBinRoot.c_str());
						return false;
					}

					LogfA(LOG_FILENAME, "\t\tPreprocess data: %s", spFile->preprocess.c_str());

					const auto vParsedPreprocessData = stdext::split_string<std::string>(spFile->preprocess, " ");
					if (vParsedPreprocessData.size() < 2)
					{
						LogfA(LOG_FILENAME, "\t\tSplit preprocess data: %s failed!", spFile->preprocess.c_str());
						return false;
					}

					auto stFirstArg = vParsedPreprocessData.at(1);
					if (stFirstArg.find(".json") != std::string::npos) // looks like a file
					{
						LogfA(LOG_FILENAME, "\t\tPreprocess data first arg: %s looks like a file", stFirstArg.c_str());

						const auto stTargetJson = fmt::format("{0}\\..\\{1}", spConfigCtx->target_path, stFirstArg);
						if (!std::filesystem::exists(stTargetJson))
						{
							LogfA(LOG_FILENAME, "\t\tPreprocess first arg file: %s does not exist!", stTargetJson.c_str());
							return false;
						}

						const auto stPreprocessTarget = fmt::format("{0}\\{1}", stBinRoot, vParsedPreprocessData.at(0));
						if (!std::filesystem::exists(stPreprocessTarget))
						{
							LogfA(LOG_FILENAME, "\t\tPreprocess target: %s does not exist!", stPreprocessTarget.c_str());
							if (m_spParams->bSkipIfNotExist)
								continue;
							else
								return false;
						}
						LogfA(LOG_FILENAME, "\t\tPreprocess target: %s", stPreprocessTarget.c_str());

						stFinalParam = fmt::format("{0} {1}", stPreprocessTarget, stTargetJson);
						LogfA(LOG_FILENAME, "\t\tPreprocess final parameter: %s", stFinalParam.c_str());
					}
					else
					{
						LogfA(LOG_FILENAME, "\t\tUnknown preprocess data: %s", stFirstArg.c_str());
						return false;
					}

					PROCESS_INFORMATION pi{ 0 };
					STARTUPINFOA si{ 0 };
					si.cb = sizeof(si);

					// Create the child process
					if (!CreateProcessA(nullptr, (LPSTR)stFinalParam.c_str(), nullptr, nullptr, 0, 0, nullptr, nullptr, &si, &pi))
					{
						LogfA(LOG_FILENAME, "\t\tCreateProcessA failed with error: %u", GetLastError());
						return false;
					}

					LogfA(LOG_FILENAME, "\t\tChild process created! PID: %u", pi.dwProcessId);

					// Wait for the process to exit
					const auto dwWaitRet = WaitForSingleObject(pi.hProcess, INFINITE);
					LogfA(LOG_FILENAME, "\t\tWait ret: %u", dwWaitRet);

					// Process has exited - check its exit code
					DWORD dwExitCode = 0;
					const auto bExitCodeRet = GetExitCodeProcess(pi.hProcess, &dwExitCode);
					LogfA(LOG_FILENAME, "\t\tChild process exit code handled: %u (Query: %d)", dwExitCode, bExitCodeRet);

					if (dwExitCode != EXIT_SUCCESS)
					{
						LogfA(LOG_FILENAME, "\t\tChild process is failed! Exit code: %u", dwExitCode);
						return false;
					}

					// Handles must be closed when they are no longer needed
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);

					// Forward output
					stFullName = fmt::format("{0}\\{1}", std::filesystem::current_path().string(), spFile->name);
					LogfA(LOG_FILENAME, "\t\tCurrent file preprocessor adjusted path: %s", stFullName.c_str());
				}

				// Exist check
				if (!std::filesystem::exists(stFullName))
				{
					if (spFile->optional)
					{
						LogfA(LOG_FILENAME, "\t\tSkipped not exist optional file: %s", stFullName.c_str());
						continue;
					}
					else
					{
						LogfA(LOG_FILENAME, "\t\tFinal file: %s does not exist!", stFullName.c_str());
						return false;
					}
				}

				// Calculate file hash
				std::string stFileHash = "";
				if (spFileContainer->method == "md5")
					stFileHash = __GetMd5(stFullName);
				else if (spFileContainer->method == "sha1")
					stFileHash = __GetSHA1(stFullName);
				else if (spFileContainer->method == "sha256")
					stFileHash = __GetSHA256(stFullName);

				if (stFileHash.empty())
				{
					LogfA(LOG_FILENAME, "\t\tFinal file: %s hash calculate failed! Method: %s", stFullName.c_str(), spFileContainer->method.c_str());
					return false;
				}

				// Fill file informations
				spFile->local_source_file = stFullName;
				spFile->size = std::filesystem::file_size(stFullName);
				spFile->hash = stFileHash;

				// Egg check
				const auto bShouldEggCheck =
					(spFile->attr & NoMercySetup::EFileAttributes::FILE_ATTR_CRYPTED_1) ||
					(spFile->attr & NoMercySetup::EFileAttributes::FILE_ATTR_COMPRESSED_1);

				if (bShouldEggCheck)
				{
					// Read file content
					void* pImage = nullptr;
					DWORD dwReadedBytes = 0;
					std::string stEggFileContent = "";
					{
						auto hFile = CreateFileA(stFullName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, nullptr);
						if (!hFile || hFile == INVALID_HANDLE_VALUE)
						{
							LogfA(LOG_FILENAME, "\t\tCreateFileA fail! Error code: %u", GetLastError());
							return false;
						}

						const auto dwFileLen = GetFileSize(hFile, nullptr);
						if (!dwFileLen || dwFileLen == INVALID_FILE_SIZE)
						{
							LogfA(LOG_FILENAME, "\t\tGetFileSize fail! Error code: %u", GetLastError());
							CloseHandle(hFile);
							return false;
						}

						pImage = reinterpret_cast<BYTE*>(malloc(dwFileLen));
						if (!pImage)
						{
							LogfA(LOG_FILENAME, "\t\tImage allocation fail!");
							CloseHandle(hFile);
							return false;
						}

						const auto readRet = ReadFile(hFile, pImage, dwFileLen, &dwReadedBytes, nullptr);
						if (!readRet || dwReadedBytes != dwFileLen)
						{
							LogfA(LOG_FILENAME, "\t\tReadFile fail! Error code: %u", GetLastError());
							CloseHandle(hFile);
							free(pImage);
							return false;
						}
						CloseHandle(hFile);
					}

					// Compress
					int nCompressedSize = dwReadedBytes;
					std::vector <uint8_t> vCompressedBuffer(dwReadedBytes);
					if (spFile->attr & NoMercySetup::EFileAttributes::FILE_ATTR_COMPRESSED_1)
					{
						const auto bound = LZ4_compressBound(dwReadedBytes);
						vCompressedBuffer = std::vector <uint8_t>(bound);

						nCompressedSize = LZ4_compress_HC(
							reinterpret_cast<const char*>(pImage), reinterpret_cast<char*>(&vCompressedBuffer[0]),
							dwReadedBytes, bound, LZ4HC_CLEVEL_MAX
						);
						if (nCompressedSize >= bound || nCompressedSize == 0)
						{
							LogfA(LOG_FILENAME, "\t\tCompression fail! Raw: %u Compressed: %u Capacity: %u", dwReadedBytes, nCompressedSize, bound);
							return false;
						}
					}
					else
					{
						memcpy(&vCompressedBuffer[0], pImage, dwReadedBytes);
					}

					// Encrypt
					std::vector <uint8_t> vCryptedBuffer(nCompressedSize);
					if (spFile->attr & NoMercySetup::EFileAttributes::FILE_ATTR_CRYPTED_1)
					{
						try
						{
							CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
							enc.ProcessData(&vCryptedBuffer[0], reinterpret_cast<const uint8_t*>(vCompressedBuffer.data()), nCompressedSize);
						}
						catch (const CryptoPP::Exception& exception)
						{
							LogfA(LOG_FILENAME, "\t\tCaught exception on encryption: %s", exception.what());
							return false;
						}
					}
					else
					{
						memcpy(&vCryptedBuffer[0], vCompressedBuffer.data(), nCompressedSize);
					}

					// Clear useless allocated memory
					free(pImage);

					// Delete old file
					if (!DeleteFileA(stFullName.c_str()))
					{
						LogfA(LOG_FILENAME, "\t\tFile: %s delete failed with error: %u", stFullName.c_str(), GetLastError());
						return false;
					}

					// Write to file
					auto hFile = CreateFileA(stFullName.c_str(), FILE_WRITE_DATA, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
					if (!hFile || hFile == INVALID_HANDLE_VALUE)
					{
						LogfA(LOG_FILENAME, "\t\tCreateFileA fail! Error code: %u", GetLastError());
						return false;
					}

					auto dwWritedBytes = 0UL;
					const auto bWritten = WriteFile(hFile, vCryptedBuffer.data(), vCryptedBuffer.size(), &dwWritedBytes, nullptr);
					if (!bWritten || dwWritedBytes != vCryptedBuffer.size())
					{
						LogfA(LOG_FILENAME, "\t\tWriteFile fail! Error code: %u", GetLastError());
						return false;
					}

					FlushFileBuffers(hFile);
					CloseHandle(hFile);

					// Calculate egg hash
					std::string stEggHash = "";
					if (spFileContainer->method == "md5")
						stEggHash = __GetMd5(stFullName);
					else if (spFileContainer->method == "sha1")
						stEggHash = __GetSHA1(stFullName);
					else if (spFileContainer->method == "sha256")
						stEggHash = __GetSHA256(stFullName);

					if (stEggHash.empty())
					{
						LogfA(LOG_FILENAME, "\t\tFinal file: %s egg hash calculate failed! Method: %s", stFullName.c_str(), spFileContainer->method.c_str());
						return false;
					}

					spFile->egg_hash = stEggHash;
					LogfA(LOG_FILENAME, "\t\tFinal file: %s egg hash calculated: %s", stFullName.c_str(), stEggHash.c_str());
				}

				LogfA(LOG_FILENAME, "\t\tFile: %s -> %s processed!", spFile->name.c_str(), stFullName.c_str());
				spFile->processed = true;
				continue;
			}
		}
	}
	
	return true;
};
bool CWorker::__CreateZipArchive()
{
	auto spConfigCtx = CConfigParser::Instance().GetConfig();

	LogfA(LOG_FILENAME, "Version: %d", spConfigCtx->version);

	if (spConfigCtx->version == 1)
	{
		LogfA(LOG_FILENAME, "Current local file path %s", spConfigCtx->target_path.c_str());

		for (auto spFileContainer : spConfigCtx->file_containers)
		{
			LogfA(LOG_FILENAME, "Current container: %s", spFileContainer->id.c_str());

			// Create the archive
			const auto stArchiveName = fmt::format("{0}.zip", spFileContainer->id);

			if (std::filesystem::exists(stArchiveName))
			{
				std::error_code ec{};
				std::filesystem::remove(stArchiveName, ec);
				if (ec)
				{
					LogfA(LOG_FILENAME, "\t Old archive: %s remove failed with error: %s", stArchiveName.c_str(), ec.message().c_str());
					return false;
				}
			}
			
			const auto spZipArchive = ZipFile::Open(stArchiveName);
			if (!spZipArchive || !spZipArchive.get())
			{
				LogfA(LOG_FILENAME, "ZIP file body could not created! Last error: %u", GetLastError());
				return false;
			}

			for (auto spFile : spFileContainer->files)
			{
				if (!spFile->processed)
				{
					LogfA(LOG_FILENAME, "\tFile: %s not processed!", spFile->name.c_str());
					continue;
				}

				LogfA(LOG_FILENAME, "\tCurrent file: %s", spFile->name.c_str());

				std::string stFile = "";
				if (!spFile->local_source_file.empty())
					stFile = spFile->local_source_file;
				else
					stFile = fmt::format("{0}\\{1}", spConfigCtx->target_path, spFile->name);
				
				const auto stContent = __ReadFileContent(stFile);
				if (stContent.empty())
				{
					LogfA(LOG_FILENAME, "\tFile: %s content read failed!", stFile.c_str());
					return false;
				}

				auto spZipEntry = spZipArchive->CreateEntry(spFile->name);
				if (!spZipEntry || !spZipEntry.get())
				{
					LogfA(LOG_FILENAME, "\tZIP entry could not created! Last error: %u", GetLastError());
					return false;
				}
				
				spZipEntry->UseDataDescriptor();
				
				// Add the new file
				Bzip2Method::Ptr ctx = Bzip2Method::Create();
				ctx->SetBlockSize(Bzip2Method::BlockSize::B600);

#pragma warning(push) 
#pragma warning(disable: 4239)
				spZipEntry->SetCompressionStream(
					std::istringstream(stContent),
					ctx,
					ZipArchiveEntry::CompressionMode::Immediate
				);
#pragma warning(pop) 

				LogfA(LOG_FILENAME, "\tZIP entry: %s (%s) created!", spFile->name.c_str(), stFile.c_str());
			}

			ZipFile::SaveAndClose(spZipArchive, stArchiveName);
			spFileContainer->archive_file = stArchiveName;
		}
	}

	return true;
};
bool CWorker::__CreateFileIndex()
{
	const auto spConfigCtx = CConfigParser::Instance().GetConfig();

	// create json index & hash list

	LogfA(LOG_FILENAME, "Version: %d", spConfigCtx->version);

	if (spConfigCtx->version == 1)
	{
		LogfA(LOG_FILENAME, "Current local file path %s", spConfigCtx->target_path.c_str());

		for (const auto spFileContainer : spConfigCtx->file_containers)
		{
			LogfA(LOG_FILENAME, "Current container: %s", spFileContainer->id.c_str());

			// Create index filename
			const auto stIndexFileName = fmt::format("{0}_index.json", spFileContainer->id);

			// Remove file if already exist
			if (std::filesystem::exists(stIndexFileName))
				std::filesystem::remove(stIndexFileName);

			// Create index file
			auto fp = msl::file_ptr(stIndexFileName, "wb");
			if (!fp)
			{
				LogfA(LOG_FILENAME, "\tIndex file: %s open failed with error: %d", stIndexFileName.c_str(), errno);
				return false;
			}

			// Create json serializer
			StringBuffer s;
			PrettyWriter <StringBuffer> writer(s);

			// Root array
			writer.StartObject();

			// Files object
			{
				writer.Key("files");
				writer.StartObject();

				for (const auto spFile : spFileContainer->files)
				{
					if (!spFile->processed)
					{
						LogfA(LOG_FILENAME, "\tFile: %s does not exist!", spFile->name.c_str());
						continue;
					}

					LogfA(LOG_FILENAME, "\tCurrent file: %s", spFile->name.c_str());

					// Current file object
					{
						writer.Key(spFile->name.c_str());
						writer.StartObject();
						{
							writer.Key("local_path");
							writer.String(spFile->local_path.c_str());

							writer.Key("size");
							writer.Uint(spFile->size);

							writer.Key("attr");
							writer.Uint(spFile->attr);

							writer.Key("hash");
							writer.String(spFile->hash.c_str());

							writer.Key("egg_hash");
							writer.String(spFile->egg_hash.c_str());

							writer.Key("binary_metadata");
							writer.StartObject();
							{
								for (const auto& metadata : spFile->binary_metadata)
								{
									writer.Key(metadata.hostname.c_str());
									writer.String(metadata.metadata.c_str());
								}
							}
							writer.EndObject();

							if (!spFile->symbol_metadata.empty())
							{
								writer.Key("symbol_metadata");
								writer.StartObject();
								{
									for (const auto& metadata : spFile->symbol_metadata)
									{
										writer.Key(metadata.hostname.c_str());
										writer.String(metadata.metadata.c_str());
									}
								}
								writer.EndObject();
							}
						}

						// Complete current file object
						writer.EndObject();
					}
				}

				// Complete files object
				writer.EndObject();
			}

			// Complete json serializer
			writer.EndObject();

			// Create string output
			std::ostringstream oss;
			oss << std::setw(4) << s.GetString() << std::endl;

			// Write serialized data to index file
			const auto stSerializedData = oss.str();
			fp.string_write(stSerializedData);
			LogfA(LOG_FILENAME, "\tSerialized data writed. Size: %u", stSerializedData.size());

			// Close file handle
			fp.close();
		}
	}

	return true;
};
bool CWorker::__UploadFilesToMinio()
{
	const auto spConfigCtx = CConfigParser::Instance().GetConfig();

	// const auto stBucketName = fmt::format("{0}.{1}.{2}", stBranch, spConfigCtx->version, nVersion);
	// const auto stBucketName = fmt::format("client-files-v{0}", spConfigCtx->version);
	const auto stBucketName = fmt::format("nomercy-client-files.v{0}", spConfigCtx->version);

	LogfA(LOG_FILENAME, "Version: %d Target bucket: %s", spConfigCtx->version, stBucketName.c_str());

	if (spConfigCtx->version == 1)
	{
		// Create bucket for current version, if not exist
		if (!CStorageHelper::Instance().HasBucket(stBucketName))
		{
			LogfA(LOG_FILENAME, "Bucket: %s does not exist, will create!", stBucketName.c_str());

			if (!CStorageHelper::Instance().CreateBucket(stBucketName))
			{
				LogfA(LOG_FILENAME, "Create bucket: %s failed!", stBucketName.c_str());
				return false;
			}
		}
		
		// Create directory for current version, if not exist
		const auto stVersionDirectory = fmt::format("{0}.{1}", spConfigCtx->version, m_spParams->u32PatchVersion);
		if (CSFTPHelper::Instance().IsInitialized())
		{
			if (!CSFTPHelper::Instance().HasDirectory(stVersionDirectory))
			{
				LogfA(LOG_FILENAME, "Directory: %s does not exist, will create!", stVersionDirectory.c_str());

				if (!CSFTPHelper::Instance().CreateDirectory(stVersionDirectory))
				{
					LogfA(LOG_FILENAME, "Create directory: %s failed!", stVersionDirectory.c_str());
					return false;
				}
			}
		}
		
		LogfA(LOG_FILENAME, "Current local file path %s", spConfigCtx->target_path.c_str());

		for (auto spFileContainer : spConfigCtx->file_containers)
		{
			LogfA(LOG_FILENAME, "Current container: %s File count: %u", spFileContainer->id.c_str(), spFileContainer->files.size());

			auto bHasProcessedFile = false;
			for (const auto& spFile : spFileContainer->files)
			{
				if (spFile->processed && spFile->preprocess.empty())
					bHasProcessedFile = true;
			}
			if (!bHasProcessedFile)
			{
				LogfA(LOG_FILENAME, "\tContainer have not any processed file!");
				continue;
			}
			else
			{
			_checkAgain:
				for (auto spFile : spFileContainer->files)
				{
					if (!spFile->processed || (m_spParams->bSkipIfNotExist && spFile->processed && !spFile->preprocess.empty()))
					{
						spFileContainer->files.erase(std::remove(spFileContainer->files.begin(), spFileContainer->files.end(), spFile), spFileContainer->files.end());
						goto _checkAgain;
					}
				}
			}

			if (!spFileContainer->archive_file.empty())
			{
				if (!std::filesystem::exists(spFileContainer->archive_file))
				{
					LogfA(LOG_FILENAME, "Archive file: %s does not exist", spFileContainer->archive_file.c_str());
					return false;
				}

				const auto stArchiveHash = __GetMd5(spFileContainer->archive_file);

				std::vector <SObjectDetails> vecMetadata;
				if (!CStorageHelper::Instance().PutObject(
					stBucketName, spFileContainer->archive_file, spFileContainer->archive_file, m_spParams->u32PatchVersion, spFileContainer->id, vecMetadata, stArchiveHash
				))
				{
					LogfA(LOG_FILENAME, "Upload binary object: %s failed!", spFileContainer->archive_file.c_str());
					return false;
				}
				else
				{
					spFileContainer->archive_metadata = vecMetadata[0].metadata;
					LogfA(LOG_FILENAME, "Upload binary object: %s succesfully, Metedata: %s!", spFileContainer->archive_file.c_str(), spFileContainer->archive_metadata.c_str());
				}

				if (CSFTPHelper::Instance().IsInitialized())
				{
					const auto stTargetFilePath = stVersionDirectory + "/" + spFileContainer->archive_file;
					if (!CSFTPHelper::Instance().UploadFile(spFileContainer->archive_file, stTargetFilePath))
					{
						LogfA(LOG_FILENAME, "Upload binary file: %s to SFTP (%s) failed!", spFileContainer->archive_file.c_str(), stTargetFilePath.c_str());
						return false;
					}
					else
					{
						LogfA(LOG_FILENAME, "Upload binary file: %s to SFTP (%s) succesfully!", spFileContainer->archive_file.c_str(), stTargetFilePath.c_str());
					}
				}
			}

			for (auto& spFile : spFileContainer->files)
			{
				LogfA(LOG_FILENAME, "\tCurrent file: %s (%s)", spFile->name.c_str(), spFile->local_source_file.c_str());

				if (spFile->local_source_file.empty())
				{
					LogfA(LOG_FILENAME, "Source file: %s does not exist a local file name, skipped!", spFile->name.c_str());
					continue;
				}

				const auto vSplittedName = stdext::split_string<std::string>(spFile->name, ".");
				if (!vSplittedName.empty())
				{
					const auto stExtension = vSplittedName.at(1);
					// if (stExtension == "exe" || stExtension == "dll" || stExtension == "sys" || stExtension == "pdb")
					{
						if (!std::filesystem::exists(spFile->local_source_file))
						{
							LogfA(LOG_FILENAME, "Source file: %s does not exist!", spFile->local_source_file.c_str());
							return false;
						}

						if (stExtension == "dll")
						{
							const auto stBackupPath = spConfigCtx->target_path + "\\..\\..\\Bin\\";
							if (std::filesystem::exists(stBackupPath))
							{
								// stBackupFile = stBackupPath + vSplittedName.at(0) + "_non_rtti.dll.bak";

								const auto stBackupFileName = spFile->name + ".bak";
								const auto stBackupFile = stBackupPath + stBackupFileName;
								if (std::filesystem::exists(stBackupFile))
								{
									LogfA(LOG_FILENAME, "Unprotected module file: %s found!", stBackupFile.c_str());

									std::vector <SObjectDetails> vecMetadata;
									if (!CStorageHelper::Instance().PutObject(stBucketName, stBackupFile, stBackupFile, m_spParams->u32PatchVersion, spFileContainer->id, vecMetadata))
									{
										LogfA(LOG_FILENAME, "Upload backup binary object: %s (%s) failed!", stBackupFileName.c_str(), stBackupFile.c_str());
										return false;
									}
									else
									{
										LogfA(LOG_FILENAME, "Upload backup binary object: %s (%s) succesfully!", stBackupFileName.c_str(), stBackupFile.c_str());
									}

									if (CSFTPHelper::Instance().IsInitialized())
									{
										const auto stTargetFilePath = stVersionDirectory + "/" + stBackupFileName;
										if (!CSFTPHelper::Instance().UploadFile(stBackupFile, stTargetFilePath))
										{
											LogfA(LOG_FILENAME, "Upload backup binary file: %s to SFTP failed!", stBackupFile.c_str());
											return false;
										}
										else
										{
											LogfA(LOG_FILENAME, "Upload backup binary file: %s to SFTP succesfully!", stBackupFile.c_str());
										}
									}
								}
							}
						}

						std::vector <SObjectDetails> vecMetadata;
						if (!CStorageHelper::Instance().PutObject(stBucketName, spFile->name, spFile->local_source_file, m_spParams->u32PatchVersion, spFileContainer->id, vecMetadata))
						{
							LogfA(LOG_FILENAME, "Upload binary object: %s (%s) failed!", spFile->name.c_str(), spFile->local_source_file.c_str());
							return false;
						}
						else
						{
							LogfA(LOG_FILENAME, "Upload binary object: %s (%s) succesfully!", spFile->name.c_str(), spFile->local_source_file.c_str());
							spFile->binary_metadata = vecMetadata;
						}

						if (CSFTPHelper::Instance().IsInitialized())
						{
							const auto stTargetFilePath = stVersionDirectory + "/" + spFile->name;
							if (!CSFTPHelper::Instance().UploadFile(spFile->local_source_file, stTargetFilePath))
							{
								LogfA(LOG_FILENAME, "Upload binary file: %s to SFTP (%s) failed!", spFile->local_source_file.c_str(), stTargetFilePath.c_str());
								return false;
							}
							else
							{
								LogfA(LOG_FILENAME, "Upload binary file: %s to SFTP (%s) succesfully!", spFile->local_source_file.c_str(), stTargetFilePath.c_str());
							}
						}

						if (!spFile->local_debug_symbol_file.empty())
						{
							LogfA(LOG_FILENAME, "\tCurrent file debug symbol: %s", spFile->local_debug_symbol_file.c_str());

							if (!std::filesystem::exists(spFile->local_debug_symbol_file))
							{
								LogfA(LOG_FILENAME, "Symbol file: %s does not exist!", spFile->local_debug_symbol_file.c_str());
							}
							else
							{
								const auto stSymbolName = vSplittedName.at(0) + ".pdb";
								std::vector <SObjectDetails> vecSymMetadata;					
								if (!CStorageHelper::Instance().PutObject(stBucketName, stSymbolName, spFile->local_debug_symbol_file, m_spParams->u32PatchVersion, spFileContainer->id, vecMetadata))
								{
									LogfA(LOG_FILENAME, "Upload symbol object: %s failed!", spFile->local_debug_symbol_file.c_str());
									return false;
								}
								else
								{
									LogfA(LOG_FILENAME, "Upload symbol object: %s succesfully!", spFile->local_debug_symbol_file.c_str());
									spFile->symbol_metadata = vecSymMetadata;
								}

								if (CSFTPHelper::Instance().IsInitialized())
								{
									const auto stTargetFilePath = stVersionDirectory + "/" + stSymbolName;
									if (!CSFTPHelper::Instance().UploadFile(spFile->local_debug_symbol_file, stTargetFilePath))
									{
										LogfA(LOG_FILENAME, "Upload symbol file: %s to SFTP (%s) failed!", spFile->local_debug_symbol_file.c_str(), stTargetFilePath.c_str());
										return false;
									}
									else
									{
										LogfA(LOG_FILENAME, "Upload symbol file: %s to SFTP (%s) succesfully!", spFile->local_debug_symbol_file.c_str(), stTargetFilePath.c_str());
									}
								}
							}
						}
					}
				}
			}

			LogfA(LOG_FILENAME, "\t%u files sent succesfully!", spFileContainer->files.size());
		}
	}
	return true;
};
bool CWorker::__UploadFileListToPatchServer()
{
	const auto spConfigCtx = CConfigParser::Instance().GetConfig();

	LogfA(LOG_FILENAME, "Version: %d", spConfigCtx->version);

	if (spConfigCtx->version == 1)
	{
		LogfA(LOG_FILENAME, "Current local file path %s", spConfigCtx->target_path.c_str());

		for (const auto spFileContainer : spConfigCtx->file_containers)
		{
			LogfA(LOG_FILENAME, "Current container: %s File count: %u", spFileContainer->id.c_str(), spFileContainer->files.size());

			auto bHasProcessedFile = false;
			for (const auto& spFile : spFileContainer->files)
			{
				if (spFile->processed && spFile->preprocess.empty())
					bHasProcessedFile = true;
			}
			if (!bHasProcessedFile)
			{
				LogfA(LOG_FILENAME, "\tContainer have not any processed file!");
				continue;
			}
			else
			{
			_checkAgain:
				for (auto spFile : spFileContainer->files)
				{
					if (!spFile->processed || (m_spParams->bSkipIfNotExist && spFile->processed && !spFile->preprocess.empty()))
					{
						spFileContainer->files.erase(std::remove(spFileContainer->files.begin(), spFileContainer->files.end(), spFile), spFileContainer->files.end());
						goto _checkAgain;
					}
				}
			}
			LogfA(LOG_FILENAME, "Processed file count: %u", spFileContainer->files.size());

			std::vector <std::shared_ptr <SFileCtx>> vExecutableFiles;
			for (auto spFile : spFileContainer->files)
			{
				const auto vSplittedName = stdext::split_string<std::string>(spFile->name, ".");
				if (!vSplittedName.empty())
				{
					const auto stExtension = vSplittedName.at(1);
					if (stExtension == "exe" || stExtension == "dll" || stExtension == "sys")
					{
						vExecutableFiles.emplace_back(spFile);
					}
				}
			}
			LogfA(LOG_FILENAME, "Executable file count: %u", vExecutableFiles.size());

			// Create index filename
			const auto stIndexFileName = fmt::format("{0}_index.json", spFileContainer->id);
			auto fp = msl::file_ptr(stIndexFileName, "rb");
			if (!fp)
			{
				LogfA(LOG_FILENAME, "\tIndex file: %s open failed with error: %d", stIndexFileName.c_str(), errno);
				return false;
			}
			auto stIndexData = fp.string_read();

			// Modify index for driver only request
			if (vExecutableFiles.size() == 1)
			{
				const auto spFile = vExecutableFiles.at(0);

				std::string stJsonOutput;
				{
					// Initialize rapidjson (pretty)writer
					StringBuffer s;
					PrettyWriter <StringBuffer> writer(s);

					// Root object
					writer.StartObject();
					{
						writer.Key("files");
						writer.StartObject();
						{
							writer.Key(spFile->name.c_str());
							writer.StartObject();
							{
								writer.Key("local_path");
								writer.String(spFile->local_path.c_str());

								writer.Key("size");
								writer.Uint(spFile->size);

								writer.Key("attr");
								writer.Uint(spFile->attr);

								writer.Key("hash");
								writer.String(spFile->hash.c_str());

								writer.Key("egg_hash");
								writer.String(spFile->egg_hash.c_str());

								writer.Key("binary_metadata");
								writer.StartObject();
								{
									for (const auto& metadata : spFile->binary_metadata)
									{
										writer.Key(metadata.hostname.c_str());
										writer.String(metadata.metadata.c_str());
									}
								}
								writer.EndObject();

								if (!spFile->symbol_metadata.empty())
								{
									writer.Key("symbol_metadata");
									writer.StartObject();
									{
										for (const auto& metadata : spFile->symbol_metadata)
										{
											writer.Key(metadata.hostname.c_str());
											writer.String(metadata.metadata.c_str());
										}
									}
									writer.EndObject();
								}
							}
							writer.EndObject();
						}
						writer.EndObject();
					}
					// End root object
					writer.EndObject();

					// Create string output
					std::ostringstream oss;
					oss << std::setw(4) << s.GetString() << std::endl;
					stJsonOutput = oss.str();
				}

				// Replace index data for single file request
				stIndexData = stJsonOutput;
			}

			auto bSingleFile = false;
			// x64 driver build
			if (vExecutableFiles.size() == 1)
				bSingleFile = true;
			// Single file request by CLI
			if (!m_spParams->stUpdateFile.empty())
				bSingleFile = true;

			LogfA(LOG_FILENAME, "\tFile container ID: '%s', Version: '%u', Single file: %d", spFileContainer->id.c_str(), m_spParams->u32PatchVersion, bSingleFile);
			LogfA(LOG_FILENAME, "\tIndex data: '%s'", stIndexData.c_str());

			// Append index file
			auto data_list = cpr::Multipart{
				{ "id", spFileContainer->id },
				{ "version", std::to_string(m_spParams->u32PatchVersion) },
				{ "branch", m_spParams->stBranchName },
				{ "data", stIndexData },
				{ "single_file", bSingleFile ? "1" : "0" },
				{ "archive_file", spFileContainer->archive_file },
				{ "archive_metadata", spFileContainer->archive_metadata },
			};

			const auto res = cpr::Post(
				cpr::Url{ sc_szPatchURL },
				data_list,
				cpr::Timeout{ 30000 }
			);

			const auto err_code = res.error.code;
			const auto status_code = res.status_code;
			const auto res_text = res.text;

			LogfA(LOG_FILENAME, "\tConnection result: err: %d status: %d response: %s", err_code, status_code, res_text.c_str());

			if (err_code != cpr::ErrorCode::OK)
			{
				LogfA(LOG_FILENAME, "\tCPR internal error: %u", (uint32_t)err_code);
				return false;
			}
			else if (status_code != 200)
			{
				LogfA(LOG_FILENAME, "\tCPR status is not ok: %d", status_code);
				return false;
			}
			else if (res_text != "1")
			{
				LogfA(LOG_FILENAME, "\tCPR result text: '%s' is not valid", res_text.c_str());
				return false;
			}

			LogfA(LOG_FILENAME, "\t%u files sent succesfully!", data_list.parts.size());
		}
	}

	return true;
};