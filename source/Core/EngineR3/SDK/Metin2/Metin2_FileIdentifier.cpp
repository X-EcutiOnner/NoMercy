#include "../../PCH.hpp"
#include "../../Index.hpp"
#include "../../Application.hpp"
#include "../SDKManager.hpp"
#include "Metin2_SDK.hpp"
#include "../../Common/DetectQueue.hpp"

namespace NoMercy
{
	inline bool list_directory_files(const std::wstring& dir, std::vector <std::wstring>& files)
	{
		std::error_code ec{};
		if (!std::filesystem::exists(dir, ec))
		{
			SDK_LOG(LL_ERR, L"Directory %s does not exist", dir.c_str());
			return false;
		}
		else if (ec)
		{
			SDK_LOG(LL_ERR, L"std::filesystem::is_directory failed with error code %d", ec.value());
			return false;
		}
		else if (!std::filesystem::is_directory(dir, ec))
		{
			SDK_LOG(LL_ERR, L"%s is not a directory", dir.c_str());
			return false;
		}
		else if (ec)
		{
			SDK_LOG(LL_ERR, L"std::filesystem::is_directory failed with error code %d", ec.value());
			return false;
		}
		
		for (const auto& entry : std::filesystem::directory_iterator(dir, ec))
		{
			if (!ec)
			{
				std::wstring fileName = entry.path().filename().wstring();
				if (fileName != xorstr_(L".") && fileName != xorstr_(L".."))
					files.emplace_back(fileName);
			}
			else
			{
				SDK_LOG(LL_ERR, L"std::filesystem::directory_iterator failed with error code %d", ec.value());
				return false;
			}
		}		
		return true;
	}


	void CMetin2SDKMgr::CheckMainFolderFiles()
	{
		auto files = std::vector<std::wstring>();
		if (!list_directory_files(std::filesystem::current_path().wstring(), files))
		{
			SDK_LOG(LL_ERR, L"list_directory_files failed");
			return;
		}

		for (size_t i = 0; i < files.size(); i++)
		{
			std::wstring file = files[i];
			std::transform(file.begin(), file.end(), file.begin(), tolower);

			if (file.substr(file.find_last_of(L".") + 1) == xorstr_(L"mix") ||
				file.substr(file.find_last_of(L".") + 1) == xorstr_(L"flt") ||
				file.substr(file.find_last_of(L".") + 1) == xorstr_(L"asi") ||
				file.substr(file.find_last_of(L".") + 1) == xorstr_(L"m3d") ||
				file.substr(file.find_last_of(L".") + 1) == xorstr_(L"def") ||
				file.substr(file.find_last_of(L".") + 1) == xorstr_(L"py"))
			{
				SDK_LOG(LL_ERR, L"Unallowed file found on main folder! File: %s", file.c_str());
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MAIN_FOLDER_UNALLOWED_EXTENSION, file);
			}

			const auto wstFileMD5 = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileMd5(file);
			if (!wstFileMD5.empty())
			{
				if (file == xorstr_(L"mss32.dll") && wstFileMD5 != xorstr_(L"6400e224b8b44ece59a992e6d8233719"))
				{
					SDK_LOG(LL_ERR, L"mss32.dll file is corrupted! Please delete it and restart game");
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MAIN_FOLDER_CORRUPTED_MILESDLL, wstFileMD5);
				}

				if (file == xorstr_(L"devil.dll") && wstFileMD5 != xorstr_(L"26eec5cc3d26cb38c93de01a3eb84cff") && wstFileMD5 != xorstr_(L"8df4d4324e5755f1a0567db3c5be4c58") && wstFileMD5 != xorstr_(L"82d8807800e9ca8f0c933f7643512be9"))
				{
					SDK_LOG(LL_ERR, L"devil.dll file is corrupted! Please delete it and restart game");
					// CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MAIN_FOLDER_CORRUPTED_DEVILDLL, wstFileMD5);
				}
			}
		}
	}

	void CMetin2SDKMgr::CheckLibFolderForPythonLibs()
	{
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsDirExist(xorstr_(L"stdlib"))) // TODO: stdlib > lib
		{
			SDK_LOG(LL_ERR, L"Please delete stdlib folder and restart game.");
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MAIN_FOLDER_UNALLOWED_LIB_FOLDER);
		}
	}

	void CMetin2SDKMgr::CheckMilesFolderForMilesPlugins()
	{
		const auto wstTargetPath = fmt::format(xorstr_(L"{0}\\miles"), std::filesystem::current_path().wstring());
		auto files = std::vector<std::wstring>();
		if (!list_directory_files(wstTargetPath, files))
		{
			SDK_LOG(LL_ERR, L"list_directory_files failed");
			return;
		}

		static std::map <std::wstring /* strFileName */, std::wstring /* strMd5 */> mapKnownFiles =
		{
			{ xorstr_(L"mssa3d.m3d"),		xorstr_(L"e089ce52b0617a6530069f22e0bdba2a") },
			{ xorstr_(L"mssds3d.m3d"),		xorstr_(L"85267776d45dbf5475c7d9882f08117c") },
			{ xorstr_(L"mssdsp.flt"),		xorstr_(L"cb71b1791009eca618e9b1ad4baa4fa9") },
			{ xorstr_(L"mssdx7.m3d"),		xorstr_(L"2727e2671482a55b2f1f16aa88d2780f") },
			{ xorstr_(L"msseax.m3d"),		xorstr_(L"788bd950efe89fa5166292bd6729fa62") },
			{ xorstr_(L"mssmp3.asi"),		xorstr_(L"189576dfe55af3b70db7e3e2312cd0fd") },
			{ xorstr_(L"mssrsx.m3d"),		xorstr_(L"7fae15b559eb91f491a5f75cfa103cd4") },
			{ xorstr_(L"msssoft.m3d"),		xorstr_(L"bdc9ad58ade17dbd939522eee447416f") },
			{ xorstr_(L"mssvoice.asi"),		xorstr_(L"3d5342edebe722748ace78c930f4d8a5") },
			{ xorstr_(L"mss32.dll"),		xorstr_(L"6400e224b8b44ece59a992e6d8233719") }
		};

		if (files.size() > mapKnownFiles.size())
		{
			SDK_LOG(LL_ERR, L"Unknown file detected on miles folder! Please delete miles folder and restart game.");
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MILES_FOLDER_FILE_COUNT_OVERFLOW, std::to_wstring(files.size()));
			return;
		}

		for (const auto& strCurrFolderFile : files)
		{
			auto strCurrFileLower = strCurrFolderFile;
			std::transform(strCurrFileLower.begin(), strCurrFileLower.end(), strCurrFileLower.begin(), tolower);

			auto it = mapKnownFiles.find(strCurrFileLower);
			if (it == mapKnownFiles.end())
			{
				SDK_LOG(LL_ERR, L"Unknown file detected on miles folder! File: %s", strCurrFolderFile.c_str());
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MILES_FOLDER_MISSING_FILE, strCurrFileLower);
				return;
			}

			std::wstring szPath = xorstr_(L"miles/");
			auto strCurrentMd5 = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileMd5(szPath + strCurrFileLower);
			auto strCorrectMd5 = it->second;
			if (strCurrentMd5 != strCorrectMd5)
			{
				SDK_LOG(LL_ERR, L"Corrupted file detected on miles folder! File: %s", strCurrFolderFile.c_str());
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_MILES_FOLDER_CORRUPTED_FILE, strCurrFileLower);
			}
		}
	}

	void CMetin2SDKMgr::CheckYmirFolder()
	{
		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsDirExist(xorstr_(L"d:/ymir work")) ||
			NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsDirExist(xorstr_(L"d:\\ymir work")))
		{
			SDK_LOG(LL_ERR, L"Unallowed folder: 'd:/ymir work' detected! Please delete it and restart game");
			// CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAIN_FOLDER, M2_CHEAT_YMIR_FOLDER);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_YMIR_FOLDER, 0, nullptr);
		}
	}
};
