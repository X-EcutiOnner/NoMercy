#pragma once

namespace NoMercyCore
{
	class CDirFunctions : public CSingleton <CDirFunctions>
	{
		public:
			std::wstring ExpandEnvPath(const std::wstring& stPath);

			bool IsFileExist(const std::wstring& stFileName);
			bool IsDirExist(const std::wstring& stFileName);
			bool ForceDeleteFile(const std::wstring& stFileName, bool bSilent = false);
			bool HideFile(const std::wstring& stFileName);

			std::wstring ReadFileContent(const std::wstring& stFileName);
			void WriteFileContent(const std::wstring& stFileName, const std::wstring& szText);
			DWORD GetFileSize(const std::wstring& stFileName);

			bool DeleteDirectory(const std::wstring& refcstrRootDirectory, bool bDeleteSubdirectories = true);

			std::wstring CurrentPath();
			std::wstring ExeName();
			std::wstring ExePath();;
			std::wstring ExeNameWithPath();
			std::wstring WinPath();
			std::wstring SystemPath();
			std::wstring SystemPath2();
			std::wstring TempPath();
			std::wstring GetSpecialDirectory(int csidl);

			bool IsFromWindowsPath(const std::wstring& szPath);
			bool IsFromCurrentPath(const std::wstring& szPath);

			std::string GetNameFromPath(std::string __wszFileName);
			std::wstring GetNameFromPath(std::wstring __wszFileName);

			std::wstring GetPathFromProcessName(std::wstring szBuffer);

			bool IsPackedExecutable(const std::wstring& szName);

			std::wstring CreateTempFileName(const std::wstring& stPrefix = L"");
	};
};
