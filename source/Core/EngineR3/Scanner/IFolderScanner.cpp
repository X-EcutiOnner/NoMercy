#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"


namespace NoMercy
{
	IFolderScanner::IFolderScanner()
	{
	}
	IFolderScanner::~IFolderScanner()
	{
	}

	bool IFolderScanner::IsScanned(std::wstring stPath)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_FOLDER, stPath);
	}
	void IFolderScanner::AddScanned(std::wstring stPath)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_FOLDER, stPath);
	}

	void IFolderScanner::ScanSync(std::wstring stPath)
	{
	}

	bool IFolderScanner::ScanAll()
	{
		return true;
	}
};
