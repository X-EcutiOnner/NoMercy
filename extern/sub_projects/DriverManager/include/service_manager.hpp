#pragma once
#include <windows.h>
#include <string>
#include <chrono>

class CServiceHelper
{
	public:
		CServiceHelper();
		CServiceHelper(const std::string& szServiceName, const std::string& szDisplayName = "", const std::string& szServicePath = "");
		~CServiceHelper() = default;

		DWORD GetServiceStatus();
		bool IsInstalled(LPDWORD pdwErrorCode);

		bool Load(DWORD dwServiceType, DWORD dwStartType, LPDWORD pdwErrorCode);
		bool Unload(LPDWORD pdwErrorCode);

		bool Start(LPDWORD pdwErrorCode);
		bool Stop(LPDWORD pdwErrorCode);

		bool SetupFilterInstance(const std::string& szDriverName, const std::string& szInstanceName, const std::string& szAltitude, DWORD Flags, bool SetAsDefaultInstance);

	private:
		std::string m_szServiceName;
		std::string m_szDisplayName;
		std::string m_szServicePath;
};
