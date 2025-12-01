#include "../include/service_manager.hpp"
#include "../../../../source/Common/SimpleTimer.hpp"
#include <filesystem>

CServiceHelper::CServiceHelper()
{
}
CServiceHelper::CServiceHelper(const std::string& szServiceName, const std::string& szDisplayName, const std::string& szServicePath) :
	m_szServiceName(szServiceName), m_szDisplayName(szDisplayName), m_szServicePath(szServicePath)
{
	printf("CServiceHelper::CServiceHelper - Name: %s (%s) File: %s\n", szServiceName.c_str(), szDisplayName.c_str(), szServicePath.c_str());
}

inline void PrintDetailedLog(SC_HANDLE shServiceHandle)
{
	DWORD bytesNeeded;
	SERVICE_STATUS_PROCESS ssStatus;
	if (QueryServiceStatusEx(shServiceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded) == FALSE)
	{
		printf("QueryServiceStatusEx fail! Error: %u\n", GetLastError());
		return;
	}

	printf("Service detailed logs handled.\n\tCurrent State: %d\n\tExit Code: %d\n\tCheck Point: %d\n\tWait Hint: %d\n",
		ssStatus.dwCurrentState, ssStatus.dwWin32ExitCode, ssStatus.dwCheckPoint, ssStatus.dwWaitHint
	);
}

DWORD CServiceHelper::GetServiceStatus()
{
	auto dwResult = 0UL;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);
	auto sStatus = SERVICE_STATUS{ 0 };

	hSCManager = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		printf("OpenSCManagerA fail! Error: %u\n", GetLastError());
		goto _Complete;
	}
	hService = OpenServiceA(hSCManager, m_szServiceName.c_str(), SERVICE_QUERY_STATUS);
	if (hService == NULL)
	{
		printf("OpenServiceA fail! Error: %u\n", GetLastError());
		goto _Complete;
	}
	if (!QueryServiceStatus(hService, &sStatus))
	{
		printf("QueryServiceStatus fail! Error: %u\n", GetLastError());
		goto _Complete;
	}

	dwResult = sStatus.dwCurrentState;

_Complete:
	if (dwResult == 0 && hService)
		PrintDetailedLog(hService);

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return dwResult;
}

bool CServiceHelper::Load(DWORD dwServiceType, DWORD dwStartType, LPDWORD pdwErrorCode)
{
	auto bRet = false;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);

	if (std::filesystem::exists(m_szServicePath) == false)
	{
		printf("Target file: %s is not exist!\n", m_szServicePath.c_str());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager)
	{
		printf("OpenSCManager fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hService = CreateServiceA(hSCManager, m_szServiceName.c_str(), m_szDisplayName.c_str(), SERVICE_ALL_ACCESS, dwServiceType,
		dwStartType, SERVICE_ERROR_NORMAL, m_szServicePath.c_str(), dwServiceType == SERVICE_FILE_SYSTEM_DRIVER ? "FSFilter Activity Monitor" : NULL,
		NULL, NULL, NULL, NULL
	);
	if (!hService)
	{
		auto dwError = GetLastError();
		printf("CreateServiceA fail! Error: %u\n", dwError);
		if (pdwErrorCode) *pdwErrorCode = dwError;
		goto _Complete;
	}

	bRet = true;

_Complete:
	if (bRet == false && hService)
		PrintDetailedLog(hService);

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return bRet;
}

bool CServiceHelper::Unload(LPDWORD pdwErrorCode)
{
	auto bRet = false;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		printf("OpenSCManager fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hService = OpenServiceA(hSCManager, m_szServiceName.c_str(), DELETE | SERVICE_QUERY_STATUS);
	if (!hService)
	{
		printf("OpenServiceA fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	if (DeleteService(hService) == FALSE)
	{
		printf("DeleteService fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	bRet = true;

_Complete:
	if (bRet == false && hService)
		PrintDetailedLog(hService);

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return bRet;
}

bool CServiceHelper::Start(LPDWORD pdwErrorCode)
{
	auto bRet = false;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		printf("OpenSCManager fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hService = OpenServiceA(hSCManager, m_szServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
	if (!hService)
	{
		printf("OpenServiceA fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	if (StartServiceA(hService, 0, NULL) == FALSE)
	{
		printf("StartServiceA fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	bRet = true;

_Complete:
	if (bRet == false && hService)
		PrintDetailedLog(hService);

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return bRet;
}

bool CServiceHelper::Stop(LPDWORD pdwErrorCode)
{
	auto bRet = false;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);
	auto sStatus = SERVICE_STATUS{ 0 };

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		printf("OpenSCManager fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hService = OpenServiceA(hSCManager, m_szServiceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
	if (!hService)
	{
		printf("OpenServiceA fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	if (ControlService(hService, SERVICE_CONTROL_STOP, &sStatus))
	{
		printf("Stopping %s ...\n", m_szServiceName.c_str());
		Sleep(500);

		auto pTimer = CStopWatch<std::chrono::milliseconds>();
		while (QueryServiceStatus(hService, &sStatus))
		{
			if (pTimer.diff() > 5000)
				break;

			if (sStatus.dwCurrentState != SERVICE_STOP_PENDING)
				break;

			printf("Stopping pending %s ...\n", m_szServiceName.c_str());
			Sleep(500);
		}

		if (sStatus.dwCurrentState == SERVICE_STOPPED)
		{
			printf("%s Has Successfully Stopped\n", m_szServiceName.c_str());
		}
		else
		{
			printf("%s Could Not Be Stopped. Status: %u Last error: %u\n", m_szServiceName.c_str(), sStatus.dwCurrentState, GetLastError());
			if (pdwErrorCode) *pdwErrorCode = GetLastError();
			goto _Complete;
		}
	}

	bRet = true;

_Complete:
	if (bRet == false && hService)
		PrintDetailedLog(hService);

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return bRet;
}

bool CServiceHelper::IsInstalled(LPDWORD pdwErrorCode)
{
	auto bRet = false;
	auto hSCManager = SC_HANDLE(nullptr);
	auto hService = SC_HANDLE(nullptr);

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		printf("OpenSCManager fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	hService = OpenServiceA(hSCManager, m_szServiceName.c_str(), SERVICE_QUERY_CONFIG);
	if (!hService)
	{
		printf("OpenServiceA fail! Error: %u\n", GetLastError());
		if (pdwErrorCode) *pdwErrorCode = GetLastError();
		goto _Complete;
	}

	bRet = true;

_Complete:
	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
		hSCManager = nullptr;
	}
	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	return bRet;
}

bool CServiceHelper::SetupFilterInstance(const std::string& szDriverName, const std::string& szInstanceName, const std::string& szAltitude, DWORD Flags, bool SetAsDefaultInstance)
{
	std::string szPath = "System\\CurrentControlSet\\Services\\" + szDriverName;

	// Registering an instance with specified flags and altitude:
	HKEY hKey = NULL;
	LSTATUS RegStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, szPath.c_str(), 0, KEY_ALL_ACCESS, &hKey);
	if (RegStatus != ERROR_SUCCESS)
		return false;

	HKEY hInstancesKey = NULL;
	DWORD Disposition = 0;
	RegStatus = RegCreateKeyExA(hKey, "Instances", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstancesKey, &Disposition);
	RegCloseKey(hKey);

	if (RegStatus != ERROR_SUCCESS)
		return false;

	if (SetAsDefaultInstance)
	{
		RegStatus = RegSetValueExA(hInstancesKey, "DefaultInstance", 0, REG_SZ, reinterpret_cast<const BYTE*>(szInstanceName.c_str()), (DWORD)szInstanceName.size());
		if (RegStatus != ERROR_SUCCESS)
		{
			RegCloseKey(hInstancesKey);
			return false;
		}
	}

	HKEY hInstanceKey = NULL;
	RegStatus = RegCreateKeyExA(hInstancesKey, szInstanceName.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstanceKey, &Disposition);
	if (RegStatus != ERROR_SUCCESS)
	{
		RegCloseKey(hInstancesKey);
		return false;
	}
	RegCloseKey(hInstancesKey);

	RegStatus = RegSetValueExA(hInstanceKey,"Altitude", 0, REG_SZ, reinterpret_cast<const BYTE*>(szAltitude.c_str()), (DWORD)szAltitude.size());
	if (RegStatus != ERROR_SUCCESS)
	{
		RegCloseKey(hInstanceKey);
		return false;
	}

	RegStatus = RegSetValueExA(hInstanceKey, "Flags", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&Flags), sizeof(Flags));

	RegCloseKey(hInstanceKey);

	return RegStatus == ERROR_SUCCESS;
};