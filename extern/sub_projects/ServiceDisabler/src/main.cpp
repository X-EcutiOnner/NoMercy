#include <windows.h>
#include <iostream>
#include <vector>
#include <filesystem>
#include "../../../source/Common/SimpleTimer.hpp"

#define NOMERCY_DRIVER "NoMercy"
#define NOMERCY_SERVICE "NoMercySvc"

static const char* CreateString(const char* c_szFormat, ...)
{
	char szTmpString[8096] = { 0 };

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	return szTmpString;
}

bool CloseService(const std::string& stName, SC_HANDLE hSCManager)
{
	auto hService = OpenServiceA(hSCManager, stName.c_str(), SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
	if (hService)
	{
		std::vector <BYTE> buffer;
		DWORD dwBytesNeeded = sizeof(QUERY_SERVICE_CONFIGA);
		LPQUERY_SERVICE_CONFIGA pConfig;

		do
		{
			buffer.resize(dwBytesNeeded);
			pConfig = (LPQUERY_SERVICE_CONFIGA)&buffer[0];

			if (QueryServiceConfigA(hService, pConfig, buffer.size(), &dwBytesNeeded))
				break;
		}
		while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

		auto sStatus = SERVICE_STATUS{ 0 };
		if (!QueryServiceStatus(hService, &sStatus))
		{
			MessageBoxA(0, CreateString("QueryServiceStatus fail! Error: %u", GetLastError()), 0, MB_ICONSTOP);
			CloseServiceHandle(hService);
			return false;
		}

		if (sStatus.dwCurrentState == SERVICE_RUNNING || sStatus.dwCurrentState == SERVICE_START_PENDING)
		{
			if (ControlService(hService, SERVICE_CONTROL_STOP, &sStatus))
			{
				Sleep(500);

				auto pTimer = CSimpleTimer<std::chrono::milliseconds>();
				while (QueryServiceStatus(hService, &sStatus))
				{
					if (pTimer.diff() > 5000)
						break;

					if (sStatus.dwCurrentState != SERVICE_STOP_PENDING)
						break;

					Sleep(500);
				}

				if (sStatus.dwCurrentState != SERVICE_STOPPED)
				{
					MessageBoxA(0, CreateString("Service could not be stopped. Status: %u Last error: %u", sStatus.dwCurrentState, GetLastError()), 0, MB_ICONSTOP);
					CloseServiceHandle(hService);
					return false;
				}
			}
		}

		if (!DeleteService(hService))
		{
			MessageBoxA(0, CreateString("DeleteService fail! Error: %u", GetLastError()), 0, MB_ICONSTOP);
			CloseServiceHandle(hService);
			return false;
		}
		
#if 0
		if (!std::filesystem::exists(pConfig->lpBinaryPathName))
		{
			MessageBoxA(0, CreateString("Service file: %s is not exist!", pConfig->lpBinaryPathName), 0, MB_ICONSTOP);
			CloseServiceHandle(hService);
			return false;			
		}

		if (!std::filesystem::remove(pConfig->lpBinaryPathName))
		{
			MessageBoxA(0, CreateString("Service file: %s could not delete!", pConfig->lpBinaryPathName), 0, MB_ICONSTOP);
			CloseServiceHandle(hService);
			return false;					
		}
#endif
	}
	else
	{
		const auto dwErrCode = GetLastError();
		switch (dwErrCode)
		{
			case ERROR_SERVICE_DOES_NOT_EXIST:
				printf("Service is not exist!\n");
				break;

			default:
				printf("OpenServiceA fail! Error: %u\n", dwErrCode);
				break;
		}
	}

	CloseServiceHandle(hService);
	return true;
}

int main()
{
	auto hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager)
	{
		MessageBoxA(0, CreateString("OpenSCManager fail! Error: %u", GetLastError()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;
	}

	CloseService(NOMERCY_SERVICE, hSCManager);
	CloseService(NOMERCY_DRIVER, hSCManager);

	CloseServiceHandle(hSCManager);
	printf("Completed!\n");
	return EXIT_SUCCESS;
}