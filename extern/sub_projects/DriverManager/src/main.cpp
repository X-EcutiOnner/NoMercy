#include "../include/device_manager.hpp"
#include "../include/service_manager.hpp"
#include "../include/filter_manager.hpp"
#include "../include/filter_message_handler.hpp"
#include <filesystem>
#include <iostream>
#include <string>

#define SE_DEBUG_PRIVILEGE (20L)
#define SE_TCB_PRIVILEGE (7L)

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s <Service_File> [Service_Name]\n", argv[0]);
		return 0;
	}

	auto szServiceFile = std::string(argv[1]);
	if (std::filesystem::exists(szServiceFile) == false)
	{
		printf("Target file: %s is not exist!\n", szServiceFile.c_str());
		return 0;
	}
	printf("Target file: %s\n", szServiceFile.c_str());

	auto szServiceName = std::string("");
	if (argc == 3) 
	{
		szServiceName = std::string(argv[2]);
	}
	else
	{
		auto uiDotPos		= szServiceFile.find_last_of(".");
		auto szExtsSplitted = szServiceFile.substr(0, uiDotPos);

		auto uiPathPos		= szExtsSplitted.find_last_of("\\/");
		if (uiPathPos)
			szExtsSplitted = szExtsSplitted.substr(uiPathPos + 1, szExtsSplitted.length() - uiPathPos);

		szServiceName = szExtsSplitted;
	}
	printf("Service name: %s\n", szServiceName.c_str());

	printf("--------------------------------------\n");

	std::string stServiceFile = szServiceFile;
	if (stServiceFile.find("\\") == std::string::npos)
		stServiceFile = std::filesystem::current_path().string() + "\\" + szServiceFile;

	static CServiceHelper kServiceMgr = CServiceHelper(szServiceName, szServiceName, stServiceFile);
	static CDeviceHelper kDeviceMgr = CDeviceHelper(szServiceName);
	static CFilterHelper kFilterMgr = CFilterHelper(szServiceName);
	static CFilterMessageHandler kFilterMsgHandler = CFilterMessageHandler();
	
	typedef NTSTATUS(NTAPI* TRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);
	const auto RtlAdjustPrivilege = reinterpret_cast<TRtlAdjustPrivilege>(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege"));
	if (!RtlAdjustPrivilege)
	{
		printf("RtlAdjustPrivilege is not found!\n");
		return 0;
	}

	BOOLEAN bPrevStat = TRUE;
	auto ntStatus = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bPrevStat);
	printf("RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE) completed with status: %p prev status: %d\n", (void*)ntStatus, bPrevStat);

	char pInput = '0';
	while (pInput != 'x')
	{
		printf(
			"\nPlease select:\n"
			 "1 --> Load service\n2 --> Unload service\n"
			 "3 --> Start service\n4 --> Stop service\n"
			 "5 --> Query service status\n"
			 "6 --> Create device handle\n7 --> Close device handle\n8 --> Ping IOCTL message\n"
			 "9 --> Create filter handle\nd --> Disconnect from filter\nt --> Send Filter message\n"
			 "c --> Create filter callbacks\n"
			 "x --> Exit\n"
		);
		std::cin >> pInput;

		std::cout << std::endl;
		switch (pInput)
		{
			case '1':
			{
				int type = 0;
				printf("Service type (1: Driver 2: FS Driver): ");
				std::cin >> type;

				if (type != 1 && type != 2)
				{
					printf("Unknown type value: %d\n", type);
					break;
				}

				DWORD dwDriverHelperErr = 0;

				if (!kServiceMgr.Load(type, SERVICE_DEMAND_START, &dwDriverHelperErr))
					printf("An error occured on load routine! Error: %u\n", dwDriverHelperErr);
				else
					printf("Load routine succesfully completed!\n");

				if (type == SERVICE_FILE_SYSTEM_DRIVER)
				{
					if (!kServiceMgr.SetupFilterInstance(szServiceName, "DefInst", "260000", 0, TRUE))
					{
						printf("SetupFilterInstance failed!\n");
						break;
					}
				}
			} break;

			case '2':
			{
				DWORD dwDriverHelperErr = 0;

				if (kServiceMgr.Unload(&dwDriverHelperErr) == false)
					printf("An error occured on unload routine! Error: %u\n", dwDriverHelperErr);
				else
					printf("Unload routine succesfully completed!\n");
			} break;

			case '3':
			{
				DWORD dwDriverHelperErr = 0;
				
				if (kServiceMgr.Start(&dwDriverHelperErr) == false)
					printf("An error occured on start routine! Error: %u\n", dwDriverHelperErr);
				else
					printf("Start routine succesfully completed!\n");
			} break;

			case '4':
			{
				DWORD dwDriverHelperErr = 0;
				
				if (kServiceMgr.Stop(&dwDriverHelperErr) == false)
					printf("An error occured on stop routine! Error: %u\n", dwDriverHelperErr);
				else
					printf("Stop routine succesfully completed!\n");
			} break;

			case '5':
			{
				auto GetReadableServiceStatus = [&]() -> std::string {
					switch (kServiceMgr.GetServiceStatus())
					{
						case SERVICE_STOPPED:
							return "SERVICE_STOPPED";
						case SERVICE_START_PENDING:
							return "SERVICE_START_PENDING";
						case SERVICE_STOP_PENDING:
							return "SERVICE_STOP_PENDING";
						case SERVICE_RUNNING:
							return "SERVICE_RUNNING";
						case SERVICE_CONTINUE_PENDING:
							return "SERVICE_CONTINUE_PENDING";
						case SERVICE_PAUSE_PENDING:
							return "SERVICE_PAUSE_PENDING";
						case SERVICE_PAUSED:
							return "SERVICE_PAUSED";
						default:
							return "UNKNOWN";
					}
				};

				DWORD dwDriverHelperErr = 0;
				
				if (!kServiceMgr.IsInstalled(&dwDriverHelperErr))
				{
					printf("Target service is not installed! Error: %u\n", dwDriverHelperErr);
					break;
				}

				const auto stServiceStatus = GetReadableServiceStatus();
				printf("Service status: %lu (%s)\n", kServiceMgr.GetServiceStatus(), stServiceStatus.c_str());
			} break;

			case '6':
			{				
				if (kDeviceMgr.Create() == false)
					printf("An error occured on create device handle routine! Error: %u\n", GetLastError());
				else
					printf("Create device handle succesfully completed!\n");
			} break;

			case '7':
			{				
				if (kDeviceMgr.Close() == false)
					printf("An error occured on close device handle routine! Error: %u\n", GetLastError());
				else
					printf("Close device handle succesfully completed!\n");
			} break;

			case '8':
			{				
				if (kDeviceMgr.PingMsg() == false)
					printf("An error occured on ping IOCTL message routine! Error: %u\n", GetLastError());
				else
					printf("Ping IOCTL message succesfully completed!\n");
			} break;

			case '9':
			{				
				if (kFilterMgr.Connect() == false)
					printf("An error occured on connect to filter routine! Error: %u\n", GetLastError());
				else
					printf("Connection to minifilter server succesfully completed!\n");
			} break;

			case 'd':
			{				
				if (kFilterMgr.Disconnect() == false)
					printf("An error occured on disconnect to filter routine! Error: %u\n", GetLastError());
				else
					printf("Disconnect from minifilter server succesfully completed!\n");
			} break;

			case 't':
			{				
				if (kFilterMgr.TestMsg() == false)
					printf("An error occured on test message to filter routine! Error: %u\n", GetLastError());
				else
					printf("Test message to minifilter server succesfully completed!\n");
			} break;

			case 'c':
			{				
				if (kFilterMsgHandler.Initialize() == false)
					printf("An error occured on initialize filter message handler routine! Error: %u\n", GetLastError());
				else
					printf("Initialize filter message handler succesfully completed!\n");
			} break;

			case 'x':
				return 0;

			default:
				continue;
		}
	}

	printf("Completed!\n");
	std::cin.get();
	return 0;
}
