#include <windows.h>
#include <iostream>

#define TimeSyncFlag_SoftResync         0x00
#define TimeSyncFlag_HardResync         0x01
#define TimeSyncFlag_ReturnResult       0x02
#define TimeSyncFlag_Rediscover         0x04
#define TimeSyncFlag_UpdateAndResync    0x08

typedef int (__stdcall* TW32TimeSyncNow)(const wchar_t *pwszComputer, unsigned int blocking, unsigned int flags);

static const char* CreateString(const char* c_szFormat, ...)
{
	char szTmpString[8096] = { 0 };

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	return szTmpString;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		MessageBoxA(0, CreateString("Usage: %s <old/new>", argv[0]), 0, MB_ICONSTOP);
		return EXIT_FAILURE;
	}
	auto arg = std::string(argv[1]);
	
	auto hW32Time = LoadLibraryA("w32time.dll");
	if (!hW32Time)
	{
		MessageBoxA(0, CreateString("LoadLibraryA failed! Error: %lu", GetLastError()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;		
	}
	auto W32TimeSyncNow = reinterpret_cast<TW32TimeSyncNow>(GetProcAddress(hW32Time, "W32TimeSyncNow"));
	if (!W32TimeSyncNow)
	{
		MessageBoxA(0, CreateString("GetProcAddress failed! Error: %lu", GetLastError()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;		
	}

	SYSTEMTIME LocalTime = { 0 };
	GetLocalTime(&LocalTime);

	wchar_t wszComputerName[1024] = { L'\0' };
	auto dwComputerNameSize = (DWORD)sizeof(wszComputerName);
	if (!GetComputerNameW(wszComputerName, &dwComputerNameSize))
	{
		MessageBoxA(0, CreateString("GetComputerNameW failed! Error: %lu", GetLastError()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;	
	}

	if (arg == "old")
	{
		LocalTime.wDay = 1;
		LocalTime.wMonth = 1;
		LocalTime.wYear = 2014;

		if (!SetLocalTime(&LocalTime))
		{
			MessageBoxA(0, CreateString("SetLocalTime failed! Error: %lu", GetLastError()), 0, MB_ICONSTOP);
			return EXIT_FAILURE;
		}
	}
	else if (arg == "new")
	{
		auto ret = W32TimeSyncNow(wszComputerName, true, TimeSyncFlag_UpdateAndResync);
		if (ret)
		{
			MessageBoxA(0, CreateString("W32TimeSyncNow failed! Error: %lu - Ret: %lu", GetLastError(), ret), 0, MB_ICONSTOP);
			return EXIT_FAILURE;
		}
	}
	else
	{
		MessageBoxA(0, CreateString("Unknown arg: %s", arg.c_str()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;
	}

	printf("Completed!\n");
	return EXIT_SUCCESS;
}