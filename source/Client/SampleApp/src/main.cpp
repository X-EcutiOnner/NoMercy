#include "../../../Common/StdExtended.hpp"
#include "../../../Client/UserModule/include/Index.h"

#include <phnt_windows.h>
#include <phnt.h>
#include <combaseapi.h>

#include <clocale>
#include <string>
#include <locale>
#include <iostream>
#include <lazy_importer.hpp>

#pragma comment(linker, "/ALIGN:0x10000")

void __stdcall OnNoMercyMessage(int Code, const char* c_szMessage, const void* lpParam)
{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	printf("NoMercy message handled! Code: %d Message: %p\n", Code, c_szMessage);
	__nop();

//	if (IsDebuggerPresent())
//		__debugbreak();
#endif
}

int main()
{
	SetConsoleTitleA("SampleApp Debug");

	CoInitializeEx(0, COINIT_MULTITHREADED);

	if (!NM_Initialize(1, 1, &OnNoMercyMessage))
	{
		printf("Initilization failed!\n");
		std::cin.get();
		return EXIT_FAILURE;
	}

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	printf(" # Initialized! # \n");
#endif

	while (1) Sleep(1000);

	CoUninitialize();
	return EXIT_SUCCESS;
}
