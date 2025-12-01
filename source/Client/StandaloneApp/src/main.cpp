#include "../../../Core/EngineR3/Index.hpp"
#include "../../../Core/EngineR3_Core/include/Defines.hpp"
#include <phnt_windows.h>
#include <phnt.h>
#include <combaseapi.h>
#include <clocale>
#include <memory>
#include <iostream>
#include <fcntl.h>

#pragma comment(linker, "/ALIGN:0x10000")

using namespace NoMercy;

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	_setmode(_fileno(stdout), _O_U16TEXT);
	
	std::setlocale(LC_ALL, "Turkish"); // for C and C++ where synced with stdio
	std::locale::global(std::locale("Turkish")); // for C++
	std::cout.imbue(std::locale()); // cerr, clog, wcout, wcerr, wclog as needed

	if (!AttachConsole(GetCurrentProcessId()))
		AllocConsole();
	SetConsoleTitleA("TestApp Debug");

	FILE* pFile = nullptr;
	freopen_s(&pFile, "CONIN$", "r", stdin);
	freopen_s(&pFile, "CONOUT$", "w", stdout);
	freopen_s(&pFile, "CONOUT$", "w", stderr);

	CoInitializeEx(0, COINIT_MULTITHREADED);

	CNoMercyIndex::Enter();
	CNoMercyIndex::InitTest();

	CoUninitialize();

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	printf(" # Initialized! # \n");
#endif

	while (true) Sleep(1000);
//	std::system("PAUSE");
	return EXIT_SUCCESS;
}

