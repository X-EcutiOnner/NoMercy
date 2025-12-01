#pragma once

struct SStackFrame
{
	DWORD64 qwFrameAddress{ 0 };
	DWORD64 qwReturnAddress{ 0 };
	DWORD64 qwStackAddress{ 0 };
	DWORD64 qwImageBaseAddress{ 0 };
	DWORD64 qwSymbolAddress{ 0 };
	DWORD64 qwDisplacement{ 0 };
	DWORD64 qwInstrPtr{ 0 };
	DWORD dwImageSize{ 0 };
	DWORD dwTimestamp{ 0 };
	DWORD dwChecksum{ 0 };
	DWORD dwSymbolCount{ 0 };
	SYM_TYPE nSymType{ SymNone };
	std::string stModuleName{ "" };
	std::string stImageName{ "" };
	std::string stLoadedImageName{ "" };
	std::string stSymbolName{ "" };
	bool bHasDebugRegister{ false };
};

extern bool GetThreadCallStack(HANDLE hProcess, HANDLE hThread, std::vector <std::shared_ptr <SStackFrame>>& vecStackData);
