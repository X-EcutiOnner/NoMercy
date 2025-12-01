#include <phnt_windows.h>
#include <phnt.h>
#include <fmt/format.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <algorithm>

static HANDLE gs_hProcess = nullptr;
static DWORD gs_dwPID = 0;

struct SMemoryData
{
	DWORD_PTR dwBase;
	uint8_t pMemDump[32];
};

inline std::string to_lower(const std::string& in)
{
	std::string out = in;
	std::transform(out.begin(), out.end(), out.begin(), [](int c) -> char { return static_cast<char>(::tolower(c)); });
	return out;
}
inline std::string dump_hex(const uint8_t* key, size_t length)
{
	std::stringstream ss;

	std::vector <uint8_t> buffer(length);
	memcpy(&buffer[0], key, length);

	for (size_t i = 0; i < length; ++i)
		ss << fmt::format("{:#02x}", buffer.at(i)) << ", ";

	auto str = ss.str();
	return str.substr(0, str.size() - 2);
}
inline const char* CreateString(const char* c_szFormat, ...)
{
	char szTmpString[8096] = { 0 };

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	return szTmpString;
}
inline bool IsEXE(std::wstring fileName)
{
	const auto p = std::filesystem::path(fileName);
	const auto ext = to_lower(p.extension().string());
	return (ext == ".exe");
}

HANDLE CreateProcessSimple(std::wstring name)
{
	PROCESS_INFORMATION pi{ 0 };
	STARTUPINFOW si{ 0 };
	si.cb = sizeof(si);

	if (!CreateProcessW(name.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess error: %ls (%08X)\n", name.c_str(), GetLastError());
		return nullptr;
	}

	CloseHandle(pi.hThread);
	return pi.hProcess;
}

PPEB GetPEBExternal()
{
	const auto hNtdll = GetModuleHandle("ntdll.dll");
	if (!hNtdll)
	{
		printf("GetModuleHandle(ntdll) failed with error: %u\n", GetLastError());
		return nullptr;
	}

	const auto NtQueryInformationProcess = (decltype(&::NtQueryInformationProcess))GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		printf("GetProcAddress(NtQueryInformationProcess) failed with error: %u\n", GetLastError());
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION pbi{ 0 };
	const auto ntStatus = NtQueryInformationProcess(gs_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
	if (!NT_SUCCESS(ntStatus))
	{
		printf("NtQueryInformationProcess failed with error: %p\n", ntStatus);
		return nullptr;
	}

	PEB peb = { 0 };
	if (!ReadProcessMemory(gs_hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), 0))
	{
		printf("ReadProcessMemory(PebBaseAddress) failed with error: %u\n", GetLastError());
		return nullptr;
	}

	return &peb;
}

bool GetDump(HANDLE hProcess, DWORD_PTR offset, PUCHAR memory, SIZE_T length)
{
	DWORD dwOldProtect = 0;
	if (!VirtualProtectEx(hProcess, (LPVOID)offset, length, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		printf("VirtualProtectEx failed with error: %u\n", GetLastError());
		return false;
	}

	SIZE_T dwReadSize = 0;
	if (!ReadProcessMemory(hProcess, (LPCVOID)offset, memory, length, &dwReadSize) || dwReadSize != length)
	{
		printf("ReadProcessMemory failed with error: %u\n", GetLastError());
		return false;
	}
	return true;
}

bool VerifyDump(std::wstring name, DWORD_PTR offset, PUCHAR memory, SIZE_T length)
{
	auto hDummyProc = CreateProcessSimple(name);
	if (!hDummyProc || hDummyProc == INVALID_HANDLE_VALUE)
	{
		printf("VerifyDump::CreateProcessSimple failed\n");
		return false;
	}

	UCHAR newmemory[32]{ 0 };
	if (!GetDump(hDummyProc, offset, newmemory, sizeof(newmemory)))
	{
		printf("VerifyDump::GetDump failed\n");
		TerminateProcess(hDummyProc, EXIT_SUCCESS);
		CloseHandle(hDummyProc);
		return false;
	}
	
	TerminateProcess(hDummyProc, EXIT_SUCCESS);
	CloseHandle(hDummyProc);

	if (memcmp(memory, newmemory, length))
	{
		printf("memcmp failed\n");
		return false;
	}

	printf("Mem dump verified!\n");
	return true;
}

bool GetExeDump(std::wstring name, SMemoryData& mem_data)
{
	auto pPeb = GetPEBExternal();
	if (!pPeb)
	{
		printf("GetPEBExternal failed\n");
		return false;
	}

	mem_data.dwBase = (DWORD_PTR)pPeb->ImageBaseAddress;

	if (!GetDump(gs_hProcess, mem_data.dwBase, mem_data.pMemDump, sizeof(mem_data.pMemDump)))
	{
		printf("GetDump failed\n");
		return false;
	}

	if (!VerifyDump(name, mem_data.dwBase, mem_data.pMemDump, sizeof(mem_data.pMemDump)))
	{
		printf("VerifyDump failed\n");
		return false;
	}

	return true;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		MessageBoxA(0, CreateString("Usage: %s <target>", argv[0]), 0, MB_ICONSTOP);
		return EXIT_FAILURE;
	}
	auto s_arg = std::string(argv[1]);
	auto arg = std::wstring(s_arg.begin(), s_arg.end());
	printf("Target: %ls\n", arg.c_str());

	if (!IsEXE(arg) || !std::filesystem::exists(arg))
	{
		MessageBoxA(0, CreateString("Not valid target file: %ls", arg.c_str()), 0, MB_ICONSTOP);
		return EXIT_FAILURE;
	}
	
	gs_hProcess = CreateProcessSimple(arg);
	if (!gs_hProcess || gs_hProcess == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(0, "CreateProcessSimple failed", 0, 0);
		return EXIT_FAILURE;
	}
	gs_dwPID = GetProcessId(gs_hProcess);

	SMemoryData mem{ 0 };
	if (!GetExeDump(arg, mem))
	{
		MessageBoxA(0, "GetExeDump failed", 0, 0);
		return EXIT_FAILURE;
	}
	
	printf("Base: %p Dump: %s\n", (void*)mem.dwBase, dump_hex(mem.pMemDump, sizeof(mem.pMemDump)).c_str());

	TerminateProcess(gs_hProcess, EXIT_SUCCESS);
	CloseHandle(gs_hProcess);

	printf("Completed!\n");
	std::cin.get();
	return EXIT_SUCCESS;
}
