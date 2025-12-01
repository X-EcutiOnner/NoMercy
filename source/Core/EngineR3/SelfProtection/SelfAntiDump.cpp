#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"
#include "../Common/ExceptionHandlers.hpp"

#define BUFFER_SIZE 0x1000

namespace NoMercy
{
	static LPVOID s_pGuardMem = nullptr;

	inline LPVOID CreateSafeMemoryPage(DWORD dwRegionSize, DWORD dwProtection)
	{
		LPVOID pMemBase = nullptr;

		__try
		{
			pMemBase = g_winAPIs->VirtualAlloc(0, dwRegionSize, MEM_COMMIT | MEM_RESERVE, dwProtection);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		return pMemBase;
	}

	bool CSelfProtection::InitializeAntiDump(HMODULE hModule)
	{
		if (!IsWindowsVistaOrGreater())
			return true;

		if (!hModule)
			return false;

		for (std::size_t i = 0; i < NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 5); i++)
			CreateSafeMemoryPage(BUFFER_SIZE, PAGE_READWRITE);

		s_pGuardMem = CreateSafeMemoryPage(BUFFER_SIZE, PAGE_READWRITE);

		for (std::size_t i = 0; i < NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomInt(1, 10); i++)
			CreateSafeMemoryPage(BUFFER_SIZE, PAGE_READWRITE);

		//	auto hTargetModule = g_winModules->hBaseModule;
		auto hTargetModule = hModule;

		const auto pDOS = (IMAGE_DOS_HEADER*)hTargetModule;
		if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = (IMAGE_NT_HEADERS*)((PBYTE)pDOS + pDOS->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
		if (!pISH)
			return false;

		auto dwOldProtect = 0UL;
		g_winAPIs->VirtualProtect((LPVOID)pISH, sizeof(LPVOID), PAGE_READWRITE, &dwOldProtect);

		pISH[0].VirtualAddress = reinterpret_cast<DWORD_PTR>(s_pGuardMem);

		g_winAPIs->VirtualProtect((LPVOID)pISH, sizeof(LPVOID), dwOldProtect, &dwOldProtect);

		return true;
	}

	bool CSelfProtection::IsDumpTriggered()
	{
		if (!IsWindowsVistaOrGreater())
			return true;
		
		if (!s_pGuardMem)
		{
			// APP_TRACE_LOG(LL_ERR, L"Null guard ptr!");
			return false;
		}

		PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { s_pGuardMem, 0 };
		if (!g_winAPIs->QueryWorkingSetEx(NtCurrentProcess(), &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
		{
			APP_TRACE_LOG(LL_ERR, L"QueryWorkingSetEx fail! Error: %u", GetLastError());
			return false;
		}

		if (pworkingSetExInformation.VirtualAttributes.Valid)
			return true;

		return false;
	}
};

