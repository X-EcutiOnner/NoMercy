#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"



namespace NoMercy
{
	void CSelfProtection::MakePePacked(HMODULE hModule)
	{
		auto pIDH = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
		if (pIDH && pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		{
			auto pINH = reinterpret_cast<IMAGE_NT_HEADERS*>((LPBYTE)hModule + pIDH->e_lfanew);
			if (pINH && pINH->Signature == IMAGE_NT_SIGNATURE)
			{
				DWORD dwOld = 0;
				if (g_winAPIs->VirtualProtect(pINH, sizeof(*pINH), PAGE_EXECUTE_READWRITE, &dwOld))
				{
					pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 1;
					pINH->OptionalHeader.AddressOfEntryPoint = 0;

					SIZE_T cbWrittenSize = 0;
					g_winAPIs->WriteProcessMemory(NtCurrentProcess(), pINH, &pINH, sizeof(*pINH), &cbWrittenSize);
					g_winAPIs->VirtualProtect(pINH, sizeof(*pINH), dwOld, &dwOld);
				}
			}
		}
	}

	void CSelfProtection::ProtectSelfPE(HMODULE hModule)
	{
		auto pIDH = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
		if (pIDH && pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		{
			auto dwOldProtect = 0UL;
			if (g_winAPIs->VirtualProtect(pIDH, 1024, PAGE_READWRITE, &dwOldProtect))
			{
				pIDH->e_magic = 0;

				auto pINH = reinterpret_cast<IMAGE_NT_HEADERS*>(pIDH + 1);
				pINH->Signature = 0;

				g_winAPIs->VirtualProtect(pIDH, 1024, dwOldProtect, &dwOldProtect);
			}
		}
	}
};
