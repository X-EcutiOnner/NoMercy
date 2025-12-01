#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"

namespace NoMercy
{
	void CSelfProtection::DestroyIAT(HMODULE hModule)
	{
		// todo: overwrite loaded API names with zeroes (this will otherwise break the IAT).

		auto pDOS = (IMAGE_DOS_HEADER*)hModule;
		if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
			return;

		auto pINH = (IMAGE_NT_HEADERS*)((PBYTE)hModule + pDOS->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return;

		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
			return;

		PIMAGE_THUNK_DATA pFirstThunkMirror, pOrigThunkMirror;

		auto pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pDOS + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pIID->Characteristics)
		{
			pFirstThunkMirror = (PIMAGE_THUNK_DATA)(pDOS + pIID->FirstThunk);

			pFirstThunkMirror->u1.Function = 0;
			pFirstThunkMirror->u1.AddressOfData = 0;
			pFirstThunkMirror->u1.Ordinal = 0;

			pOrigThunkMirror = (PIMAGE_THUNK_DATA)(pDOS + pIID->OriginalFirstThunk);
			while (pOrigThunkMirror->u1.AddressOfData)
			{
				pOrigThunkMirror->u1.Function = 0;
				pOrigThunkMirror->u1.Ordinal = 0;

				pOrigThunkMirror++;
				pFirstThunkMirror++;
			}

			pIID++;
		}

		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}
};
