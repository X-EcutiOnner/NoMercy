#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../SelfProtection/SelfProtection.hpp"

extern "C" void OnCfgDispatch(void* addr)
{
	static bool s_bOnce = false;
	if (!s_bOnce)
	{
		s_bOnce = true;

		DWORD64 disp = 0;

		BYTE pBuffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME + 1] = { 0x0 };

		auto pSymbol64 = reinterpret_cast<IMAGEHLP_SYMBOL64*>(pBuffer);
		pSymbol64->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
		pSymbol64->MaxNameLength = MAX_SYM_NAME;

		BOOL bret = SymGetSymFromAddr64(NtCurrentProcess(), (DWORD64)addr, &disp, pSymbol64);

		if (bret)
		{
			APP_TRACE_LOG(LL_WARN, L"call to: %p (%s+%lx)", addr, pSymbol64->Name, disp);
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"call to: %p", addr);
		}

		s_bOnce = false;
	}
	
}

namespace NoMercy
{
	bool CSelfProtection::InitializeCFGHook(PVOID pvDllBase)
	{
		const auto pINH = g_winAPIs->RtlImageNtHeader(pvDllBase);
		if (pINH && pINH->Signature == IMAGE_NT_SIGNATURE)
		{
			if (pINH->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
			{
				ULONG ulSize = 0;
				auto pILCD = (PIMAGE_LOAD_CONFIG_DIRECTORY)g_winAPIs->RtlImageDirectoryEntryToData(pvDllBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &ulSize);
				if (pILCD)
				{
					DWORD dwOldProtection = 0;
					if (g_winAPIs->VirtualProtect((PVOID)pILCD->GuardCFCheckFunctionPointer, sizeof(PVOID), PAGE_READWRITE, &dwOldProtection))
					{
						*(PVOID*)pILCD->GuardCFCheckFunctionPointer = (PVOID)(ULONG_PTR)&OnCfgDispatch;

						g_winAPIs->VirtualProtect((PVOID)pILCD->GuardCFCheckFunctionPointer, sizeof(PVOID), dwOldProtection, &dwOldProtection);
						return true;
					}
				}
			}
		}
		return false;
	}
}
