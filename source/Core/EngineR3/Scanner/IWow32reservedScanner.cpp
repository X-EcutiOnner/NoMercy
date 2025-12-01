#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
#ifndef _M_X64

	inline wchar_t* GetBaseName(wchar_t* string)
	{
		unsigned long i = wcslen(string);
		while (string[i - 1] != '\\') i--;
		return &string[i];
	}

	unsigned short cs_ = 0;
	unsigned char* WOW32Reserved = 0;
	unsigned long PEB64 = 0;
	__forceinline void GetWow32ReservedInfo()
	{
		__asm
		{
			pushad
			mov eax, dword ptr fs : [0xC0]
			mov WOW32Reserved, eax
			mov eax, dword ptr fs : [0x30]
			add eax, 0x1000
			mov PEB64, eax
			mov cs_, cs
			popad
		}
	}

#endif

	inline bool Wow32ReservedIsHooked()
	{
#ifndef _M_X64
		bool bIsHooked = false;

		if (stdext::is_wow64() == false)
		{
			APP_TRACE_LOG(LL_SYS, L"IsSysWow64 returned as false, Skipped Wow32reserved hook check");
			return bIsHooked;
		}

		GetWow32ReservedInfo();

		if (!WOW32Reserved)
		{
			APP_TRACE_LOG(LL_SYS, L"WOW32Reserved returned as false, Skipped Wow32reserved hook check");
			return bIsHooked;
		}

		if ((*WOW32Reserved == 0xEA) && (*(unsigned short*)(WOW32Reserved + 5) != cs_))
		{
			unsigned long CpupReturnFromSimulatedCode = *(unsigned long*)(WOW32Reserved + 1);

			MEMORY_BASIC_INFORMATION MBI = { 0 };
			g_winAPIs->VirtualQuery((void*)CpupReturnFromSimulatedCode, &MBI, sizeof(MBI));

			if (MBI.Type == MEM_IMAGE)
			{
				char* p = (char*)g_winAPIs->LocalAlloc(LMEM_ZEROINIT, 0x1000);
				if (NT_SUCCESS(g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), (void*)CpupReturnFromSimulatedCode, MemoryMappedFilenameInformation /*filename*/, p, 0x1000, 0) >= 0))
				{
					if (((UNICODE_STRING*)p)->Length)
					{
						const auto wstOwnerName = std::wstring(((UNICODE_STRING*)p)->Buffer, ((UNICODE_STRING*)p)->Length);
						const std::wstring wstWow64Cpu = xorstr_(L"wow64cpu.dll");

						if (wstOwnerName.find(wstWow64Cpu) == std::wstring::npos)
						{
							APP_TRACE_LOG(LL_ERR, L"CpupReturnFromSimulatedCode module owner is: %ls", wstOwnerName.c_str());
							bIsHooked = true;
						}
					}
				}
				g_winAPIs->LocalFree(p);
			}
		}

		return bIsHooked;
#else
		return false;
#endif
	}

	void IScanner::CheckWow32ReservedHook()
	{
		APP_TRACE_LOG(LL_TRACE, L"CheckWow32ReservedHook has been started!");

		if (Wow32ReservedIsHooked())
		{
			APP_TRACE_LOG(LL_ERR, L"Wow32reserved hook detected");
			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_WOW32RESERVED_HOOK);
		}

		APP_TRACE_LOG(LL_TRACE, L"CheckWow32ReservedHook completed!");
	}
};
