#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"

#pragma optimize("", off)

#pragma warning(push) 
#pragma warning(disable: 4330)

#pragma section(".vm", execute, read, write)
#pragma comment(linker,"/SECTION:.vm,ERW")
#pragma code_seg(push, ".vm")

#pragma warning(pop) 

namespace NoMercy
{
	static HMODULE gs_module = nullptr;
	static uint8_t gs_encryption_key = 0x00;

	PIMAGE_SECTION_HEADER get_section_by_name(const std::string& name)
	{
		auto nt = g_winAPIs->RtlImageNtHeader(gs_module);
		if (!nt)
			return nullptr;
		
		auto section = IMAGE_FIRST_SECTION(nt);
		if (!section)
			return nullptr;
		
		for (std::size_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (!_stricmp(reinterpret_cast<char*>(section->Name), name.c_str()))
				return section;
		}

		return nullptr;
	};

	void encrypt_section(PIMAGE_SECTION_HEADER section)
	{
		if (!section)
			return;
		
		auto modulebase = reinterpret_cast<uintptr_t>(gs_module);
		if (!modulebase)
			return;
		
		auto valid_page_count = section->Misc.VirtualSize / 0x1000;
		if (!valid_page_count)
			return;
		
		for (std::size_t page_idx = 0; page_idx < valid_page_count; page_idx++)
		{
			uintptr_t address = modulebase + section->VirtualAddress + page_idx * 0x1000;

			DWORD old = 0;
			if (!LI_FN(VirtualProtect).safe_cached()(reinterpret_cast<LPVOID>(address), 0x1000, PAGE_EXECUTE_READWRITE, &old))
				return;
			
			for (auto off = 0; off < 0x1000; off += 0x1)
			{
				*reinterpret_cast<BYTE*>(address + off) = _rotr8((*reinterpret_cast<BYTE*>(address + off) + 0x10) ^ gs_encryption_key, 69);
			}
			
			LI_FN(VirtualProtect).safe_cached()(reinterpret_cast<LPVOID>(address), 0x1000, PAGE_NOACCESS, &old);
		}

		return;
	}

	bool find_ip_in_module(uintptr_t ip)
	{
		PPEB peb = NtCurrentPeb();
		if (!peb)
			return false;
		
		PPEB_LDR_DATA ldr = peb->Ldr;
		if (!ldr)
			return false;
		
		PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
		while (list && list != &ldr->InMemoryOrderModuleList)
		{
			auto mdl = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (mdl)
			{
				PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
					reinterpret_cast<uintptr_t>(mdl->DllBase) +
					(reinterpret_cast<PIMAGE_DOS_HEADER>(mdl->DllBase))->e_lfanew
					);
				if (nt && nt->Signature == IMAGE_NT_SIGNATURE)
				{
					if ((ip >= reinterpret_cast<uintptr_t>(mdl->DllBase)) && (ip <= reinterpret_cast<uintptr_t>(mdl->DllBase) + nt->OptionalHeader.SizeOfImage))
						return true;
				}
			}
			
			list = list->Flink;
		}

		return false;
	}

	LONG NTAPI handler(struct _EXCEPTION_POINTERS* ExceptionInfo)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
		{
			auto page_start = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
			page_start = page_start - (page_start % 0x1000);

#if defined _M_IX86
			if (find_ip_in_module(ExceptionInfo->ContextRecord->Eip))
#else
			if (find_ip_in_module(ExceptionInfo->ContextRecord->Rip))
#endif
			{
				DWORD old = 0;
				if (LI_FN(VirtualProtect).safe_cached()(reinterpret_cast<LPVOID>(page_start), 0x1000, PAGE_READWRITE, &old))
				{
					for (auto off = 0; off < 0x1000; off += 0x1)
					{
						*reinterpret_cast<BYTE*>(page_start + off) = (_rotl8(*reinterpret_cast<BYTE*>(page_start + off), 69) ^ gs_encryption_key) - 0x10;
					}

					LI_FN(VirtualProtect).safe_cached()(reinterpret_cast<LPVOID>(page_start), 0x1000, PAGE_EXECUTE_READ, &old);
				}
			}
		}
		
		return EXCEPTION_CONTINUE_SEARCH;
	}

	void CSelfProtection::initialize_protection(HMODULE mdl, const std::string& section_to_encrypt)
	{
		std::srand(std::time(nullptr));
		gs_encryption_key = std::rand() % 255 + 1;
		
		gs_module = mdl;
		if (!gs_module)
			return;

//		if (!CThreadFunctions::ChangeThreadsStatus(true))
//			return;

		g_winAPIs->AddVectoredExceptionHandler(0x1, handler);
		encrypt_section(get_section_by_name(section_to_encrypt));
		
		for (std::size_t i = 0; i < reinterpret_cast<uintptr_t>(&find_ip_in_module) - reinterpret_cast<uintptr_t>(&encrypt_section); i += 0x1)
		{
			*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&encrypt_section) + i) = 0x0;
		}
		
//		CThreadFunctions::ChangeThreadsStatus(false);
	}
};

#pragma code_seg(pop, ".vm")
#pragma optimize("", on)
