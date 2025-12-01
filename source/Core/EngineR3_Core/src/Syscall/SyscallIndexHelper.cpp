#include "../../include/PCH.hpp"
#include "../../include/Defines.hpp"
#include "../../include/SyscallIndexHelper.hpp"
#include "../../include/LDasm.hpp"
#include "../../include/ExitHelper.hpp"
#include "../../include/PEHelper.hpp"
#include "../../include/Pe.hpp"
#include "../../include/disassembler.hpp"




namespace NoMercyCore
{
	CSyscallIndexHelper::CSyscallIndexHelper()
	{
	}
	CSyscallIndexHelper::~CSyscallIndexHelper()
	{
		m_syscall_indexes.clear();
	}

	DWORD CSyscallIndexHelper::GetSyscallId(const std::string& stFunction)
	{
		auto dwFunctionHash = GetFunctionHash(stFunction);
		return m_syscall_indexes[dwFunctionHash];
	}

	DWORD CSyscallIndexHelper::GetFunctionHash(const std::string& stFunction)
	{
		return CApplication::Instance().CryptFunctionsInstance()->GetStringHash((LPVOID)stFunction.c_str(), FALSE, stFunction.size());
	}

	ULONG CSyscallIndexHelper::ExtractSyscallNumber(LPCSTR FunctionName)
	{
		PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
		PIMAGE_RUNTIME_FUNCTION_ENTRY ImageRuntimeEntry = NULL;
		PULONG NameTableBase;
		PULONG AddressTableBase;
		PUSHORT NameOrdinalTableBase;
		PCHAR exportName;
		ULONG i, j, syscallNumber, syscallBase;
		DWORD RVA;
		USHORT servicePrefix;

		union {
			PIMAGE_NT_HEADERS64 nt64;
			PIMAGE_NT_HEADERS32 nt32;
			PIMAGE_NT_HEADERS nt;
		} NtHeaders;

		const auto pvImageBase = g_winModules->hNtdll_o;
		if (!pvImageBase)
		{
			APP_TRACE_LOG(LL_ERR, L"ntdll image not found!");
			return 0;
		}

		auto ntStatus = g_winAPIs->RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, pvImageBase, 0, &NtHeaders.nt);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlImageNtHeaderEx failed with status: %p", ntStatus);
			return 0;
		}

		if (!NtHeaders.nt)
		{
			APP_TRACE_LOG(LL_ERR, L"NT headers not found in ntdll!");
			return 0;
		}

		if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {

			RVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (RVA == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"x64 >> EAT base not found!");
				return 0;
			}

			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pvImageBase, RVA);

			RVA = NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
			if (RVA == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"x64 >> Exception table base not found!");
				return 0;
			}

			ImageRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlOffsetToPointer(pvImageBase, RVA);

		}
		else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

			RVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (RVA == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"x86 >> EAT base not found!");
				return 0;
			}

			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pvImageBase, RVA);

			RVA = NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
			if (RVA == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"x86 >> Exception table base not found!");
				return 0;
			}

			ImageRuntimeEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RtlOffsetToPointer(pvImageBase, RVA);

		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"Unknown file targeted arch: %p", NtHeaders.nt->FileHeader.Machine);
			return 0;
		}

		if (ExportDirectory == NULL || ImageRuntimeEntry == NULL)
		{
			APP_TRACE_LOG(LL_ERR, L"Unknown export or runtime address: %p/%p", ExportDirectory, ImageRuntimeEntry);
			return 0;
		}

		syscallNumber = 0;
		servicePrefix = 'wZ';
		syscallBase = 0;

		NameTableBase = (PULONG)RtlOffsetToPointer(pvImageBase, (ULONG)ExportDirectory->AddressOfNames);
		NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(pvImageBase, (ULONG)ExportDirectory->AddressOfNameOrdinals);
		AddressTableBase = (PULONG)RtlOffsetToPointer(pvImageBase, (ULONG)ExportDirectory->AddressOfFunctions);

		for (i = 0; ImageRuntimeEntry[i].BeginAddress; i++)
		{
			for (j = 0; j < ExportDirectory->NumberOfFunctions; j++)
			{
				if (AddressTableBase[NameOrdinalTableBase[j]] == ImageRuntimeEntry[i].BeginAddress)
				{
					exportName = (PCHAR)RtlOffsetToPointer(pvImageBase, NameTableBase[j]);

					if (strcmpi(FunctionName, exportName) == 0)
						return syscallNumber + syscallBase;

					if (*(USHORT*)exportName == servicePrefix)
						syscallNumber++;
				}
			}
		}

		return 0;
	}

	bool CSyscallIndexHelper::ParseFromNtdllFile(const std::string& szAPIName, LPDWORD pdwSysIndex)
	{
		auto IsX64System = [] {
			SYSTEM_INFO SysInfo = { 0 };
			g_winAPIs->GetNativeSystemInfo(&SysInfo);

			return (SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);
		};

		static auto is_x64 = IsX64System();
		static auto is_wow64 = stdext::is_wow64();

		uintptr_t api_addr = 0;
		if (is_wow64)
		{
			api_addr = wow64pp::import(wow64pp::module_handle(xorstr_("ntdll.dll")), szAPIName.c_str());
			api_addr -= wow64pp::module_handle(xorstr_("ntdll.dll"));
		}
		else
		{
			api_addr = (uintptr_t)g_winAPIs->GetProcAddress(g_winAPIs->GetModuleHandleW(xorstr_(L"ntdll.dll")), szAPIName.c_str());
			api_addr -= (uintptr_t)g_winAPIs->GetModuleHandleW(xorstr_(L"ntdll.dll"));
		}

		auto dwFileOffset = 0UL;
		if (is_wow64 || is_x64)
		{
			BYTE pNtdllHeader[PE_HEADER_SIZE] = { 0x0 };
			if (is_wow64)
			{
				try
				{
					wow64pp::detail::read_memory<BYTE[PE_HEADER_SIZE]>(wow64pp::module_handle(xorstr_("ntdll.dll")), &pNtdllHeader, PE_HEADER_SIZE);
				}
				catch (const std::system_error& e)
				{
					OnPreFail(0, CORE_ERROR_SYSCALL_READ_NT_HEADER_FAIL, e.code().value());
					return false;
				}
			}
			else
			{
				SIZE_T read_size = 0;
				auto ret = g_winAPIs->ReadProcessMemory(NtCurrentProcess(), g_winAPIs->GetModuleHandleW(xorstr_(L"ntdll.dll")), &pNtdllHeader, PE_HEADER_SIZE, &read_size);
				if (!ret || read_size != sizeof(pNtdllHeader))
				{
					OnPreFail(0, CORE_ERROR_SYSCALL_READ_NT_HEADER_FAIL, g_winAPIs->GetLastError());
					return false;
				}
			}

			auto pIDH = (PIMAGE_DOS_HEADER)pNtdllHeader;
			if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			{
				OnPreFail(0, CORE_ERROR_SYSCALL_PARSE_NT_HEADER_FAIL, 1);
				return false;
			}

			auto pINH = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pIDH + pIDH->e_lfanew);
			if (pINH->Signature != IMAGE_NT_SIGNATURE)
			{
				OnPreFail(0, CORE_ERROR_SYSCALL_PARSE_NT_HEADER_FAIL, 2);
				return false;
			}

			auto pISH = (PIMAGE_SECTION_HEADER)(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pINH);
			for (std::size_t i = 0; i < pINH->FileHeader.NumberOfSections; i++)
			{
				if (pISH->VirtualAddress <= api_addr && api_addr <= (pISH->VirtualAddress + pISH->Misc.VirtualSize))
				{
					break;
				}
				pISH++;
			}
			dwFileOffset = (DWORD)(api_addr - pISH->VirtualAddress + pISH->PointerToRawData);
		}
		else
		{
			auto pIDH = (PIMAGE_DOS_HEADER)g_winAPIs->GetModuleHandleW(xorstr_(L"ntdll.dll"));
			if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			{
				OnPreFail(0, CORE_ERROR_SYSCALL_PARSE_NT_HEADER_FAIL, 1);
				return false;
			}

			auto pINH = (PIMAGE_NT_HEADERS)((char*)pIDH + pIDH->e_lfanew);
			if (pINH->Signature != IMAGE_NT_SIGNATURE)
			{
				OnPreFail(0, CORE_ERROR_SYSCALL_PARSE_NT_HEADER_FAIL, 2);
				return false;
			}

			auto pISH = (PIMAGE_SECTION_HEADER)(sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)pINH);
			for (std::size_t i = 0; i < pINH->FileHeader.NumberOfSections; i++)
			{
				if (pISH->VirtualAddress <= api_addr && api_addr <= (pISH->VirtualAddress + pISH->Misc.VirtualSize))
				{
					break;
				}
				pISH++;
			}
			dwFileOffset = (DWORD)(api_addr - pISH->VirtualAddress + pISH->PointerToRawData);
		}
		if (dwFileOffset == 0)
		{
			OnPreFail(0, CORE_ERROR_SYSCALL_PARSE_OFFSET_FAIL, 0);
			return false;
		}

		PVOID OldValue = nullptr;
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			OnPreFail(0, CORE_ERROR_SYSCALL_FS_REDIRECTION_FAIL, 1);
			return false;
		}

		auto szNtdll = CApplication::Instance().DirFunctionsInstance()->SystemPath() + xorstr_(L"\\ntdll.dll");
		auto hNtdll = g_winAPIs->CreateFileW(szNtdll.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!IS_VALID_HANDLE(hNtdll))
		{
			OnPreFail(0, CORE_ERROR_SYSCALL_NTDLL_OPEN_FAIL, g_winAPIs->GetLastError());
			return false;
		}

		g_winAPIs->SetFilePointer(hNtdll, dwFileOffset, nullptr, FILE_CURRENT);

		auto dwReadByteCount = 0UL;
		BYTE pOpcode[64] = { 0 };
		if (!g_winAPIs->ReadFile(hNtdll, pOpcode, (DWORD)sizeof(pOpcode), &dwReadByteCount, nullptr))
		{
			g_winAPIs->CloseHandle(hNtdll);
			OnPreFail(0, CORE_ERROR_SYSCALL_NTDLL_READ_FAIL, g_winAPIs->GetLastError());
			return false;
		}
		g_winAPIs->CloseHandle(hNtdll);

		auto dwEax = 0UL;
		auto pEip = pOpcode;
		while (true)
		{
			ldasm_data ld = { 0 };
			auto dwLength = ldasm(pEip, &ld, is_x64);

			if (dwLength == 5 && pEip[0] == 0xB8)
			{
				dwEax = *(DWORD*)(&pEip[1]);
				break;
			}
			pEip += dwLength;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr))
		{
			OnPreFail(0, CORE_ERROR_SYSCALL_FS_REDIRECTION_FAIL, 2);
			return false;
		}

		if (pdwSysIndex) *pdwSysIndex = dwEax;
		return true;
	}

	DWORD CSyscallIndexHelper::GetSyscallIdFromFile(const std::string& stFunction)
	{
		// already parsed & cached
		const auto it = m_syscall_indexes.find(GetFunctionHash(stFunction));
		if (it != m_syscall_indexes.end())
			return it->second;

		// parse & store
		DWORD id;
		if (!ParseFromNtdllFile(stFunction, &id))
			id = 0;
		return id;
	}

	DWORD CSyscallIndexHelper::GetSyscallIdFromMemory(const std::string& stFunction)
	{
		DWORD id = 0;

		// already parsed & cached
		const auto it = m_syscall_indexes.find(GetFunctionHash(stFunction));
		if (it != m_syscall_indexes.end())
			return it->second;

		// parse & store
		auto dwAddress = (DWORD_PTR)g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, stFunction.c_str());
		if (!dwAddress)
		{
			APP_TRACE_LOG(LL_ERR, L"#1 NT Function: %s not found", stFunction.c_str());
			return id;
		}

		/*
		const auto dwRealAddress = (DWORD_PTR)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetRealAddress((PVOID)dwAddress);
		if (!dwRealAddress)
		{
			APP_TRACE_LOG(LL_ERR, L"#2 NT Function: %s not found", stFunction.c_str());
			return id;
		}

		if (dwAddress != dwRealAddress)
		{
			APP_TRACE_LOG(LL_SYS, L"NT Function: %s redirected to %p", stFunction.c_str(), dwRealAddress);
			dwAddress = dwRealAddress;
		}
		*/
		
		auto disassembleHelper = stdext::make_unique_nothrow<disassembler>(ZYDIS_MACHINE_MODE_LONG_COMPAT_32);
		if (IS_VALID_SMART_PTR(disassembleHelper))
		{
			auto disassembly_output = disassembleHelper->disassemble((void*)dwAddress, 8);
			if (!disassembly_output.empty())
			{
				auto found_eax = false;
				auto mov_eax_string = std::wstring();
				for (const auto& instruction : disassembly_output)
				{
					if (instruction.find(xorstr_(L"mov eax")) != std::string::npos)
					{
						mov_eax_string = instruction;

						found_eax = true;
						break;
					}
				}

				if (found_eax)
				{
					auto comma_position = mov_eax_string.find(',');
					auto number_as_string = mov_eax_string.substr(comma_position + 2);

					uint32_t final_syscall_id;

					std::wstringstream stream;
					stream << std::hex << number_as_string;
					stream >> final_syscall_id;
					id = final_syscall_id;
				}
			}
		}
		
		if (!id)
		{
#ifdef _WIN64
		if (*(uint8_t*)dwAddress == 0x49 || *(uint8_t*)dwAddress == 0x4C)
			id = *(DWORD*)(dwAddress + 4);
#else
		if (*(uint8_t*)dwAddress == 0xB8)
			id = *(DWORD*)(dwAddress + 1);
#endif
		}

		if (!id)
		{
			APP_TRACE_LOG(LL_ERR, L"NT Function: %s memory not valid: 0x%X", stFunction.c_str(), *(uint8_t*)dwAddress);
			return 0;
		}

		return id;
	}

	bool CSyscallIndexHelper::AppendFunctionID(const std::string& stFunction, bool bFromFile)
	{
		DWORD id = 0;
		if (bFromFile)
			id = GetSyscallIdFromFile(stFunction);
		else
			id = GetSyscallIdFromMemory(stFunction);

		if (!id && !bFromFile)
			id = GetSyscallIdFromFile(stFunction);

		const auto hash = GetFunctionHash(stFunction);
		if (!hash || !id)
		{
			APP_TRACE_LOG(LL_ERR, L"Corrupted data for %hs (%p / %u)", stFunction.c_str(), hash, id);
			return false;
		}

		m_syscall_indexes.emplace(hash, id);
		APP_TRACE_LOG(LL_SYS, L"Func: %hs(%p) syscall: %u", stFunction.c_str(), hash, id);
		return true;
	}

	bool CSyscallIndexHelper::BuildSyscallList(bool bFromFile)
	{
		const auto lstSyscallFuncs = {
			xorstr_("NtClose"), xorstr_("NtAllocateVirtualMemory"), xorstr_("NtFreeVirtualMemory"), xorstr_("NtReadVirtualMemory"),
			xorstr_("NtWriteVirtualMemory"), xorstr_("NtQueryVirtualMemory"), xorstr_("NtProtectVirtualMemory"), xorstr_("NtLockVirtualMemory"),
			xorstr_("NtFlushInstructionCache"), xorstr_("NtCreateSection"), xorstr_("NtMapViewOfSection"), xorstr_("NtUnmapViewOfSection"),
			xorstr_("NtOpenThread"), xorstr_("NtSuspendThread"), xorstr_("NtResumeThread"), xorstr_("NtSuspendProcess"),
			xorstr_("NtQuerySystemInformation"), xorstr_("NtTerminateProcess"), xorstr_("NtGetContextThread"),xorstr_("NtOpenFile"),
			xorstr_("NtCreateSection"), xorstr_("NtMapViewOfSection"),
			xorstr_("NtCreateFile"), xorstr_("NtReadFile"), xorstr_("NtWriteFile"), xorstr_("NtWaitForSingleObject"),
		};

		uint32_t idx = 0;
		for (const auto& c_szSyscallFunc : lstSyscallFuncs)
		{
			idx++;

			if (!AppendFunctionID(c_szSyscallFunc, bFromFile))
			{
				APP_TRACE_LOG(LL_ERR, L"#1 Syscall: %u func: %s could not initialized", idx, c_szSyscallFunc);
				continue;
			}
		}

		return true;
	}

	bool CSyscallIndexHelper::BuildAllSyscalls()
	{
		const auto ntdll = Pe::Pe32::fromModule(g_winModules->hNtdll);
		if (!ntdll.valid())
		{
			APP_TRACE_LOG(LL_ERR, L"Ntdll PE not valid");
			return false;
		}

		uint32_t idx = 0;
		for (const auto& exp : ntdll.exports())
		{
			idx++;
			
			if (!exp.valid())
			{
				APP_TRACE_LOG(LL_ERR, L"Ntdll export %u not valid", idx);
				continue;
			}
			if (!exp.hasName())
			{
				APP_TRACE_LOG(LL_ERR, L"Ntdll export %u has no name", idx);
				continue;
			}

			const auto bNtApi = std::string(exp.name()).substr(0, 2) == "Nt"s;
			if (!bNtApi)
				continue;

			if (!AppendFunctionID(exp.name(), false))
			{
				APP_TRACE_LOG(LL_ERR, L"#2 Syscall: %u func: %s could not initialized", idx, exp.name());
				return false;
			}
		}

		return true;
	}
};
