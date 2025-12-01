#include "../../include/PCH.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/PEHelper.hpp"
#include "../../include/ApiSetMap.hpp"
#include "../../include/disassembler.hpp"
#include "../../include/Pe.hpp"

namespace NoMercyCore
{
	DWORD_PTR GetProcAddressWrapper(std::wstring wstModuleName, const char* c_szAPIName)
	{
		if (wstModuleName.empty() || !c_szAPIName)
			return 0;

		const auto stAPIName = HIWORD((DWORD)c_szAPIName) ? c_szAPIName : std::to_string(reinterpret_cast<WORD>(c_szAPIName));
		APP_TRACE_LOG(LL_TRACE, L"GetProcAddressWrapper: %s, %hs", wstModuleName.c_str(), stAPIName.c_str());

		// Load api set schema
		static const auto pApiSetNamespace = ApiSetMap::GetApiSetNamespace();
		if (!pApiSetNamespace)
		{
			APP_TRACE_LOG(LL_ERR, L"GetApiSetNamespace failed!");
			return 0;
		}
		static const auto upApiSetMap = ApiSetMap::ApiSetSchemaImpl::ParseApiSetSchema(pApiSetNamespace);
		if (!IS_VALID_SMART_PTR(upApiSetMap))
		{
			APP_TRACE_LOG(LL_ERR, L"ParseApiSetSchema failed!");
			return 0;
		}

		// If the stModuleName starts with api- or ext-, resolve the redirected name and load it
		if (wstModuleName.compare(0, 5, xorstr_(L"api-")) == 0 || wstModuleName.compare(0, 5, xorstr_(L"ext-")) == 0)
		{
			const auto vecApiSetSchema = upApiSetMap->Lookup(wstModuleName);
			if (vecApiSetSchema.size() != 1)
			{
				APP_TRACE_LOG(LL_ERR, L"ApiSetSchema lookup failed! Ret: %u", vecApiSetSchema.size());
				return 0;
			}

			wstModuleName = vecApiSetSchema[0];
			APP_TRACE_LOG(LL_SYS, L"ApiSetSchema resolved: %ls", wstModuleName.c_str());

			if (wstModuleName.empty() || !std::filesystem::exists(wstModuleName))
			{
				APP_TRACE_LOG(LL_ERR, L"ApiSetSchema resolved file not found: %ls", wstModuleName.c_str());
				return 0;
			}
		}

		// Try find module by name
		const auto hMemModule = g_winAPIs->GetModuleHandleW_o(wstModuleName.c_str());
		if (!hMemModule)
		{
			APP_TRACE_LOG(LL_TRACE, L"GetModuleHandleA failed! %ls", wstModuleName.c_str());
			return 0;
		}

		const auto hModule = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()->Find(wstModuleName);
		if (!hModule)
		{
			APP_TRACE_LOG(LL_TRACE, L"Module %ls not found", wstModuleName.c_str());
			return 0;
		}

		PVOID pvAPIAddr = nullptr;
		if (HIWORD((DWORD)c_szAPIName))
		{
			// API name is string
			pvAPIAddr = CPEFunctions::GetExportEntry(hModule, c_szAPIName);
		}
		else
		{
			// API name is ordinal
			pvAPIAddr = CPEFunctions::GetExportEntry(hModule, "", reinterpret_cast<WORD>(c_szAPIName));
		}

		if (pvAPIAddr)
		{
			pvAPIAddr = (PVOID)((DWORD_PTR)pvAPIAddr - (DWORD_PTR)hModule + (DWORD_PTR)hMemModule);
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"GetExportEntry failed! '%s', '%hs'", wstModuleName.c_str(), stAPIName.c_str());
		}

		return (DWORD_PTR)pvAPIAddr;
	}

	bool IsGlobalVariable(PIMAGE_NT_HEADERS pINH, DWORD_PTR dwRVA)
	{
		auto pISH = IMAGE_FIRST_SECTION(pINH);
		if (!pISH)
			return false;
		
		for (std::size_t i = 0; i < pINH->FileHeader.NumberOfSections; i++)
		{
			if (pISH[i].VirtualAddress <= dwRVA && pISH[i].VirtualAddress + pISH[i].SizeOfRawData > dwRVA)
			{
				return false;
			}
		}
		return true;
	}

	DWORD_PTR FileNameRedirection(const std::string& stRedirectionName)
	{
		APP_TRACE_LOG(LL_TRACE, L"Redirecting file name: %hs", stRedirectionName.c_str());
		
		// Sanity check
		const auto pos = stRedirectionName.find_last_of('.');
		if (pos == std::string::npos)
			return 0;

		auto stModuleName = stRedirectionName.substr(0, pos);
		const auto stAPIName = stRedirectionName.substr(pos + 1);

		if (stModuleName.empty() || stAPIName.empty())
			return 0;

		stModuleName += xorstr_(".dll");
		APP_TRACE_LOG(LL_TRACE, L"Fixed name: %hs > %hs", stModuleName.c_str(), stAPIName.c_str());

		// Load api set schema
		static const auto pApiSetNamespace = ApiSetMap::GetApiSetNamespace();
		if (!pApiSetNamespace)
		{
			APP_TRACE_LOG(LL_ERR, L"GetApiSetNamespace failed!");
			return 0;
		}
		static const auto upApiSetMap = ApiSetMap::ApiSetSchemaImpl::ParseApiSetSchema(pApiSetNamespace);
		if (!IS_VALID_SMART_PTR(upApiSetMap))
		{
			APP_TRACE_LOG(LL_ERR, L"ParseApiSetSchema failed!");
			return 0;
		}

		// If the stModuleName starts with api- or ext-, resolve the redirected name and load it
		auto wstModuleName = stdext::to_wide(stModuleName);
		if (wstModuleName.compare(0, 5, xorstr_(L"api-")) == 0 || wstModuleName.compare(0, 5, xorstr_(L"ext-")) == 0)
		{
			const auto vecApiSetSchema = upApiSetMap->Lookup(wstModuleName);
			if (vecApiSetSchema.size() != 1)
			{
				APP_TRACE_LOG(LL_ERR, L"ApiSetSchema lookup failed! Ret: %u", vecApiSetSchema.size());
				return 0;
			}

			wstModuleName = vecApiSetSchema[0];
			APP_TRACE_LOG(LL_SYS, L"ApiSetSchema resolved: %ls", wstModuleName.c_str());

			if (wstModuleName.empty() || !std::filesystem::exists(wstModuleName))
			{
				APP_TRACE_LOG(LL_ERR, L"ApiSetSchema resolved file not found: %ls", wstModuleName.c_str());
				return 0;
			}
		}

		const auto hMemModule = g_winAPIs->GetModuleHandleW_o(wstModuleName.c_str());
		if (!hMemModule)
		{
			const auto nLogLevel = g_winAPIs->GetLastError();
			APP_TRACE_LOG(nLogLevel == ERROR_MOD_NOT_FOUND ? LL_TRACE : LL_ERR, L"GetModuleHandleA: %s failed with: %u", wstModuleName.c_str(), nLogLevel);
			return 0;
		}
		
		const auto hModule = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()->Find(wstModuleName);
		if (!hModule)
		{
			APP_TRACE_LOG(LL_TRACE, L"Module %ls not found", wstModuleName.c_str());
			return 0;
		}
		
		PVOID pvAPIAddr = nullptr;
		if (stAPIName.front() == '#')
		{
			const auto dwOrdinal = std::stoul(stAPIName.substr(1), nullptr, 10);
			pvAPIAddr = CPEFunctions::GetExportEntry(hModule, "", dwOrdinal);
		}
		else
		{
			pvAPIAddr = CPEFunctions::GetExportEntry(hModule, stAPIName.c_str());
		}

		if (pvAPIAddr)
		{
			pvAPIAddr = (PVOID)((DWORD_PTR)pvAPIAddr - (DWORD_PTR)hModule + (DWORD_PTR)hMemModule);
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"FileNameRedirection failed! %ls, %hs", wstModuleName.c_str(), stAPIName.c_str());
		}
		
		return (DWORD_PTR)pvAPIAddr;
	}

	bool ScanInlineHook(const std::string& stApiName, DWORD_PTR dwOriAddress, DWORD_PTR dwMemAddr, DWORD_PTR dwMemModule, DWORD_PTR dwMappedModule)
	{
		auto disasm = stdext::make_unique_nothrow<disassembler>(ZYDIS_MACHINE_MODE_LONG_COMPAT_32);
		if (!disasm)
		{
			APP_TRACE_LOG(LL_ERR, L"disassembler::disassembler allocation failed!");
			return false;
		}
		
		DWORD_PTR getRVA = (dwMemAddr - (DWORD_PTR)dwMemModule);
		DWORD_PTR mappedPrologue = ((DWORD_PTR)dwMappedModule + getRVA);

		for (std::size_t Index = 0; Index < 15; ++Index) // 15
		{
			if ((*(BYTE*)(mappedPrologue + Index)) != (*(BYTE*)(dwMemAddr + Index)))
			{
				APP_TRACE_LOG(LL_ERR, L"Inline hook detected in %s", stApiName.c_str());
				
				auto src = *(BYTE*)(dwMemAddr + Index);
				auto dst = *(BYTE*)(mappedPrologue + Index);

				const auto& [status, instruction, operands] = disasm->disassemble_instruction((void*)(dwMemAddr + Index), 1);
				const auto& [status2, instruction2, operands2] = disasm->disassemble_instruction((void*)(mappedPrologue + Index), 1);

				if (ZYAN_SUCCESS(status))
				{
					APP_TRACE_LOG(LL_ERR, L"ScanInlineHook: %s, %u", stApiName.c_str(), instruction->mnemonic);

					if (instruction->mnemonic == ZYDIS_MNEMONIC_JMP)
					{
						std::uintptr_t jmp_destination = disasm->get_instruction_absolute_address(*instruction, operands, dwMemAddr + Index);
						APP_TRACE_LOG(LL_ERR, L"ScanInlineHook abs ptr: %p", jmp_destination);
					}
				}

				return true;
			}
		}
		
		return false;
	}

	template <typename T>
	T rva2_va(LPVOID base, const DWORD rva)
	{
		return reinterpret_cast<T>(reinterpret_cast<ULONG_PTR>(base) + rva);
	}

	bool __CheckEATHooks(HMODULE hModule)
	{
		// Whitelist
		if (hModule == g_winModules->hShell32)
			return false;

		// Checks
		const auto pBaseModule = (LPBYTE)hModule;
		if (!pBaseModule)
			return false;

		const auto stModuleName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)hModule);
		if (stModuleName.empty())
			return false;

		const auto pIDH = (PIMAGE_DOS_HEADER)pBaseModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = (PIMAGE_NT_HEADERS)(pBaseModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pIDD = (PIMAGE_DATA_DIRECTORY)(&pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		if (pIDD->VirtualAddress == 0 || pIDD->Size == 0)
			return false;

		auto pIED = (PIMAGE_EXPORT_DIRECTORY)(pBaseModule + pIDD->VirtualAddress);
		if (pIED->AddressOfNameOrdinals == 0 || pIED->AddressOfNames == 0 || pIED->NumberOfFunctions == 0)
			return false;

		const auto pAddrOfNames = rva2_va<PDWORD>(pBaseModule, pIED->AddressOfNames);
		// auto pAddrOfNames = (DWORD_PTR*)(pBaseModule + pIED->AddressOfNames);
		const auto pAddrOfNameOrds = rva2_va<PWORD>(pBaseModule, pIED->AddressOfNameOrdinals);
		// auto pAddrOfNameOrds = (WORD*)(pBaseModule + pIED->AddressOfNameOrdinals);
		const auto pAddrOfFuncs = rva2_va<PDWORD>(pBaseModule, pIED->AddressOfFunctions);
		// auto pAddrOfFuncs = (DWORD_PTR*)(pBaseModule + pIED->AddressOfFunctions);

		if (!pAddrOfNames || !pAddrOfNameOrds || !pAddrOfFuncs)
			return false;

		const auto hMappedModule = (LPBYTE)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()->Find(stModuleName);
		if (!hMappedModule)
			return false;
		
		const auto pOriIDH = (PIMAGE_DOS_HEADER)hMappedModule;
		if (pOriIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pOriINH = (PIMAGE_NT_HEADERS)(hMappedModule + pOriIDH->e_lfanew);
		if (pOriINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pOriIDD = (PIMAGE_DATA_DIRECTORY)(&pOriINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		if (pOriIDD->VirtualAddress == 0 || pOriIDD->Size == 0)
			return false;

		auto pOriIED = (PIMAGE_EXPORT_DIRECTORY)(hMappedModule + pOriIDD->VirtualAddress);
		if (pOriIED->AddressOfNameOrdinals == 0 || pOriIED->AddressOfNames == 0 || pOriIED->NumberOfFunctions == 0)
			return false;
		
		const auto pOriAddrOfFuncs = rva2_va<PDWORD>(hMappedModule, pOriIED->AddressOfFunctions);
		//  auto pOriAddrOfFuncs = (DWORD_PTR*)(hMappedModule + pOriIED->AddressOfFunctions);
		if (!pOriAddrOfFuncs)
			return false;

		for (auto i = 0u; i < pIED->NumberOfNames; ++i)
		{
			if (IsGlobalVariable(pINH, pOriAddrOfFuncs[pAddrOfNameOrds[i]]))
				continue;

			const auto pApiName = rva2_va<LPSTR>(hModule, pAddrOfNames[i]);
			// const auto pApiName = reinterpret_cast<PCCH>(hModule) + static_cast<DWORD_PTR>(pAddrOfNames[i]);
			if (!stdext::is_alphanumeric(pApiName))
				continue;

			// auto pApiName = (char*)(pAddrOfNames[i] + (DWORD_PTR)pBaseModule);
			auto pApiAddress = (DWORD_PTR)rva2_va<BYTE*>(pBaseModule, pAddrOfFuncs[pAddrOfNameOrds[i]]);
			//auto pApiAddress = pAddrOfFuncs[pAddrOfNameOrds[i]] + (DWORD_PTR)pBaseModule;
			auto pOriApiAddress = pOriAddrOfFuncs[pAddrOfNameOrds[i]] + (DWORD_PTR)pBaseModule;
			auto pTem = pOriAddrOfFuncs[pAddrOfNameOrds[i]] + (DWORD_PTR)hMappedModule;

			if (pTem >= (DWORD_PTR)pOriIED && pTem < ((DWORD_PTR)pOriIED + pOriIDD->Size))
				pOriApiAddress = FileNameRedirection((char*)pTem);
			else
				ScanInlineHook(pApiName, pOriApiAddress, pApiAddress, (DWORD_PTR)pBaseModule, (DWORD_PTR)hModule);

			if (pOriAddrOfFuncs[pAddrOfNameOrds[i]] != pAddrOfFuncs[pAddrOfNameOrds[i]] && pOriApiAddress != pApiAddress)
			{
				auto disasm = std::make_unique<disassembler>(ZYDIS_MACHINE_MODE_LONG_COMPAT_32);
				auto disassembled = disasm->disassemble((void*)pApiAddress, 16);

				auto bHooked = false;
				const auto pFirstByte = *(BYTE*)pApiAddress;
				if (pFirstByte == 0xE9 || pFirstByte == 0xE8 || pFirstByte == 0xCC || *(WORD*)pApiAddress == 0x25FF)
					bHooked = true;
				
				APP_TRACE_LOG(bHooked ? LL_ERR : LL_TRACE, L"EAT API: %hs > 0x%X (h:%d)", pApiName, pFirstByte, bHooked);

				if (bHooked && !disassembled.empty())
				{
					bool whitelisted = true;
					const auto& first_inst = stdext::to_lower_ansi(disassembled.front());

					APP_TRACE_LOG(LL_SYS, L"EAT Hook: %hs ", pApiName);

					for (const auto& inst : disassembled)
					{
						APP_TRACE_LOG(LL_SYS, L"%s", inst.c_str());
					}
					// TODO: Check ptr jumped module area
					// return true;
				}
			}
		}
		
		return false;
	}

	/*
	TODO
	BOOL __forceinline Detections::DoesIATContainHooked()
{
	list<ProcessData::ImportFunction*> IATFunctions = Process::GetIATEntries();

	for (ProcessData::ImportFunction* IATEntry : IATFunctions)
	{
		DWORD moduleSize = Process::GetModuleSize(IATEntry->Module);

		if (moduleSize != 0)
		{
			//UINT64 MinAddress = (UINT64)IATEntry->Module;
			//UINT64 MaxAddress = (UINT64)IATEntry->Module + (UINT64)moduleSize;

			UINT64 MinAddress = 0x00007FF400000000; //crummy workaround for the fact that some routines point to other module functions and throw a false positive in our check (some k32 points to ntdll routines on my windows version)
			UINT64 MaxAddress = 0x00007FFFFFFFFFFF; //ideal way would be to use the commented lines above and then 'whitelist' whatever functions are known to redirect to other dlls

			if (IATEntry->AddressOfData <= MinAddress || IATEntry->AddressOfData >= MaxAddress)
			{
				Logger::logf("UltimateAnticheat.log", Info, " IAT function was hooked: %llX, %s\n", IATEntry->AddressOfData, IATEntry->AssociatedModuleName.c_str());
				return TRUE;
			}
		}
		else //error, we shouldnt get here!
		{
			Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch  module size @ Detections::DoesIATContainHooked\n");
			return FALSE;
		}
	}

	return FALSE;
}

	*/
	
	bool __CheckIATHooks(HMODULE hModule)
	{
		const auto pBaseModule = (LPBYTE)hModule;
		if (!pBaseModule)
			return false;

		const auto pIDH = (PIMAGE_DOS_HEADER)pBaseModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		const auto pINH = (PIMAGE_NT_HEADERS)(pBaseModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto pIDD = (PIMAGE_DATA_DIRECTORY)(&pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
		if (pIDD->VirtualAddress == 0 || pIDD->Size == 0)
			return false;

		auto pIDDVA = (PIMAGE_IMPORT_DESCRIPTOR)(pBaseModule + pIDD->VirtualAddress);
		if (pIDDVA == nullptr || pIDDVA->FirstThunk == 0 || pIDDVA->OriginalFirstThunk == 0)
			return false;

		while (pIDDVA->FirstThunk)
		{
			if (pIDDVA->OriginalFirstThunk)
			{
				auto DllName = (char*)(pIDDVA->Name + (DWORD_PTR)pBaseModule);
				auto OriThunk = (PIMAGE_THUNK_DATA)(pIDDVA->OriginalFirstThunk + (DWORD_PTR)pBaseModule);
				auto FirstThunk = (PIMAGE_THUNK_DATA)(pIDDVA->FirstThunk + (DWORD_PTR)pBaseModule);
				
				while (FirstThunk->u1.Function)
				{
					DWORD_PTR OriApiAddress = 0;
					std::string ApiName;
					auto ApiAddress = FirstThunk->u1.Function;
					
					auto wstDllName = stdext::to_lower_wide(DllName);
					if (OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || OriThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
					{
						auto Ordinal = OriThunk->u1.Ordinal & 0x0000FFFF;
						OriApiAddress = GetProcAddressWrapper(wstDllName, (char*)Ordinal);
						ApiName = fmt::format(xorstr_("{:#04x}"), Ordinal);
					}
					else
					{
						auto ByName = (PIMAGE_IMPORT_BY_NAME)(OriThunk->u1.AddressOfData + (DWORD_PTR)pBaseModule);
						ApiName = ByName->Name;
						OriApiAddress = GetProcAddressWrapper(wstDllName, ApiName.c_str());
					}
					
					if (OriApiAddress && ApiAddress != OriApiAddress)
					{
						auto disasm = std::make_unique<disassembler>(ZYDIS_MACHINE_MODE_LONG_COMPAT_32);
						auto disassembled = disasm->disassemble((void*)ApiAddress, 16);

						auto bHooked = false;
						const auto pFirstByte = *(BYTE*)ApiAddress;
						if (pFirstByte == 0xE9 || pFirstByte == 0xE8 || pFirstByte == 0xCC || *(WORD*)ApiAddress == 0x25FF)
							bHooked = true;

						APP_TRACE_LOG(bHooked ? LL_ERR : LL_TRACE, L"IAT API: %hs %hs > 0x%X (h:%d)", DllName, ApiName.c_str(), pFirstByte, bHooked);

						if (bHooked && !disassembled.empty())
						{
							bool whitelisted = true;
							const auto& first_inst = stdext::to_lower_ansi(disassembled.front());

							std::wstring wstDisassembled;
							for (const auto& inst : disassembled)
							{
								wstDisassembled += xorstr_(L"'") + inst + xorstr_(L"', ");
							}
							if (wstDisassembled.size() > 2)
								wstDisassembled.erase(wstDisassembled.size() - 2);
							
							APP_TRACE_LOG(LL_WARN, L"IAT Hook: %hs.%hs, Disassembled: %s", DllName, ApiName.c_str(), wstDisassembled.c_str());

							// TODO: Check ptr jumped module area
							// return true;
						}
					}

					++OriThunk;
					++FirstThunk;
				}
			}
			++pIDDVA;
		}
	
		return false;
	}

	bool __CheckInlineHooks(HMODULE hModule)
	{
#if 0 // TODO
		if (hModule)
		{
			MODULEINFO mi{};
			if (!g_winAPIs->GetModuleInformation(NtCurrentProcess(), hModule, &mi, sizeof(mi)))
			{
				APP_TRACE_LOG(LL_ERR, L"GetModuleInformation failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			std::unique_ptr <std::uint8_t> _moduleBuffer(new (std::nothrow) std::uint8_t[mi.SizeOfImage]{});
			if (!_moduleBuffer.get())
			{
				APP_TRACE_LOG(LL_ERR, L"_moduleBuffer allocation failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			std::size_t _lastSize = 0;
			MEMORY_BASIC_INFORMATION mbi{};
			while (g_winAPIs->VirtualQueryEx(NtCurrentProcess(), (LPCVOID)((DWORD_PTR)mi.lpBaseOfDll + _lastSize), &mbi, sizeof mbi))
			{
				SIZE_T _readSize = 0;
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
					NtCurrentProcess(), mbi.BaseAddress, &_moduleBuffer.get()[_lastSize], mbi.RegionSize, &_readSize
				);

				_lastSize += mbi.RegionSize;

				if (_lastSize >= mi.SizeOfImage)
					break;
			}

			auto pe_mem = Pe::Pe32::fromModule(_moduleBuffer.get());
			if (!pe_mem.valid())
				return;

			if (pe_mem.exports().valid())
			{
				const auto wstFile = std::wstring(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length);
				APP_TRACE_LOG(LL_SYS, L"Found export table in module: %s (%p)", wstFile.c_str(), mi.lpBaseOfDll);

				std::vector <uint8_t> vFileBuffer;
				if (!_readbinary_file(wstFile, vFileBuffer))
					return;

				const auto pe_file = Pe::Pe32::fromFile(vFileBuffer.data());
				if (!pe_file.valid())
					return;

				int _numEntries = 0;

				for (const auto& exp : pe_mem.exports())
				{
						std::uint32_t _fileOffset = (uint32_t)pe_file.byRva<std::uint32_t>((uint32_t)exp.address());
						std::uint32_t _mappedOffset = (uint32_t)exp.address();
						//pepp::mem::ByteVector _origBytes, _patchBytes;

						for (const auto& sec : pe_mem.sections())
						{
							if (sec.VirtualAddress == _mappedOffset)
							{
								if (!(sec.Characteristics & SCN_MEM_EXECUTE))
									return;
							}
						}

						ZydisDecodedInstruction _fInsn{};
						ZydisDecodedOperand _foperands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

						ZydisDecodedInstruction _mInsn{};
						ZydisDecodedOperand _moperands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

						int						_curFileOffset{},
							_curMemOffset{};
						std::vector<JmpInfo_t>	jmp{};
						JmpInfo_t				_jmpInfo{};
						std::unordered_map<int, std::uintptr_t> _regSet;

						
						while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder, (void*)(vFileBuffer.data()[_fileOffset + _curFileOffset]), 0x40, &_fInsn, _foperands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)) &&
							ZYAN_SUCCESS(ZydisDecoderDecodeFull(&m_decoder, (void*)(_moduleBuffer.get()[_mappedOffset + _curMemOffset]), 0x40, &_mInsn, _moperands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
						{
							//
							// Instruction by instruction, compare if they're the same.
							if (memcmp(&vFileBuffer.data()[_fileOffset + _curMemOffset],
								&_moduleBuffer.get()[_mappedOffset + _curMemOffset],
								_fInsn.length) == 0)
							{
								//
								// Equal instructions, jump out.
								break;
							}

#ifndef _WIN64
							if (_fInsn.opcode == _mInsn.opcode && _mInsn.mnemonic != ZYDIS_MNEMONIC_JMP)
								break;
#endif
							//
							// Trace registers used for JMPs
							// e.g mov r10, #address; jmp r10
							if (_mInsn.mnemonic == ZYDIS_MNEMONIC_MOV)
							{
								if (_mInsn.operand_count == 2)
								{
									if (_moperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
										_moperands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
									{
										_regSet[_moperands[0].reg.value] = _moperands[1].imm.value.u;
									}
								}
							}

							//
							// Chain JMPs
							else if (_mInsn.mnemonic == ZYDIS_MNEMONIC_JMP)
							{
								ZydisDecodedInstruction tmp_instr{};
								ZyanU64 ptr = ((LPBYTE)mi.lpBaseOfDll + _mappedOffset + _curMemOffset);

								//
								// Follow.
								if (_moperands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
								{
									if (_moperands[0].imm.is_relative)
										ZydisCalcAbsoluteAddress(&_mInsn, &_moperands[0], (mod.base_address + _mappedOffset + _curMemOffset), &ptr);
									else
										ptr = _moperands[0].imm.value.u;
								}
								else if (_moperands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
								{
									if (_moperands[0].mem.disp.has_displacement)
										ptr = _moperands[0].mem.disp.value;
								}
								else if (_moperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
								{
									std::uintptr_t imm = _regSet[_moperands[0].reg.value];
									if (imm > 0)
										ptr = imm;
								}

								//
								// Possible that a hook won't lead to a legitimate module, and maybe just some allocated executable
								// memory.
								ModuleInformation_t _tmp{};
								if (GetModuleFromAddress(ptr, &_tmp))
								{
									_jmpInfo.dst_ptr = ptr;
									_jmpInfo.dst_rva = (ptr - _tmp.base_address);
									_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
								}
								else
								{
									MEMORY_BASIC_INFORMATION _tmpMbi{};
									if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
									{
										_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
										_jmpInfo.dst_module = fmt::format("memory@{:X}",
											(std::uintptr_t)_tmpMbi.AllocationBase);
										_jmpInfo.dst_ptr = ptr;
									}
								}


#ifndef _WIN64
								//
								// On X86, we'll need to ignore JMPs that had relocations processed on them.
								// This check isn't exactly the best way but it is convenient and good enough for this purpose.
								if (_fInsn.opcode == 0xff && ptr > 0)
								{
									ZyanU64 _fptr = vFileBuffer.data().deref<uint32_t>(_fileOffset + _curFileOffset + 2);

									//
									// Translate to an RVA
									_fptr -= vFileBuffer.GetPEHeader().GetOptionalHeader().GetImageBase();

									//
									// Leads to the same place, false positive!
									if (_fptr == _jmpInfo.dst_rva)
									{
										break;
									}
								}
#endif


								//
								// Append a JMP
								jmp.emplace_back(std::move(_jmpInfo));

								//
								// This is really ugly and bad, but it was added last minute as a method to follow JMPs
								// I will come back and fix it when I have time.
								bool tmp_val = true;
								uint8_t tmp_buf[0x20];

								while (tmp_val)
								{
									if (m_process.ReadMemory(ptr, tmp_buf, sizeof tmp_buf))
									{
										while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, tmp_buf, 0x20, &tmp_instr)))
										{
											if (tmp_instr.mnemonic == ZYDIS_MNEMONIC_JMP)
											{
												switch (tmp_instr.operands[0].type)
												{
												case ZYDIS_OPERAND_TYPE_IMMEDIATE:
												{
													if (tmp_instr.operands[0].imm.is_relative)
														ZydisCalcAbsoluteAddress(&tmp_instr,
															&tmp_instr.operands[0], ptr, &ptr);
													else
														ptr = tmp_instr.operands[0].imm.value.u;

													if (GetModuleFromAddress(ptr, &_tmp))
													{
														_jmpInfo.dst_ptr = ptr;
														_jmpInfo.dst_rva = (ptr - _tmp.base_address);
														_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
													}
													else
													{
														MEMORY_BASIC_INFORMATION _tmpMbi{};
														if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
														{
															_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
															_jmpInfo.dst_module = fmt::format("memory@{:X}",
																(std::uintptr_t)_tmpMbi.AllocationBase);
															_jmpInfo.dst_ptr = ptr;
														}
													}

													jmp.emplace_back(std::move(_jmpInfo));
													_patchBytes.push_raw(tmp_buf, tmp_instr.length);
													break;
												}
												case ZYDIS_OPERAND_TYPE_MEMORY:
												{
													//
													// This will only be used on X64 usually.
													if (tmp_instr.operands[0].mem.base == REGISTER_IP)
													{
														ptr += tmp_instr.length;

														//
														// Read the JMP destination.
														m_process.ReadMemory(ptr, &ptr, sizeof(ptr));

														if (GetModuleFromAddress(ptr, &_tmp))
														{
															_jmpInfo.dst_ptr = ptr;
															_jmpInfo.dst_rva = (ptr - _tmp.base_address);
															_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
														}
														else
														{
															MEMORY_BASIC_INFORMATION _tmpMbi{};
															if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
															{
																_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
																_jmpInfo.dst_module = fmt::format("memory@{:X}",
																	(std::uintptr_t)_tmpMbi.AllocationBase);
																_jmpInfo.dst_ptr = ptr;
															}
														}

														jmp.emplace_back(std::move(_jmpInfo));
														_patchBytes.push_raw(tmp_buf, tmp_instr.length);
													}
													break;
												}
												case ZYDIS_OPERAND_TYPE_REGISTER:
												{
													ptr = _regSet[_moperands[0].reg.value];
													if (ptr > 0)
													{
														if (GetModuleFromAddress(ptr, &_tmp))
														{
															_jmpInfo.dst_ptr = ptr;
															_jmpInfo.dst_rva = (ptr - _tmp.base_address);
															_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
														}
														else
														{
															MEMORY_BASIC_INFORMATION _tmpMbi{};
															if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
															{
																_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
																_jmpInfo.dst_module = fmt::format("memory@{:X}",
																	(std::uintptr_t)_tmpMbi.AllocationBase);
																_jmpInfo.dst_ptr = ptr;
															}
														}

														jmp.emplace_back(std::move(_jmpInfo));
														_patchBytes.push_raw(tmp_buf, tmp_instr.length);
													}
													else
													{
														tmp_val = false;
													}

													break;
												}
												default:
													tmp_val = false;
													break;
												}
											}
											else if (tmp_instr.mnemonic == ZYDIS_MNEMONIC_MOV)
											{
												if (tmp_instr.operand_count == 2)
												{
													if (tmp_instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
														tmp_instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
													{
														_regSet[tmp_instr.operands[0].reg.value] = tmp_instr.operands[1].imm.value.u;
														break;
													}
												}

												tmp_val = false;
											}
											else
											{
												tmp_val = false;
											}

											break;
										}
									}
									else
									{
										tmp_val = false;
									}
								}
							}


							//
							// Mismatch, add them into the stream.
							_origBytes.push_raw(&vFileBuffer.buffer()[_fileOffset + _curFileOffset], _fInsn.length);
							_patchBytes.push_raw(&_moduleBuffer.buffer()[_mappedOffset + _curMemOffset], _mInsn.length);

							//
							// See notes regarding "Heal" @ Main.cpp
	//#ifdef _WIN64
							if (cfg.Heal)
							{
								//
								// Write back the file's bytes into the process (this currently won't take into account many things, so this option
								// should be used with care.
								m_process.WriteMemory(mod.base_address + _mappedOffset + _curMemOffset, &vFileBuffer.buffer()[_fileOffset + _curFileOffset], _fInsn.length);

								if (cfg.Verbose)
								{
									g_log->debug("* Healing memory @ <{}+0x{:X}> (0x{:X})", _moduleName, _mappedOffset + _curMemOffset, mod.base_address + _mappedOffset + _curMemOffset);
								}
							}
							//#endif

							_curFileOffset += _fInsn.length;
							_curMemOffset += _mInsn.length;
						}

						//while (mappedImg.buffer()[mapped_offset] != fileImg.buffer()[file_offset])
						//{
						//	origBytes.push_back(fileImg.buffer()[file_offset++]);
						//	patchBytes.push_back(mappedImg.buffer()[mapped_offset++]);
						//}

						if (!_origBytes.empty())
						{
							m_mismatches[_moduleName].emplace_back(
								mod.base_address + exp->rva,
								vFileBuffer.GetPEHeader().GetOptionalHeader().GetImageBase() + exp->rva,
								std::move(exp->name),
								std::move(_origBytes),
								std::move(_patchBytes),
								std::move(jmp));
							++_numMismatches;

							if (cfg.DumpModules)
							{
								g_log->debug("Dumping entry {}", _moduleName);

								vFileBuffer.WriteToFile(fmt::format("{}-unpatched.bin", _moduleName));
								_moduleBuffer.WriteToFile(fmt::format("{}-patched.bin", _moduleName));
							}
						}

						++_numEntries;
					}
				);

				if (cfg.Verbose)
					g_log->info("Finished scan of module {}, found {} mismatches from {} entries.", _moduleName, _numMismatches, _numEntries);
			}

			});
#endif

			return true;
	}
};
