#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"
#include <Zydis/Zydis.h>

namespace NoMercy
{
	bool CheckModule(const std::wstring& name, LPVOID base, size_t size)
	{
		auto bRet = false;
		LPVOID lpModuleHeaderBuffer = nullptr;
		LPBYTE lpModuleBuffer = nullptr;
		HANDLE hFile = nullptr;
		HANDLE hMappedFile = nullptr;
		ZyanU8* lpMapView = nullptr;
		IMAGE_EXPORT_DIRECTORY* pIED = nullptr;

		do
		{
			lpModuleHeaderBuffer = g_winAPIs->VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!lpModuleHeaderBuffer)
			{
				APP_TRACE_LOG(LL_ERR, L"VirtualAlloc(header) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			auto bReadRet = g_winAPIs->ReadProcessMemory(NtCurrentProcess(), (LPCVOID)base, lpModuleHeaderBuffer, 0x1000, NULL);
			if (!bReadRet || !lpModuleHeaderBuffer)
			{
				APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(header) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			const auto pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(lpModuleHeaderBuffer);
			if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s DOS header magic verify failed!", name.c_str());
				break;
			}

			const auto pINH = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONG_PTR>(lpModuleHeaderBuffer) + pIDH->e_lfanew);
			if (pINH->Signature != IMAGE_NT_SIGNATURE)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s NT header signature verify failed!", name.c_str());
				break;
			}

			const auto pIDE = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!pIDE)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s export table is zero!", name.c_str());
				break;
			}

			const auto pExportTableBase = pIDE->VirtualAddress;
			const auto pExportTableSize = pIDE->Size;

			if (!pExportTableBase || !pExportTableSize)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s export table address or size is zero!", name.c_str());
				break;
			}

			DWORD dwSectionBase = 0;
			DWORD dwSectionSize = 0;

			auto pISH = IMAGE_FIRST_SECTION(pINH);
			for (std::size_t i = 0; i != pINH->FileHeader.NumberOfSections; ++i, ++pISH)
			{
				if (strstr((char*)pISH->Name, xorstr_(".text")))
				{
					dwSectionBase = pISH->VirtualAddress;
					dwSectionSize = pISH->Misc.VirtualSize;
				}
			}

			if (!dwSectionBase || !dwSectionSize)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s section base or size is zero!", name.c_str());
				break;
			}

			pIED = (IMAGE_EXPORT_DIRECTORY*)g_winAPIs->VirtualAlloc(nullptr, pExportTableSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!pIED)
			{
				APP_TRACE_LOG(LL_ERR, L"VirtualAlloc(export table) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			bReadRet = g_winAPIs->ReadProcessMemory(
				NtCurrentProcess(),
				reinterpret_cast<LPCVOID>((LPBYTE)base + pExportTableBase),
				pIED,
				pExportTableSize,
				NULL
			);
			if (!bReadRet)
			{
				APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(export table) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			lpModuleBuffer = (LPBYTE)g_winAPIs->VirtualAlloc(nullptr, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!lpModuleBuffer)
			{
				APP_TRACE_LOG(LL_ERR, L"VirtualAlloc(module) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			bReadRet = g_winAPIs->ReadProcessMemory(
				NtCurrentProcess(),
				(LPCVOID)base,
				lpModuleBuffer,
				pINH->OptionalHeader.SizeOfImage,
				NULL
			);
			if (!bReadRet)
			{
				APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(module) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			hFile = g_winAPIs->CreateFileW(name.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
			if (!IS_VALID_HANDLE(hFile))
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s open file failed with error: %u", name.c_str(), g_winAPIs->GetLastError());
				break;
			}

			hMappedFile = g_winAPIs->CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
			if (!IS_VALID_HANDLE(hMappedFile))
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s create file mapping failed with error: %u", name.c_str(), g_winAPIs->GetLastError());
				break;
			}

			lpMapView = reinterpret_cast<ZyanU8*>(g_winAPIs->MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0));
			if (!lpMapView)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s map view of file failed with error: %u", name.c_str(), g_winAPIs->GetLastError());
				break;
			}

			auto pOrdinalAddress = reinterpret_cast<WORD*>(pIED->AddressOfNameOrdinals + reinterpret_cast<uintptr_t>(pIED) - pExportTableBase);
			auto pNamesAddress = reinterpret_cast<DWORD*>(pIED->AddressOfNames + reinterpret_cast<uintptr_t>(pIED) - pExportTableBase);
			auto pFunctionAddress = reinterpret_cast<DWORD*>(pIED->AddressOfFunctions + reinterpret_cast<uintptr_t>(pIED) - pExportTableBase);

			for (std::size_t i = 0; i < pIED->NumberOfNames; ++i)
			{
				const auto wOrdinal = pOrdinalAddress[i];
				if (wOrdinal < 0 || wOrdinal >  pIED->NumberOfNames)
					continue;

				const auto dwFuncAddr = pFunctionAddress[wOrdinal];
				if (dwFuncAddr >= size)
					continue;

				if (dwFuncAddr < dwSectionBase || dwFuncAddr > dwSectionBase + dwSectionSize)
					continue;

				auto bIsDifferent = false;
				for (int x = 0; x < 15 && !bIsDifferent; ++x)
					bIsDifferent = lpMapView[dwFuncAddr + x] != lpModuleBuffer[dwFuncAddr + x];

				if (bIsDifferent)
				{
					auto szExportName = reinterpret_cast<char*>(pNamesAddress[i] + reinterpret_cast<uintptr_t>(pIED) - pExportTableBase);
					if (!szExportName || !*szExportName || stdext::has_special_char(szExportName))
						continue;		
					auto stExportName = std::string(szExportName);

					APP_TRACE_LOG(LL_WARN, L"Found difference at %s!%s addr:0x%X", name.c_str(), stExportName.c_str(), dwFuncAddr);

					const auto wstOrigMemCopy = stdext::dump_hex(lpMapView + dwFuncAddr, 15);
					APP_TRACE_LOG(LL_SYS, L"Original Buffer: %s", wstOrigMemCopy.c_str());

					const auto wstNewMemCopy = stdext::dump_hex(lpModuleBuffer + dwFuncAddr, 15);
					APP_TRACE_LOG(LL_SYS, L"Modified Buffer: %s", wstNewMemCopy.c_str());

					// Initialize decoder context
					ZydisDecoder decoder;
#if defined (_WIN64)
					ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZydisStackWidth::ZYDIS_STACK_WIDTH_64);
#else
					ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZydisStackWidth::ZYDIS_STACK_WIDTH_32);
#endif

					ZydisFormatter formatter;
					ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

					ZyanU64 runtime_address = dwFuncAddr;
					ZyanUSize offset = 0;
					const ZyanUSize length = 15;
					ZydisDecodedInstruction instruction;
					ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
					while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, lpModuleBuffer + dwFuncAddr + offset, length - offset, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
					{
						// Print current instruction pointer.
						APP_TRACE_LOG(LL_SYS, L"IP: %llu", runtime_address);

						char buffer[256]{ '\0' };
						ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);

						APP_TRACE_LOG(LL_SYS, L"%s", buffer);

						offset += instruction.length;
						runtime_address += instruction.length;
					}

					APP_TRACE_LOG(LL_CRI, L"Found difference at %s!%s addr:0x%X Copy: %s/%s",
						name.c_str(), stExportName.c_str(), dwFuncAddr, wstOrigMemCopy.c_str(), wstNewMemCopy.c_str()
					);
				}
			}

			bRet = true;
		} while (false);

		APP_TRACE_LOG(LL_SYS, L"Module: %s finished! Success: %d", name.c_str(), bRet);

		if (lpModuleBuffer)
		{
			g_winAPIs->VirtualFree(lpModuleBuffer, 0, MEM_RELEASE);
			lpModuleBuffer = nullptr;
		}
		if (lpModuleHeaderBuffer)
		{
			g_winAPIs->VirtualFree(lpModuleHeaderBuffer, 0, MEM_RELEASE);
			lpModuleHeaderBuffer = nullptr;
		}
		if (lpMapView)
		{
			g_winAPIs->UnmapViewOfFile(lpMapView);
			lpMapView = nullptr;
		}
		if (pIED)
		{
			g_winAPIs->VirtualFree(pIED, 0, MEM_RELEASE);
			pIED = nullptr;
		}
		if (hMappedFile)
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hMappedFile);
			hMappedFile = nullptr;
		}
		if (hFile)
		{
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hFile);
			hFile = nullptr;
		}

		return bRet;
	}

	template <typename type>
	std::tuple <type, bool> read_remote_memory(HANDLE process_handle, std::uintptr_t address)
	{
		type buffer{};

		if (g_winAPIs->ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(type), 0))
			return { buffer, true };

		return { {}, false };
	}

	std::vector <std::tuple <std::uintptr_t, std::uint32_t, std::wstring, std::wstring>> get_process_modules(HANDLE process_handle, std::uint32_t process_id)
	{
		std::vector <std::tuple <std::uintptr_t, std::uint32_t, std::wstring, std::wstring>> process_modules{};

		auto snapshot = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
		if (!IS_VALID_HANDLE(snapshot))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot failed with error: %u", g_winAPIs->GetLastError());
			return process_modules;
		}

		MODULEENTRY32W module_info;
		module_info.dwSize = sizeof(module_info);
		if (g_winAPIs->Module32FirstW(snapshot, &module_info))
		{
			auto [dos, success_dos] = read_remote_memory<IMAGE_DOS_HEADER>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr));
			auto [nt, success_nt] = read_remote_memory<IMAGE_NT_HEADERS>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr) + dos.e_lfanew);

			process_modules.push_back(std::tuple<std::uintptr_t, std::uint32_t, std::wstring, std::wstring>(reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr), nt.OptionalHeader.SizeOfImage, module_info.szExePath, module_info.szModule));
		}

		while (g_winAPIs->Module32NextW(snapshot, &module_info))
		{
			auto [dos, success_dos] = read_remote_memory<IMAGE_DOS_HEADER>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr));
			auto [nt, success_nt] = read_remote_memory<IMAGE_NT_HEADERS>(process_handle, reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr) + dos.e_lfanew);

			process_modules.push_back(std::tuple<std::uintptr_t, std::uint32_t, std::wstring, std::wstring>(reinterpret_cast<std::uintptr_t>(module_info.modBaseAddr), nt.OptionalHeader.SizeOfImage, module_info.szExePath, module_info.szModule));
		}

		g_winAPIs->CloseHandle(snapshot);
		return process_modules;
	}
	
	bool CSelfProtection::CheckSelfPatchs()
	{
		auto module_array = get_process_modules(NtCurrentProcess(), HandleToULong(NtCurrentProcessId()));
		for (const auto& [base, size, full_name, file_naem] : module_array)
		{
			if (!base || !size)
				continue;
			
			if (full_name.empty() || !std::filesystem::exists(full_name))
				continue;

			APP_TRACE_LOG(LL_SYS, L"Module: %s checking...", full_name.c_str());

			CheckModule(full_name, (LPVOID)base, size);
		};

		return true;
	}
};
