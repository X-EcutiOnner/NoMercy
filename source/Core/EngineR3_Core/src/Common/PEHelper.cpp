#include "../../include/PCH.hpp"
#include "../../include/Defines.hpp"
#include "../../include/PEHelper.hpp"
#include "../../include/Application.hpp"
#include "../../include/LDasm.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/ProcessFunctions.hpp"

#define SECTOR_SIZE 0x200
#define PAGE_SIZE 0x1000
#define PADDING(p, size) p / size * size + (p % size ? size : 0)
#define RVA2VA(type, base, rva) (type)((ULONG_PTR)base + rva)
#define VA2RVA(type, base, va) (type)((ULONG_PTR)va - (ULONG_PTR)base)
#define RVA_TO_VA(B,O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))
#define MAKE_PTR(B,O,T) (T)(RVA_TO_VA(B,O))

namespace NoMercyCore
{
	bool CPEFunctions::IsValidPEHeader(LPVOID pvBaseAddress)
	{
		if (!pvBaseAddress)
			return false;

		auto pIDH = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto pIOH = (PIMAGE_OPTIONAL_HEADER)&pINH->OptionalHeader;
		if (pIOH->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return false;

		return true;
	}

	PVOID CPEFunctions::GetEntryPoint(HMODULE hModule)
	{
		if (!hModule)
			return nullptr;

		auto pIDH = (PIMAGE_DOS_HEADER)hModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		auto pIOH = (PIMAGE_OPTIONAL_HEADER)&pINH->OptionalHeader;
		return (PBYTE)hModule + pIOH->AddressOfEntryPoint;
	}

	bool CPEFunctions::GetSectionInformation(const std::string& szSectionName, LPVOID pvBaseAddress, LPVOID* ppvOffset, PSIZE_T pcbLength)
	{
		auto pImageDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pImageDosHeader || pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pvBaseAddress + pImageDosHeader->e_lfanew);
		if (!pImageNtHeaders || pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
		if (!pImageSectionHeader)
			return false;

		for (std::size_t i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			if (!strcmp(szSectionName.c_str(), (char*)pImageSectionHeader[i].Name))
			{
				*ppvOffset = (LPVOID)((UINT_PTR)pvBaseAddress + pImageSectionHeader[i].VirtualAddress);
				*pcbLength = pImageSectionHeader[i].Misc.VirtualSize;
				return true;
			}
		}
		return false;
	}

	PIMAGE_SECTION_HEADER CPEFunctions::GetSectionInformation(const std::string& szSectionName, LPVOID pvBaseAddress)
	{
		auto pImageDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pImageDosHeader || pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		auto pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pvBaseAddress + pImageDosHeader->e_lfanew);
		if (!pImageNtHeaders || pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		auto pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
		if (!pImageSectionHeader)
			return nullptr;

		for (std::size_t i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			if (!strcmp(szSectionName.c_str(), (char*)pImageSectionHeader[i].Name))
			{
				return &pImageSectionHeader[i];
			}
		}
		return nullptr;
	}

	bool CPEFunctions::GetTextSectionInformation(LPVOID pvBaseAddress, LPVOID* ppvOffset, PSIZE_T pcbLength)
	{
		return GetSectionInformation(xorstr_(".text"), pvBaseAddress, ppvOffset, pcbLength);
	}

	LPVOID CPEFunctions::GetSectionPtr(PSTR name, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase)
	{
		auto section = IMAGE_FIRST_SECTION(pNTHeader);
		
		for (std::size_t i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
		{
			if (strncmp((char*)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return (LPVOID)(section->PointerToRawData + imageBase);
		}		
		
		return 0;
	}
	PIMAGE_SECTION_HEADER CPEFunctions::GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
	{
		auto section = IMAGE_FIRST_SECTION(pNTHeader);
		
		for (std::size_t i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
		{
			auto size = section->Misc.VirtualSize;
			if (0 == size)
				size = section->SizeOfRawData;
			
			if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
				return section;
		}

		return 0;
	}
	template <class T>
	LPVOID CPEFunctions::GetPtrFromRVA(DWORD rva, T* pNTHeader, PBYTE imageBase)
	{
		const auto pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
		if (!pSectionHdr)
			return nullptr;
		
		const auto delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
		return (PVOID)(imageBase + rva - delta);
	}
	template <class T>
	LPVOID CPEFunctions::GetPtrFromVA(PVOID ptr, T* pNTHeader, PBYTE pImageBase)
	{
		DWORD rva = PtrToLong((PBYTE)ptr - pNTHeader->OptionalHeader.ImageBase);
		return GetPtrFromRVA(rva, pNTHeader, pImageBase);
	}
	
	bool CPEFunctions::DumpExportsSection(const std::wstring& c_wstModuleName, std::multimap <PVOID, std::string>& ExportsList)
	{
		if (c_wstModuleName.size() < 3)
			return false;

//		const auto c_wstModuleName = stdext::to_wide(c_stModuleName);
		if (!g_winAPIs->GetModuleHandleW_o(c_wstModuleName.c_str()))
			return false;
		
		std::wstring wstSystemPath;
		if (stdext::is_wow64())
			wstSystemPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->SystemPath2();
		else
			wstSystemPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->SystemPath();

		if (wstSystemPath.empty() || !std::filesystem::exists(wstSystemPath))
			return false;

		const auto c_stModulePath = wstSystemPath + xorstr_(L"\\") + c_wstModuleName;
		if (!std::filesystem::exists(c_stModulePath))
			return false;

		auto fp = msl::file_ptr(c_stModulePath, xorstr_(L"rb"));
		if (!fp)
			return false;

		const auto c_stBuffer = fp.string_read();
		if (c_stBuffer.empty())
			return false;

		const auto pImageBase = (PBYTE)c_stBuffer.data();
		const auto pIDH = (IMAGE_DOS_HEADER*)pImageBase;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		
		const auto pINH = MakePtr(PIMAGE_NT_HEADERS, pIDH, pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		const auto exportsStartRVA = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportsStartRVA)
			return false;
		
		const auto exportsEndRVA = exportsStartRVA + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		if (!exportsEndRVA)
			return false;

		const auto header = GetEnclosingSectionHeader(exportsStartRVA, pINH);
		if (!header)
			return false;
		
		auto pExportDir = (PIMAGE_EXPORT_DIRECTORY)GetPtrFromRVA(exportsStartRVA, pINH, pImageBase);
		auto pszFilename = (PSTR)GetPtrFromRVA(pExportDir->Name, pINH, pImageBase);
		auto pdwFunctions = (PDWORD_PTR)GetPtrFromRVA(pExportDir->AddressOfFunctions, pINH, pImageBase);
		auto pwOrdinals = (PWORD)GetPtrFromRVA(pExportDir->AddressOfNameOrdinals, pINH, pImageBase);
		auto pszFuncNames = (DWORD_PTR*)GetPtrFromRVA(pExportDir->AddressOfNames, pINH, pImageBase);

		if (!pExportDir || !pszFilename || !pdwFunctions || !pwOrdinals || !pszFuncNames)
			return false;

		for (std::size_t i = 0; i < pExportDir->NumberOfFunctions; i++, pdwFunctions++)
		{
			auto entryPointRVA = *pdwFunctions;
			if (entryPointRVA == 0)
				continue;
			
			for (unsigned j = 0; j < pExportDir->NumberOfNames; j++)
			{
				if (pwOrdinals[j] == i)
				{
					std::string fname = (char*)GetPtrFromRVA(pszFuncNames[j], pINH, pImageBase);
					
					const auto funcAddr = (PVOID)((DWORD_PTR)g_winAPIs->GetModuleHandleW_o(c_wstModuleName.c_str()) + entryPointRVA);
					ExportsList.insert(ExportsList.begin(), std::pair <PVOID, std::string>(funcAddr, fname));
				}
			}
		}
		return true;
	}

	bool CPEFunctions::DumpImportsSection(const std::wstring& c_wstModuleName, std::multimap <PVOID, std::tuple <std::string, std::string>>& ImportsList)
	{
//		const auto c_wstModuleName = stdext::to_wide(c_stModuleName);

		auto hModule = c_wstModuleName.empty() ? g_winModules->hBaseModule : g_winAPIs->GetModuleHandleW_o(c_wstModuleName.c_str());
		if (!hModule)
			return false;

		auto pIDH = (IMAGE_DOS_HEADER*)hModule;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pINH = (PIMAGE_NT_HEADERS)((BYTE*)pIDH + pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;
		
		auto pIID = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pIDH + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (!pIID)
			return false;

		for (; pIID->Name != 0; pIID++)
		{
			for (int func_idx = 0; *(func_idx + (void**)(pIID->FirstThunk + (size_t)hModule)) != nullptr; func_idx++)
			{
				char* mod_func_name = (char*)(*(func_idx + (size_t*)(pIID->OriginalFirstThunk + (size_t)hModule)) + (size_t)hModule + 2);
				const intptr_t nmod_func_name = (intptr_t)mod_func_name;
				
				if (nmod_func_name >= 0)
				{
					std::string DllName = (char*)(pIID->Name + (size_t)hModule);
					
					for (DWORD x = 0; x < DllName.size(); x++)
						DllName[x] = tolower(DllName[x]);
					
					ImportsList.insert(ImportsList.begin(),
						std::pair<PVOID, std::tuple<std::string, std::string>>(*(func_idx + (void**)(pIID->FirstThunk + (size_t)hModule)),
							std::make_tuple(mod_func_name, DllName)));
				}
			}
		}
		return true;
	}

	uintptr_t FindRawAddress(PIMAGE_NT_HEADERS ntHeader, uintptr_t va)
	{
		// Since sections contains both a raw address and virtual address field,
		// we can use it to get the raw address from a virtual address.
		auto section = IMAGE_FIRST_SECTION(ntHeader);

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
		{
			if (va >= section->VirtualAddress &&
				va <= (section->VirtualAddress + section->Misc.VirtualSize))
			{

				uintptr_t offset = va - section->VirtualAddress;
				uintptr_t rawAddress = section->PointerToRawData + offset;

				return rawAddress;
			}
			section++;
		}

		return 0;
	}

	template <class T>
	T FindRawPointer(PIMAGE_NT_HEADERS headers, HMODULE hMod, uintptr_t va)
	{
		return (T)((uintptr_t)hMod + FindRawAddress(headers, va));
	}

	FARPROC CPEFunctions::GetProcAddressDisk(HMODULE hMod, const std::string& szAPIName)
	{
		const auto ntHeader = RVA2VA(PIMAGE_NT_HEADERS, hMod, ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
		if (!ntHeader)
			return nullptr;

		const auto dataDirectory = ntHeader->OptionalHeader.DataDirectory;
		if (!dataDirectory)
			return nullptr;

		const auto exportsVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportsVA)
			return nullptr;

		const auto pExports = FindRawPointer<PIMAGE_EXPORT_DIRECTORY>(ntHeader, hMod, exportsVA);
		if (!pExports)
			return nullptr;
		
		uint16_t* nameOrdinals = FindRawPointer<uint16_t*>(ntHeader, hMod, pExports->AddressOfNameOrdinals);
		uint32_t* functions = FindRawPointer<uint32_t*>(ntHeader, hMod, pExports->AddressOfFunctions);
		uint32_t* names = FindRawPointer<uint32_t*>(ntHeader, hMod, pExports->AddressOfNames);

		if (nameOrdinals && functions && names)
		{
			for (uint32_t i = 0; i < pExports->NumberOfFunctions; i++)
			{
				const char* exportName = FindRawPointer<const char*>(ntHeader, hMod, names[i]);
				if (exportName && !strcmp(exportName, szAPIName.c_str()))
				{
					uint32_t offset = functions[nameOrdinals[i]];
					if (offset)
						return FindRawPointer<FARPROC>(ntHeader, hMod, offset);
				}
			}
		}

		return nullptr;
	}

	PVOID CPEFunctions::GetExportEntry(HMODULE hModule, const std::string& stAPIName, DWORD dwOrdinal)
	{
		if (!hModule || (stAPIName.empty() && dwOrdinal == -1))
			return nullptr;

		const auto pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
		if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pImageDosHeader->e_lfanew);
		if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		const auto pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
		if (!pImageSectionHeader)
			return nullptr;

		DWORD dwExportSize = 0;
		const auto pImageExport = (PIMAGE_EXPORT_DIRECTORY)g_winAPIs->RtlImageDirectoryEntryToData((LPVOID)hModule, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &dwExportSize);
		if (!pImageExport || !dwExportSize)
			return nullptr;

		const auto AddressOfNames = (PULONG)((ULONG_PTR)hModule + pImageExport->AddressOfNames);
		const auto AddressOfFunctions = (PULONG)((ULONG_PTR)hModule + pImageExport->AddressOfFunctions);
		const auto AddressOfOrdinals = (PSHORT)((ULONG_PTR)hModule + pImageExport->AddressOfNameOrdinals);

		if (!AddressOfNames || !AddressOfFunctions || !AddressOfOrdinals)
			return nullptr;

		const auto max_name = pImageExport->NumberOfNames;
		const auto max_func = pImageExport->NumberOfFunctions;

		if (!max_name || !max_func)
			return nullptr;

		for (ULONG i = 0; i < pImageExport->NumberOfNames; ++i)
		{
			if (!AddressOfNames[i] || !AddressOfFunctions[i])
				continue;

			const auto ord = (DWORD)AddressOfOrdinals[i];
			if (ord >= max_func)
				return nullptr;

			if (dwOrdinal != -1)
			{
				if (ord != dwOrdinal)
					continue;

				const auto func =
					AddressOfFunctions[dwOrdinal - pImageExport->Base] != 0 ?
					(DWORD_PTR)hModule + AddressOfFunctions[dwOrdinal - pImageExport->Base] :
					0;
				return (PVOID)func;
			}
			else
			{
				const auto name = (PCHAR)((ULONG_PTR)hModule + AddressOfNames[i]);
				if (strcmp(name, stAPIName.c_str()))
					continue;

				const auto func = (PVOID)((ULONG_PTR)hModule + AddressOfFunctions[ord]);
				return func;
			}
		}

		return nullptr;
	}

	DWORD CPEFunctions::GetPeChecksum(PVOID pvImageBase, SIZE_T cbSize)
	{
		auto CalculateCheckSum = [](UINT CheckSum, PVOID FileBase, INT Length)
		{
			INT* Data;
			INT sum;

			if (Length && FileBase != NULL)
			{
				Data = (INT*)FileBase;
				do
				{
					sum = *(WORD*)Data + CheckSum;
					Data = (INT*)((CHAR*)Data + 2);
					CheckSum = (WORD)sum + (sum >> 16);
				} while (--Length);
			}

			return CheckSum + (CheckSum >> 16);
		};

		auto dwCheckSum = 0UL;

		auto pDosHeader = (PIMAGE_DOS_HEADER)pvImageBase;
		if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"Not valid dos signature");
			return dwCheckSum;
		}

		auto pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pvImageBase + pDosHeader->e_lfanew);
		if (!pNtHeader || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"Not valid nt signature");
			return dwCheckSum;
		}

		auto PeHeaderSize = (DWORD_PTR)pNtHeader - (DWORD_PTR)pvImageBase + ((DWORD_PTR)&pNtHeader->OptionalHeader.CheckSum - (DWORD_PTR)pNtHeader);
		auto RemainDataSize = (INT)((cbSize - PeHeaderSize - 4) >> 1);
		auto RemainData = &pNtHeader->OptionalHeader.Subsystem;
		auto PeHeaderCheckSum = CalculateCheckSum(0, (PVOID)pvImageBase, (INT)PeHeaderSize >> 1);
		auto FileCheckSum = CalculateCheckSum(PeHeaderCheckSum, RemainData, RemainDataSize);

		if (cbSize & 1)
			FileCheckSum += (WORD) * ((CHAR*)pvImageBase + cbSize - 1);

		dwCheckSum = cbSize + FileCheckSum;

		return dwCheckSum;
	}

	uint64_t CPEFunctions::CalculateMemChecksumFast(LPCVOID c_pvBase, std::size_t unLength)
	{
		uint64_t qwChecksumResult = 0ULL;
		LPVOID pvData = nullptr;

		__try
		{
			pvData = CMemHelper::Allocate(unLength);
			if (pvData)
			{
				stdext::CRT::mem::__memcpy(pvData, c_pvBase, unLength);

				qwChecksumResult = XXH64(pvData, unLength, 1337);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		if (pvData)
		{
			CMemHelper::Free(pvData);
			pvData = nullptr;
		}

		return qwChecksumResult;
	}

	std::wstring CPEFunctions::CalculateMemChecksumSHA256(LPCVOID c_pvBase, std::size_t unLength)
	{
		std::wstring wstChecksumResult;
		LPVOID pvData = nullptr;
		bool bCopied = false;

		auto fnCopyMemSafeImpl = [&]() {
			__try
			{
				pvData = CMemHelper::Allocate(unLength);
				if (pvData)
				{
					stdext::CRT::mem::__memcpy(pvData, c_pvBase, unLength);
					bCopied = true;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		fnCopyMemSafeImpl();

		auto fnSafeGetHashImpl = [&]() {
			wstChecksumResult = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256((std::uint8_t*)pvData, unLength);
		};
		auto fnSafeGetHash = [&]() {
			__try
			{
				fnSafeGetHashImpl();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		if (bCopied)
		{
			fnSafeGetHash();
		}

		if (pvData)
		{
			CMemHelper::Free(pvData);
			pvData = nullptr;
		}

		return wstChecksumResult;
	}

	uint64_t CPEFunctions::CalculateRemoteMemChecksumFast(HANDLE hProcess, PVOID pvBase, ULONG ulLength)
	{
		auto CalculateChecksumEx = [&] {
			uint64_t qwChecksumResult = 0ULL;

			auto pvData = CMemHelper::Allocate(ulLength);
			if (pvData)
			{
				SIZE_T cbReadBytes = 0;
				const auto ntStatus = CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(hProcess, pvBase, pvData, ulLength, &cbReadBytes);
				if (NT_SUCCESS(ntStatus) && cbReadBytes == ulLength)
				{
					qwChecksumResult = XXH64(pvData, cbReadBytes, 1337);
				}
			}

			if (pvData)
			{
				CMemHelper::Free(pvData);
				pvData = nullptr;
			}
			
			return qwChecksumResult;
		};

		uint64_t qwChecksumResult = 0ULL;
		__try
		{
			qwChecksumResult = CalculateChecksumEx();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		return qwChecksumResult;
	}

	std::wstring CPEFunctions::CalculateRemoteMemChecksumSHA256(HANDLE hProcess, ptr_t pvBase, ULONG ulLength)
	{
		std::wstring wstChecksumResult;

		LPVOID pvData = nullptr;
		auto CalculateChecksumEx = [&] {
			pvData = CMemHelper::Allocate(ulLength);
			if (pvData)
			{
				SIZE_T cbReadBytes = 0;
				const auto ntStatus = CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(hProcess, (PVOID64)pvBase, pvData, ulLength, &cbReadBytes);
				if (NT_SUCCESS(ntStatus) && cbReadBytes == ulLength)
				{
					wstChecksumResult = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256((std::uint8_t*)pvData, ulLength);
				}
			}
		};

		auto fnCalculateChecksumSafe = [&]() {
			__try
			{
				CalculateChecksumEx();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		fnCalculateChecksumSafe();

		if (pvData)
		{
			CMemHelper::Free(pvData);
			pvData = nullptr;
		}

		return wstChecksumResult;
	}

	std::size_t CPEFunctions::GetPEHeaderSize(LPVOID pvBaseAddress)
	{
		auto pDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		if (!pNTHeader->FileHeader.SizeOfOptionalHeader)
			return 0;

		auto wSize = pNTHeader->FileHeader.SizeOfOptionalHeader;
		return wSize;
	}

	std::size_t CPEFunctions::GetSizeofCode(LPVOID pvBaseAddress)
	{
		auto pDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		return pNTHeader->OptionalHeader.SizeOfCode;
	}

	std::size_t CPEFunctions::OffsetToCode(LPVOID pvBaseAddress)
	{
		auto pDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
		if (!pOptionalHeader)
			return NULL;

		return pOptionalHeader->BaseOfCode;
	}

	std::size_t CPEFunctions::GetModuleImageSize(LPVOID pvBaseAddress)
	{
		auto pDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		return pNTHeader->OptionalHeader.SizeOfImage;
	}

	PIMAGE_SECTION_HEADER CPEFunctions::ImageRVA2Section(IMAGE_NT_HEADERS* pImage_NT_Headers, LPVOID pvRVA)
	{
		if (pImage_NT_Headers)
		{
			auto pISH = (IMAGE_SECTION_HEADER*)(((BYTE*)pImage_NT_Headers) + sizeof(IMAGE_NT_HEADERS));
			for (std::size_t i = 0; i < pImage_NT_Headers->FileHeader.NumberOfSections; i++)
			{
				if ((pISH->VirtualAddress) && ((UINT_PTR)pvRVA <= (pISH->VirtualAddress + pISH->SizeOfRawData)))
				{
					return (PIMAGE_SECTION_HEADER)pISH;
				}

				pISH++;
			}
		}
		return nullptr;
	}

	UINT_PTR CPEFunctions::Rva2Offset(LPVOID pvBaseAddress, UINT_PTR pRVA)
	{
		auto lpDosHdr = (IMAGE_DOS_HEADER*)pvBaseAddress;
		auto pNtHdrs = (IMAGE_NT_HEADERS*)((UINT_PTR)pvBaseAddress + lpDosHdr->e_lfanew);
		auto pISH = IMAGE_FIRST_SECTION(pNtHdrs);

		for (std::size_t i = 0, sections = pNtHdrs->FileHeader.NumberOfSections; i < sections; i++, pISH++)
		{
			if (pISH->VirtualAddress <= pRVA)
			{
				if ((pISH->VirtualAddress + pISH->Misc.VirtualSize) > pRVA)
				{
					pRVA -= pISH->VirtualAddress;
					pRVA += pISH->PointerToRawData;
					return pRVA;
				}
			}
		}
		return 0;
	}

	bool CPEFunctions::IsInModule(PVOID Address, DWORD Type, DWORD_PTR& Base)
	{
		uint32_t counter = 0;
		CApplication::Instance().WinAPIManagerInstance()->EnumerateModules([&](LDR_DATA_TABLE_ENTRY* entry) {
			counter++;

			auto ModuleBase = (DWORD_PTR)entry->DllBase;

			auto pIDH = (PIMAGE_DOS_HEADER)ModuleBase;
			if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
				return;

			auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);
			if (pINH->Signature != IMAGE_NT_SIGNATURE)
				return;

			auto pISH = IMAGE_FIRST_SECTION(pINH);
			if (!pISH)
				return;

			DWORD_PTR ExecuteSize = 0;
			for (DWORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
			{
				if (pISH[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					ExecuteSize += PADDING(pISH[i].Misc.VirtualSize, pINH->OptionalHeader.SectionAlignment);
				else
					break;
			}

			DWORD_PTR result = 0;

			// The address is in .text section
			if (Type == 0 && (DWORD_PTR)Address >= ((DWORD_PTR)ModuleBase + (DWORD_PTR)pINH->OptionalHeader.SectionAlignment) && (DWORD_PTR)Address < (DWORD_PTR)ModuleBase + (DWORD_PTR)pINH->OptionalHeader.SectionAlignment + ExecuteSize)
				result = ModuleBase;

			// The address is in module (return base address)
			else if (Type == 1 && (DWORD_PTR)Address >= (DWORD_PTR)ModuleBase && (DWORD_PTR)Address < (DWORD_PTR)ModuleBase + (DWORD_PTR)pINH->OptionalHeader.SizeOfImage)
				result = ModuleBase;

			// The address is in module (return module's InMemoryOrderModuleList order)
			else if (Type == 2 && (DWORD_PTR)Address >= (DWORD_PTR)ModuleBase && (DWORD_PTR)Address < (DWORD_PTR)ModuleBase + (DWORD_PTR)pINH->OptionalHeader.SizeOfImage)
				result = counter;

			else
				return;

			Base = result;
		});

		if (Base)
		{
			APP_TRACE_LOG(LL_TRACE, L"Target address: %p inside in: %p", Address, Base);

			wchar_t wszMappedName[2048]{ L'\0' };
			if (g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)Base, wszMappedName, 2048) && wszMappedName[0] != L'\0')
			{
				const auto c_wstNormalizedName = CProcessFunctions::DosDevicePath2LogicalPath(wszMappedName);
				if (!c_wstNormalizedName.empty())
				{
					APP_TRACE_LOG(LL_TRACE, L"Mapped name: %s", c_wstNormalizedName.c_str());
					
					// mapped
					const auto lpKnownModule = (DWORD_PTR)g_winAPIs->GetModuleHandleW_o(c_wstNormalizedName.c_str());
					if (!lpKnownModule)
					{
						APP_TRACE_LOG(LL_CRI, L"%s is not mapped module!", c_wstNormalizedName.c_str());
						return true;
					}
					
					// cloacked
					if (lpKnownModule != Base)
					{
						wchar_t wszKnownMappedName[2048]{ L'\0' };
						g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)lpKnownModule, wszKnownMappedName, 2048);
						
						APP_TRACE_LOG(LL_CRI, L"%s is cloacked module! Linked module: %p (%s), Found base: %p", c_wstNormalizedName.c_str(), lpKnownModule, wszKnownMappedName, Base);
						return true;
					}
				}
			}
		}

		return !!Base;
	}

	bool CPEFunctions::FillPEHeader(LPVOID pvBaseAddress, OUT NPEHelper::PE_HEADER& PEHeader)
	{
		if (!IsValidPEHeader(pvBaseAddress))
			return false;

		PEHeader.dosHeader = PIMAGE_DOS_HEADER(pvBaseAddress);
		PEHeader.ntHeaders = PIMAGE_NT_HEADERS(ULONG_PTR(PEHeader.dosHeader) + PEHeader.dosHeader->e_lfanew);
		PEHeader.fileHeader = PIMAGE_FILE_HEADER(&PEHeader.ntHeaders->FileHeader);
		PEHeader.optionalHeader = PIMAGE_OPTIONAL_HEADER(&PEHeader.ntHeaders->OptionalHeader);

		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
			PEHeader.dataDirectory[i] = &PEHeader.ntHeaders->OptionalHeader.DataDirectory[i];

		const ULONG_PTR firstSectionHeader = ULONG_PTR(IMAGE_FIRST_SECTION(PEHeader.ntHeaders));
		for (int i = 0; i < PEHeader.fileHeader->NumberOfSections; i++)
			PEHeader.sectionHeaders.push_back(PIMAGE_SECTION_HEADER(i * sizeof(IMAGE_SECTION_HEADER) + firstSectionHeader));

		return true;
	}

	bool CPEFunctions::FillRemotePEHeader(HANDLE ProcessHandle, LPVOID pvBaseAddress, OUT NPEHelper::REMOTE_PE_HEADER& PEHeader)
	{
		ZeroMemory(PEHeader.rawData, PE_HEADER_SIZE);

		if (!ReadProcessMemory(ProcessHandle, pvBaseAddress, PEHeader.rawData, PE_HEADER_SIZE, NULL))
			return false;

		if (!FillPEHeader(&PEHeader.rawData, PEHeader))
			return false;

		PEHeader.remoteBaseAddress = pvBaseAddress;
		return true;
	}

	bool CPEFunctions::IsPackedImage(LPVOID pvBaseAddress)
	{
		auto pDosHeader = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pNTHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)pvBaseAddress + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto pOEP = pNTHeader->OptionalHeader.AddressOfEntryPoint;
		auto pISH = IMAGE_FIRST_SECTION(pNTHeader);
		for (std::size_t i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
		{
			if (pOEP >= pISH[i].VirtualAddress && pOEP <= pISH[i].VirtualAddress + pISH[i].Misc.VirtualSize)
			{
				auto pSection = pISH[i];
				if (pSection.Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					if (memcmp(pSection.Name, xorstr_(L".textbss"), 8) != 0
						&& memcmp(pSection.Name, xorstr_(L".text\x0\x0\x0"), 8) != 0
						&& memcmp(pSection.Name, xorstr_(L"CODE\x0\x0\x0\x0"), 8) != 0
						&& memcmp(pSection.Name, xorstr_(L"INIT\0\0\0\0"), 8) != 0)
					{
						return true;
					}
				}
				if (i > 2)
				{
					if (pNTHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
					{
						if (memcmp(pSection.Name, xorstr_(L"INIT\0\0\0\0"), 8) == 0)
							return false;
					}
					return true;
				}
				break;
			}
		}
		return false;
	}

	static const char* GetFnNameByOrdinal(LPCSTR pImportModuleName, DWORD dwOrd)
	{
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)g_winAPIs->GetModuleHandleA(pImportModuleName);
		PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (!pDOSHeader
			|| IsBadReadPtr(pDOSHeader, sizeof(PIMAGE_DOS_HEADER))
			|| pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE
			|| pNTHeader->Signature != IMAGE_NT_SIGNATURE
			|| pExportDir == (PIMAGE_EXPORT_DIRECTORY)pNTHeader)
		{
			return 0;
		}

		LPDWORD pNames = MakePtr(LPDWORD, pDOSHeader, pExportDir->AddressOfNames);
		LPWORD pOrdNames = MakePtr(LPWORD, pDOSHeader, pExportDir->AddressOfNameOrdinals);

		for (int i = 0; i < (int)pExportDir->NumberOfNames; i++)
		{
			DWORD dwFoundOrd = pOrdNames[i] + pExportDir->Base;

			if (dwFoundOrd == dwOrd)
			{
				const char* pszName = (char*)MakePtr(char*, pDOSHeader, pNames[i]);
				return pszName;
			}
		}

		return 0;
	}
	BOOL CPEFunctions::GetFunctionPtrFromIAT(void* pDosHdr, LPCSTR pImportModuleName, LPCSTR pFunctionSymbol, PVOID* ppvFn)
	{
		if (!ppvFn || !pDosHdr || !pImportModuleName || !pFunctionSymbol || pImportModuleName[0] == 0 || pFunctionSymbol[0] == 0)
		{
			return FALSE;
		}

		*ppvFn = 0;

		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pDosHdr;
		PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (IsBadReadPtr(pDOSHeader, sizeof(PIMAGE_DOS_HEADER))
			|| pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE
			|| pNTHeader->Signature != IMAGE_NT_SIGNATURE
			|| pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR)pNTHeader)
		{
			return FALSE;
		}

		while (pImportDesc->Name)
		{
			LPCSTR pszDllName = MakePtr(LPCSTR, pDOSHeader, pImportDesc->Name);

			if (_stricmp(pszDllName, pImportModuleName) == 0)
			{
				PIMAGE_THUNK_DATA pThunk = MakePtr(PIMAGE_THUNK_DATA, pDOSHeader, pImportDesc->FirstThunk);
				PIMAGE_THUNK_DATA pThunk1 = MakePtr(PIMAGE_THUNK_DATA, pDOSHeader, pImportDesc->OriginalFirstThunk);
				int idx = 0;

				while (pThunk[idx].u1.Function)
				{
					const char* pszProcName = 0;

					if ((pThunk1[idx].u1.AddressOfData & 0x80000000) != 0)
					{
						pszProcName = GetFnNameByOrdinal(pImportModuleName, pThunk1[idx].u1.AddressOfData & 0x7FFFFFFF);
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImgData = MakePtr(PIMAGE_IMPORT_BY_NAME, pDOSHeader, pThunk1[idx].u1.AddressOfData);
						pszProcName = (char*)pImgData->Name;
					}

					if (pszProcName && _stricmp(pszProcName, pFunctionSymbol) == 0)
					{
						*ppvFn = ULongToPtr(pThunk[idx].u1.Function);
						return TRUE;
					}

					idx++;
				}
			}

			pImportDesc++;
		}

		return FALSE;
	}

	IMAGE_SECTION_HEADER* WINAPI ImageVaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, void* Va)
	{
		if (!NtHeaders)
			return nullptr;

		DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
		if (!dwNumberOfSections)
			return nullptr;

		UINT_PTR ImageOffset = (BYTE*)Va - (BYTE*)Base;

		WORD SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
		IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&NtHeaders->OptionalHeader + SizeOfOptionalHeader);
		for (DWORD i = 0; i < dwNumberOfSections; i++)
		{
			DWORD PointerToRawData = pSectionHeaders[i].PointerToRawData;
			DWORD SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
			if ((ImageOffset >= PointerToRawData) && (ImageOffset < (PointerToRawData + SizeOfRawData)))
				return &pSectionHeaders[i];
		}
		return nullptr;
	}

	DWORD WINAPI ImageVaToRva(PIMAGE_NT_HEADERS NtHeaders, void* Base, void* Va)
	{
		IMAGE_SECTION_HEADER* ResultSection = nullptr;

		ResultSection = ImageVaToSection(NtHeaders, (PVOID)Base, Va);
		if (!ResultSection)
			return NULL;

		DWORD ImageOffset = (BYTE*)Va - (BYTE*)Base;

		return (ImageOffset - ResultSection->PointerToRawData) + ResultSection->VirtualAddress;
	}
	DWORD WINAPI ImageVaToRva(void* Base, void* Va)
	{
		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)Base;
		IMAGE_NT_HEADERS* ImageNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

		return ImageVaToRva(ImageNtHeader, Base, Va);
	}

	PVOID WINAPI ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader)
	{
		*(ULONG*)Size = NULL;

		if (!DataDirectory->VirtualAddress || !DataDirectory->Size || !SizeOfHeaders)
			return nullptr;

		*(ULONG*)Size = DataDirectory->Size;
		if (MappedAsImage || DataDirectory->VirtualAddress < SizeOfHeaders)
			return (char*)Base + DataDirectory->VirtualAddress;

		WORD SizeOfOptionalHeader = ImageFileHeader->SizeOfOptionalHeader;
		WORD NumberOfSections = ImageFileHeader->NumberOfSections;
		if (!NumberOfSections || !SizeOfOptionalHeader)
			return nullptr;

		IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ImageOptionalHeader + SizeOfOptionalHeader);
		for (DWORD i = 0; i < NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER* pSectionHeader = &pSectionHeaders[i];
			if ((DataDirectory->VirtualAddress >= pSectionHeader->VirtualAddress) &&
				(DataDirectory->VirtualAddress < (pSectionHeader->SizeOfRawData + pSectionHeader->VirtualAddress)))
			{
				return (char*)Base + (DataDirectory->VirtualAddress - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
			}
		}
		return nullptr;
	}
	PVOID WINAPI ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader)
	{
		*(ULONG*)Size = NULL;

		if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
			return nullptr;

		IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
		if (!DataDirectory->VirtualAddress || !DataDirectory->Size)
			return nullptr;

		return ImageDirectoryEntryToDataInternal(Base,
			MappedAsImage,
			Size,
			ImageOptionalHeader->SizeOfHeaders,
			DataDirectory,
			ImageFileHeader,
			ImageOptionalHeader);
	}
	PVOID WINAPI ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader)
	{
		*(ULONG*)Size = NULL;

		if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
			return nullptr;

		IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
		if (!DataDirectory->VirtualAddress || !DataDirectory->Size)
			return nullptr;

		return ImageDirectoryEntryToDataInternal(Base,
			MappedAsImage,
			Size,
			ImageOptionalHeader->SizeOfHeaders,
			DataDirectory,
			ImageFileHeader,
			ImageOptionalHeader);
	}
	PVOID WINAPI ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders)
	{
		*(ULONG*)Size = NULL;

		if (ImageFileHeader->NumberOfSections <= 0u || !ImageFileHeader->SizeOfOptionalHeader)
			return nullptr;

		IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ImageRomHeaders + ImageFileHeader->SizeOfOptionalHeader);

		WORD j = 0;
		for (; j < ImageFileHeader->NumberOfSections; j++, pSectionHeader++)
		{
			if (DirectoryEntry == 3 && _stricmp((char*)pSectionHeader->Name, xorstr_(".pdata")) == NULL)
				break;
			if (DirectoryEntry == 6 && _stricmp((char*)pSectionHeader->Name, xorstr_(".rdata")) == NULL)
			{
				*(ULONG*)Size = NULL;
				for (BYTE* i = (BYTE*)Base + pSectionHeader->PointerToRawData + 0xC; *(DWORD*)i; i += 0x1C)
					*Size += 0x1C;
				break;
			}
		}
		if (j >= ImageFileHeader->NumberOfSections)
			return nullptr;

		return (char*)Base + pSectionHeader->PointerToRawData;
	}
	PVOID WINAPI ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size)
	{
		*(ULONG*)Size = NULL;

		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)Base;
		if (!pDosHeader)
			return nullptr;

		IMAGE_FILE_HEADER* ImageFileHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* ImageOptionalHeader = nullptr;

		LONG NtHeaderFileOffset = pDosHeader->e_lfanew;
		IMAGE_NT_HEADERS* ImageNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + NtHeaderFileOffset);

		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE
			&& NtHeaderFileOffset > 0
			&& NtHeaderFileOffset < 0x10000000u
			&& ImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			ImageFileHeader = &ImageNtHeader->FileHeader;
			ImageOptionalHeader = &ImageNtHeader->OptionalHeader;
		}
		else
		{
			ImageFileHeader = (IMAGE_FILE_HEADER*)Base;
			ImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)Base + 0x14);
		}
		switch (ImageOptionalHeader->Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return ImageDirectoryEntryToData32(
				Base,
				MappedAsImage,
				DirectoryEntry,
				Size,
				ImageFileHeader,
				(IMAGE_OPTIONAL_HEADER32*)ImageOptionalHeader);
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			return ImageDirectoryEntryToData64(
				Base,
				MappedAsImage,
				DirectoryEntry,
				Size,
				ImageFileHeader,
				(IMAGE_OPTIONAL_HEADER64*)ImageOptionalHeader);
		case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			return ImageDirectoryEntryToDataRom(
				Base,
				IMAGE_ROM_OPTIONAL_HDR_MAGIC,
				DirectoryEntry,
				Size,
				ImageFileHeader,
				(IMAGE_ROM_OPTIONAL_HEADER*)ImageOptionalHeader);
		}
		return nullptr;
	}
	IMAGE_SECTION_HEADER* WINAPI ImageRva2Section(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva)
	{
		if (!NtHeaders)
			return nullptr;

		DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
		if (!dwNumberOfSections)
			return nullptr;

		WORD SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
		IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&NtHeaders->OptionalHeader + SizeOfOptionalHeader);
		for (DWORD i = 0; i < dwNumberOfSections; i++)
		{
			DWORD VirtualAddress = pSectionHeaders[i].VirtualAddress;
			DWORD SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
			if ((Rva >= VirtualAddress) && (Rva < (SizeOfRawData + VirtualAddress)))
				return &pSectionHeaders[i];
		}
		return nullptr;
	}
	PVOID WINAPI ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva)
	{
		IMAGE_SECTION_HEADER* ResultSection = nullptr;

		ResultSection = ImageRva2Section(NtHeaders, (PVOID)Base, Rva);
		if (!ResultSection)
			return nullptr;

		return (char*)Base + (Rva - ResultSection->VirtualAddress) + ResultSection->PointerToRawData;
	}

	FARPROC CPEFunctions::GetExportAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName, _In_ BOOLEAN MappedAsImage)
	{
		if (lpProcName == NULL)
			return nullptr;

		unsigned short ProcOrdinal = 0xFFFF;
		if ((ULONG_PTR)lpProcName < 0xFFFF)
			ProcOrdinal = (ULONG_PTR)lpProcName & 0xFFFF;
		else
		{
			//in case of "#123" resolve the ordinal to 123
			if (lpProcName[0] == '#')
			{
				DWORD OrdinalFromString = atoi(lpProcName + 1);
				if (OrdinalFromString < 0xFFFF &&
					OrdinalFromString != 0)
				{
					ProcOrdinal = OrdinalFromString & 0xFFFF;
					lpProcName = (LPCSTR)(ProcOrdinal);
				}
			}
		}
		IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
		if (!DosHeader || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		//only OptionalHeader is different between 64bit and 32bit so try not to touch it!
		IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)DosHeader + DosHeader->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		ULONG ExportDirectorySize = NULL;
		IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToDataEx(DosHeader, MappedAsImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirectorySize);
		if (!ExportDirectory || !ExportDirectorySize)
			return nullptr;

		//check if any export functions are present
		if (!ExportDirectory->NumberOfFunctions)
			return nullptr;

		//from BlackBone
		//https://github.com/DarthTon/Blackbone/blob/3dc33d815011b83855af607013d34c836b9d0877/src/BlackBone/Process/ProcessModules.cpp#L266
		// Fix invalid directory size
		if (ExportDirectorySize <= sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			// New size should take care of max number of present names (max name length is assumed to be 255 chars)
			ExportDirectorySize = static_cast<DWORD>(ExportDirectory->AddressOfNameOrdinals - (DWORD)((BYTE*)(ExportDirectory)-(BYTE*)(DosHeader))
				+ max(ExportDirectory->NumberOfFunctions, ExportDirectory->NumberOfNames) * 255);
		}

		DWORD AddressOfNamesRVA = ExportDirectory->AddressOfNames;
		DWORD AddressOfFunctionsRVA = ExportDirectory->AddressOfFunctions;
		DWORD AddressOfNameOrdinalsRVA = ExportDirectory->AddressOfNameOrdinals;

		DWORD* ExportNames = (DWORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfNamesRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfNamesRVA));
		DWORD* Functions = (DWORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfFunctionsRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfFunctionsRVA));
		WORD* Ordinals = (WORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfNameOrdinalsRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfNameOrdinalsRVA));

		if (!ExportNames || !Functions || !Ordinals)
			return nullptr;

		for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			unsigned short OrdinalIndex = Ordinals[i];

			DWORD ExportFncOffset = Functions[OrdinalIndex];
			if (!ExportFncOffset)
				continue;

			char* ProcNamePtr = (char*)(MappedAsImage ? ((char*)DosHeader + ExportNames[i]) : ImageRvaToVa(NtHeader, DosHeader, ExportNames[i]));
			BYTE* ExportFnc = (BYTE*)(MappedAsImage ? ((BYTE*)DosHeader + ExportFncOffset) : ImageRvaToVa(NtHeader, DosHeader, ExportFncOffset));

			//Forwarded exports:
			if (MappedAsImage &&	//Not supported on images that are not mapped
									//Not supported with ordinals for forwarded export by name
				//Check for forwarded export:
				ExportFnc > ((BYTE*)ExportDirectory) &&
				ExportFnc < ((BYTE*)ExportDirectory + ExportDirectorySize))
			{
				//for example inside the Kernelbase.dll's export table
				//NTDLL.RtlDecodePointer
				//It could also forward an ordinal
				//NTDLL.#123
				char* ForwardedString = (char*)ExportFnc;
				DWORD ForwardedStringLen = (DWORD)strlen(ForwardedString) + 1;
				if (ForwardedStringLen >= 256)
					continue;
				char szForwardedLibraryName[256];
				memcpy(szForwardedLibraryName, ForwardedString, ForwardedStringLen);
				char* ForwardedFunctionName = NULL;
				char* ForwardedFunctionOrdinal = NULL;
				for (DWORD s = 0; s < ForwardedStringLen; s++)
				{
					if (szForwardedLibraryName[s] == '.')
					{
						szForwardedLibraryName[s] = NULL;
						ForwardedFunctionName = &ForwardedString[s + 1];
						break;
					}
				}

				//forwarded by ordinal
				if (ForwardedFunctionName != nullptr && ForwardedFunctionName[0] == '#')
				{
					ForwardedFunctionOrdinal = ForwardedFunctionName + 1;
					ForwardedFunctionName = NULL;
				}
				if (ForwardedFunctionName)
				{
					if (strcmp(lpProcName, ForwardedFunctionName) != NULL)
						continue;

					HMODULE hForwardedDll = g_winAPIs->LoadLibraryA(szForwardedLibraryName);
					FARPROC ForwardedFunction = (FARPROC)GetExportAddress(hForwardedDll, ForwardedFunctionName, MappedAsImage);
					return (FARPROC)ForwardedFunction;
				}
				else
					if (ForwardedFunctionOrdinal && ProcOrdinal < 0xFFFF)
					{
						DWORD ForwardedOrdinal = atoi(ForwardedFunctionOrdinal);
						if (ForwardedOrdinal > 0xFFFF ||
							ForwardedOrdinal == 0 ||
							ForwardedOrdinal != ProcOrdinal)
							continue;

						HMODULE hForwardedDll = g_winAPIs->LoadLibraryA(szForwardedLibraryName);
						FARPROC ForwardedFunction = (FARPROC)GetExportAddress(hForwardedDll, (char*)(ForwardedOrdinal & 0xFFFF), MappedAsImage);
						return (FARPROC)ForwardedFunction;
					}
					else
						continue;
			}

			if ((ULONG_PTR)lpProcName > 0xFFFF && strcmp(lpProcName, ProcNamePtr) == NULL)
				return (FARPROC)ExportFnc;
			else
			{
				if ((OrdinalIndex + 1) == ProcOrdinal)
					return (FARPROC)ExportFnc;
			}
		}
		return nullptr;
	}

	HMODULE GetRemoteLibrary(HANDLE process, const std::wstring& library_name)
	{
		auto hSnap = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, g_winAPIs->GetProcessId(process));
		if (!IS_VALID_HANDLE(hSnap))
			return nullptr;

		MODULEENTRY32W me{ 0 };
		me.dwSize = sizeof(me);

		if (g_winAPIs->Module32FirstW(hSnap, &me))
		{
			do
			{
				if (!lstrcmpi(me.szModule, library_name.c_str()))
				{
					g_winAPIs->CloseHandle(hSnap);
					return reinterpret_cast<HMODULE>(me.modBaseAddr);
				}
			} while (Module32NextW(hSnap, &me));
		}

		g_winAPIs->CloseHandle(hSnap);
		return nullptr;
	}

	FARPROC get_remote_proc_address(HANDLE process, HMODULE module, const char* proc_name)
	{
		IMAGE_DOS_HEADER dos_headers;
		if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module), &dos_headers, sizeof(dos_headers), NULL))
			return nullptr;

		if (dos_headers.e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		IMAGE_NT_HEADERS nt_headers;
		if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + dos_headers.e_lfanew, &nt_headers, sizeof(nt_headers), NULL))
			return nullptr;

		if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		IMAGE_EXPORT_DIRECTORY export_dir;

		if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &export_dir, sizeof(export_dir), NULL))
			return nullptr;

		unsigned int* function_rvas = new unsigned int[export_dir.NumberOfFunctions];

		if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + export_dir.AddressOfFunctions, function_rvas, export_dir.NumberOfFunctions * sizeof(unsigned int), NULL))
		{
			delete[] function_rvas;
			return nullptr;
		}

		unsigned int rva_buffer = 0;

		if (HIWORD(proc_name))
		{
			unsigned int* name_rvas = new unsigned int[export_dir.NumberOfNames];

			if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + export_dir.AddressOfNames, name_rvas, export_dir.NumberOfNames * sizeof(unsigned int), NULL))
			{
				delete[] name_rvas;
				delete[] function_rvas;
				return nullptr;
			}

			unsigned short* name_ordinal_rvas = new unsigned short[export_dir.NumberOfNames];

			if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + export_dir.AddressOfNameOrdinals, name_ordinal_rvas, export_dir.NumberOfNames * sizeof(unsigned short), NULL))
			{
				delete[] name_ordinal_rvas;
				delete[] name_rvas;
				delete[] function_rvas;
				return nullptr;
			}

			char* name_buffer = new char[strlen(proc_name) + 1];

			for (unsigned int i = 0; i < export_dir.NumberOfNames; i++)
			{
				if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + name_rvas[i], name_buffer, strlen(proc_name) + 1, NULL))
				{
					delete[] name_ordinal_rvas;
					delete[] name_rvas;
					delete[] function_rvas;
					return nullptr;
				}

				if (!strcmp(name_buffer, proc_name))
					rva_buffer = function_rvas[name_ordinal_rvas[i]];
			}

			delete[] name_ordinal_rvas;
			delete[] name_rvas;
		}
		else
		{
			rva_buffer = function_rvas[reinterpret_cast<DWORD>(proc_name) - export_dir.Base];
		}

		delete[] function_rvas;

		if (!rva_buffer)
			return nullptr;

		if (rva_buffer >= nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			rva_buffer < nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			char forward_buffer[100];

			if (!g_winAPIs->ReadProcessMemory(process, reinterpret_cast<unsigned char*>(module) + rva_buffer, forward_buffer, sizeof(forward_buffer), NULL))
				return nullptr;

			char* dot_offset = strrchr(forward_buffer, '.');

			std::string library_name = std::string(forward_buffer, dot_offset - forward_buffer) + std::string(".dll");
			std::string api_name(dot_offset + 1);

			HMODULE library_module = GetRemoteLibrary(process, stdext::to_wide(library_name));

			if (!library_module)
				return nullptr;

			return get_remote_proc_address(process, library_module, api_name.c_str());
		}
		else
		{
			return reinterpret_cast<FARPROC>(reinterpret_cast<unsigned char*>(module) + rva_buffer);
		}
	}

	size_t CPEFunctions::GetFunctionSize(PVOID pFunc)
	{
		if (!pFunc)
			return 0;

		uint8_t byInstrCopy[0x3]{ 0x0 };

		auto fnGetInstrCopyImpl = [&]() {
			memcpy(byInstrCopy, pFunc, sizeof(byInstrCopy));
		};
		auto fnGetInstrCopy = [&fnGetInstrCopyImpl]() {
			__try
			{
				fnGetInstrCopyImpl();
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
			return false;
		};
		if (fnGetInstrCopy())
		{
			APP_TRACE_LOG(LL_TRACE, L"Func: %p Opcode: 0x%X, 0x%X, 0x%X", pFunc, byInstrCopy[0], byInstrCopy[1], byInstrCopy[2]);

			if (byInstrCopy[0] == 0x48 && byInstrCopy[1] == 0xFF && byInstrCopy[2] == 0x25)
				return 7;
			else if (byInstrCopy[0] == 0xFF && (byInstrCopy[1] == 0x25 || byInstrCopy[1] == 0x15))
				return 6;
			else if (byInstrCopy[0] == 0x90 && byInstrCopy[1] == 0xE9)
				return 6;
			else if (byInstrCopy[0] == 0x90 && byInstrCopy[1] == 0x90 && byInstrCopy[2] == 0xE9)
				return 7;
			else if (byInstrCopy[0] == 0x8B && byInstrCopy[1] == 0xFF && byInstrCopy[2] == 0xE9)
				return 7;
			else if (byInstrCopy[0] == 0x8B && byInstrCopy[1] == 0xFF && byInstrCopy[2] == 0x55)
				return 5;
			else if (byInstrCopy[0] == 0xE9 || byInstrCopy[0] == 0xE8 || byInstrCopy[0] == 0xEB || byInstrCopy[0] == 0x9A)
				return 5;
			else
			{
				APP_TRACE_LOG(LL_WARN, L"Size could not determined! Func: %p Opcode: 0x%X, 0x%X, 0x%X", pFunc, byInstrCopy[0], byInstrCopy[1], byInstrCopy[2]);
			}
		}
		return 0;
		/*
		PBYTE pMem = (PBYTE)pFunc;
		size_t nFuncSize = 0;
		do
		{
			++nFuncSize;
		} while (*(pMem++) != 0xC3);
		return nFuncSize;
		*/
	}
	
	int CPEFunctions::ValidateFunction(LPVOID pFunction, int* piBpCount, int* piFunctionSize, uint64_t* pqwChecksum)
	{
		auto GetBreakpointCount = [](DWORD_PTR dwStartAddress, DWORD dwLength) {
			DWORD count = 0;

			DWORD_PTR dwCurrentAddress = dwStartAddress;
			while (dwStartAddress + dwLength > dwCurrentAddress)
			{
				if (*(BYTE*)dwCurrentAddress == 0xCC)
					count++;

				dwCurrentAddress++;
			}

			return count;
		};

		const auto dwFunctionAddress = reinterpret_cast<DWORD_PTR>(pFunction);

		MEMORY_BASIC_INFORMATION mbi;
		if (!g_winAPIs->VirtualQuery(reinterpret_cast<LPCVOID>(dwFunctionAddress), &mbi, sizeof(mbi)))
			return 1;

		if (mbi.Protect == PAGE_NOACCESS)
			return 2;

		if (mbi.Protect & PAGE_GUARD)
			return 3;

		if (*(BYTE*)dwFunctionAddress == 0xCC)
			return 4;

		if (*(BYTE*)dwFunctionAddress == 0x64)
			return 5;
		if (*(BYTE*)dwFunctionAddress == 0x67)
			return 6;

		if (*(BYTE*)dwFunctionAddress == 0x0F)
		{
			if (*(BYTE*)dwFunctionAddress + 1 == 0xB9)
				return 7;
			if (*(BYTE*)dwFunctionAddress + 1 == 0x10)
				return 8;
			if (*(BYTE*)dwFunctionAddress + 1 == 0x0B)
				return 9;
			if (*(BYTE*)dwFunctionAddress + 1 == 0x33)
				return 10;
		}

		if (*(BYTE*)dwFunctionAddress == 0xCD)
		{
			if (*(BYTE*)dwFunctionAddress + 1 == 0xCE)
				return 11;
			if (*(BYTE*)dwFunctionAddress + 1 == 0x03)
				return 12;
			if (*(BYTE*)dwFunctionAddress + 1 == 0x01)
				return 13;
		}

		if (*(BYTE*)dwFunctionAddress == 0xF1)
			return 14;

		if (*(BYTE*)dwFunctionAddress == 0x2C)
			return 15;
		if (*(BYTE*)dwFunctionAddress == 0x2D)
			return 16;
		if (*(BYTE*)dwFunctionAddress == 0x41)
			return 17;

		PUCHAR pOpcode;
		DWORD dwFuncLength = SizeOfCode(pFunction, &pOpcode);

		if (piFunctionSize)
			*piFunctionSize = dwFuncLength;

		if (piBpCount)
		{
			auto iBpCount = GetBreakpointCount(dwFunctionAddress, dwFuncLength);
			*piBpCount = iBpCount;
		}

		if (pqwChecksum)
			*pqwChecksum = CalculateMemChecksumFast(pFunction, dwFuncLength);

		return 0;
	}

	bool IsValidMachineForCodeIntegrifyCheck(DWORD dwMachine, std::uint32_t Bits)
	{
		if (Bits & 64)
		{
			// AMD64 is always allowed
			if (dwMachine == IMAGE_FILE_MACHINE_AMD64)
				return true;

			// Returns STATUS_INVALID_IMAGE_FORMAT due to page size being 0x2000
			if (dwMachine == IMAGE_FILE_MACHINE_IA64)
				return true;

			if (dwMachine == IMAGE_FILE_MACHINE_ARM64)
				return true;
		}

		if (Bits & 32)
		{
			// Any of these is allowed
			if (dwMachine == IMAGE_FILE_MACHINE_I386 || dwMachine == IMAGE_FILE_MACHINE_ARM)
				return true;

			// Since Windows 8, IMAGE_FILE_MACHINE_ARMNT is alowed here as well
			if (dwMachine == IMAGE_FILE_MACHINE_ARMNT)
				return true;
		}

		return false;
	}
	bool ValidateCodeIntegrity(LPVOID pvBaseAddress, DWORD dwSize)
	{
		if (!pvBaseAddress)
			return false;

		auto pIDH = (PIMAGE_DOS_HEADER)pvBaseAddress;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto pIOH = (PIMAGE_OPTIONAL_HEADER)&pINH->OptionalHeader;
		if (pIOH->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
			return false;
		
		auto pISH = IMAGE_FIRST_SECTION(pINH);
		if (!pISH)
			return false;

		if (pIOH->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
		{
			const auto& SecurityDir = pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
			std::uint32_t sizeOfNtHeaders = sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
			std::uint32_t endOfRawData;
			std::size_t peFileSize = dwSize;

			if (pIDH->e_lfanew < sizeof(IMAGE_DOS_HEADER))
				return true;
			if (pIDH->e_lfanew > (LONG)pIOH->SectionAlignment)
				return true;
			if (((LONG)pIOH->SectionAlignment - pIDH->e_lfanew) <= pIDH->e_lfanew)
				return true;
			if ((pIDH->e_lfanew + sizeOfNtHeaders) > pIOH->SectionAlignment)
				return true;

			if (pINH->Signature != IMAGE_NT_SIGNATURE)
				return true;
			if (pINH->FileHeader.SizeOfOptionalHeader == 0)
				return true;

			if (!IsValidMachineForCodeIntegrifyCheck(pINH->FileHeader.Machine, 32 | 64))
				return true;

			if (pIOH->MajorLinkerVersion < 3 && pIOH->MajorLinkerVersion < 5)
				return true;
			if (pIOH->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && pIOH->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return true;

			// Check whether there is match between bitness of the optional header and machine
			if (pIOH->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && !IsValidMachineForCodeIntegrifyCheck(pINH->FileHeader.Machine, 32))
				return true;
			if (pIOH->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && !IsValidMachineForCodeIntegrifyCheck(pINH->FileHeader.Machine, 64))
				return true;

			if (pIOH->SizeOfHeaders == 0 || pIOH->SizeOfHeaders > peFileSize)
				return true;
			if (pIOH->FileAlignment == 0 || (pIOH->FileAlignment & (pIOH->FileAlignment - 1)))
				return true;
			if (pIOH->SectionAlignment & (pIOH->SectionAlignment - 1))
				return true;
			if (pIOH->FileAlignment > pIOH->SectionAlignment)
				return true;
			if ((pIOH->FileAlignment & (SECTOR_SIZE - 1)) && (pIOH->FileAlignment != pIOH->SectionAlignment))
				return true;

			// End of headers altogether must fit in the first page
			endOfRawData = pIDH->e_lfanew + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader;
			endOfRawData += (pINH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			if (endOfRawData >= PAGE_SIZE)
				return true;

			for (DWORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
			{
				const auto section = pISH[i];
				if (section.SizeOfRawData == 0)
					continue;

				// Windows's ci!CipImageGetImageHash wants start of any section past SizeOfHeaders
				// TODO: This check doesn't seem to hapeen for 32-bit images. Need confirm/deny this
				// Sample: 0E2EEAC29F7BAD81C67F0283541A050FAED973C114F46CF5F270355623A7BA8A
				if (pIOH->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				{
					if (section.PointerToRawData && section.SizeOfRawData && section.PointerToRawData < pIOH->SizeOfHeaders)
					{
						return true;
					}
				}

				if (section.PointerToRawData != 0 && section.PointerToRawData < endOfRawData)
					return true;
				if ((section.PointerToRawData + section.SizeOfRawData) < section.PointerToRawData)
					return true;
				if ((section.PointerToRawData + section.SizeOfRawData) > peFileSize)
					return true;
				if ((section.VirtualAddress + section.SizeOfRawData - 1) < section.SizeOfRawData)
					return true;

				if (section.SizeOfRawData != 0 && (section.PointerToRawData + section.SizeOfRawData) > endOfRawData)
					endOfRawData = (section.PointerToRawData + section.SizeOfRawData);
			}

			// Verify the position and range of the digital signature
			if (SecurityDir.VirtualAddress && SecurityDir.Size)
			{
				if (SecurityDir.VirtualAddress < endOfRawData || SecurityDir.VirtualAddress > peFileSize)
					return true;
				if ((SecurityDir.VirtualAddress + SecurityDir.Size) != peFileSize)
					return true;
				if ((SecurityDir.VirtualAddress + SecurityDir.Size) < endOfRawData)
					return true;
				if (SecurityDir.VirtualAddress < pIOH->SizeOfHeaders)
					return true;
				if (SecurityDir.VirtualAddress & 0x03)
					return true;
			}

			// Windows 8+ fails to load the image if the certificate is zeroed
			// We don't want to parse and verify the certificate here,
			// just check for the most blatantly corrupt certificates
			//if (forceIntegrityCheckCertificate)
			{
				std::uint8_t* certPtr = (uint8_t*)pvBaseAddress + SecurityDir.VirtualAddress;
				if (SecurityDir.Size > 2 && certPtr[0] == 0 && certPtr[1] == 0)
					return true;
			}
		}

		// All checks passed.
		return false;
	}
}
