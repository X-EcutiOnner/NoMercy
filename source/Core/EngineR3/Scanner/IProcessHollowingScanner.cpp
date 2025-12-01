#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"




namespace NoMercy
{
	void IScanner::CheckProcessHollow(HANDLE hProcess)
	{
		IMAGE_DOS_HEADER ProcessDosHeader{ 0 };
		IMAGE_NT_HEADERS64 ProcessNtHeader64{ 0 };
		IMAGE_NT_HEADERS ProcessNtHeader32{ 0 };
		PIMAGE_SECTION_HEADER ProcessSecHeaders = nullptr;
		WORD NumOfSecProcess = 0;

		IMAGE_DOS_HEADER DiskImageDosHeader{ 0 };
		IMAGE_NT_HEADERS64 DiskImageNtHeader64{ 0 };
		IMAGE_NT_HEADERS DiskImageNtHeader32{ 0 };
		PIMAGE_SECTION_HEADER DiskImageSecHeaders = nullptr;
		WORD NumOfSecImage = 0;

		auto CmpNtFileHeaders = [](auto ProcHeader, auto ImageHeader)
		{
			if (ProcHeader.FileHeader.TimeDateStamp == ImageHeader.FileHeader.TimeDateStamp)
			{
				if (ProcHeader.FileHeader.SizeOfOptionalHeader == ImageHeader.FileHeader.SizeOfOptionalHeader)
				{
					if (ProcHeader.FileHeader.Characteristics == ImageHeader.FileHeader.Characteristics)
					{
						return 0;
					}
				}
			}
			return 1;
		};
		auto CmpNtOptHeaders = [](auto ProcHeader, auto ImageHeader)
		{
			if (ProcHeader.OptionalHeader.CheckSum == ImageHeader.OptionalHeader.CheckSum)
			{
				if (ProcHeader.OptionalHeader.AddressOfEntryPoint == ImageHeader.OptionalHeader.AddressOfEntryPoint)
				{
					if (ProcHeader.OptionalHeader.BaseOfCode == ImageHeader.OptionalHeader.BaseOfCode)
					{
						// if (ProcHeader.OptionalHeader.BaseOfData == ImageHeader.OptionalHeader.BaseOfData)
						{
							if (ProcHeader.OptionalHeader.SizeOfInitializedData == ImageHeader.OptionalHeader.SizeOfInitializedData)
							{
								if (ProcHeader.OptionalHeader.SizeOfImage == ImageHeader.OptionalHeader.SizeOfImage)
								{
									return 0;
								}
							}
						}
					}
				}
			}
			return 1;
		};
		auto CmpSecHeaders = [](PIMAGE_SECTION_HEADER ProcessHeaders, PIMAGE_SECTION_HEADER ImageHeaders, int Sections)
		{
			std::vector <IMAGE_SECTION_HEADER> vProcHeaders;
			std::vector <IMAGE_SECTION_HEADER> vImageHeaders;
			for (int num = 0; num < Sections; num++)
			{
				vProcHeaders.emplace_back(ProcessHeaders[num]);
				vImageHeaders.emplace_back(ImageHeaders[num]);
			}

			for (const auto& procHeader : vProcHeaders)
			{
				auto bFound = false;
				for (const auto& imageHeader : vImageHeaders)
				{
					if (!memcmp(procHeader.Name, imageHeader.Name, 8) &&
						procHeader.VirtualAddress == imageHeader.VirtualAddress &&
						procHeader.SizeOfRawData == imageHeader.SizeOfRawData &&
						procHeader.Characteristics == imageHeader.Characteristics)
					{
						bFound = true;
					}
				}

				if (!bFound)
					return 1;
			}
			return 0;
		};

		auto get_sections_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				SCANNER_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return false;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return false;
			}

			NTSTATUS ntStat = 0;
			ULONG64 ul64ReadBytes = 0;

			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pPBI = { 0 };
			ntStat = g_winAPIs->NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtWow64QueryInformationProcess64(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (!pPBI.PebBaseAddress)
			{
				SCANNER_LOG(LL_ERR, L"pPBI.PebBaseAddress is null");
				return false;
			}

			wow64pp::defs::PEB_64 pPEB = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_WARN, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			auto nullBuff = { 0x0 };
			if (!memcmp(&pPEB, &nullBuff, sizeof(pPEB)))
			{
				SCANNER_LOG(LL_ERR, L"pPEB is null");
				return false;
			}

			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)pPEB.ImageBaseAddress, &ProcessDosHeader, sizeof(ProcessDosHeader), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(2) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (ProcessDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			{
				SCANNER_LOG(LL_ERR, L"invalid dos signature");
				return false;
			}

			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, hProcess, (PVOID64)(ProcessDosHeader.e_lfanew + pPEB.ImageBaseAddress), &ProcessNtHeader64, sizeof(ProcessNtHeader64), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(3) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (ProcessNtHeader64.Signature != IMAGE_NT_SIGNATURE)
			{
				SCANNER_LOG(LL_ERR, L"invalid nt signature");
				return false;
			}

			NumOfSecProcess = ProcessNtHeader64.FileHeader.NumberOfSections;
			if (!NumOfSecProcess)
			{
				SCANNER_LOG(LL_ERR, L"null section count");
				return false;
			}

			ProcessSecHeaders = (PIMAGE_SECTION_HEADER)CMemHelper::Allocate(NumOfSecProcess * sizeof(IMAGE_SECTION_HEADER));
			if (!ProcessSecHeaders)
			{
				SCANNER_LOG(LL_ERR, L"null sections ptr");
				return false;
			}

			for (WORD num = 0; num < NumOfSecProcess; num++)
			{
				ntStat = wow64pp::call_function(x64_NtReadVirtualMemory,
					hProcess,
					(PVOID64)(pPEB.ImageBaseAddress + ProcessDosHeader.e_lfanew + sizeof(ProcessNtHeader64) + num * sizeof(IMAGE_SECTION_HEADER)),
					ProcessSecHeaders + num, sizeof(IMAGE_SECTION_HEADER), &ul64ReadBytes
				);
				if (!NT_SUCCESS(ntStat))
				{
					SCANNER_LOG(LL_ERR, L"x64_NtReadVirtualMemory(4#%d) fail! Target process: %p Status: %p", num, hProcess, ntStat);
					return false;
				}
			}

			if (!memcmp(ProcessSecHeaders, &nullBuff, NumOfSecProcess * sizeof(IMAGE_SECTION_HEADER)))
			{
				SCANNER_LOG(LL_ERR, L"ProcessSecHeaders is null");
				return false;
			}

			return true;
		};
		auto get_sections_native = [&] {
			NTSTATUS ntStat = 0;
			SIZE_T ulReadBytes = 0;

			PROCESS_BASIC_INFORMATION pPBI = { 0 };
			ntStat = g_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtQueryInformationProcess(ProcessBasicInformation) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (!pPBI.PebBaseAddress)
			{
				SCANNER_LOG(LL_ERR, L"pPBI.PebBaseAddress is null");
				return false;
			}

			PEB pPEB = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ulReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_WARN, L"NtReadVirtualMemory(1) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			auto nullBuff = { 0x0 };
			if (!memcmp(&pPEB, &nullBuff, sizeof(pPEB)))
			{
				SCANNER_LOG(LL_ERR, L"pPEB is null");
				return false;
			}

			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)pPEB.ImageBaseAddress, &ProcessDosHeader, sizeof(ProcessDosHeader), &ulReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtReadVirtualMemory(2) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (ProcessDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
			{
				SCANNER_LOG(LL_ERR, L"invalid dos signature");
				return false;
			}

			ntStat = g_winAPIs->NtReadVirtualMemory(hProcess, (PVOID)(ProcessDosHeader.e_lfanew + (DWORD_PTR)pPEB.ImageBaseAddress), &ProcessNtHeader32, sizeof(ProcessNtHeader32), &ulReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				SCANNER_LOG(LL_ERR, L"NtReadVirtualMemory(3) fail! Target process: %p Status: %p", hProcess, ntStat);
				return false;
			}

			if (ProcessNtHeader32.Signature != IMAGE_NT_SIGNATURE)
			{
				SCANNER_LOG(LL_ERR, L"invalid nt signature");
				return false;
			}

			NumOfSecProcess = ProcessNtHeader32.FileHeader.NumberOfSections;
			if (!NumOfSecProcess)
			{
				SCANNER_LOG(LL_ERR, L"null section count");
				return false;
			}

			ProcessSecHeaders = (PIMAGE_SECTION_HEADER)CMemHelper::Allocate(NumOfSecProcess * sizeof(IMAGE_SECTION_HEADER));
			if (!ProcessSecHeaders)
			{
				SCANNER_LOG(LL_ERR, L"null sections ptr");
				return false;
			}

			for (WORD num = 0; num < NumOfSecProcess; num++)
			{
				ntStat = g_winAPIs->NtReadVirtualMemory(
					hProcess,
					(PVOID)((DWORD_PTR)pPEB.ImageBaseAddress + ProcessDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + num * sizeof(IMAGE_SECTION_HEADER)),
					ProcessSecHeaders + num, sizeof(IMAGE_SECTION_HEADER), &ulReadBytes
				);
				if (!NT_SUCCESS(ntStat))
				{
					SCANNER_LOG(LL_ERR, L"NtReadVirtualMemory(4#%d) fail! Target process: %p Status: %p", num, hProcess, ntStat);
					return false;
				}
			}

			if (!memcmp(ProcessSecHeaders, &nullBuff, NumOfSecProcess * sizeof(IMAGE_SECTION_HEADER)))
			{
				SCANNER_LOG(LL_ERR, L"ProcessSecHeaders is null");
				return false;
			}

			return true;
		};

		auto get_disk_sections_wow64 = [&](const wchar_t* wszFilePath) {
			auto hFile = g_winAPIs->CreateFileW(wszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (!IS_VALID_HANDLE(hFile))
			{
				SCANNER_LOG(LL_ERR, L"CreateFileA failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			if (!g_winAPIs->ReadFile(hFile, &DiskImageDosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL))
			{
				SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageDosHeader) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->SetFilePointer(hFile, DiskImageDosHeader.e_lfanew, NULL, FILE_BEGIN))
			{
				SCANNER_LOG(LL_ERR, L"SetFilePointer(DiskImageDosHeader.e_lfanew) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->ReadFile(hFile, &DiskImageNtHeader64, sizeof(DiskImageNtHeader64), NULL, NULL))
			{
				SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageNtHeader) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->SetFilePointer(hFile, DiskImageDosHeader.e_lfanew + sizeof(DiskImageNtHeader64), NULL, FILE_BEGIN))
			{
				SCANNER_LOG(LL_ERR, L"SetFilePointer(DiskImageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			NumOfSecImage = DiskImageNtHeader64.FileHeader.NumberOfSections;
			if (!NumOfSecImage)
			{
				SCANNER_LOG(LL_ERR, L"null disk section count");
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			DiskImageSecHeaders = (PIMAGE_SECTION_HEADER)CMemHelper::Allocate(NumOfSecImage * sizeof(IMAGE_SECTION_HEADER));
			for (WORD num = 0; num < NumOfSecImage; num++)
			{
				if (!g_winAPIs->ReadFile(hFile, DiskImageSecHeaders + num, sizeof(IMAGE_SECTION_HEADER), NULL, NULL))
				{
					SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageSecHeaders + %u) failed with error: %u", num, g_winAPIs->GetLastError());
					g_winAPIs->CloseHandle(hFile);
					return false;
				}
			}

			g_winAPIs->CloseHandle(hFile);
			return true;
		};
		auto get_disk_sections_native = [&](const wchar_t* wszFilePath) {
			auto hFile = g_winAPIs->CreateFileW(wszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (!IS_VALID_HANDLE(hFile))
			{
				SCANNER_LOG(LL_ERR, L"CreateFileA failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			if (!g_winAPIs->ReadFile(hFile, &DiskImageDosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL))
			{
				SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageDosHeader) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->SetFilePointer(hFile, DiskImageDosHeader.e_lfanew, NULL, FILE_BEGIN))
			{
				SCANNER_LOG(LL_ERR, L"SetFilePointer(DiskImageDosHeader.e_lfanew) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->ReadFile(hFile, &DiskImageNtHeader32, sizeof(DiskImageNtHeader32), NULL, NULL))
			{
				SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageNtHeader) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			if (!g_winAPIs->SetFilePointer(hFile, DiskImageDosHeader.e_lfanew + sizeof(DiskImageNtHeader32), NULL, FILE_BEGIN))
			{
				SCANNER_LOG(LL_ERR, L"SetFilePointer(DiskImageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)) failed with error: %u", g_winAPIs->GetLastError());
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			auto NumOfSecImage = DiskImageNtHeader32.FileHeader.NumberOfSections;
			if (!NumOfSecImage)
			{
				SCANNER_LOG(LL_ERR, L"null disk section count");
				g_winAPIs->CloseHandle(hFile);
				return false;
			}

			DiskImageSecHeaders = (PIMAGE_SECTION_HEADER)CMemHelper::Allocate(NumOfSecImage * sizeof(IMAGE_SECTION_HEADER));
			for (WORD num = 0; num < NumOfSecImage; num++)
			{
				if (!g_winAPIs->ReadFile(hFile, DiskImageSecHeaders + num, sizeof(IMAGE_SECTION_HEADER), NULL, NULL))
				{
					SCANNER_LOG(LL_ERR, L"ReadFile(DiskImageSecHeaders + %u) failed with error: %u", num, g_winAPIs->GetLastError());
					g_winAPIs->CloseHandle(hFile);
					return false;
				}
			}

			g_winAPIs->CloseHandle(hFile);
			return true;
		};

		auto bRet = false;
		const auto is_wow64 = CApplication::Instance().FunctionsInstance()->IsWow64Process(NtCurrentProcess());
		if (is_wow64)
			bRet = get_sections_wow64();
		else
			bRet = get_sections_native();

		if (!bRet)
		{
			SCANNER_LOG(LL_ERR, L"get_sections has been failed!");
			return;
		}

		wchar_t wszFilePath[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->GetModuleFileNameExW(hProcess, NULL, wszFilePath, MAX_PATH))
		{
			SCANNER_LOG(LL_ERR, L"GetModuleFileNameExA failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		if (is_wow64)
			bRet = get_disk_sections_wow64(wszFilePath);
		else
			bRet = get_disk_sections_native(wszFilePath);

		if (!bRet)
		{
			SCANNER_LOG(LL_ERR, L"get_disk_sections has been failed!");
			return;
		}

		if (NumOfSecProcess != NumOfSecImage)
		{
			SCANNER_LOG(LL_ERR, L"section count mismatch: %u/%u", NumOfSecProcess, NumOfSecImage);
			return; // TODO: throw
		}

		DWORD DosStatus = 0;
		DWORD NtFileStatus = 0;
		DWORD NtOptStatus = 0;
		DWORD SecStatus = 0;

		if (is_wow64)
		{
			DosStatus = ProcessDosHeader.e_lfanew != DiskImageDosHeader.e_lfanew ? 1 : 0;
			NtFileStatus = CmpNtFileHeaders(ProcessNtHeader64, DiskImageNtHeader64);
			NtOptStatus = CmpNtOptHeaders(ProcessNtHeader64, DiskImageNtHeader64);
			SecStatus = CmpSecHeaders(ProcessSecHeaders, DiskImageSecHeaders, NumOfSecImage);
		}
		else
		{
			DosStatus = ProcessDosHeader.e_lfanew != DiskImageDosHeader.e_lfanew ? 1 : 0;
			NtFileStatus = CmpNtFileHeaders(ProcessNtHeader32, DiskImageNtHeader32);
			NtOptStatus = CmpNtOptHeaders(ProcessNtHeader32, DiskImageNtHeader32);
			SecStatus = CmpSecHeaders(ProcessSecHeaders, DiskImageSecHeaders, NumOfSecImage);
		}

		if (DosStatus || NtFileStatus || NtOptStatus || SecStatus)
		{
			SCANNER_LOG(LL_ERR, L"Process: %s pe header mismatch: %u-%u-%u-%u, %u/%u", wszFilePath, DosStatus, NtFileStatus, NtOptStatus, SecStatus, NumOfSecProcess, NumOfSecImage);
			return; // TODO: throw
		}

		CMemHelper::Free(ProcessSecHeaders);
		CMemHelper::Free(DiskImageSecHeaders);
	}
};
