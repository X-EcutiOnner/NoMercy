#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <fstream>
#include <sstream>

bool StripDebugInfo(const std::string& stFileName)
{
	bool bRet = false;
	typedef PIMAGE_NT_HEADERS(NTAPI* TRtlImageNtHeader)(IN PVOID ModuleAddress);
	typedef PIMAGE_NT_HEADERS(WINAPI* TCheckSumMappedFile)(_In_ PVOID BaseAddress, _In_ DWORD FileLength, _Out_ PDWORD HeaderSum, _Out_ PDWORD CheckSum);

	HMODULE hNtdll = nullptr;
	HMODULE hImageHlp = nullptr;
	TRtlImageNtHeader RtlImageNtHeader = nullptr;
	TCheckSumMappedFile CheckSumMappedFile = nullptr;
	
	HANDLE  hFile = nullptr;
	HANDLE  hFileMap = nullptr;
	DWORD   FileSize = 0;
	LPVOID  ImageBase = nullptr;

	INT i, cEntries = 0;

	PIMAGE_OPTIONAL_HEADER32    oh32 = nullptr;
	PIMAGE_OPTIONAL_HEADER64    oh64 = nullptr;
	PIMAGE_SECTION_HEADER       SectionHeader = nullptr;

	ULONG DebugDirRva, DebugDirSize, Offset, CurrentCheckSum, NewCheckSum = 0;

	IMAGE_NT_HEADERS* NtHeaders = nullptr;
	IMAGE_DEBUG_DIRECTORY* DebugDirectory = nullptr;
	LPBYTE pDebugInfo = nullptr;

	__try
	{
		hNtdll = LoadLibraryA("ntdll.dll");
		if (!hNtdll)
		{
			printf("LoadLibraryA(ntdll) failed with error: %u", GetLastError());
			return false;
		}
		hImageHlp = LoadLibraryA("imagehlp.dll");
		if (!hImageHlp)
		{
			printf("LoadLibraryA(imagehlp) failed with error: %u", GetLastError());
			return false;
		}

		RtlImageNtHeader = (TRtlImageNtHeader)GetProcAddress(hNtdll, "RtlImageNtHeader");
		if (!RtlImageNtHeader)
		{
			printf("GetProcAddress failed with error: %u", GetLastError());
			return false;
		}
		CheckSumMappedFile = (TCheckSumMappedFile)GetProcAddress(hImageHlp, "CheckSumMappedFile");
		if (!CheckSumMappedFile)
		{
			printf("GetProcAddress failed with error: %u", GetLastError());
			return false;
		}
		
		hFile = CreateFileA(stFileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			printf("CreateFileA failed with error: %u", GetLastError());
			__leave;
		}

		FileSize = GetFileSize(hFile, NULL);
		if (!FileSize || FileSize == INVALID_FILE_SIZE)
		{
			printf("GetFileSize failed with error: %u", GetLastError());
			__leave;
		}

		hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
		if (!hFileMap)
		{
			printf("CreateFileMapping failed with error: %u", GetLastError());
			__leave;
		}

		ImageBase = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
		if (!ImageBase)
		{
			printf("MapViewOfFile failed with error: %u", GetLastError());
			__leave;
		}

		NtHeaders = RtlImageNtHeader(ImageBase);
		if (!NtHeaders)
		{
			printf("RtlImageNtHeader failed with error: %u", GetLastError());
			__leave;
		}

		oh32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader;
		oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

		if (NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && 
			NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		{
			printf("Unsuported FileHeader.Machine value");
			__leave;
		}

		if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			DebugDirRva = oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
			if (!DebugDirRva)
			{
				printf("DebugDirectory address not set");
				__leave;
			}
			else
			{
				printf("Setting DebugDirectory.VirtualAddress to zero");
				oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
			}

			DebugDirSize = oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			if (!DebugDirSize)
			{
				printf("DebugDirectory is zero size");
				__leave;
			}
			else
			{
				printf("Setting DebugDirectory.Size to zero");
				oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
			}
		}
		else
		{
			DebugDirRva = oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
			if (!DebugDirRva)
			{
				printf("DebugDirectory address not set");
				__leave;
			}
			else
			{
				printf("Setting DebugDirectory.VirtualAddress to zero");
				oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
			}

			DebugDirSize = oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			if (!DebugDirSize)
			{
				printf("DebugDirectory is zero size");
				__leave;
			}
			else
			{
				printf("Setting DebugDirectory.Size to zero");
				oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
			}
		}

		SectionHeader = ImageRvaToSection(NtHeaders, ImageBase, DebugDirRva);
		if (SectionHeader)
		{
			Offset = DebugDirRva - ((ULONG)(SectionHeader->VirtualAddress - SectionHeader->PointerToRawData));
			cEntries = DebugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
			
			DebugDirectory = (IMAGE_DEBUG_DIRECTORY *)((ULONG_PTR)ImageBase + Offset);
			if (DebugDirectory)
			{
				for (i = 1; i <= cEntries; i++)
				{
					if (DebugDirectory->Type == IMAGE_DEBUG_TYPE_POGO)
					{
						pDebugInfo = (LPBYTE)((ULONG_PTR)ImageBase + DebugDirectory->PointerToRawData);
						if (pDebugInfo)
						{
							RtlSecureZeroMemory(pDebugInfo, DebugDirectory->SizeOfData);
							printf("Zeroing debug data");
						}
					}
					
					DebugDirectory++;
					
					if (DebugDirectory->SizeOfData == 0)
						continue;
				}
			}
			else
			{
				printf("DebugDirectory address invalid");
			}
		}
		else
		{
			printf("SectionHeader address invalid");
		}

		NewCheckSum = 0;
		CheckSumMappedFile(ImageBase, FileSize, &CurrentCheckSum, &NewCheckSum);
		
		if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			oh64->CheckSum = NewCheckSum;
		}
		else
		{
			oh32->CheckSum = NewCheckSum;
		}
		
		bRet = true;
	}
	__finally
	{
		if (ImageBase)
		{
			FlushViewOfFile(ImageBase, 0);
			UnmapViewOfFile(ImageBase);
		}

		if (hFileMap && hFileMap != INVALID_HANDLE_VALUE)
			CloseHandle(hFileMap);

		if (hFile && hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}

	return bRet;
}
