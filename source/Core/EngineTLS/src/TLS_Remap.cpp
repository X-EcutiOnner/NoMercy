#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"


namespace NoMercyTLS
{
#define PAGE_SIZE 0x1000
#define POINTER_IS_ALIGNED(Pointer, Alignment) \
	(((((ULONG_PTR)(Pointer)) & (((Alignment)-1))) == 0) ? TRUE : FALSE)

	static ULONG g_CharacteristicsProtectionMap[2][2][2] =
	{
		{
			{ PAGE_NOACCESS, PAGE_WRITECOPY },
			{ PAGE_READONLY, PAGE_READWRITE }

		},
		{
			{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
			{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE }
		},
	};

	static bool ValidateRemappedPeSectionProtection(PVOID pSectionBase)
	{
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		auto ntStatus = NT::NtQueryVirtualMemory(NtCurrentProcess(), pSectionBase, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			TLS_LOG("NtQueryVirtualMemory (%p) failed with error: %p", pSectionBase, ntStatus);
			return false;
		}

		ULONG TestProtect = 0;
		if (PAGE_EXECUTE_READWRITE != mbi.Protect)
			TestProtect = PAGE_EXECUTE_READWRITE;
		else
			TestProtect = PAGE_NOACCESS;

		ULONG PreviousProtect = 0;
		PVOID pvTargetAddr = pSectionBase;
		SIZE_T cbTargetSize = mbi.RegionSize;

		ntStatus = NT::NtProtectVirtualMemory(NtCurrentProcess(), &pvTargetAddr, &cbTargetSize, TestProtect, &PreviousProtect);
		if (NT_SUCCESS(ntStatus))
		{
			TLS_LOG("NtProtectVirtualMemory (%p / %p) failed with error: %p", pSectionBase, PreviousProtect, ntStatus);
			return false;
		}

		return true;
	}

	static bool ValidateRemappedImageProtection(ULONG_PTR ImageBase)
	{
#ifdef _DEBUG
		TLS_LOG("Validating remapped image protection.");
#endif

		const auto dos_header = (PIMAGE_DOS_HEADER)ImageBase;
		if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			TLS_LOG("ValidateRemappedImageProtection module dos header is not valid");
			return false;
		}

		auto pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + dos_header->e_lfanew);
		if (!pNtHeaders || pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			TLS_LOG("ValidateRemappedImageProtection module nt header is not valid");
			return false;
		}

		auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		if (!pSectionHeader)
		{
			TLS_LOG("IMAGE_FIRST_SECTION failed. (BaseAddress = 0x%IX)", ImageBase);
			return false;
		}

		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			if (!ValidateRemappedPeSectionProtection((PVOID)(ImageBase + pSectionHeader[i].VirtualAddress)))
			{
				TLS_LOG("ValidateRemappedPeSectionProtection failed. Section: %s", (char*)pSectionHeader[i].Name);
				return false;
			}
		}

		if (!ValidateRemappedPeSectionProtection((PVOID)ImageBase))
		{
			TLS_LOG("ValidateRemappedPeSectionProtection failed.");
			return false;
		}

		return true;
	}

	static bool MapProtectedView(HANDLE hProcess, HANDLE hSection, ULONG_PTR BaseAddress, SIZE_T cbSize, SIZE_T cbOffset, ULONG Protection)
	{
		auto pViewBase = (PVOID)BaseAddress;
		auto cbViewSize = cbSize;

		LARGE_INTEGER cbSectionOffset = {};
		cbSectionOffset.QuadPart = cbOffset;

		const auto ntStatus = NT::NtMapViewOfSection(hSection, hProcess, &pViewBase, 0, 0, &cbSectionOffset, &cbViewSize, ViewUnmap, SEC_NO_CHANGE, Protection);
		if (!NT_SUCCESS(ntStatus))
		{
			TLS_LOG("NtMapViewOfSection failed: 0x%X (Base = 0x%p, Offset = 0x%lld, Size = 0x%IX)", ntStatus, pViewBase, cbSectionOffset.QuadPart, cbViewSize);
			return false;
		}

		return true;
	}

	static ULONG ConvertSectionCharacteristicsToPageProtection(ULONG Characteristics)
	{
		auto fExecutable = false;
		auto fReadable = false;
		auto fWritable = false;

		if (IMAGE_SCN_MEM_EXECUTE & Characteristics)
			fExecutable = true;

		if (IMAGE_SCN_MEM_READ & Characteristics)
			fReadable = true;

		if (IMAGE_SCN_MEM_WRITE & Characteristics)
			fWritable = true;

		auto Protection = g_CharacteristicsProtectionMap[fExecutable][fReadable][fWritable];
		if (IMAGE_SCN_MEM_NOT_CACHED & Characteristics)
			Protection |= PAGE_NOCACHE;

		return Protection;
	}

	static bool VerifyPeSectionAlignment(PIMAGE_NT_HEADERS pNtHeaders)
	{
		bool bRet = false;
#ifdef _DEBUG
		TLS_LOG("Verifying pe section alignment:");
#endif

		// Query the system allocation granularity.
		SYSTEM_INFO SystemInfo = {};
		GetSystemInfo(&SystemInfo);

		auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		if (!pSectionHeader)
		{
			TLS_LOG("Section header does not exist!");
			goto _complete;
		}

		// Verify section alignment.
		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			auto SectionBase = pNtHeaders->OptionalHeader.ImageBase + pSectionHeader[i].VirtualAddress;

#ifdef _DEBUG
			TLS_LOG("%-8.8s 0x%IX - 0x%IX, 0x%08X",
				pSectionHeader[i].Name, SectionBase, SectionBase + pSectionHeader[i].Misc.VirtualSize, pSectionHeader[i].Misc.VirtualSize
			);
#endif

			if (!POINTER_IS_ALIGNED(SectionBase, SystemInfo.dwAllocationGranularity))
			{
#ifdef _DEBUG
				TLS_LOG("Unexpected section alignment in section: %p", SectionBase);
#endif
				goto _complete;
			}
		}

		// Verify pe header alignment.
		if (!POINTER_IS_ALIGNED(pNtHeaders->OptionalHeader.ImageBase, SystemInfo.dwAllocationGranularity))
		{
#ifdef _DEBUG
			TLS_LOG("Unexpected section alignment in pe header: %p", pNtHeaders->OptionalHeader.ImageBase);
#endif
			goto _complete;
		}

		bRet = true;
_complete:
		return bRet;
	}

	static void CopyPeSections(PIMAGE_NT_HEADERS pNtHeaders, ULONG_PTR DestinationBase)
	{
		auto SourceBase = pNtHeaders->OptionalHeader.ImageBase;
		if (!SourceBase)
		{
			TLS_LOG("SourceBase does not exist!");
			return;
		}

		auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		if (!pSectionHeader)
		{
			TLS_LOG("Section header does not exist!");
			return;
		}

		// We copy each pe section individually because images compiled with the '/ALIGN' linker option will have reserved memory padding.
		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
#ifdef _DEBUG
			TLS_LOG("Copying %-8.8s from 0x%IX to 0x%IX, 0x%08X",
				pSectionHeader[i].Name, SourceBase + pSectionHeader[i].VirtualAddress, DestinationBase + pSectionHeader[i].VirtualAddress, pSectionHeader[i].Misc.VirtualSize);
#endif

			RtlCopyMemory(
				(PVOID)(DestinationBase + pSectionHeader[i].VirtualAddress),
				(PVOID)(SourceBase + pSectionHeader[i].VirtualAddress),
				pSectionHeader[i].Misc.VirtualSize
			);
		}

		// Copy the pe header.
		RtlCopyMemory((PVOID)DestinationBase, (PVOID)SourceBase, PAGE_SIZE);
	}

	bool __cdecl RemapImageRoutine(HANDLE hProcess, PVOID pRemapRegion, DWORD dwSize)
	{
		const auto dos_header = (PIMAGE_DOS_HEADER)pRemapRegion;
		if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			TLS_LOG("Remapped module dos header is not valid");
			return false;
		}

		auto pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pRemapRegion + dos_header->e_lfanew);
		if (!pNtHeaders || pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			TLS_LOG("Remapped module nt header is not valid");
			return false;
		}

		LARGE_INTEGER cbSectionSize = {};
		cbSectionSize.QuadPart = pNtHeaders->OptionalHeader.SizeOfImage;

		// Create a page-file-backed section to store the remapped image.
		HANDLE hSection = nullptr;
		auto ntstatus = NT::NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, &cbSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, nullptr);
		if (!NT_SUCCESS(ntstatus))
		{
			TLS_LOG("NtCreateSection failed with error: %p", ntstatus);
			return false;
		}

		// Map a view of the entire section.
		PVOID pViewBase = nullptr;
		SIZE_T cbViewSize = 0;
		LARGE_INTEGER cbSectionOffset = {};
		ntstatus = NT::NtMapViewOfSection(hSection, hProcess, &pViewBase, 0, pNtHeaders->OptionalHeader.SizeOfImage, &cbSectionOffset, &cbViewSize, ViewUnmap, 0, PAGE_READWRITE);
		if (!NT_SUCCESS(ntstatus))
		{
			TLS_LOG("NtMapViewOfSection failed with error: %p", ntstatus);
			NT::NtClose(hSection);
			return false;
		}

		// Copy the image to our view.
		auto SourceBase = pNtHeaders->OptionalHeader.ImageBase;
		if (!SourceBase)
		{
			TLS_LOG("Target image base does not exist!");
			NT::NtClose(hSection);
			return false;
		}

		auto pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		if (!pSectionHeader)
		{
			TLS_LOG("1/ Target section header does not exist!");
			NT::NtClose(hSection);
			return false;
		}

		// We copy each pe section individually because images compiled with the  '/ALIGN' linker option will have reserved memory padding.
		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
#ifdef _DEBUG
			TLS_LOG("Copying %-8.8s from 0x%IX to 0x%IX, 0x%08X",
				pSectionHeader[i].Name, SourceBase + pSectionHeader[i].VirtualAddress, (DWORD_PTR)pViewBase + pSectionHeader[i].VirtualAddress, pSectionHeader[i].Misc.VirtualSize
			);
#endif

			SIZE_T write_size = 0;
			ntstatus = NT::NtWriteVirtualMemory(hProcess, (PVOID)((DWORD_PTR)pViewBase + pSectionHeader[i].VirtualAddress), (PVOID)(SourceBase + pSectionHeader[i].VirtualAddress), pSectionHeader[i].Misc.VirtualSize, &write_size);
			if (!NT_SUCCESS(ntstatus))
			{
				TLS_LOG("NtWriteVirtualMemory(1-%d) failed with error: %p", i, ntstatus);
				NT::NtClose(hSection);
				return false;
			}
		}

		// Copy the pe header.
		SIZE_T write_size = 0;
		ntstatus = NT::NtWriteVirtualMemory(hProcess, (PVOID)pViewBase, (PVOID)SourceBase, PAGE_SIZE, &write_size);
		if (!NT_SUCCESS(ntstatus))
		{
			TLS_LOG("NtWriteVirtualMemory(2) failed: %p", ntstatus);
			NT::NtClose(hSection);
			return false;
		}

		// Unmap the copy-view because we no longer need it.
		ntstatus = NT::NtUnmapViewOfSection(hProcess, pViewBase);
		if (!NT_SUCCESS(ntstatus))
		{
			TLS_LOG("NtUnmapViewOfSection(1) failed: 0x%X", ntstatus);
			NT::NtClose(hSection);
			return false;
		}

		// Unmap the original image.
		ULONG_PTR ImageBase = pNtHeaders->OptionalHeader.ImageBase;
#ifdef _DEBUG
		TLS_LOG("Unmapping image base: %p", ImageBase);
#endif

		ntstatus = NT::NtUnmapViewOfSection(hProcess, (PVOID)ImageBase);
		if (!NT_SUCCESS(ntstatus))
		{
			TLS_LOG("NtUnmapViewOfSection(2) failed: 0x%X", ntstatus);
			NT::NtClose(hSection);
			return false;
		}

		// Reconstruct the image by mapping a view of the section for each pe section in the image.
		pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		if (!pSectionHeader)
		{
			TLS_LOG("2/ Target section header does not exist!");
			NT::NtClose(hSection);
			return false;
		}

		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
		{
			auto Protection = ConvertSectionCharacteristicsToPageProtection(pSectionHeader[i].Characteristics);

			if (!MapProtectedView(hProcess, hSection, ImageBase + pSectionHeader[i].VirtualAddress, pSectionHeader[i].Misc.VirtualSize, pSectionHeader[i].VirtualAddress, Protection))
			{
				TLS_LOG("MapProtectedView (%d) failed in section: %-8.8s", i, pSectionHeader[i].Name);
				NT::NtClose(hSection);
				return false;
			}
		}

		// Map a view for the pe header.
		if (!MapProtectedView(hProcess, hSection, ImageBase, PAGE_SIZE, 0, PAGE_READONLY))
		{
			TLS_LOG("MapProtectedView (pe) failed.");
			NT::NtClose(hSection);
			return false;
		}

		NT::NtClose(hSection);
		return true;
	}

	bool TLS_RemapImage(ULONG_PTR ImageBase)
	{
#ifdef _DEBUG
		TLS_LOG("Remapping module: %p", ImageBase);
#endif
		bool bRet = false;
		PVOID pvBaseAddress = nullptr;

		auto pNtHeaders = RtlImageNtHeader((PVOID)ImageBase);
		if (!pNtHeaders)
		{
			TLS_LOG("RtlImageNtHeader (%p) failed.", ImageBase);
			goto _complete;
		}

		if (!VerifyPeSectionAlignment(pNtHeaders))
		{
#ifdef _DEBUG
			TLS_LOG("VerifyPeSectionAlignment failed.");
#endif
			bRet = true;
			goto _complete;
		}

		// Allocate an executable and writable buffer where the remap routine will execute.
		SIZE_T cbRegionSize = pNtHeaders->OptionalHeader.SizeOfImage;
		auto ntStatus = NT::NtAllocateVirtualMemory(NtCurrentProcess(), &pvBaseAddress, 0, &cbRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(ntStatus))
		{
			TLS_LOG("NtAllocateVirtualMemory failed with error: %p", ntStatus);
			goto _complete;
		}

#ifdef _DEBUG
		TLS_LOG("RemapRegion: 0x%p", (ULONG_PTR)pvBaseAddress);
#endif

		// Copy the image to the remap region.
		CopyPeSections(pNtHeaders, (ULONG_PTR)pvBaseAddress);
		
#if 1 // test
		// Locate the address of the remap routine inside the remap region.
		typedef BOOL(NTAPI* REMAP_ROUTINE)(_In_ PVOID pRemapRegion);

		auto fpRemapRoutine = (REMAP_ROUTINE)(
			(ULONG_PTR)pvBaseAddress +
			(ULONG_PTR)TLS_RemapImage -
			ImageBase
		);

#ifdef _DEBUG
		TLS_LOG("RemapRoutine: 0x%p", (ULONG_PTR)fpRemapRoutine);
#endif

		// Invoke the remap routine inside the remap region.
		if (!fpRemapRoutine(pvBaseAddress))
		{
			TLS_LOG("RemapImageRoutine failed.");
			goto _complete;
		}
#else
		// Invoke the remap routine inside the remap region.
		if (!RemapImageRoutine(NtCurrentProcess(), pvBaseAddress, ImageBase))
		{
			TLS_LOG("RemapImageRoutine failed.");
			goto _complete;
		}
#endif

		// Verify that each pe section in the remapped image is protected.
		if (!ValidateRemappedImageProtection(ImageBase))
		{
			TLS_LOG("ValidateRemappedImageProtection failed.");
			goto _complete;
		}

		bRet = true;
_complete:
		if (pvBaseAddress)
			NT::NtFreeVirtualMemory(NtCurrentProcess(), &pvBaseAddress, &cbRegionSize, MEM_RELEASE);

		return bRet;
	}
}
