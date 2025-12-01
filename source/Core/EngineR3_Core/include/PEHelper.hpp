#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <array>
#include <vector>
#include <string>

namespace NoMercyCore
{
	static constexpr auto PE_HEADER_SIZE = 0x1000;

	namespace NPEHelper
	{
		struct PE_HEADER
		{
			PIMAGE_DOS_HEADER dosHeader;
			PIMAGE_NT_HEADERS ntHeaders;
			PIMAGE_FILE_HEADER fileHeader;
			PIMAGE_OPTIONAL_HEADER optionalHeader;
			std::array<PIMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> dataDirectory;
			std::vector<PIMAGE_SECTION_HEADER> sectionHeaders;
		};

		struct REMOTE_PE_HEADER : PE_HEADER
		{
			PVOID remoteBaseAddress;
			BYTE rawData[PE_HEADER_SIZE];
		};
	}

	class CPEFunctions
	{
		public:
			static bool IsValidPEHeader(LPVOID pvBaseAddress);
			static PVOID GetEntryPoint(HMODULE hModule);

			static bool GetSectionInformation(const std::string& szSectionName, LPVOID pvBaseAddress, LPVOID* ppvOffset, PSIZE_T pcbLength);
			static PIMAGE_SECTION_HEADER GetSectionInformation(const std::string& szSectionName, LPVOID pvBaseAddress);
			static bool GetTextSectionInformation(LPVOID pvBaseAddress, LPVOID* ppvOffset, PSIZE_T pcbLength);

			static LPVOID GetSectionPtr(PSTR name, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase);
			static PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader);
			template <class T>
			static LPVOID GetPtrFromRVA(DWORD rva, T* pNTHeader, PBYTE imageBase);
			template <class T>
			static LPVOID GetPtrFromVA(PVOID ptr, T* pNTHeader, PBYTE pImageBase);
			static bool DumpExportsSection(const std::wstring& c_stModuleName, std::multimap <PVOID, std::string>& ExportsList);
			static bool DumpImportsSection(const std::wstring& c_stModuleName, std::multimap <PVOID, std::tuple <std::string, std::string>>& ImportsList);

			static DWORD GetPeChecksum(PVOID pvImageBase, SIZE_T cbSize);

			static FARPROC GetExportAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName, _In_ BOOLEAN MappedAsImage);
			static FARPROC GetProcAddressDisk(HMODULE hMod, const std::string& szAPIName);
			static PVOID GetExportEntry(HMODULE hModule, const std::string& stAPIName, DWORD dwOrdinal = -1);
			static uint64_t CalculateMemChecksumFast(LPCVOID c_pvBase, std::size_t unLength);
			static std::wstring CalculateMemChecksumSHA256(LPCVOID c_pvBase, std::size_t unLength);
			static uint64_t CalculateRemoteMemChecksumFast(HANDLE hProcess, PVOID pvBase, ULONG ulLength);
			static std::wstring CalculateRemoteMemChecksumSHA256(HANDLE hProcess, ptr_t pvBase, ULONG ulLength);
			static std::size_t GetPEHeaderSize(LPVOID pvBaseAddress);
			static std::size_t GetSizeofCode(LPVOID pvBaseAddress);
			static std::size_t OffsetToCode(LPVOID pvBaseAddress);
			static std::size_t GetModuleImageSize(LPVOID pvBaseAddress);

			static PIMAGE_SECTION_HEADER ImageRVA2Section(IMAGE_NT_HEADERS* pImage_NT_Headers, LPVOID pvRVA);
			static UINT_PTR Rva2Offset(LPVOID pvBaseAddress, UINT_PTR pRVA);

			static bool FillPEHeader(LPVOID pvBaseAddress, OUT NPEHelper::PE_HEADER& PEHeader);
			static bool FillRemotePEHeader(HANDLE ProcessHandle, LPVOID pvBaseAddress, OUT NPEHelper::REMOTE_PE_HEADER& PEHeader);

			static bool IsPackedImage(LPVOID pvBaseAddress);

			static bool IsInModule(PVOID Address, DWORD Type, DWORD_PTR& Base);

			static BOOL GetFunctionPtrFromIAT(void* pDosHdr, LPCSTR pImportModuleName, LPCSTR pFunctionSymbol, PVOID* ppvFn);

			static size_t GetFunctionSize(PVOID pFunc);
			static int ValidateFunction(LPVOID pFunction, int* piBpCount = nullptr, int* piFunctionSize = nullptr, uint64_t* pqwChecksum = nullptr);
	};
}
