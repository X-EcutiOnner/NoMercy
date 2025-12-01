#pragma once
#include "../../EngineR3_Core/include/Defines.hpp"

namespace NoMercy
{
	class CMemoryHelper
	{
	public:
		CMemoryHelper(HANDLE hProcess = NtCurrentProcess());
		~CMemoryHelper();

		ptr_t Alloc(std::size_t cbSize, DWORD dwProtection = PAGE_EXECUTE_READWRITE, ptr_t lpBaseAddress = nullptr);
		bool Free(ptr_t pvBaseAddress, std::size_t cbSize);
		bool Read(ptr_t pvAddress, ptr_t pvBuffer, std::size_t cbSize, std::size_t* pkReadSize = nullptr);
		bool Write(ptr_t pvAddress, PVOID pvBuffer, std::size_t cbSize, std::size_t* pkWriteSize = nullptr);
		bool Protect(ptr_t pvBaseAddress, std::size_t cbSize, DWORD dwProtectFlag, PDWORD pdwOldProtect);
		bool Query(ptr_t pvBaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, std::size_t MemoryInformationLength);
		bool Flush(ptr_t pvBaseAddress = nullptr, std::size_t cbSize = 0);

		std::shared_ptr <MEMORY_BASIC_INFORMATION> BasicQuery(ptr_t pvBaseAddress);
	
		ptr_t Commit(PVOID pvData, std::size_t cbSize);
		bool Patch(ptr_t pvTarget, PVOID pvSource, std::size_t cbSize);

		bool IsReadSafePage(ptr_t pvAddress);
		bool IsExecutablePage(ptr_t pvAddress);

		template <typename T>
		T ReadMemory(ptr_t pvAddress);
		
		template <typename T>
		T* ReadStruct(ptr_t pvAddress);
		
		template <typename T>
		bool ReadStruct(ptr_t pvAddress, T& data);

		template <typename T>
		bool WriteMemory(ptr_t pvAddress, T data, std::size_t cbSize);
		
		template <typename T>
		bool WriteMemory(ptr_t pvAddress, T ret);

	private:
		HANDLE m_hProcessUser;
	};
};
