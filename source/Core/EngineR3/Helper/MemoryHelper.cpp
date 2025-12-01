#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "MemoryHelper.hpp"

namespace NoMercy
{
	CMemoryHelper::CMemoryHelper(HANDLE hProcess) :
		m_hProcessUser(hProcess)
	{
	}
	CMemoryHelper::~CMemoryHelper()
	{
	}

	ptr_t CMemoryHelper::Alloc(std::size_t cbSize, DWORD dwProtection, ptr_t pvBaseAddress)
	{
		const auto pvMemory = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->AllocateVirtualMemory(
			m_hProcessUser, (PVOID64)pvBaseAddress, cbSize, MEM_COMMIT | MEM_RESERVE, dwProtection
		);
		return pvMemory;
	}
	bool CMemoryHelper::Free(ptr_t pvBaseAddress, std::size_t cbSize)
	{		
		const auto bRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->FreeVirtualMemory(
			m_hProcessUser, (PVOID64)pvBaseAddress, cbSize, MEM_RELEASE
		);
		return bRet;
	}
	bool CMemoryHelper::Read(ptr_t pvAddress, ptr_t pvBuffer, std::size_t cbSize, std::size_t* pkReadSize)
	{
		const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
			m_hProcessUser, (PVOID64)pvAddress, Ptr64ToPtr(pvBuffer), cbSize, nullptr
		);
		return NT_SUCCESS(ntStatus);
	}
	bool CMemoryHelper::Write(ptr_t pvAddress, PVOID pvBuffer, std::size_t cbSize, std::size_t* pkWriteSize)
	{		
		SIZE_T cbWriteSize = 0;
		const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->WriteVirtualMemory(
			m_hProcessUser, (PVOID64)pvAddress, pvBuffer, cbSize, &cbWriteSize
		);
		if (pkWriteSize) *pkWriteSize = cbWriteSize;
		return NT_SUCCESS(ntStatus);
	}
	bool CMemoryHelper::Protect(ptr_t pvBaseAddress, std::size_t cbSize, DWORD dwProtectFlag, PDWORD pdwOldProtect)
	{
		const auto bRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ProtectVirtualMemory(
			m_hProcessUser, (PVOID64)pvBaseAddress, cbSize, dwProtectFlag, pdwOldProtect
		);
		return bRet;
	}
	bool CMemoryHelper::Query(ptr_t pvBaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, std::size_t MemoryInformationLength)
	{		
		const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryVirtualMemory(
			m_hProcessUser, (PVOID64)pvBaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength
		);
		return NT_SUCCESS(ntStatus);
	}
	bool CMemoryHelper::Flush(ptr_t pvBaseAddress, std::size_t cbSize)
	{
		const auto bRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->FlushVirtualMemory(
			m_hProcessUser, (PVOID64)pvBaseAddress, cbSize
		);
		return bRet;
	}


	std::shared_ptr <MEMORY_BASIC_INFORMATION> CMemoryHelper::BasicQuery(ptr_t pvBaseAddress)
	{
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (Query(pvBaseAddress, MemoryBasicInformation, &mbi, sizeof(mbi)))
			return std::make_shared<MEMORY_BASIC_INFORMATION>(mbi);
		return {};
	}

	ptr_t CMemoryHelper::Commit(PVOID pvData, std::size_t cbSize)
	{
		const auto lpAllocatedMemory = Alloc(cbSize);
		if (!lpAllocatedMemory)
			return nullptr;

		if (Write(lpAllocatedMemory, pvData, cbSize))
			return lpAllocatedMemory;

		Free(lpAllocatedMemory, cbSize);
		return nullptr;
	}
	bool CMemoryHelper::Patch(ptr_t pvTarget, PVOID pvSource, std::size_t cbSize)
	{
		ULONG ulOldProtect = 0;
		__try
		{
			if (!Protect(pvTarget, cbSize, PAGE_EXECUTE_READWRITE, &ulOldProtect))
				return false;

			if (!Write(pvTarget, pvSource, cbSize))
				return false;

			if (!Protect(pvTarget, cbSize, ulOldProtect, &ulOldProtect))
				return false;

			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	bool CMemoryHelper::IsReadSafePage(ptr_t pvAddress)
	{
		const auto mbi = BasicQuery(pvAddress);
		if (!mbi->BaseAddress)
			return false;

		if (!(mbi->State & MEM_COMMIT))
			return false;

		if (mbi->State & MEM_RELEASE)
			return false;

		if (mbi->Protect == PAGE_NOACCESS || mbi->Protect & PAGE_GUARD)
			return false;

		if (mbi->Protect != PAGE_READONLY && mbi->Protect != PAGE_READWRITE && mbi->Protect != PAGE_EXECUTE_READ && mbi->Protect != PAGE_EXECUTE_READWRITE && mbi->Protect != PAGE_EXECUTE_WRITECOPY)
			return false;

		return true;
	}
	bool CMemoryHelper::IsExecutablePage(ptr_t pvAddress)
	{
		const auto mbi = BasicQuery(pvAddress);
		if (!mbi->BaseAddress)
			return false;

		if (!(mbi->State & MEM_COMMIT))
			return false;

		if (mbi->State & MEM_RELEASE)
			return false;

		if (mbi->Protect == PAGE_NOACCESS || mbi->Protect & PAGE_GUARD)
			return false;

		if (!(mbi->Protect & PAGE_EXECUTE || mbi->Protect & PAGE_EXECUTE_READ || mbi->Protect & PAGE_EXECUTE_READWRITE || mbi->Protect & PAGE_EXECUTE_WRITECOPY))
			return false;

		return true;
	}

	template <typename T>
	T CMemoryHelper::ReadMemory(ptr_t pvAddress)
	{
		T ret;

		std::size_t cbReadSize = 0;
		if (this->Read(pvAddress, &ret, sizeof(ret), &cbReadSize) && cbReadSize == sizeof(ret))
			return ret;
		return {};
	}
	template <typename T>
	T* CMemoryHelper::ReadStruct(ptr_t pvAddress)
	{
		T ret;

		std::size_t cbReadSize = 0;
		if (this->Read(pvAddress, &ret, sizeof(T), &cbReadSize) && cbReadSize == sizeof(T))
			return &ret;
		return nullptr;
	}
	template <typename T>
	bool CMemoryHelper::ReadStruct(ptr_t pvAddress, T& data)
	{
		std::size_t cbReadSize = 0;
		return this->Read(pvAddress, &data, sizeof(T), &cbReadSize) && cbReadSize == sizeof(T);
	}

	template <typename T>
	bool CMemoryHelper::WriteMemory(ptr_t pvAddress, T data, std::size_t cbSize)
	{
		std::size_t cbWriteSize = 0;
		return this->Write(pvAddress, &data, cbSize, &cbWriteSize) && cbWriteSize == cbSize;
	}
	template <typename T>
	bool CMemoryHelper::WriteMemory(ptr_t pvAddress, T ret)
	{
		return WriteMemory<T>(pvAddress, ret, sizeof(ret));
	}
}
