#include "../../include/PCH.hpp"
#include "../../include/MemAllocator.hpp"

#if 0
// Override new and delete operators for use the our memory allocator
void* operator new(std::size_t nSize)
{
	return NoMercyCore::CMemHelper::Allocate(nSize);
}
void* operator new(std::size_t nSize, std::align_val_t nAlign)
{
	return NoMercyCore::CMemHelper::AllocateAlign(nSize, nAlign);
}

void operator delete(void* ptr)
{
	NoMercyCore::CMemHelper::Free(ptr);
}
void operator delete(void* ptr, std::align_val_t /* al */)
{
	NoMercyCore::CMemHelper::FreeAlign(ptr);
}
#endif

//
namespace NoMercyCore
{
	CMemHelper::CAllocator CMemHelper::MemAllocator;

	void* CMemHelper::Allocate(size_t length)
	{
		auto pBuffer = std::calloc(length, 1);
		assert(pBuffer != nullptr);

		return pBuffer;
	}

	void* CMemHelper::AllocateAlign(size_t length, std::align_val_t alignment)
	{
		auto pBuffer = _aligned_malloc(length, static_cast<size_t>(alignment));
		assert(pBuffer != nullptr);

		if (pBuffer)
			ZeroMemory(pBuffer, length);

		return pBuffer;
	}

	void* CMemHelper::AllocateHeap(size_t length)
	{
		const auto pProcHeap = MemAllocator.getHeapBase();
		assert(pProcHeap != nullptr);

		const auto fnRtlAllocateHeap = LI_FN(RtlAllocateHeap).forwarded_safe_cached();
		assert(fnRtlAllocateHeap != nullptr);

		auto pBuffer = fnRtlAllocateHeap(pProcHeap, HEAP_ZERO_MEMORY, length);
		assert(pBuffer != nullptr);

		return pBuffer;
	}

	void CMemHelper::Free(void* data)
	{
		if (data)
		{
			free(data);
		}
	}

	void CMemHelper::Free(const void* data)
	{
		CMemHelper::Free(const_cast<void*>(data));
	}

	void CMemHelper::FreeAlign(void* data)
	{
		if (data)
		{
			_aligned_free(data);
		}
	}

	void CMemHelper::FreeAlign(const void* data)
	{
		CMemHelper::FreeAlign(const_cast<void*>(data));
	}

	void CMemHelper::FreeHeap(void* data)
	{
		if (data && MemAllocator.getHeapBase())
		{
			const auto fnRtlFreeHeap = LI_FN(RtlFreeHeap).forwarded_safe_cached();
			if (fnRtlFreeHeap)
				fnRtlFreeHeap(MemAllocator.getHeapBase(), 0, data);
		}
	}

	void CMemHelper::FreeHeap(const void* data)
	{
		CMemHelper::FreeHeap(const_cast<void*>(data));
	}

	void* CMemHelper::ReAlloc(void* data, size_t length)
	{
		CMemHelper::Free(data);
		return CMemHelper::Allocate(length);
	}

	void* CMemHelper::ReAlloc(const void* data, size_t length)
	{
		CMemHelper::Free(data);
		return CMemHelper::Allocate(length);
	}

	void* CMemHelper::ReAllocAlign(void* data, size_t length, std::align_val_t alignment)
	{
		CMemHelper::Free(data);
		return CMemHelper::AllocateAlign(length, alignment);
	}

	void* CMemHelper::ReAllocAlign(const void* data, size_t length, std::align_val_t alignment)
	{
		CMemHelper::Free(data);
		return CMemHelper::AllocateAlign(length, alignment);
	}

	void* CMemHelper::ReAllocHeap(void* data, size_t length)
	{
		CMemHelper::Free(data);
		return CMemHelper::AllocateHeap(length);
	}

	void* CMemHelper::ReAllocHeap(const void* data, size_t length)
	{
		CMemHelper::Free(data);
		return CMemHelper::AllocateHeap(length);
	}

	template <class T>
	void CMemHelper::Fill(T& data)
	{
		std::fill(std::begin(data), std::end(data), typename T::value_type());
	}

	bool CMemHelper::IsFilledWithChar(void* mem, char chr, size_t length)
	{
		char* memArr = reinterpret_cast<char*>(mem);

		for (size_t i = 0; i < length; ++i)
		{
			if (memArr[i] != chr)
			{
				return false;
			}
		}

		return true;
	}

	bool CMemHelper::IsBadReadPtr(const void* ptr)
	{
		const auto fnVirtualQuery = LI_FN(VirtualQuery).forwarded_safe_cached();
		if (!fnVirtualQuery)
			return true;

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (!fnVirtualQuery(ptr, &mbi, sizeof(mbi)))
			return true;

		const auto mask = (PAGE_READONLY | PAGE_READWRITE | /* PAGE_WRITECOPY | */ PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		if (!(mbi.Protect & mask))
			return true;

		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			return true;
		
		return false;
	}

	bool CMemHelper::IsBadCodePtr(const void* ptr)
	{
		const auto fnVirtualQuery = LI_FN(VirtualQuery).forwarded_safe_cached();
		if (!fnVirtualQuery)
			return true;

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (!fnVirtualQuery(ptr, &mbi, sizeof(mbi)))
			return true;

		const auto mask = (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

		auto ret = !(mbi.Protect & mask);
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			ret = true;

		return ret;
	}

	CMemHelper::CAllocator* CMemHelper::GetAllocator()
	{
		return &CMemHelper::MemAllocator;
	}
};
