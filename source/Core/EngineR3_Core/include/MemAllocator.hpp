#pragma once
#include <mutex>
#include <string>
#include <unordered_map>

namespace NoMercyCore
{
	class CMemHelper
	{
		// Memory guard
		template <typename T>
		struct SMemGuard
		{
			void operator() (T* pBlock) const
			{
				return CMemHelper::Free(pBlock);
			};
		};

		// Hand-made smart pointer template
		template <typename T>
		using NMSmartMemPtr = std::unique_ptr <T, SMemGuard <T>>;

	public:
		class CAllocator
		{
			typedef void(*FreeCallback)(void*);

		public:
			CAllocator()
			{
				this->m_heapBase = NtCurrentPeb()->ProcessHeap;
				this->m_pool.clear();
				this->m_refMemory.clear();
			}
			~CAllocator()
			{
				this->clear();
			}

			void clear()
			{
				std::lock_guard <std::mutex> __lock(this->m_mutex);

				for (auto i = this->m_refMemory.begin(); i != this->m_refMemory.end(); ++i)
				{
					if (i->first && i->second)
					{
						i->second(i->first);
					}
				}

				this->m_refMemory.clear();

				for (auto& data : this->m_pool)
				{
					CMemHelper::Free(data);
				}

				this->m_pool.clear();
				this->m_heapBase = nullptr;
			}

			void free(void* data)
			{
				std::lock_guard <std::mutex> __lock(this->m_mutex);

				auto i = this->m_refMemory.find(data);
				if (i != this->m_refMemory.end())
				{
					i->second(i->first);
					this->m_refMemory.erase(i);
				}

				auto j = std::find(this->m_pool.begin(), this->m_pool.end(), data);
				if (j != this->m_pool.end())
				{
					CMemHelper::Free(data);
					this->m_pool.erase(j);
				}
			}

			void free(const void* data)
			{
				this->free(const_cast<void*>(data));
			}

			void reference(void* memory, FreeCallback callback)
			{
				std::lock_guard <std::mutex> __lock(this->m_mutex);

				this->m_refMemory[memory] = callback;
			}

			void* allocate(size_t length)
			{
				std::lock_guard<std::mutex> _(this->m_mutex);

				void* data = CMemHelper::Allocate(length);
				this->m_pool.push_back(data);
				return data;
			}
			template <typename T> inline T* allocate()
			{
				return this->allocateArray<T>(1);
			}
			template <typename T> inline T* allocateArray(size_t count = 1)
			{
				return static_cast<T*>(this->allocate(count * sizeof(T)));
			}

			bool empty()
			{
				return (this->m_pool.empty() && this->m_refMemory.empty());
			}

			bool isPointerMapped(void* ptr)
			{
				return this->m_ptrMap.find(ptr) != this->m_ptrMap.end();
			}

			template <typename T> T* getPointer(void* oldPtr)
			{
				if (this->isPointerMapped(oldPtr))
				{
					return reinterpret_cast<T*>(this->m_ptrMap[oldPtr]);
				}

				return nullptr;
			}

			void mapPointer(void* oldPtr, void* newPtr)
			{
				this->m_ptrMap[oldPtr] = newPtr;
			}

			PVOID getHeapBase()
			{
				return m_heapBase;
			}

		private:
			PVOID m_heapBase;
			std::mutex m_mutex;
			std::vector <void*> m_pool;
			std::unordered_map<void*, void*> m_ptrMap;
			std::unordered_map<void*, FreeCallback> m_refMemory;
		};

		// Primitive allocators
		static void* Allocate(size_t length);
		static void* AllocateAlign(size_t length, std::align_val_t alignment);
		static void* AllocateHeap(size_t length);

		// Type defined primitive allocators
		template <typename T>
		static inline T* AllocateArray()
		{
			return AllocateArray<T>(1);
		}

		template <typename T>
		static inline T* Allocate(size_t count = 1)
		{
			return static_cast<T*>(Allocate(count * sizeof(T)));
		}

		// Leak-free memory allocators
		template <typename T = std::uint8_t>
		static inline NMSmartMemPtr <T> AllocSafeMemory(std::size_t nCount)
		{
			return NMSmartMemPtr<T>((T*)CMemHelper::Allocate(sizeof(T) * nCount));
		}
		template <typename T = std::uint8_t>
		static inline NMSmartMemPtr <T> ReAllocSafeMemory(NMSmartMemPtr <T>& nsmpOldBlock, std::size_t nNewCount)
		{
			auto pNewData = CMemHelper::ReAlloc(nsmpOldBlock.release(), sizeof(T) * nNewCount);
			return NMSmartMemPtr<T>((T*)pNewData);
		}

		static void Free(void* data);
		static void Free(const void* data);

		static void FreeAlign(void* data);
		static void FreeAlign(const void* data);

		static void FreeHeap(void* data);
		static void FreeHeap(const void* data);

		static void* ReAlloc(void* data, size_t length);
		static void* ReAlloc(const void* data, size_t length);

		static void* ReAllocAlign(void* data, size_t length, std::align_val_t alignment);
		static void* ReAllocAlign(const void* data, size_t length, std::align_val_t alignment);

		static void* ReAllocHeap(void* data, size_t length);
		static void* ReAllocHeap(const void* data, size_t length);

		template <class T> static void Fill(T& data);
		static bool IsFilledWithChar(void* mem, char chr, size_t length);

		static bool IsBadReadPtr(const void* ptr);
		static bool IsBadCodePtr(const void* ptr);

		static CMemHelper::CAllocator* GetAllocator();

	private:
		static CMemHelper::CAllocator MemAllocator;
	};
};
