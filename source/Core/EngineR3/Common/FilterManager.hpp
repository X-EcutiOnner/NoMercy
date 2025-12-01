#pragma once

namespace NoMercy
{
	struct SModuleFilterCtx
	{
		DWORD_PTR dwBase;
		std::wstring wstName;
	};
	struct SMemoryFilterCtx
	{
		DWORD_PTR dwBase;
		DWORD_PTR dwAllocationBase;
		std::wstring wstName;
		SIZE_T ullSize;
		DWORD dwProtect;
		DWORD dwType;
	};

	template <typename T>
	class IFilterNode
	{
#define LOCK_MTX_F std::lock_guard <std::recursive_mutex> lock(m_rmMutex);

	public:
		virtual ~IFilterNode() {};

		virtual void Add(const T& obj)
		{
			std::lock_guard <std::recursive_mutex> lock(m_rmMutex);

			m_vContainer.emplace_back(obj);
		};

		virtual bool IsKnown(const T& obj) = 0;
		virtual T Find(const T& obj) = 0;

	protected:
		mutable std::recursive_mutex m_rmMutex;
		std::vector <T> m_vContainer;
	};

	class CModuleFilter : IFilterNode <SModuleFilterCtx>
	{
	public:
		SModuleFilterCtx Find(const SModuleFilterCtx& obj) override
		{
			std::lock_guard <std::recursive_mutex> lock(m_rmMutex);
			
			for (const auto& it : m_vContainer)
			{
				if (obj.dwBase == it.dwBase)
					return it;
			}
			return {};
		}
		bool IsKnown(const SModuleFilterCtx& obj) override
		{
			std::lock_guard <std::recursive_mutex> lock(m_rmMutex);
			
			for (const auto& it : m_vContainer)
			{
				if (obj.dwBase == it.dwBase)
					return true;
			}
			return false;
		}
	};
	class CMemoryFilter : IFilterNode <SMemoryFilterCtx>
	{
	public:
		SMemoryFilterCtx Find(const SMemoryFilterCtx& obj) override
		{
			for (const auto& it : m_vContainer)
			{
				if (obj.dwBase == it.dwBase && obj.dwAllocationBase == it.dwAllocationBase && obj.ullSize == it.ullSize)
					return it;
			}
			return {};
		}
		bool IsKnown(const SMemoryFilterCtx& obj) override
		{
			for (const auto& it : m_vContainer)
			{
				if (obj.dwBase == it.dwBase && obj.dwAllocationBase == it.dwAllocationBase && obj.ullSize == it.ullSize)
					return true;
			}
			return false;
		}
	};

	class CFilterManager : public std::enable_shared_from_this <CFilterManager>
	{
	public:
		CFilterManager();
		virtual ~CFilterManager();

		bool Initialize();
		void Release();

		auto IsInitialized() const { return m_bInitialized; };

		bool IsAddressInKnownModule(DWORD_PTR dwTarget);
		bool IsKnownMemory(DWORD_PTR dwTarget);
		bool IsWinHookOrigin(DWORD_PTR dwTarget);

		void AddKnownModule(DWORD_PTR dwBase, SIZE_T cbSize, const std::wstring& stName);
		void AddKnownMemory(DWORD_PTR dwBase, DWORD_PTR dwAllocationBase, SIZE_T cbSize, const std::wstring& wstOwnerName);

		void RemoveKnownModule(DWORD_PTR dwBase);
		
	private:
		bool m_bInitialized;

		std::shared_ptr <CModuleFilter> m_spModuleContainer;
		std::shared_ptr <CMemoryFilter> m_spMemoryContainer;
	};
};
