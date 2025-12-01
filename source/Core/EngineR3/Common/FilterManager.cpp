#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "FilterManager.hpp"

namespace NoMercy
{
	CFilterManager::CFilterManager() :
		m_bInitialized(false)
	{
	}
	CFilterManager::~CFilterManager()
	{
	}

	bool CFilterManager::Initialize()
	{
		// ...
		// Allocate containers

		m_bInitialized = true;
		return true;
	}

	void CFilterManager::Release()
	{
		if (!m_bInitialized)
			return;
		m_bInitialized = false;

		// ...
	}

	bool CFilterManager::IsAddressInKnownModule(DWORD_PTR dwTarget)
	{
		return true;
	}
	bool CFilterManager::IsKnownMemory(DWORD_PTR dwTarget)
	{
		return true;
	}
	bool CFilterManager::IsWinHookOrigin(DWORD_PTR dwTarget)
	{
		return CApplication::Instance().SelfHooksInstance()->IsWinHookOrigin((PVOID)dwTarget);
	}

	void CFilterManager::AddKnownModule(DWORD_PTR dwBase, SIZE_T cbSize, const std::wstring& wstName)
	{

	}
	void CFilterManager::AddKnownMemory(DWORD_PTR dwBase, DWORD_PTR dwAllocationBase, SIZE_T cbSize, const std::wstring& wstOwnerName)
	{

	}

	void CFilterManager::RemoveKnownModule(DWORD_PTR dwBase)
	{
		
	}
};
