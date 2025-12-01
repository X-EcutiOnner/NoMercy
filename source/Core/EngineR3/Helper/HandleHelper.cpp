#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "HandleHelper.hpp"
#include "ProcessHelper.hpp"
#include "ModuleHelper.hpp"

namespace NoMercy
{
	CHandle::CHandle() :
		m_pOwnerProcess(nullptr), m_hHandle(nullptr), m_pObject(nullptr), m_uTypeIndex(0), m_dwGrantedAccess(0), m_bIsValid(false)
	{
	}
	CHandle::CHandle(CProcess* Process, HANDLE hHandle, PVOID pObject, USHORT uTypeIndex, DWORD dwGrantedAccess) :
		m_hHandle(hHandle), m_pObject(pObject), m_uTypeIndex(uTypeIndex), m_dwGrantedAccess(dwGrantedAccess), m_bIsValid(false)
	{
		m_pOwnerProcess = Process;
		
		if (hHandle)
			m_bIsValid = true;
	}
	CHandle::~CHandle()
	{
		m_pOwnerProcess = nullptr;
		
		m_hHandle = nullptr;
		m_pObject = nullptr;
		m_uTypeIndex = 0;
		m_dwGrantedAccess = 0;
		m_bIsValid = false;
	}

	// moveable
	inline CHandle::CHandle(CHandle&& other) noexcept
	{
		*this = std::forward<CHandle>(other);
	}
	inline CHandle& CHandle::operator=(CHandle&& other) noexcept
	{
		std::swap(m_pOwnerProcess, other.m_pOwnerProcess);
		std::swap(m_hHandle, other.m_hHandle);
		std::swap(m_pObject, other.m_pObject);
		std::swap(m_uTypeIndex, other.m_uTypeIndex);
		std::swap(m_dwGrantedAccess, other.m_dwGrantedAccess);
		std::swap(m_bIsValid, other.m_bIsValid);

		return *this;
	}

	inline CHandle::operator bool() noexcept
	{
		return IsValid();
	}

	bool CHandle::IsValid() const
	{
		return m_bIsValid;
	}
	HANDLE CHandle::GetHandle() const
	{
		return m_hHandle;
	}
	PVOID CHandle::GetObject() const
	{
		return m_pObject;
	}
	USHORT CHandle::GetTypeIndex() const
	{
		return m_uTypeIndex;
	}
	DWORD CHandle::GetGrantedAccess() const
	{
		return m_dwGrantedAccess;
	}
};
