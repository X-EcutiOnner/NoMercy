#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SectionHelper.hpp"
#include "ProcessHelper.hpp"
#include "ModuleHelper.hpp"

namespace NoMercy
{
	CSection::CSection() :
		m_pOwnerProcess(nullptr), m_upPatternScanner(nullptr), m_wstModuleName(L""), m_pBase(nullptr),
		m_pAllocationBase(nullptr), m_uiSize(0), m_bIsValid(false), m_bIs64Bit(false)
	{
	}
	CSection::CSection(CProcess* Process, const ptr_t pBase, const ptr_t pAllocationBase, const std::size_t uiSize) :
		m_upPatternScanner(nullptr), m_wstModuleName(L""), m_pBase(pBase),
		m_pAllocationBase(pAllocationBase), m_uiSize(uiSize), m_bIsValid(true), m_bIs64Bit(false)
	{
		m_pOwnerProcess = Process;
		m_upPatternScanner = std::make_unique<CPatternScanner>();

		if (m_pBase && m_uiSize)
			m_bIsValid = true;
	}
	CSection::~CSection()
	{
		m_pOwnerProcess = nullptr;
		m_upPatternScanner.reset();

		m_wstModuleName.clear();
		m_pBase = nullptr;
		m_pAllocationBase = nullptr;
		m_uiSize = 0;
		m_bIsValid = false;
		m_bIs64Bit = false;
	}

	inline CSection::CSection(CSection&& other) noexcept
	{
		*this = std::forward<CSection>(other);
	}
	inline CSection& CSection::operator=(CSection&& other) noexcept
	{
		std::swap(m_pOwnerProcess, other.m_pOwnerProcess);
		std::swap(m_upPatternScanner, other.m_upPatternScanner);
		std::swap(m_wstModuleName, other.m_wstModuleName);
		std::swap(m_pBase, other.m_pBase);
		std::swap(m_pAllocationBase, other.m_pAllocationBase);
		std::swap(m_uiSize, other.m_uiSize);
		std::swap(m_bIsValid, other.m_bIsValid);
		std::swap(m_bIs64Bit, other.m_bIs64Bit);

		return *this;
	}

	inline CSection::operator bool() noexcept
	{
		return IsValid();
	}
	
	DWORD CSection::GetOwnerProcessID() const
	{
		if (m_pOwnerProcess)
			return m_pOwnerProcess->GetID();
		return 0;
	}
	std::wstring CSection::GetOwnerModuleName() const
	{
		std::wstring wstModuleName;
		
		if (m_pOwnerProcess)
		{
			m_pOwnerProcess->EnumerateModules([&](std::shared_ptr <CModule> mdl) -> bool {
				if ((uint64_t)m_pBase >= (uint64_t)mdl->GetBase() && (uint64_t)m_pBase < ((uint64_t)mdl->GetBase() + mdl->GetSize()))
				{
					wstModuleName = mdl->GetName();
					return false;
				}
				return true;
			});
		}

		return wstModuleName;
	}
	std::shared_ptr <MEMORY_BASIC_INFORMATION> CSection::GetBasicInformation() const
	{
		if (m_pOwnerProcess)
		{
			return m_pOwnerProcess->GetMemoryManager()->BasicQuery(m_pBase);
		}
		return {};
	}
	bool CSection::IsValid() const
	{
		return m_bIsValid;
	}
	uint8_t* CSection::GetDataPtr() const
	{
		if (!m_pBase || !m_uiSize)
			return nullptr;

		auto pBuffer = CMemHelper::Allocate(m_uiSize);
		if (!pBuffer)
			return nullptr;

		if (!m_pOwnerProcess->GetMemoryManager()->Read(m_pBase, pBuffer, m_uiSize))
		{
			CMemHelper::Free(pBuffer);
			return nullptr;
		}

		return (uint8_t*)pBuffer;
	}
	std::vector <uint8_t> CSection::GetData() const
	{
		if (!m_pBase || !m_uiSize)
			return {};

		std::vector <uint8_t> vBuffer;
		if (!m_pOwnerProcess->GetMemoryManager()->Read(m_pBase, &vBuffer[0], m_uiSize))
		{
			vBuffer.clear();
			return {};
		}

		return vBuffer;
	}
	ptr_t CSection::GetBase() const
	{
		return m_pBase;
	}
	std::size_t	CSection::GetSize() const
	{
		return m_uiSize;
	}
	ptr_t CSection::FindPattern(const Pattern& pattern) const
	{
		if (!m_upPatternScanner)
			return {};

		return m_upPatternScanner->findPatternSafe(Ptr64ToPtr(m_pBase), m_uiSize, pattern);
	}
}
