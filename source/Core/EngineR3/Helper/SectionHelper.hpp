#pragma once
#include "PatternScanner.hpp"

namespace NoMercy
{
	class CProcess;
	
	class CSection
	{
	public:
		CSection();
		CSection(CProcess* Process, const ptr_t pBase, const ptr_t pAllocationBase = nullptr, const std::size_t uiSize = 0);
		~CSection();
		
		// moveable
		CSection(CSection&& other) noexcept;
		CSection& operator=(CSection&& other) noexcept;

		explicit operator bool() noexcept;

		DWORD										GetOwnerProcessID() const;
		std::wstring								GetOwnerModuleName() const;
		std::shared_ptr <MEMORY_BASIC_INFORMATION>	GetBasicInformation() const;
		bool										IsValid() const;
		uint8_t*									GetDataPtr() const; // allocated
		std::vector <uint8_t>						GetData() const; // stack
		ptr_t										GetBase() const;
		std::size_t									GetSize() const;
		ptr_t										FindPattern(const Pattern& pattern) const;

	private:
		CProcess* m_pOwnerProcess;
		std::unique_ptr <CPatternScanner>	m_upPatternScanner;
		std::wstring						m_wstModuleName;
		ptr_t								m_pBase;
		ptr_t								m_pAllocationBase;
		std::size_t							m_uiSize;
		bool								m_bIsValid;
		bool								m_bIs64Bit;
	};
}
