#pragma once
#include "PatternScanner.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"

namespace NoMercy
{
	class CProcess;

	class CModule
	{
	public:
		CModule();
		CModule(CProcess* Process, const std::wstring& wstModuleName);
		CModule(CProcess* Process, const ptr_t pModuleBase, const std::size_t uiModuleSize, const std::wstring& wstModuleName);
		virtual ~CModule();

		// moveable
		CModule(CModule&& other) noexcept;
		CModule& operator=(CModule&& other) noexcept;

		explicit operator bool() noexcept;

		DWORD							GetOwnerProcessID() const;
		bool							IsValid() const;
		uint8_t*						GetDataPtr(bool bPeOnly = false) const; // allocated
		std::vector <uint8_t>			GetData() const; // stack
		std::unique_ptr <Pe::Pe32>		GetHeader32() const;
		std::unique_ptr <Pe::Pe64>		GetHeader64() const;
		std::wstring					GetName() const;
		std::wstring					GetResolvedName() const;
		ptr_t							GetBase() const;
		std::size_t						GetSize() const;
		std::unique_ptr <msl::file_ptr>	GetFilePtr() const;
		ptr_t							FindPattern(const Pattern& pattern) const;
		
		// check module arch, if proc works under wow64 some modules (like ntdll, wow64***) can be 64bit
		bool Isx86() const;
		bool Isx64() const;
		
	protected:
		void __SetModuleBase();
		void __SetModuleArch();

	private:
		CProcess*			m_pOwnerProcess;
		std::unique_ptr <CPatternScanner>	m_upPatternScanner;
		std::wstring						m_wstModuleName;
		ptr_t								m_pModuleBase;
		std::size_t							m_uiModuleSize;
		std::vector <uint8_t>				m_vecBuffer;
		bool								m_bIsValid;
		bool								m_bIs64Bit;
	};
}
