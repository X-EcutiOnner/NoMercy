#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ModuleHelper.hpp"
#include "MemoryHelper.hpp"
#include "ProcessHelper.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"
#include "../../EngineR3_Core/include/MemAllocator.hpp"
#include "../../EngineR3_Core/include/ApiSetMap.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"

namespace NoMercy
{
	CModule::CModule() :
		m_pOwnerProcess(nullptr), m_upPatternScanner(nullptr), m_wstModuleName(L""),
		m_pModuleBase(0), m_uiModuleSize(0), m_bIsValid(false), m_bIs64Bit(false)
	{
	}
	CModule::CModule(CProcess* Process, const std::wstring& wstModuleName) :
		m_upPatternScanner(nullptr), m_wstModuleName(wstModuleName),
		m_pModuleBase(0), m_uiModuleSize(0), m_bIsValid(false), m_bIs64Bit(false)
	{
		m_pOwnerProcess = Process;
		m_upPatternScanner = std::make_unique<CPatternScanner>();

		__SetModuleBase();
		__SetModuleArch();
	}
	CModule::CModule(CProcess* Process, const ptr_t pModuleBase, const std::size_t uiModuleSize, const std::wstring& wstModuleName) :
		 m_upPatternScanner(nullptr), m_wstModuleName(wstModuleName),
		m_pModuleBase(pModuleBase), m_uiModuleSize(uiModuleSize), m_bIsValid(false), m_bIs64Bit(false)
	{
		m_pOwnerProcess = Process;
		m_upPatternScanner = std::make_unique<CPatternScanner>();

		__SetModuleArch();
	}
	CModule::~CModule()
	{
		m_pOwnerProcess = nullptr;
		m_upPatternScanner.reset();
		
		m_wstModuleName.clear();
		m_pModuleBase = 0;
		m_uiModuleSize = 0;
		m_vecBuffer.clear();
		m_bIsValid = false;
		m_bIs64Bit = false;
	}

	inline CModule::CModule(CModule&& other) noexcept
	{
		*this = std::forward<CModule>(other);
	}
	inline CModule& CModule::operator=(CModule&& other) noexcept
	{
		std::swap(m_pOwnerProcess, other.m_pOwnerProcess);
		std::swap(m_upPatternScanner, other.m_upPatternScanner);
		std::swap(m_wstModuleName, other.m_wstModuleName);
		std::swap(m_pModuleBase, other.m_pModuleBase);
		std::swap(m_uiModuleSize, other.m_uiModuleSize);
		std::swap(m_vecBuffer, other.m_vecBuffer);
		std::swap(m_bIsValid, other.m_bIsValid);
		std::swap(m_bIs64Bit, other.m_bIs64Bit);

		return *this;
	}

	inline CModule::operator bool() noexcept
	{
		return IsValid();
	}

	DWORD CModule::GetOwnerProcessID() const
	{
		return m_pOwnerProcess->GetID();
	}
	bool CModule::IsValid() const
	{
		return m_bIsValid;
	}
	uint8_t* CModule::GetDataPtr(bool bPeOnly) const
	{
		if (!m_pModuleBase || !m_uiModuleSize)
			return nullptr;

		auto pBuffer = CMemHelper::Allocate(m_uiModuleSize);
		if (!pBuffer)
			return nullptr;

		if (!m_pOwnerProcess->GetMemoryManager()->Read(m_pModuleBase, pBuffer, bPeOnly ? 0x1000 : m_uiModuleSize))
		{
			CMemHelper::Free(pBuffer);
			return nullptr;
		}

		return (uint8_t*)pBuffer;
	}
	std::vector <uint8_t> CModule::GetData() const
	{
		if (!m_pModuleBase || !m_uiModuleSize)
			return {};

		std::vector <uint8_t> vBuffer;
		if (!m_pOwnerProcess->GetMemoryManager()->Read(m_pModuleBase, &vBuffer[0], m_uiModuleSize))
		{
			vBuffer.clear();
			return {};
		}

		return vBuffer;
	}
	std::unique_ptr <Pe::Pe32> CModule::GetHeader32() const
	{
		if (!m_pModuleBase || !m_uiModuleSize)
			return {};

		auto pe = std::make_unique<Pe::Pe32>(Pe::Pe32::fromModule(m_pModuleBase));
		if (!pe->valid())
			return {};
		
		return pe;
	}
	std::unique_ptr <Pe::Pe64> CModule::GetHeader64() const
	{
		if (!m_pModuleBase || !m_uiModuleSize)
			return {};

		auto pe = std::make_unique<Pe::Pe64>(Pe::Pe64::fromModule(m_pModuleBase));
		if (!pe->valid())
			return {};

		return pe;
	}
	std::wstring CModule::GetName() const
	{
		return m_wstModuleName;
	}
	std::wstring CModule::GetResolvedName() const
	{
		if (m_wstModuleName.empty())
			return {};
		
		static const auto pApiSetNamespace = ApiSetMap::GetApiSetNamespace();
		if (!pApiSetNamespace)
		{
			APP_TRACE_LOG(LL_ERR, L"GetApiSetNamespace failed!");
			return {};
		}
		static const auto upApiSetMap = ApiSetMap::ApiSetSchemaImpl::ParseApiSetSchema(pApiSetNamespace);
		if (!IS_VALID_SMART_PTR(upApiSetMap))
		{
			APP_TRACE_LOG(LL_ERR, L"ParseApiSetSchema failed!");
			return {};
		}
		
		auto wstModuleName = m_wstModuleName;
		if (wstModuleName.compare(0, 5, xorstr_(L"api-")) == 0 || wstModuleName.compare(0, 5, xorstr_(L"ext-")) == 0)
		{
			const auto vecApiSetSchema = upApiSetMap->Lookup(wstModuleName);
			if (vecApiSetSchema.size() != 1)
			{
				APP_TRACE_LOG(LL_ERR, L"ApiSetSchema lookup failed! Ret: %u", vecApiSetSchema.size());
				return 0;
			}

			wstModuleName = vecApiSetSchema[0];
			APP_TRACE_LOG(LL_SYS, L"ApiSetSchema resolved: %ls", wstModuleName.c_str());
		}
		else
		{
			return {};
		}
		return wstModuleName;
	}
	ptr_t CModule::GetBase() const
	{
		return m_pModuleBase;
	}
	std::size_t	CModule::GetSize() const
	{
		return m_uiModuleSize;
	}
	std::unique_ptr <msl::file_ptr> CModule::GetFilePtr() const
	{
		if (m_wstModuleName.empty())
			return {};
		
		auto fp = std::make_unique<msl::file_ptr>(msl::file_ptr(m_wstModuleName));
		if (!fp->is_open())
		{
			APP_TRACE_LOG(LL_ERR, L"File open failed! %ls", m_wstModuleName.c_str());
			return {};
		}
		return fp;
	}
	ptr_t CModule::FindPattern(const Pattern& pattern) const
	{
		if (!m_upPatternScanner)
			return nullptr;
		return m_upPatternScanner->findPatternSafe(Ptr64ToPtr(m_pModuleBase), m_uiModuleSize, pattern);
	}

	bool CModule::Isx86() const
	{
		return !m_bIs64Bit;
	}
	bool CModule::Isx64() const
	{
		return m_bIs64Bit;
	}

	void CModule::__SetModuleBase()
	{
		m_pOwnerProcess->EnumerateModules([&](std::shared_ptr <CModule> mdl) -> bool {
			if (mdl->GetName() == m_wstModuleName)
			{
				m_pModuleBase = mdl->GetBase();
				return false;
			}
			return true;
		});
		return;
	}
	void CModule::__SetModuleArch()
	{
		if (!m_pModuleBase)
			return;

		const auto pData = GetDataPtr(true);
		if (!pData)
			return;
		
		const auto pIDH = (PIMAGE_DOS_HEADER)pData;
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			CMemHelper::Free(pData);
			return;
		}
		
		const auto pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pData + pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			CMemHelper::Free(pData);
			return;
		}
		
		m_bIs64Bit = (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
		m_bIsValid = true;
		CMemHelper::Free(pData);
		return;
	}
}
