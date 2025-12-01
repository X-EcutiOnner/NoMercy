#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Quarentine.hpp"

namespace NoMercy
{
	CQuarentine::CQuarentine() :
		m_bInitialized(false)
	{
	}
	CQuarentine::~CQuarentine()
	{
	}

	bool CQuarentine::Initialize()
	{
		if (m_bInitialized)
			return true;

		// Allocate quarentine nodes
		m_spSymlinkQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spEventNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spMutantNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spSemaphoreNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spJobNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spFileMappingNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spServiceNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spHandleOwnerClassQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spDriverFileNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spWindowsStationQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spWaitableTimerQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spHandleObjectNameQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spDebugStringQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();

		m_spWindowQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SWindowCheckObjects>>();
		m_spProcessQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SProcessCheckObjects>>();
		m_spModuleQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SModuleCheckObjects>>();
		m_spFileQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SFileCheckObjects>>();
		m_spMemoryQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SMemoryCheckObjects>>();
		m_spThreadQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SThreadCheckObject>>();

		m_spProcessHollowingQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spArbitaryUserPointerQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();
		m_spDebugPrivRemovedProcessQuarentine = stdext::make_shared_nothrow<IQuarentineNode<SCommonQuarentineHandler>>();

		// -----------------------------------
		// Sanity check for quarentine nodes
		if (!IS_VALID_SMART_PTR(m_spSymlinkQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Symlink quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_SYMLINK));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spEventNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Event name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_EVENT_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spMutantNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Mutant name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_MUTANT_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spSemaphoreNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Semaphore name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_SEMAPHORE_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spJobNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Job name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_JOB_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spFileMappingNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for File mapping name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_FILE_MAPPING_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spServiceNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Service name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_SERVICE_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spHandleOwnerClassQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Handle owner class quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_HANDLE_OWNER_CLASS));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spDriverFileNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Driver file name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_DRIVER_FILE_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spWindowsStationQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for windows station quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_WINDOWS_STATION));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spWaitableTimerQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for waitable timer quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_WAITABLE_TIMER));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spHandleObjectNameQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for handle object name quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_HANDLE_OBJECT_NAME));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spDebugStringQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for debug string quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_DEBUG_STRING));
			return false;
		}
		
		
		else if (!IS_VALID_SMART_PTR(m_spWindowQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Window quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_WINDOW));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spProcessQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Process quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_PROCESS));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spModuleQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Module quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_MODULE));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spFileQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for File quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_FILE));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spMemoryQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Mapped file quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_MEMORY));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spThreadQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Thread quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::BL_THREAD));
			return false;
		}

		
		else if (!IS_VALID_SMART_PTR(m_spProcessHollowingQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Process hollowing quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::WL_PROCESS_HOLLOWING));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spArbitaryUserPointerQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Arbitary user pointer quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::WL_ARBITARY_USER_POINTER));
			return false;
		}
		else if (!IS_VALID_SMART_PTR(m_spDebugPrivRemovedProcessQuarentine))
		{
			APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for Debug priv removed process quarentine node! Error: %u", g_winAPIs->GetLastError());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_QUARENTINE_NODE_ALLOC_FAIL, static_cast<uint32_t>(EQuarentineTypes::WL_DEBUG_PRIV_REMOVED_PROCESS));
			return false;
		}

		
		APP_TRACE_LOG(LL_SYS, L"Successfully allocated memory for quarentine nodes!");
		return true;
	}
	void CQuarentine::Release()
	{
		if (!m_bInitialized)
			return;
		
		m_bInitialized = false;
	}

	bool CQuarentine::IsAllowedFileCertificate(const std::wstring& serial, const std::wstring& subject, const std::wstring& issuer, const std::wstring& provider, const std::wstring& hash)
	{
		APP_TRACE_LOG(LL_SYS, L"Serial: %ls, Subject: %ls, Issuer: %ls, Provider: %ls, Hash: %ls",
			serial.c_str(), subject.c_str(), issuer.c_str(), provider.c_str(), hash.c_str()
		);

		if (!IS_VALID_SMART_PTR(this->FileQuarentine()))
			return true;

		// self signed
		if (issuer == subject)
		{
			APP_TRACE_LOG(LL_ERR, L"File is self-signed!");
			return false;
		}

		std::size_t obj_count = 0;
		if (!serial.empty())
			obj_count++;
		if (!subject.empty())
			obj_count++;
		if (!issuer.empty())
			obj_count++;
		if (!provider.empty())
			obj_count++;
		if (!hash.empty())
			obj_count++;

		const auto vecWhiteList = this->FileQuarentine()->GetWhitelist();
		for (const auto& item : vecWhiteList)
		{
			std::size_t count = 0;

			if (!item.cert_hash.empty() && !hash.empty() && item.cert_hash == hash)
				count++;
			if (!item.cert_serial.empty() && !serial.empty() && item.cert_serial == serial)
				count++;
			if (!item.cert_subject.empty() && !subject.empty() && item.cert_subject == subject)
				count++;
			if (!item.cert_issuer.empty() && !issuer.empty() && item.cert_issuer == issuer)
				count++;
			if (!item.cert_provider.empty() && !provider.empty() && item.cert_provider == provider)
				count++;

			if (count == obj_count)
			{
				APP_TRACE_LOG(LL_ERR, L"File is whitelisted!");
				return true;
			}
		}

		const auto vecBlackList = this->FileQuarentine()->GetBlacklist();
		for (const auto& [item, opts] : vecBlackList)
		{
			std::size_t count = 0;

			if (!item.cert_hash.empty() && !hash.empty() && item.cert_hash == hash)
				count++;
			if (!item.cert_serial.empty() && !serial.empty() && item.cert_serial == serial)
				count++;
			if (!item.cert_subject.empty() && !subject.empty() && item.cert_subject == subject)
				count++;
			if (!item.cert_issuer.empty() && !issuer.empty() && item.cert_issuer == issuer)
				count++;
			if (!item.cert_provider.empty() && !provider.empty() && item.cert_provider == provider)
				count++;

			if (count == obj_count)
			{
				APP_TRACE_LOG(LL_ERR, L"File is blacklisted!");
				return false;
			}
		}

		return true;
	}
};
