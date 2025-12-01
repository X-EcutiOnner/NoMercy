#include "PCH.hpp"
#include "Core.hpp"
#include "../EngineR3_Core/include/Index.hpp"
#include "../EngineR3_Core/include/BasicLog.hpp"
#include "../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../EngineTLS/include/TLS.hpp"
#include <cxxopts.hpp>

#ifdef _DEBUG
	#define CREATE_INSTANCE_DEBUG_LOG(step)\
		NoMercyCore::LogfA(CUSTOM_LOG_FILENAME_A, "Process: %u AppID: %u CreateInstance step: %d completed!\n", HandleToUlong(NtCurrentProcessId()), nAppID, step);
#else
	#define CREATE_INSTANCE_DEBUG_LOG(step)
#endif

namespace NoMercy
{
	inline std::string GetTimeStr()
	{
		const auto fnGetTime = LI_FN(GetLocalTime).forwarded_safe();
		if (!fnGetTime)
			return {};

		SYSTEMTIME sysTime = { 0 };
		fnGetTime(&sysTime);

		char szTimeBuf[1024]{ 0 };
		snprintf(szTimeBuf, sizeof(szTimeBuf), xorstr_("%02d-%02d-%02d_%02d-%02d-%d"), sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wDay, sysTime.wMonth, sysTime.wYear);
		return szTimeBuf;
	}

	CCore::CCore() :
		m_nAppID(0), m_abHasInstance(false), m_lpModuleInfo(nullptr)
	{
	}
	CCore::~CCore()
	{
	}

	bool CCore::CreateInstance(uint8_t nAppID, LPCVOID c_lpModuleInfo)
	{
		CREATE_INSTANCE_DEBUG_LOG(1);

		// Check for duplicate instance
		if (m_abHasInstance.load())
		{
			NoMercyCore::OnPreFail(nAppID, CORE_ERROR_ALREADY_EXIST_INSTANCE);
			return false;
		}

		CREATE_INSTANCE_DEBUG_LOG(2);

		// TLS routine run validation
#if USE_VMPROTECT_SDK != 1
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		if (!IsDebuggerPresent())
#endif
		{
			if (nAppID != NM_STANDALONE && !NoMercyTLS::IsTlsCompleted())
			{
				NoMercyCore::OnPreFail(nAppID, CORE_ERROR_TLS_VALIDATION_FAIL);
				return false;
			}
		}
#endif
		
		// Register current application ID
		m_nAppID = nAppID;
		m_lpModuleInfo = c_lpModuleInfo;

		CREATE_INSTANCE_DEBUG_LOG(3);

		// Initialize core engine
		if (!NoMercyCore::CCoreIndex::Init(m_nAppID, nullptr, m_lpModuleInfo))
		{
			auto [dwErrCode1, dwErrCode2] = NoMercyCore::CCoreIndex::GetErrorCodes();
			if (!dwErrCode1)
				dwErrCode1 = CORE_ERROR_CORE_ENGINE_INIT_UNKNOWN_ERROR;

			NoMercyCore::OnPreFail(m_nAppID, (ECoreErrorCodes)dwErrCode1, dwErrCode2);
			return false;
		}

		CREATE_INSTANCE_DEBUG_LOG(4);

		// Allocate core class singletons
		m_upApplication = stdext::make_unique_nothrow<CApplication>();

		CREATE_INSTANCE_DEBUG_LOG(5);

		// Validate allocated class instances
		__ValidateCoreInstances();

		CREATE_INSTANCE_DEBUG_LOG(6);

		APP_TRACE_LOG(LL_SYS, L"Application: %u core prepared!", nAppID);
		m_abHasInstance.store(true);
		return true;
	}
	bool CCore::ReleaseInstance() const
	{
		// Check for undefined instance
		if (!m_abHasInstance.load())
		{
			NoMercyCore::OnPreFail(m_nAppID, CORE_ERROR_NOT_EXIST_INSTANCE);
			return false;
		}

		if (CApplication::InstancePtr())
			CApplication::Instance().Finalize();

		return true;
	}

	bool CCore::IsInstanceCreated() const
	{
		return m_abHasInstance.load();
	}
	uint8_t CCore::GetAppID() const
	{
		return m_nAppID;
	}

	LPCVOID CCore::GetModuleInfo() const
	{
		return m_lpModuleInfo;
	}

	void CCore::__ValidateCoreInstances()
	{
		const auto __IsAllInstancesAreNotValid = [&] {
			if (!m_upApplication || !m_upApplication.get())
				return 2;
			return 0;
		};

#ifdef _DEBUG
		APP_TRACE_LOG(LL_TRACE, L"m_upApplication:%p", m_upApplication.get());
#endif

		const auto nValidateRet = __IsAllInstancesAreNotValid();
		if (nValidateRet)
		{
			LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"Core instance validation failed with error: %d"), nValidateRet);
			NoMercyCore::OnPreFail(m_nAppID, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 1);
		}

		if (!NoMercyCore::CCoreIndex::IsInitialized())
		{
			LogfW(CUSTOM_LOG_FILENAME_W,xorstr_(L"Core engine validation failed"));
			NoMercyCore::OnPreFail(m_nAppID, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 2);
		}
	}
};
