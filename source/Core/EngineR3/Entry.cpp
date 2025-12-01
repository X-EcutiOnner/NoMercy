#include "PCH.hpp"
#include "Index.hpp"
#include "Core.hpp"
#include "../EngineR3_Core/include/Defines.hpp"

namespace NoMercy
{
	inline bool __InitializeEx(uint8_t nAppType, LPCVOID c_lpCallbackPtr = nullptr, LPCVOID c_lpModuleInfo = nullptr, HINSTANCE hInstance = nullptr)
	{
		if (CCore::Instance().IsInstanceCreated())
			return false;

#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Initialization started for: %u\n", nAppType);
#endif

		if (CCore::Instance().CreateInstance(nAppType, c_lpModuleInfo) == false)
		{
			APP_TRACE_LOG(LL_CRI, L"Base allocation failed!");
			return false;
		}

		if (CApplication::Instance().PrepareCore(nAppType) == false)
		{
			APP_TRACE_LOG(LL_CRI, L"Pre-Initialize failed!");
			return false;
		}

		if (nAppType == NM_STANDALONE)
		{
//			NoMercyCore::CApplication::Instance().DataInstance()->SetLicenseCode(xorstr_(L"ABCDEF123490"));
//			NoMercyCore::CApplication::Instance().DataInstance()->AddLicensedIp(xorstr_(L"127.0.0.1"));
//			NoMercyCore::CApplication::Instance().DataInstance()->AddLicensedIp(xorstr_(L"192.168.2.1"));
		}
		else if (nAppType == NM_CLIENT)
		{
			CApplication::Instance().SDKHelperInstance()->CreateMessageHandler((TNMCallback)c_lpCallbackPtr);
			NoMercyCore::CApplication::Instance().DataInstance()->SetAntiModuleInformations(c_lpModuleInfo);
		}

		if (CApplication::Instance().Initialize() == false)
		{
			APP_TRACE_LOG(LL_CRI, L"Initialize failed! Error: %u", CApplication::Instance().GetInitStatusCode());
			NoMercyCore::OnPreFail(nAppType, CORE_ERROR_APPLICATION_SANITY_CHECK_FAIL, CApplication::Instance().GetInitStatusCode());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Initilization completed!");
		return true;
	}


	BOOL CNoMercyIndex::Enter()
	{
		if (gs_pkCoreInstance || CCore::InstancePtr())
		{
			APP_TRACE_LOG(LL_CRI, L"[ENTER] Already has a core instance!");
			return FALSE;
		}

		gs_pkCoreInstance = new(std::nothrow) CCore();
		if (!gs_pkCoreInstance)
		{
			APP_TRACE_LOG(LL_CRI, L"[ENTER] Core instance allocation failed with error: %d", errno);
			return FALSE;
		}

#ifdef _DEBUG
		APP_TRACE_LOG(LL_CRI, L"[ENTER] Core instance body: 0x%X allocated.\n", gs_pkCoreInstance);
#endif

		return TRUE;
	}

	void CNoMercyIndex::OnThreadAttach(DWORD dwThreadID)
	{
		if (!CCore::InstancePtr() || !CCore::Instance().IsInstanceCreated())
			return;
		if (!CApplication::InstancePtr())
			return;

		CApplication::Instance().OnThreadAttach(dwThreadID);
	}

	void CNoMercyIndex::Exit()
	{
		if (!CCore::InstancePtr() || !CCore::Instance().IsInstanceCreated())
			return;

		CCore::Instance().ReleaseInstance();
	}


	bool CNoMercyIndex::InitCore(uint8_t unVersion, LPCVOID c_lpCallbackPtr, LPCVOID c_lpModuleInfo)
	{
		auto nAppType = NM_CLIENT;
#ifdef _DEBUG
		if (unVersion == 255)
		{
			APP_TRACE_LOG(LL_WARN, L"Application type switched to NM_STANDALONE(%d)", NM_STANDALONE);
			nAppType = NM_STANDALONE;
		}
		else if (unVersion != std::atoi(__MAJOR_VERSION__) && unVersion != 255)
#else
		if (unVersion != std::atoi(__MAJOR_VERSION__))
#endif
		{
			APP_TRACE_LOG(LL_CRI, L"[CORE] NoMercy data version check failed!");
			NoMercyCore::OnPreFail(nAppType, CORE_ERROR_CORE_SANITY_CHECK_FAIL, 1);
			return false;
		}

		if (!c_lpCallbackPtr)
		{
			APP_TRACE_LOG(LL_CRI, L"[CORE] Sanitilization check failed! Step: 1");
			NoMercyCore::OnPreFail(nAppType, CORE_ERROR_CORE_SANITY_CHECK_FAIL, 2);
			return false;
		}

		if (!c_lpModuleInfo)
		{
			APP_TRACE_LOG(LL_CRI, L"[CORE] Sanitilization check failed! Step: 2");
			NoMercyCore::OnPreFail(nAppType, CORE_ERROR_CORE_SANITY_CHECK_FAIL, 3);
			return false;
		}

		return __InitializeEx(nAppType, c_lpCallbackPtr, c_lpModuleInfo);
	}

	bool CNoMercyIndex::InitTest()
	{
		return __InitializeEx(NM_STANDALONE);
	}


	bool CNoMercyIndex::Release()
	{
		if (CCore::Instance().IsInstanceCreated() == false)
		{
			APP_TRACE_LOG(LL_CRI, L"[FINAL] Base class not found!");

			// NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 1);
			NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);

			return false;
		}

		if (CApplication::Instance().AppIsInitiliazed() == false)
		{
			APP_TRACE_LOG(LL_CRI, L"[FINAL] Application is already not initialized!");

			// NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 2);
			NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);

			return false;
		}

		if (CApplication::Instance().Finalize() == false)
		{
			APP_TRACE_LOG(LL_CRI, L"[FINAL] Finalize failed! Error: %u", CApplication::Instance().GetInitStatusCode());

			// NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 3);
			NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);

			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"[FINAL] Finalization completed!");
		return true;
	}

	bool CNoMercyIndex::SendNMMessage(int32_t nCode, LPCVOID c_lpMessage)
	{
		if (!CCore::InstancePtr() || !CCore::Instance().IsInstanceCreated())
		{
			APP_TRACE_LOG(LL_CRI, L"[MSG2] Base class not found! Msg=%d/%p", nCode, c_lpMessage);
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 1);
			return false;
		}
		if (!IS_VALID_SMART_PTR(CApplication::Instance().SDKHelperInstance()))
		{
			APP_TRACE_LOG(LL_CRI, L"[MSG2] SDK Manager is not found!");
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 2);
			return false;
		}
		return CApplication::Instance().SDKHelperInstance()->ProcessClientMessage(nCode, c_lpMessage);
	}

	void CNoMercyIndex::SetUserData(const wchar_t* c_szUserToken, unsigned int nUserTokenSize)
	{
		if (!CCore::InstancePtr() || !CCore::Instance().IsInstanceCreated())
		{
			APP_TRACE_LOG(LL_CRI, L"[UDATA] Base class not found!");
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 1);
			return;
		}
		if (!IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().DataInstance()))
		{
			APP_TRACE_LOG(LL_CRI, L"[UDATA] Data Instance is not found!");
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 2);
			return;
		}

		if (NoMercyCore::CApplication::Instance().DataInstance()->GetUserToken().empty())
			NoMercyCore::CApplication::Instance().DataInstance()->SetUserToken(c_szUserToken);
	}

	const wchar_t* CNoMercyIndex::GetUserSessionID()
	{
		if (!CCore::InstancePtr() || !CCore::Instance().IsInstanceCreated())
		{
			APP_TRACE_LOG(LL_CRI, L"[USID] Base class not found!");
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 1);
			return L"";
		}
		if (!IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().HWIDManagerInstance()))
		{
			APP_TRACE_LOG(LL_CRI, L"[USID] Hwid Manager is not found!");
			NoMercyCore::OnPreFail(0, CORE_ERROR_INSTANCE_VALIDATION_FAIL, 2);
			return L"";
		}

		const auto c_wstSessionID = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetSessionID();
		return c_wstSessionID.c_str();
	}
};
