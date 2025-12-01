#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Hooks.hpp"

namespace NoMercy
{
	VOID NTAPI LdrDllNotificationCallback(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
	{
		auto fnAnalyseModuleCall = [&]() {
			HOOK_LOG(LL_SYS, L"LdrDllNotification called! Reason: %u", NotificationReason);

			if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
			{
				const auto wstModuleName = std::wstring(NotificationData->Loaded.FullDllName->Buffer, NotificationData->Loaded.FullDllName->Length);
				HOOK_LOG(LL_SYS, L"LdrDllNotification loaded dll: %ls", wstModuleName.c_str());

				auto bSuspicious = false;
				auto bAnalysed = CApplication::Instance().AnalyserInstance()->OnModuleLoaded(wstModuleName, NtCurrentThread(), CHECK_TYPE_LdrDllNotificationCallback, bSuspicious);
				HOOK_LOG(LL_SYS, L"Module: %ls analysed, Completed: %d Suspicious: %d", wstModuleName.c_str(), bAnalysed, bSuspicious);

				CApplication::Instance().FilterMgrInstance()->AddKnownModule((DWORD_PTR)NotificationData->Loaded.DllBase, NotificationData->Loaded.SizeOfImage, wstModuleName);
			}
			else if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_UNLOADED)
			{
				const auto wstModuleName = std::wstring(NotificationData->Unloaded.FullDllName->Buffer, NotificationData->Unloaded.FullDllName->Length);
				HOOK_LOG(LL_SYS, L"LdrDllNotification unloaded dll: %ls", wstModuleName.c_str());

				CApplication::Instance().FilterMgrInstance()->RemoveKnownModule((DWORD_PTR)NotificationData->Loaded.DllBase);
			}			
		};

		__try
		{
			fnAnalyseModuleCall();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

	bool CSelfApiHooks::InitDllNotificationCallback()
	{
		HOOK_LOG(LL_SYS, L"LdrRegisterDllNotification has been initializing");

		if (!IsWindowsVistaOrGreater())
		{
			HOOK_LOG(LL_SYS, L"LdrRegisterDllNotification passed in this OS");
			return true;
		}

		const auto ntStat = g_winAPIs->LdrRegisterDllNotification(0, LdrDllNotificationCallback, NULL, &m_lpDllNotificationCookie);
		if (!NT_SUCCESS(ntStat))
		{
			HOOK_LOG(LL_ERR, L"LdrRegisterDllNotification fail! ntStat: %p", ntStat);
			return false;
		}

		HOOK_LOG(LL_SYS, L"LdrRegisterDllNotification succesfully initialized");
		return true;
	}

	void CSelfApiHooks::ReleaseDllNotificationCallback()
	{
		if (!IsWindowsVistaOrGreater())
		{
			HOOK_LOG(LL_SYS, L"LdrRegisterDllNotification passed in this OS");
			return;
		}

		if (m_lpDllNotificationCookie)
		{
			g_winAPIs->LdrUnregisterDllNotification(m_lpDllNotificationCookie);
			m_lpDllNotificationCookie = nullptr;
		}
	}
};
