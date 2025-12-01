#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	IServiceScanner::IServiceScanner()
	{
	}
	IServiceScanner::~IServiceScanner()
	{
	}

	std::wstring __GetServiceExecutable(const SC_HANDLE hSvcManager, const std::wstring& wstService)
	{
		std::wstring wstServiceName;
		SC_HANDLE hService = nullptr;
		LPQUERY_SERVICE_CONFIGW lpServiceConfig = nullptr;

		do
		{
			if (!hSvcManager || wstService.empty())
				break;

			hService = g_winAPIs->OpenServiceW(hSvcManager, wstService.c_str(), SERVICE_QUERY_CONFIG);
			if (!hService)
			{
				SCANNER_LOG(LL_ERR, L"OpenServiceW failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			DWORD dwRequiredBytes = 0;
			if (!g_winAPIs->QueryServiceConfigW(hService, nullptr, 0, &dwRequiredBytes))
			{
				const auto dwError = g_winAPIs->GetLastError();
				if (dwError == ERROR_INSUFFICIENT_BUFFER)
				{
					lpServiceConfig = (LPQUERY_SERVICE_CONFIGW)CMemHelper::Allocate(dwRequiredBytes);
				}
				else
				{
					SCANNER_LOG(LL_ERR, L"QueryServiceConfigW (1) failed with error: %u", g_winAPIs->GetLastError());
					break;
				}
			}

			if (!lpServiceConfig)
			{
				SCANNER_LOG(LL_ERR, L"Allocate memory failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			if (!g_winAPIs->QueryServiceConfigW(hService, lpServiceConfig, dwRequiredBytes, &dwRequiredBytes))
			{
				SCANNER_LOG(LL_ERR, L"QueryServiceConfigW (2) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			wstServiceName = lpServiceConfig->lpBinaryPathName;
		} while (FALSE);

		if (hService)
		{
			g_winAPIs->CloseServiceHandle(hService);
			hService = nullptr;
		}
		if (lpServiceConfig)
		{
			CMemHelper::Free(lpServiceConfig);
			lpServiceConfig = nullptr;
		}

		return wstServiceName;
	}

	bool IServiceScanner::IsScanned(std::shared_ptr <SServiceScanContext> pServiceCtx)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_SERVICE, pServiceCtx->stServiceName);
	}
	void IServiceScanner::AddScanned(std::shared_ptr <SServiceScanContext> pServiceCtx)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_SERVICE, pServiceCtx->stServiceName);
	}

	void IServiceScanner::ScanSync(std::shared_ptr <SServiceScanContext> pServiceCtx)
	{
		SCANNER_LOG(LL_SYS, L"Service scanner has been started! Target: %s (%s)", pServiceCtx->stServiceName.c_str(), pServiceCtx->stServiceDisplayName.c_str());

		if (!IS_VALID_HANDLE(pServiceCtx->hSvcManager) || pServiceCtx->stServiceName.empty())
			return;

		if (IsScanned(pServiceCtx))
		{
			SCANNER_LOG(LL_SYS, L"Service: %s already scanned!", pServiceCtx->stServiceName.c_str());
			return;
		}
		AddScanned(pServiceCtx);

		const auto vecBlaclist = CApplication::Instance().QuarentineInstance()->ServiceNameQuarentine()->GetBlacklist();
		for (const auto& [data, opts] : vecBlaclist)
		{
			const auto& [id, name] = data;
			
			if (name == pServiceCtx->stServiceName)
			{
				SCANNER_LOG(LL_SYS, L"Service: %s is in blacklist!", pServiceCtx->stServiceName.c_str());
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_SERVICE_SCAN, id, name);
			}
		}
		
		if (!pServiceCtx->stServiceExecutable.empty())
			CApplication::Instance().ScannerInstance()->FileScanner()->Scan(pServiceCtx->stServiceExecutable, FILE_SCAN_TYPE_SERVICE);
	}

	bool IServiceScanner::ScanAll()
	{		
		SCANNER_LOG(LL_SYS, L"Service scanner routine started!");

		CApplication::Instance().ScannerInstance()->EnumerateServices([](std::shared_ptr <SServiceScanContext> ctx) -> bool {
			if (IS_VALID_SMART_PTR(ctx))
			{
				if (ctx->dwServiceState == SERVICE_RUNNING)
				{
					CApplication::Instance().ScannerInstance()->ServiceScanner()->ScanAsync(ctx);
				}
			}
			return true;
		}); 

		SCANNER_LOG(LL_SYS, L"Service scanner routine completed!");
		return true;
	}

	bool IScanner::EnumerateServices(std::function<bool(std::shared_ptr<SServiceScanContext>)> cb)
	{
		SCANNER_LOG(LL_SYS, L"Service enum routine started!");

		auto hSvcManager = g_winAPIs->OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
		if (!hSvcManager)
		{
			SCANNER_LOG(LL_ERR, L"OpenSCManagerA failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		ENUM_SERVICE_STATUS* lpServiceStatus = 0;
		ENUM_SERVICE_STATUS struct_ServiceStatus{ 0 };
		DWORD dwBytesNeeded = 0;
		DWORD dwServiceCount = 0;
		DWORD dwResumeHandle = 0;
		DWORD dwServiceType = SERVICE_DRIVER;
		DWORD dwServiceState = SERVICE_ACTIVE;

		if (!g_winAPIs->EnumServicesStatusW(hSvcManager, dwServiceType, dwServiceState, &struct_ServiceStatus, sizeof(struct_ServiceStatus), &dwBytesNeeded, &dwServiceCount, &dwResumeHandle))
		{
			const auto dwError = g_winAPIs->GetLastError();

			if (dwError == ERROR_MORE_DATA)
			{
				DWORD dwBytes = dwBytesNeeded + sizeof(ENUM_SERVICE_STATUS);
				lpServiceStatus = new (std::nothrow) ENUM_SERVICE_STATUS[dwBytes];
				g_winAPIs->EnumServicesStatusW(hSvcManager, dwServiceType, dwServiceState, lpServiceStatus, dwBytes, &dwBytesNeeded, &dwServiceCount, &dwResumeHandle);
			}
			else
			{
				SCANNER_LOG(LL_ERR, L"EnumServicesStatusA failed with error: %u", dwError);
				g_winAPIs->CloseServiceHandle(hSvcManager);
				return false;
			}
		}

		if (!lpServiceStatus)
		{
			g_winAPIs->CloseServiceHandle(hSvcManager);
			return false;
		}

		for (DWORD i = 0; i < dwServiceCount; i++)
		{
			auto ctx = stdext::make_shared_nothrow<SServiceScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->hSvcManager = hSvcManager;
				ctx->stServiceName = lpServiceStatus[i].lpServiceName;
				ctx->stServiceDisplayName = lpServiceStatus[i].lpDisplayName;
				ctx->stServiceExecutable = __GetServiceExecutable(hSvcManager, ctx->stServiceName);

				if (!cb(ctx))
					break;
			}
		}

		if (lpServiceStatus)
		{
			delete[] lpServiceStatus;
			lpServiceStatus = nullptr;
		}

		g_winAPIs->CloseServiceHandle(hSvcManager);

		SCANNER_LOG(LL_SYS, L"Service enum routine completed!");
		return true;
	}
};
