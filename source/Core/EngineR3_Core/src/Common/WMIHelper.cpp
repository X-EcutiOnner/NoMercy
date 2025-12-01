#include "../../include/PCH.hpp"
#include "../../include/WMIHelper.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/ProcessFunctions.hpp"
#include "../../include/WMI/WbemClassObject.hpp"
#include "../../include/WMI/WbemClassObjectEnumerator.hpp"

namespace NoMercyCore
{
	static void NTAPI __ThreadTerminateWatcher(PVOID pCtx, BOOLEAN)
	{
		const auto dwThreadId = reinterpret_cast<DWORD_PTR>(pCtx);
		WMI_LOG(LL_ERR, L"Access lost to thread: %u", dwThreadId);
	}

	CWMIHelper::CWMIHelper()
	{
	}
	CWMIHelper::~CWMIHelper()
	{
	}

	HANDLE CWMIHelper::CreateAsyncWatcherThread(const std::wstring& wstQuery, const TWmiAsyncCallback& fnCallback)
	{
		HANDLE hThread = nullptr;

		try
		{
			auto pkQueryHandlerThread = new(std::nothrow) CWMIAsyncQueryThreadImpl();
			if (!pkQueryHandlerThread)
			{
				WMI_LOG(LL_ERR, L"CWMIAsyncQueryThreadImpl allocation failed, last error: %u", g_winAPIs->GetLastError());
				return nullptr;
			}

			if (!pkQueryHandlerThread->initialize(wstQuery, fnCallback))
			{
				WMI_LOG(LL_ERR, L"pkQueryHandlerThread->initialize failed with error: %u", g_winAPIs->GetLastError());
				
				delete pkQueryHandlerThread;
				pkQueryHandlerThread = nullptr;
				return nullptr;
			}
			WMI_LOG(LL_SYS, L"Async watcher thread: %u created for: %s", pkQueryHandlerThread->get_threadid(), wstQuery.c_str());

			/*
			HANDLE hWaitObj = nullptr;
			if (!g_winAPIs->RegisterWaitForSingleObject(
				&hWaitObj, pkQueryHandlerThread->getHandle(), __ThreadTerminateWatcher, (PVOID)pkQueryHandlerThread->get_threadid(), INFINITE, WT_EXECUTEONLYONCE))
			{
				WMI_LOG(LL_ERR, L"RegisterWaitForSingleObject failed with error: %u", g_winAPIs->GetLastError());

				delete pkQueryHandlerThread;
				pkQueryHandlerThread = nullptr;
				return nullptr;
			}
			WMI_LOG(LL_SYS, L"Async watcher thread wait object created: %p", hWaitObj);

			m_mapAsyncThreadWaitObjects.emplace(pkQueryHandlerThread->get_threadid(), hWaitObj);
			*/
			m_mapAsyncThreads.emplace(pkQueryHandlerThread->get_threadid(), pkQueryHandlerThread);
			hThread = pkQueryHandlerThread->getHandle();

			pkQueryHandlerThread->start();
		}
		catch (SOL::Exception& ex)
		{
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery exception handled! SOL::Exception: %hs", ex.getErrorMessage());
			return hThread;
		}
		catch (std::exception& ex)
		{
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery exception handled! std::exception: %hs", ex.what());
			return hThread;
		}
		catch (...)
		{
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery unhandled exception throwned!");
			return hThread;
		}

		return hThread;
	}
	void CWMIHelper::TerminateAsyncWatcherThread(DWORD dwThreadID)
	{
		if (dwThreadID)
		{
			auto it = m_mapAsyncThreads.find(dwThreadID);
			if (it != m_mapAsyncThreads.end())
			{
				if (it->second)
				{
					it->second->kill();

					delete it->second;
					it->second = nullptr;
				}

				m_mapAsyncThreads.erase(it);
			}
		}
	}

	void CWMIHelper::StopWatcher(DWORD dwThreadID)
	{
		if (dwThreadID)
		{
			auto it = m_mapAsyncThreads.find(dwThreadID);
			if (it != m_mapAsyncThreads.end())
			{
				if (it->second)
					it->second->stop();
			}
		}
	}

	void CWMIHelper::TerminateThreads()
	{
		for (auto& [dwThreadID, pkSolThread] : m_mapAsyncThreads)
		{
			if (dwThreadID && pkSolThread)
			{
				pkSolThread->stop();
				pkSolThread->terminate(0);

				delete pkSolThread;
			}
		}
		m_mapAsyncThreads.clear();
	}

	bool CWMIHelper::ExecuteQuery(const std::wstring& wstNamespace, const std::wstring& wstQuery, const TWmiCallback& fnCallback, const TWmiOnFailCallback& fnOnFail)
	{
		try
		{
			SOL::MultiThreadedModel model;

			// 1 Create a locator
			SOL::WbemLocator locator;

			// 2 Connect to a server 
			SOL::WbemServices services = locator.connectServer((BSTR)wstNamespace.c_str());

			// 3 ExecQuery
			SOL::WbemClassObjectEnumerator enumerator = services.execQuery((BSTR)wstQuery.c_str());

			// 4 Display the properites (pairs of name-value) of WbemClassObject 
			while (true)
			{
				try
				{
					auto next_obj_ptr = enumerator.next();
					if (!next_obj_ptr)
						break;
					SOL::WbemClassObject object = next_obj_ptr;

					// 5 Get SafeArray of names of 'properties' of the object.
					SOL::SafeArray sarray = object.getNames();

					TWmiDataContainer container;

					long lLowerBound = sarray.getLBound();
					long lUpperBound = sarray.getUBound();

					auto lElementCount = lUpperBound - lLowerBound + 1;

					for (long i = 0; i < lElementCount; i++)
					{
						try
						{
							// 6 Get a name of i-th element of the sarray.
							_bstr_t name = sarray.getString(i);

							// 7 Get a variant-value of the name from the object
							_variant_t variant = object.get(name);

							SOL::COMTypeConverter converter;
							_bstr_t value = converter.toString(variant);

							container.emplace(std::wstring(name, g_winAPIs->SysStringLen(name)), std::wstring(value, g_winAPIs->SysStringLen(value)));
						}
						catch (...)
						{
							WMI_LOG(LL_ERR, L"[1] Unhandled exception!");
						}

//						g_winAPIs->Sleep(10);
					}

					if (fnCallback && !container.empty())
						fnCallback(container);
				}
				catch (...)
				{
					WMI_LOG(LL_ERR, L"[2] Unhandled exception!");
					break;
				}

//				g_winAPIs->Sleep(10);
			}
		}
		catch (HRESULT hr)
		{
			_com_error err(hr);
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery exception handled! hResult: %p (%s)", hr, err.ErrorMessage());
			if (fnOnFail)
				fnOnFail(hr);
			return false;
		}
		catch (SOL::Exception& ex)
		{
			_com_error err(ex.getHRESULT());
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery exception handled! SOL::Exception: %hs (%s)", ex.getErrorMessage(), err.ErrorMessage());
			if (fnOnFail)
				fnOnFail(ex.getHRESULT());
			return false;
		}
		catch (...)
		{
			WMI_LOG(LL_ERR, L"CWMIHelper::ExecuteQuery unhandled exception throwned!");
			return false;
		}

		return true;
	}

	bool CWMIHelper::CheckWMIIntegirty()
	{
		auto HasRestriction = [&] {
			auto nBufSize = 1024UL;
			auto dwBuffer = 0UL;

			auto dwFlags = KEY_READ | KEY_QUERY_VALUE;
			if (stdext::is_wow64())
				dwFlags |= KEY_WOW64_64KEY;

			HKEY hKey = nullptr;
			auto res = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Restrictions"), 0, dwFlags, &hKey);
			if (res == ERROR_FILE_NOT_FOUND)
			{
				return false;
			}
			else if (res != ERROR_SUCCESS)
			{
				WMI_LOG(LL_ERR, L"RegOpenKeyExW failed with status: %p", res);
				return false;
			}
			return true;
		};

		auto IsServiceIntegirtyCorrupted = [](const std::wstring& wstServiceName) {
			bool bRet = true;

			SC_HANDLE shServiceMgr = nullptr;
			SC_HANDLE shService = nullptr;
			LPBYTE lpBuffer = nullptr;

			do
			{
				shServiceMgr = g_winAPIs->OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
				if (!shServiceMgr)
				{
					WMI_LOG(LL_ERR, L"OpenSCManagerW failed with status: %u", g_winAPIs->GetLastError());
					break;
				}

				shService = g_winAPIs->OpenServiceW(shServiceMgr, wstServiceName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
				if (!shService)
				{
					WMI_LOG(LL_ERR, L"OpenServiceW failed with status: %u", g_winAPIs->GetLastError());
					break;
				}

				DWORD dwReqSize = 0;
				if (!g_winAPIs->QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO, nullptr, 0, &dwReqSize) && !dwReqSize)
				{
					WMI_LOG(LL_ERR, L"QueryServiceStatusEx (1) failed with status: %u", g_winAPIs->GetLastError());
					break;
				}

				lpBuffer = (BYTE*)CMemHelper::Allocate(dwReqSize);
				if (!lpBuffer)
				{
					WMI_LOG(LL_ERR, L"%u bytes memory allocation failed with error: %u", dwReqSize, errno);
					break;
				}

				if (!g_winAPIs->QueryServiceStatusEx(shService, SC_STATUS_PROCESS_INFO, lpBuffer, dwReqSize, &dwReqSize) || !lpBuffer)
				{
					WMI_LOG(LL_ERR, L"QueryServiceStatusEx (2) failed with status: %u", g_winAPIs->GetLastError());
					break;
				}

				const auto lpProcessStatus = (SERVICE_STATUS_PROCESS*)lpBuffer;
				if (!lpProcessStatus->dwProcessId)
				{
					WMI_LOG(LL_ERR, L"Service query buffer does not contain process id");
					break;
				}
				WMI_LOG(LL_SYS, L"Service status: %u Host process: %u", lpProcessStatus->dwCurrentState, lpProcessStatus->dwProcessId);

				if (lpProcessStatus->dwCurrentState != SERVICE_RUNNING)
				{
					WMI_LOG(LL_ERR, L"Service is not running!");
					break;
				}

				if (!CProcessFunctions::ProcessIsItAlive(lpProcessStatus->dwProcessId))
				{
					WMI_LOG(LL_ERR, L"Service host process not alive!");
					break;
				}

				if (CProcessFunctions::HasSuspendedThread(lpProcessStatus->dwProcessId))
				{
					WMI_LOG(LL_ERR, L"Service host process contains suspended threads!");
					break;
				}

				bRet = false;
			} while (FALSE);

			if (shServiceMgr)
			{
				g_winAPIs->CloseServiceHandle(shServiceMgr);
				shServiceMgr = nullptr;
			}
			if (shService)
			{
				g_winAPIs->CloseServiceHandle(shService);
				shService = nullptr;
			}
			if (lpBuffer)
			{
				CMemHelper::Free(lpBuffer);
				lpBuffer = nullptr;
			}

			return bRet;
		};

		if (HasRestriction())
		{
			WMI_LOG(LL_ERR, L"WMI Restriction registry has been found!");
			return false;
		}
		else if (IsServiceIntegirtyCorrupted(xorstr_(L"winmgmt")))
		{
			WMI_LOG(LL_ERR, L"WMI service integrity corrupted!");
			return false;
		}
		else if (!CProcessFunctions::GetProcessIdFromProcessName(xorstr_(L"wmiprvse.exe")))
		{
			WMI_LOG(LL_ERR, L"WMI host process integrity corrupted!");
			return false;
		}

		return true;
	}
}
