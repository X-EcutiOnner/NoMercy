#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"



namespace NoMercy
{
	IHandleScanner::IHandleScanner() :
		m_dwCurrentSessionId(0)
	{
	}
	IHandleScanner::~IHandleScanner()
	{
	}

	bool IHandleScanner::IsScanned(std::shared_ptr <SHandleScanContext> pHandleCtx)
	{
		// return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_HANDLE, fmt::format(xorstr_(L"{0}"), fmt::ptr(pHandleCtx->hHandle)));

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		for (auto& [dwSourcePid, hHandle, pObject] : m_vScannedHandles)
		{
			if (dwSourcePid == pHandleCtx->hSourcePid && hHandle == pHandleCtx->hHandle && pObject == pHandleCtx->pObject)
				return true;
		}
		return false;
	}
	void IHandleScanner::AddScanned(std::shared_ptr <SHandleScanContext> pHandleCtx)
	{
		// CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_HANDLE, fmt::format(xorstr_(L"{0}"), fmt::ptr(pHandleCtx->hHandle)));

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_vScannedHandles.emplace_back(std::make_tuple(pHandleCtx->hSourcePid, pHandleCtx->hHandle, pHandleCtx->pObject));
	}

	bool IHandleScanner::IsUnopenedProcess(DWORD dwProcessId) const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		return (std::find(m_vUnopenedProcesses.begin(), m_vUnopenedProcesses.end(), dwProcessId) != m_vUnopenedProcesses.end());
	}
	void IHandleScanner::AddUnopenedProcess(DWORD dwProcessId)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_vUnopenedProcesses.emplace_back(dwProcessId);
	}

	bool IHandleScanner::KillHandle(DWORD dwProcessId, HANDLE hHandleValue)
	{
		if (g_winAPIs->GetCurrentProcessId() == dwProcessId)
			return NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hHandleValue);

		SafeHandle pkProcess = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, dwProcessId);
		if (!pkProcess.IsValid())
			return false;

		HANDLE hLocalHandle = nullptr;
		const auto ntStatus = g_winAPIs->NtDuplicateObject(
			// pkProcess.get(), hHandleValue, NtCurrentProcess(), &hLocalHandle, 0L, 0L, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES | DUPLICATE_CLOSE_SOURCE
			pkProcess.get(), hHandleValue, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE
		);
		const auto bRet = NT_SUCCESS(ntStatus);
		if (bRet) {
			APP_TRACE_LOG(LL_SYS, L"Process: %u Handle %p has been closed!", dwProcessId, hHandleValue);
		} else {
			APP_TRACE_LOG(LL_ERR, L"Process: %u Handle %p close failed with status: %p", dwProcessId, hHandleValue, ntStatus);
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hLocalHandle);		
		return bRet;
	}

	bool IHandleScanner::IsProtectedHandle(HANDLE hValue)
	{
		if (!hValue)
			return false;

		ULONG size{};
		OBJECT_HANDLE_FLAG_INFORMATION handle_info{};
		if (NT_SUCCESS(g_winAPIs->NtQueryObject(hValue, ObjectHandleFlagInformation, &handle_info, sizeof(handle_info), &size)))
		{
			if (handle_info.ProtectFromClose)
				return true;
		}

		return false;
	}

	DWORD IHandleScanner::GetGrantedAccess(HANDLE handle)
	{
		if (!handle)
			return 0;
		
		DWORD size{};
		OBJECT_BASIC_INFORMATION basic_info{};
		if (NT_SUCCESS(g_winAPIs->NtQueryObject(handle, ObjectBasicInformation, &basic_info, sizeof(basic_info), &size)))
			return basic_info.GrantedAccess;

		return 0;
	}

	void IHandleScanner::ScanSync(std::shared_ptr <SHandleScanContext> pHandleCtx)
	{
//		APP_TRACE_LOG(LL_SYS, L"Handle scanner has been started! Target: %p", pHandleCtx->hHandle);

		if (!pHandleCtx->hHandle)
			return;

		const auto dwSourcePID = (DWORD)pHandleCtx->hSourcePid;
		if (IsUnopenedProcess(dwSourcePID))
			return;

		if (dwSourcePID < 5) // System 
		{
			APP_TRACE_LOG(LL_WARN, L"Handle scanner skipped system process: %u", dwSourcePID)
			AddUnopenedProcess(dwSourcePID);
			return;
		}

		const auto dwCurrPID = g_winAPIs->GetCurrentProcessId();
		if (dwSourcePID == dwCurrPID) // Our created handle
			return;

		if (IsScanned(pHandleCtx))
			return;
		AddScanned(pHandleCtx);

		// Check Session ID for speed up scanning
		auto bKnownProcess = true;
		if (!stdext::in_vector(m_vecScannedPIDs, dwSourcePID))
		{
			m_vecScannedPIDs.emplace_back(dwSourcePID);
			bKnownProcess = false;

			DWORD dwCurrProcSID = 0;
			if (g_winAPIs->ProcessIdToSessionId(dwSourcePID, &dwCurrProcSID))
			{
				if (m_dwCurrentSessionId != dwCurrProcSID)
				{
					APP_TRACE_LOG(LL_WARN, L"Handle scanner skipped process from another session: %u", dwSourcePID);
					AddUnopenedProcess(dwSourcePID);
					return;
				}
			}
			else
			{
				APP_TRACE_LOG(LL_WARN, L"ProcessIdToSessionId (%u) failed with error: %u", dwSourcePID, g_winAPIs->GetLastError());
				// AddUnopenedProcess(dwSourcePID);
				// return;
			}
		}

		// Quick check for all other system processes
		auto wstOwnerProcessBaseName = CProcessFunctions::GetProcessNameFromProcessId(dwSourcePID);
		if (!wstOwnerProcessBaseName.empty())
		{
			wstOwnerProcessBaseName = stdext::to_lower_wide(wstOwnerProcessBaseName);

			static auto vecWhitelistedItems = std::vector <std::wstring>{
				xorstr_(L"system"),
				xorstr_(L"secure system"),
				xorstr_(L"registry"),
				xorstr_(L"memory compression"),
				xorstr_(L"hotpatch"), 
				xorstr_(L"csrss.exe"),
				xorstr_(L"lsass.exe")
			};
			if (stdext::in_vector(vecWhitelistedItems, wstOwnerProcessBaseName))
			{
				APP_TRACE_LOG(LL_WARN, L"Handle scanner skipped whitelisted process: %u (%s)", dwSourcePID, wstOwnerProcessBaseName.c_str());
				AddUnopenedProcess(dwSourcePID);
				return;
			}

#ifdef _DEBUG
			if (!bKnownProcess)
			{
				APP_TRACE_LOG(LL_SYS, L"Scanning process: %u (%s)", dwSourcePID, wstOwnerProcessBaseName.c_str());
			}
#endif
		}
		else
		{
			// APP_TRACE_LOG(LL_WARN, L"Process: %u name query failed with error: %u", dwSourcePID, g_winAPIs->GetLastError());
		}

		// APP_TRACE_LOG(LL_SYS, L"PID: %u Object %p Handle %p Type: %u Access: %p", dwSourcePID, pHandleCtx->pObject, pHandleCtx->hHandle, pHandleCtx->uTypeIndex, pHandleCtx->dwGrantedAccess);

		// Create a handle to the source process for NtDuplicateObject
		auto hSourceProcess = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, dwSourcePID);
		if (!IS_VALID_HANDLE(hSourceProcess))
		{
			const auto stProcessName = CProcessFunctions::GetProcessNameFromProcessId(dwSourcePID);
			APP_TRACE_LOG(LL_ERR, L"Source process: %u (%s) open failed with error: %u", dwSourcePID, stProcessName.c_str(), g_winAPIs->GetLastError());
			AddUnopenedProcess(dwSourcePID);
			return;
		}

		// Check process launch time for speed up scanning
		static constexpr auto dwMaxProcessLaunchTime = 1000 * 60 * 30; // 30 minutes
		if (!bKnownProcess)
		{
			const auto dwProcessStartTime = CProcessFunctions::GetProcessCreationTime(hSourceProcess);
			if (dwProcessStartTime)
			{
				const auto dwCurrentTime = stdext::get_current_epoch_time();
				const auto uliProcessStartTime = dwCurrentTime - dwProcessStartTime;

				APP_TRACE_LOG(LL_SYS, L"Process: %u (%s) launch time: %u", dwSourcePID, wstOwnerProcessBaseName.c_str(), uliProcessStartTime);

				if (uliProcessStartTime > dwMaxProcessLaunchTime)
				{
					APP_TRACE_LOG(LL_WARN, L"Handle scanner skipped process %u (%s) due than launch time is more than %u minutes", dwSourcePID, wstOwnerProcessBaseName.c_str(), dwMaxProcessLaunchTime / 1000 / 60);
					AddUnopenedProcess(dwSourcePID);
					return;
				}
			}
			else
			{
				APP_TRACE_LOG(LL_WARN, L"GetProcessTimes (%u) failed with error: %u", dwSourcePID, g_winAPIs->GetLastError());
				// AddUnopenedProcess(dwSourcePID);
				// return;
			}
		}

		// Duplicate handle to the current process
		HANDLE hDupHandle = nullptr;
		auto ntStatus = g_winAPIs->NtDuplicateObject(hSourceProcess, pHandleCtx->hHandle, NtCurrentProcess(), &hDupHandle, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
		if (!NT_SUCCESS(ntStatus))
		{
			if (ntStatus != STATUS_NOT_SUPPORTED)
			{
				APP_TRACE_LOG(LL_TRACE, L"NtDuplicateObject failed with status: %p", ntStatus);
			}
			g_winAPIs->CloseHandle(hSourceProcess);
			return;
		}

		const auto stObjectType = CApplication::Instance().ScannerInstance()->GetHandleObjectType(hDupHandle);
		if (stObjectType.empty())
		{
			APP_TRACE_LOG(LL_TRACE, L"GetHandleObjectType failed");
			g_winAPIs->CloseHandle(hSourceProcess);
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
			return;
		}

		const auto dwHandleType = stdext::hash(stObjectType.c_str());
#ifdef _DEBUG
		// APP_TRACE_LOG(LL_SYS, L"Object type: %s (%p)", stObjectType.c_str(), dwHandleType);
#endif
		/*
			// When calling NtQueryObject with ObjectNameInformation, the function may never return if the access mask is equals to checked values.
			if (pHandleCtx->dwGrantedAccess == 0x00120089 || pHandleCtx->dwGrantedAccess == 0x0012019F || pHandleCtx->dwGrantedAccess == 0x0012008D)
			{
				APP_TRACE_LOG(LL_TRACE, L"Skipped handle due than whitelisted access mask");
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return;
			}

			if (CApplication::Instance().ScannerInstance()->IsHandleInheritable(hDupHandle))
			{
				APP_TRACE_LOG(LL_TRACE, L"Inheritable handle skipped than scan.");
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return;
			}	
		*/
		if (dwHandleType != stdext::hash("process") && dwHandleType != stdext::hash("thread"))
		{


			/*
			const auto stObjectName = CApplication::Instance().ScannerInstance()->GetHandleObjectName(hSourceProcess, hDupHandle);

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Object type: %s Name: %s", stObjectType.c_str(), stObjectName.c_str());
#endif
			*/
		}

		if (dwHandleType == stdext::hash("thread"))
		{			
			THREAD_BASIC_INFORMATION ti;
			g_winAPIs->NtQueryInformationThread(hDupHandle, ThreadBasicInformation, &ti, sizeof(ti), NULL);

#ifdef _DEBUG
			// APP_TRACE_LOG(LL_SYS, L"Object type: %s Target: %u", stObjectType.c_str(), (DWORD_PTR)ti.ClientId.UniqueThread);
#endif
		}
		else if (dwHandleType == stdext::hash("process"))
		{
			PROCESS_BASIC_INFORMATION pbi{};
			ntStatus = g_winAPIs->NtQueryInformationProcess(hDupHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				// APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed for process handle with status: %p", ntStatus);
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return;
			}

			auto dwThreadOwnerPID = 0ul;
			THREAD_BASIC_INFORMATION tbi{};
			ntStatus = g_winAPIs->NtQueryInformationThread(hDupHandle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
			if (NT_SUCCESS(ntStatus))
			{
				dwThreadOwnerPID = (DWORD_PTR)tbi.ClientId.UniqueProcess;
			}

			const auto dwProcessID = (DWORD_PTR)pbi.UniqueProcessId;
			if (dwProcessID != dwCurrPID && dwThreadOwnerPID != dwCurrPID)
			{
				// APP_TRACE_LOG(LL_WARN, L"Process handle target is not current process! Target: %u", dwProcessID);
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return;
			}

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Handle access found to current process! Object type: %s", stObjectType.c_str());
#endif

			// Check protected handle
			if (IsProtectedHandle(pHandleCtx->hHandle) || IsProtectedHandle(hDupHandle))
			{
				APP_TRACE_LOG(LL_ERR, L"Protected handle detected! Handle: %p Source: %u (%s)", pHandleCtx->hHandle, dwProcessID, wstOwnerProcessBaseName.c_str());
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				return;
			}

			auto wstOwnerProcName = CProcessFunctions::GetProcessName(hSourceProcess);
			if (wstOwnerProcName.empty())
			{
				APP_TRACE_LOG(LL_WARN, L"Process: %u name query failed with error: %u", dwProcessID, g_winAPIs->GetLastError());
				wstOwnerProcName = wstOwnerProcessBaseName;
			}
			wstOwnerProcName = stdext::to_lower_wide(wstOwnerProcName);

			APP_TRACE_LOG(LL_SYS, L"Handle owner process: %p (%u) Name: %s", hSourceProcess, dwProcessID, wstOwnerProcName.c_str());

			if (stdext::is_debug_build() && stdext::is_known_debugger_process(wstOwnerProcName, true))
			{
				APP_TRACE_LOG(LL_WARN, L"Debugger process skipped for current environment!");
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				AddUnopenedProcess(dwSourcePID);
				return;
			}

			static auto vecWhitelistedWindowsItems = std::vector <std::wstring>{
				xorstr_(L"sndvol.exe"), xorstr_(L"audiodg.exe"), xorstr_(L"svchost.exe"), xorstr_(L"taskmgr.exe")
			};
			for (const auto& wstProcessName : vecWhitelistedWindowsItems)
			{
				if (stdext::ends_with(wstOwnerProcName, wstProcessName) &&
					NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(wstOwnerProcName))
				{
					APP_TRACE_LOG(LL_WARN, L"#1 Handle owner process skipped than whitelisted process: %u (%s)", dwProcessID, wstOwnerProcName.c_str());
					g_winAPIs->CloseHandle(hSourceProcess);
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
					AddUnopenedProcess(dwSourcePID);
					return;
				}
			}

			static auto vecWhitelisted3rdItems = std::vector <std::wstring>{
				xorstr_(L"overwolfhelper.exe"),						// c:\program files (x86)\common files\overwolf\0.254.0.13\overwolfhelper.exe
				xorstr_(L"overwolfhelper64.exe"),					// c:\program files (x86)\common files\overwolf\0.254.0.13\overwolfhelper64.exe
				xorstr_(L"mediasdk_server.exe"),					// c:\program files\tiktok live studio\0.61.2\resources\app\electron\sdk\lib\mediasdk_server.exe
				xorstr_(L"tiktok live studio.exe"),					// c:\program files\tiktok live studio\0.61.2\tiktok live studio.exe
				xorstr_(L"cnext\\presentmon-x64.exe"),				// c:\program files\amd\cnext\cnext\presentmon-x64.exe
				xorstr_(L"assets\\native\\ngenuity2helper.exe"),	// c:\program files\windowsapps\33c30b79.hyperxngenuity_5.26.0.0_x64__0a78dr3hq0pvt\assets\native\ngenuity2helper.exe
				xorstr_(L"audio\\hda\\ravbg64.exe"),				// c:\program files\realtek\audio\hda\ravbg64.exe	
			};
			for (const auto& wstProcessName : vecWhitelistedWindowsItems)
			{
				if (stdext::ends_with(wstOwnerProcName, wstProcessName) &&
					(wstOwnerProcName.find(xorstr_(L":\\program files (x86)\\")) != std::wstring::npos || wstOwnerProcName.find(xorstr_(L":\\program files\\")) != std::wstring::npos))
				{
					APP_TRACE_LOG(LL_WARN, L"#2 Handle owner process skipped than whitelisted process: %u (%s)", dwProcessID, wstOwnerProcName.c_str());
					g_winAPIs->CloseHandle(hSourceProcess);
					NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
					AddUnopenedProcess(dwSourcePID);
					return;
				}
			}

			const auto wstExeNameWithPath = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath());
			if (wstExeNameWithPath == wstOwnerProcName)
			{
				APP_TRACE_LOG(LL_WARN, L"Handle owner process skipped than current process: %u (%s)", dwProcessID, wstOwnerProcName.c_str());
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				AddUnopenedProcess(dwSourcePID);
				return;
			}

			const auto wstCrashHandler = stdext::to_lower_wide(fmt::format(xorstr_(L"{0}\\{1}"), NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExePath(), CRASHPAD_NAME));
			if (wstCrashHandler == wstOwnerProcName)
			{
				APP_TRACE_LOG(LL_WARN, L"Handle owner process skipped than crash handler: %u (%s)", dwProcessID, wstOwnerProcName.c_str());
				g_winAPIs->CloseHandle(hSourceProcess);
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
				AddUnopenedProcess(dwSourcePID);
				return;
			}

			APP_TRACE_LOG(LL_ERR, L"Remote Access Detected. Access owner PID: %u Name: %s Handle info: %p (Access: %p) Crash handler: %s",
				dwProcessID, wstOwnerProcName.c_str(), pHandleCtx->hHandle, pHandleCtx->dwGrantedAccess, wstCrashHandler.c_str()
			);

			CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_REMOTE_HANDLE_ACCESS, dwSourcePID, wstOwnerProcName.size() ? wstOwnerProcName : wstOwnerProcessBaseName);
			g_winAPIs->Sleep(10000);

			// Terminate created handle
			if (!KillHandle(dwSourcePID, pHandleCtx->hHandle))
			{
				APP_TRACE_LOG(LL_ERR, L"Remote handle: 0x%X can NOT terminated!", pHandleCtx->hHandle);
				CApplication::Instance().OnCloseRequest(EXIT_ERR_FORCED_HANDLE_ACCESS, dwSourcePID);
				return;
			}
			APP_TRACE_LOG(LL_SYS, L"Remote handle: %p succesfully terminated!", pHandleCtx->hHandle);

			//auto bDecreasePrivRet = g_gwApp->AccessHelperInstance()->DecreaseProcessDebugAccess(handle.ProcessId);
			//APP_TRACE_LOG(LL_SYS, L"Decrease priv ret: %d Target: %u", bDecreasePrivRet, handle.ProcessId);
		}
		else if (dwHandleType == stdext::hash("section"))
		{

		}
		else if (dwHandleType == stdext::hash("debugobject"))
		{

		}
		else if (dwHandleType == stdext::hash("key"))
		{

		}
		else if (dwHandleType == stdext::hash("symboliclink"))
		{

		}
		else if (dwHandleType == stdext::hash("pipe"))
		{

		}
		// driver || device
		// port
		
		g_winAPIs->CloseHandle(hSourceProcess);
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDupHandle);
		return;
	}

	bool IHandleScanner::ScanProcess(DWORD dwProcessID)
	{
		if (!dwProcessID)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Handle scanner has been started for process: %u", dwProcessID);

		static auto timer = CStopWatch<std::chrono::microseconds>();

		const auto bRet = CApplication::Instance().ScannerInstance()->EnumerateHandles([&](SHandleScanContext* lpHandleCtx) {
			if (lpHandleCtx->hSourcePid == dwProcessID)
			{
				auto ctx = stdext::make_shared_nothrow<SHandleScanContext>();
				if (IS_VALID_SMART_PTR(ctx))
				{
					ctx->dwGrantedAccess = lpHandleCtx->dwGrantedAccess;
					ctx->hHandle = lpHandleCtx->hHandle;
					ctx->hSourcePid = lpHandleCtx->hSourcePid;
					ctx->pObject = lpHandleCtx->pObject;
					ctx->uTypeIndex = lpHandleCtx->uTypeIndex;

					// ScanAsync(ctx); // Takes so long time

					auto spScanner = CApplication::Instance().ScannerInstance();
					if (!IS_VALID_SMART_PTR(spScanner) ||
						!IS_VALID_SMART_PTR(spScanner->HandleScanner()))
					{
						return false; // Stop scanning, scanner instance is no longer valid somehow
					}

					spScanner->HandleScanner()->ScanSync(ctx);
				}
			}
			return true;
		});

		APP_TRACE_LOG(LL_SYS, L"Handle scan completed on: %lu ms", timer.diff());

		// Cache scanned handles
		for (auto& [dwSourcePid, hHandle, pObject] : m_vScannedHandles)
		{
			CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_HANDLE, fmt::format(xorstr_(L"{0}|{1}{2}"), dwSourcePid, fmt::ptr(hHandle), fmt::ptr(pObject)));
			g_winAPIs->Sleep(1);
		}

		// Save cache
		CApplication::Instance().ScannerInstance()->SaveScanCacheToFile();

		return bRet;
	}

	bool IHandleScanner::ScanLastObjects()
	{
		APP_TRACE_LOG(LL_SYS, L"Fast Handle scanner has been started");

		static auto timer = CStopWatch<std::chrono::microseconds>();
		static auto counter = 0;

		const auto bRet = CApplication::Instance().ScannerInstance()->EnumerateHandles([&](SHandleScanContext* lpHandleCtx) {
			counter++;
			if (counter > 1000)
			{
				APP_TRACE_LOG(LL_SYS, L"Handle scan completed on: %lu ms", timer.diff());
				counter = 0;
				return false;
			}

			auto ctx = stdext::make_shared_nothrow<SHandleScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->dwGrantedAccess = lpHandleCtx->dwGrantedAccess;
				ctx->hHandle = lpHandleCtx->hHandle;
				ctx->hSourcePid = lpHandleCtx->hSourcePid;
				ctx->pObject = lpHandleCtx->pObject;
				ctx->uTypeIndex = lpHandleCtx->uTypeIndex;

				auto spScanner = CApplication::Instance().ScannerInstance();
				if (!IS_VALID_SMART_PTR(spScanner) ||
					!IS_VALID_SMART_PTR(spScanner->HandleScanner()))
				{
					return false; // Stop scanning, scanner instance is no longer valid somehow
				}

				// ScanAsync(ctx); // Takes so long time
				spScanner->HandleScanner()->ScanSync(ctx);
			}
			return true;
		});

		APP_TRACE_LOG(LL_SYS, L"Handle scan completed on: %lu ms", timer.diff());

		// Cache scanned handles
		for (auto& [dwSourcePid, hHandle, pObject] : m_vScannedHandles)
		{
			CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_HANDLE, fmt::format(xorstr_(L"{0}|{1}{2}"), dwSourcePid, fmt::ptr(hHandle), fmt::ptr(pObject)));
			g_winAPIs->Sleep(1);
		}

		// Save cache
		CApplication::Instance().ScannerInstance()->SaveScanCacheToFile();

		return bRet;
	}

	bool IHandleScanner::ScanAll()
	{
		APP_TRACE_LOG(LL_SYS, L"Handle scanner has been started");

		g_winAPIs->ProcessIdToSessionId(g_winAPIs->GetCurrentProcessId(), &m_dwCurrentSessionId);

		static auto timer = CStopWatch<std::chrono::microseconds>();

		const auto bRet = CApplication::Instance().ScannerInstance()->EnumerateHandles([&](SHandleScanContext* lpHandleCtx) {
			auto ctx = stdext::make_shared_nothrow<SHandleScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->dwGrantedAccess = lpHandleCtx->dwGrantedAccess;
				ctx->hHandle = lpHandleCtx->hHandle;
				ctx->hSourcePid = lpHandleCtx->hSourcePid;
				ctx->pObject = lpHandleCtx->pObject;
				ctx->uTypeIndex = lpHandleCtx->uTypeIndex;

				auto spScanner = CApplication::Instance().ScannerInstance();
				if (!IS_VALID_SMART_PTR(spScanner) ||
					!IS_VALID_SMART_PTR(spScanner->HandleScanner()))
				{
					return false; // Stop scanning, scanner instance is no longer valid somehow
				}

				// ScanAsync(ctx); // Takes so long time
				spScanner->HandleScanner()->ScanSync(ctx);
			}
			return true;
		});

		APP_TRACE_LOG(LL_SYS, L"Handle scan completed on: %lu ms", timer.diff());

		// Cache scanned handles
		for (auto& [dwSourcePid, hHandle, pObject] : m_vScannedHandles)
		{
			CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_HANDLE, fmt::format(xorstr_(L"{0}|{1}{2}"), dwSourcePid, fmt::ptr(hHandle), fmt::ptr(pObject)));
			g_winAPIs->Sleep(1);
		}

		// Save cache
		CApplication::Instance().ScannerInstance()->SaveScanCacheToFile();

		return bRet;
	}

	bool IScanner::IsHandleInheritable(HANDLE hObject)
	{
		auto bRet = false;

		auto objInfo = (POBJECT_HANDLE_FLAG_INFORMATION)g_winAPIs->VirtualAlloc(nullptr, 0x100, MEM_COMMIT, PAGE_READWRITE);
		if (!objInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualAlloc failed with error: %u", g_winAPIs->GetLastError());
			return bRet;
		}

		const auto ntStat = g_winAPIs->NtQueryObject(hObject, ObjectHandleFlagInformation, objInfo, 0x100, NULL);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryObject failed with error: %p", ntStat);
			g_winAPIs->VirtualFree(objInfo, 0, MEM_RELEASE);
			return bRet;
		}

		bRet = objInfo->Inherit ? true : false;

		g_winAPIs->VirtualFree(objInfo, 0, MEM_RELEASE);
		return bRet;
	}
	std::wstring IScanner::GetHandleObjectType(HANDLE hObject)
	{
		static constexpr auto OBJECT_TYPE_SIZE = sizeof(OBJECT_TYPE_INFORMATION) + 0x1000;

		auto stOut = L""s;

		auto objInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(g_winAPIs->VirtualAlloc(nullptr, OBJECT_TYPE_SIZE, MEM_COMMIT, PAGE_READWRITE));
		if (!objInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualAlloc failed with error: %u", g_winAPIs->GetLastError());
			return stOut;
		}

		const auto ntStat = g_winAPIs->NtQueryObject(hObject, ObjectTypeInformation, objInfo, OBJECT_TYPE_SIZE, nullptr);
		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryObject failed with error: %p", ntStat);
			g_winAPIs->VirtualFree(objInfo, 0, MEM_RELEASE);
			return stOut;
		}

		if (objInfo->TypeName.Buffer && objInfo->TypeName.Length)
		{
			const auto wstName = std::wstring(objInfo->TypeName.Buffer, objInfo->TypeName.Length);
			stOut = stdext::to_lower_wide(wstName);
		}

		g_winAPIs->VirtualFree(objInfo, 0, MEM_RELEASE);
		return stOut;
	}
	std::wstring IScanner::GetHandleObjectName(HANDLE hProcess, HANDLE hObject)
	{		
		auto stOut = L""s;
		POBJECT_NAME_INFORMATION objInfo = nullptr;

		if (g_winAPIs->WaitForSingleObject(hObject, 100) == WAIT_TIMEOUT)
		{
			// TODO: https://www.dima.to/blog/?p=220   /// 386
		}
		else
		{
			do
			{
				objInfo = (POBJECT_NAME_INFORMATION)g_winAPIs->VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
				if (!objInfo)
				{
					APP_TRACE_LOG(LL_ERR, L"VirtualAlloc failed with error: %u", g_winAPIs->GetLastError());
					break;
				}

				const auto ntStat = g_winAPIs->NtQueryObject(hObject, ObjectNameInformation, objInfo, 0x1000, nullptr);
				if (!NT_SUCCESS(ntStat))
				{
					APP_TRACE_LOG(LL_ERR, L"NtQueryObject failed with error: %p", ntStat);
					break;
				}

				if (objInfo->Name.Buffer && objInfo->Name.Length)
				{
					const auto wstName = std::wstring(objInfo->Name.Buffer, objInfo->Name.Length);
					stOut = stdext::to_lower_wide(wstName);
				}
			} while (false);

			if (objInfo)
				g_winAPIs->VirtualFree(objInfo, 0, MEM_RELEASE);
		}

		return stOut;
	}

	bool IScanner::EnumerateHandles(std::function<bool(SHandleScanContext*)> cb)
	{		
		if (!cb)
			return false;

		auto dwHandleInfoSize = 2000;
		auto ntStat = NTSTATUS(0x0);

//		auto lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION)CMemHelper::Allocate(dwHandleInfoSize);
		auto lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)CMemHelper::Allocate(dwHandleInfoSize);
		if (!lpHandleInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"lpHandleInfo allocation failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

//		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemHandleInformation, lpHandleInfo, dwHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemExtendedHandleInformation, lpHandleInfo, dwHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwHandleInfoSize *= 2;
//			lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION)CMemHelper::ReAlloc(lpHandleInfo, dwHandleInfoSize);
			lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)CMemHelper::ReAlloc(lpHandleInfo, dwHandleInfoSize);
		}

		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQuerySystemInformation failed with error: %p", ntStat);
			CMemHelper::Free(lpHandleInfo);
			return false;
		}

		// Reverse order for speed up scanning
		for (std::size_t i = lpHandleInfo->NumberOfHandles - 1; i > 0; i--)
		// for (std::size_t i = 0; i < lpHandleInfo->NumberOfHandles; i++)
		{
			auto hCurrHandle = lpHandleInfo->Handles[i];

			auto context = (SHandleScanContext*)CMemHelper::Allocate(sizeof(SHandleScanContext));
			if (context)
			{
				context->hSourcePid = hCurrHandle.UniqueProcessId;
				context->hHandle = (HANDLE)hCurrHandle.HandleValue;
				context->pObject = hCurrHandle.Object;
				context->uTypeIndex = hCurrHandle.ObjectTypeIndex;
				context->dwGrantedAccess = hCurrHandle.GrantedAccess;

				const auto ret = cb(context);

				CMemHelper::Free(context);

				if (!ret)
					break;
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Context allocation failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			g_winAPIs->Sleep(1);
		}

		CMemHelper::Free(lpHandleInfo);
		return true;
	}
};
