#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Analyser.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"

namespace NoMercy
{
	void CAnalyser::OnProcessCreateOrTerminate(std::shared_ptr <SProcessCallbackCtx> ctx)
	{
		const auto c_szReason = ctx->bCreated ? xorstr_(L"created") : xorstr_(L"terminated");
		WMI_LOG(LL_SYS,
			L"Process %s: PID: %u SID: %d Thread: %d Path: %s File: %s Class: %s",
			c_szReason, ctx->dwProcessID, ctx->iSID, ctx->iThreadCount, ctx->wszFileAndPathname, ctx->wszFilename, ctx->wszClassname
		);

		if (!IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()) ||
			!IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()->ProcessScanner()))
		{
			return;
		}

		if (ctx->bCreated)
		{
			CApplication::Instance().ScannerInstance()->ProcessScanner()->ScanAsync(ctx->dwProcessID);
			// CApplication::Instance().ScannerInstance()->HandleScanner()->ScanProcess(ctx->dwProcessID);
		}
		else
		{
			auto hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ctx->dwProcessID);
			if (IS_VALID_HANDLE(hProcess))
			{
				CApplication::Instance().ScannerInstance()->ProcessScanner()->OnScanTerminatedProcess(hProcess);
				g_winAPIs->CloseHandle(hProcess);
			}
			else
			{
				WMI_LOG(LL_ERR, L"Failed to open process %u with error %u", ctx->dwProcessID, g_winAPIs->GetLastError());
			}
		}
	}
	void CAnalyser::OnThreadCreate(std::shared_ptr <SThreadCallbackCtx> ctx)
	{
		WMI_LOG(LL_SYS,
			L"Thread: %u created in Process: %u Wait mode: %u Addr: %p",
			ctx->dwTID, ctx->dwProcessId, ctx->dwWaitMode, ctx->dwStartAddress
		);

		if (!IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()) || !IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()->ThreadScanner()))
			return;

		if (g_winAPIs->GetCurrentProcessId() == ctx->dwProcessId)
			CApplication::Instance().ScannerInstance()->ThreadScanner()->ScanSync(ctx->dwTID);

	}
	void CAnalyser::OnModuleLoad(std::shared_ptr <SModuleCallbackCtx> ctx)
	{
		WMI_LOG(LL_SYS,
			L"Module: %s loaded to Process: %u (%s) Addr: %p Size: %p",
			ctx->wszFilename, ctx->dwProcessID, ctx->wszExecutable, ctx->dwBaseAddress, ctx->dwImageSize
		);

		if (!IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()) || !IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()->ModuleScanner()))
			return;

		if (g_winAPIs->GetCurrentProcessId() == ctx->dwProcessID)
		{
			auto hProcess = g_winAPIs->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ctx->dwProcessID);
			if (IS_VALID_HANDLE(hProcess))
			{
				CApplication::Instance().ScannerInstance()->ModuleScanner()->OnScan(hProcess, ctx->wszFilename, (LPCVOID)ctx->dwBaseAddress, ctx->dwImageSize);
				g_winAPIs->CloseHandle(hProcess);
			}
			else
			{
				WMI_LOG(LL_ERR, L"Failed to open process %u with error %u", ctx->dwProcessID, g_winAPIs->GetLastError());
			}
		}
	}
	void CAnalyser::OnDriverLoad(std::shared_ptr <SDriverCallbackCtx> ctx)
	{
		WMI_LOG(LL_SYS,
			L"Driver: %s (%s) loaded. State: %s Type: %s Started: %d",
			ctx->wszName, ctx->wszPath, ctx->wszState, ctx->wszType, ctx->bStarted ? 1 : 0
		);

		if (IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()) &&
			IS_VALID_SMART_PTR(CApplication::Instance().ScannerInstance()->DriverScanner()))
		{
			CApplication::Instance().ScannerInstance()->DriverScanner()->ScanAsync(ctx->wszPath);
		}
	}

	void CAnalyser::OnWMITriggered(EAnalyseTypes analyseType, std::map <std::wstring /* szType */, std::wstring /* szValue */> mDataMap)
	{
#if 0
		APP_TRACE_LOG(LL_SYS, L"Analyse type: %d", analyseType);

		for (const auto& currentElement : mDataMap)
		{
			auto szType = std::wstring(currentElement.first.begin(), currentElement.first.end());
			auto szValue = std::wstring(currentElement.second.begin(), currentElement.second.end());

			APP_TRACE_LOG(LL_SYS, L"Type: %s Value: %s", szType.c_str(), szValue.c_str());
		}
#endif

		switch (analyseType)
		{
		case EAnalyseTypes::ANALYSE_PROCESS_CREATE:
		case EAnalyseTypes::ANALYSE_PROCESS_TERMINATE:
		{
			{
				auto procInfos = stdext::make_shared_nothrow<SProcessCallbackCtx>();
				if (!IS_VALID_SMART_PTR(procInfos))
					return;

				auto it_dwPID = mDataMap.find(xorstr_(L"ProcessId"));
				if (it_dwPID != mDataMap.end())
					procInfos->dwProcessID = std::stol(it_dwPID->second);

				auto it_dwSID = mDataMap.find(xorstr_(L"SessionId"));
				if (it_dwSID != mDataMap.end())
					procInfos->iSID = std::stoi(it_dwSID->second);

				auto it_iThreadCount = mDataMap.find(xorstr_(L"ThreadCount"));
				if (it_iThreadCount != mDataMap.end())
					procInfos->iThreadCount = std::stoi(it_iThreadCount->second);

				auto it_szClassName = mDataMap.find(xorstr_(L"CreationClassName"));
				if (it_szClassName != mDataMap.end())
					wcsncpy_s(procInfos->wszClassname, it_szClassName->second.c_str(), sizeof(procInfos->wszClassname));

				auto it_szCommandLine = mDataMap.find(xorstr_(L"CommandLine"));
				if (it_szCommandLine != mDataMap.end())
					wcsncpy_s(procInfos->wszCommandline, it_szCommandLine->second.c_str(), sizeof(procInfos->wszCommandline) - 1);

				auto it_szExePathAndName = mDataMap.find(xorstr_(L"ExecutablePath"));
				if (it_szExePathAndName != mDataMap.end())
					wcsncpy_s(procInfos->wszFileAndPathname, it_szExePathAndName->second.c_str(), sizeof(procInfos->wszFileAndPathname));

				auto it_szName = mDataMap.find(xorstr_(L"Name"));
				if (it_szName != mDataMap.end())
					wcsncpy_s(procInfos->wszFilename, it_szName->second.c_str(), sizeof(procInfos->wszFilename));

				procInfos->bCreated = analyseType == EAnalyseTypes::ANALYSE_PROCESS_CREATE;
				OnProcessCreateOrTerminate(procInfos);
			}
		} break;

		case EAnalyseTypes::ANALYSE_THREAD:
		{
			auto threadInfos = stdext::make_shared_nothrow<SThreadCallbackCtx>();
			if (!IS_VALID_SMART_PTR(threadInfos))
				return;

			auto it_dwTID = mDataMap.find(xorstr_(L"ThreadID"));
			if (it_dwTID != mDataMap.end())
				threadInfos->dwTID = std::stol(it_dwTID->second);

			auto it_dwPID = mDataMap.find(xorstr_(L"ProcessID"));
			if (it_dwPID != mDataMap.end())
				threadInfos->dwProcessId = std::stol(it_dwPID->second);

			auto it_dwWaitMode = mDataMap.find(xorstr_(L"WaitMode"));
			if (it_dwWaitMode != mDataMap.end())
				threadInfos->dwWaitMode = std::stol(it_dwWaitMode->second);

			auto it_dwStartAddress = mDataMap.find(xorstr_(L"Win32StartAddr"));
			if (it_dwStartAddress != mDataMap.end())
				threadInfos->dwStartAddress = std::stol(it_dwStartAddress->second);

			OnThreadCreate(threadInfos);
		} break;

		case EAnalyseTypes::ANALYSE_MODULE:
		{
			auto moduleInfos = stdext::make_shared_nothrow<SModuleCallbackCtx>();
			if (!IS_VALID_SMART_PTR(moduleInfos))
				return;

			auto it_dwPID = mDataMap.find(xorstr_(L"ProcessID"));
			if (it_dwPID != mDataMap.end())
				moduleInfos->dwProcessID = std::stol(it_dwPID->second);

			auto it_dwTID = mDataMap.find(xorstr_(L"ImageBase"));
			if (it_dwTID != mDataMap.end())
				moduleInfos->dwBaseAddress = std::stol(it_dwTID->second);

			auto it_dwWaitMode = mDataMap.find(xorstr_(L"ImageSize"));
			if (it_dwWaitMode != mDataMap.end())
				moduleInfos->dwImageSize = std::stol(it_dwWaitMode->second);

			auto it_szName = mDataMap.find(xorstr_(L"FileName"));
			if (it_szName != mDataMap.end())
				wcsncpy_s(moduleInfos->wszFilename, it_szName->second.c_str(), sizeof(moduleInfos->wszFilename));

			OnModuleLoad(moduleInfos);
		} break;

		case EAnalyseTypes::ANALYSE_DRIVER:
		{
			auto driverInfos = stdext::make_shared_nothrow<SDriverCallbackCtx>();
			if (!IS_VALID_SMART_PTR(driverInfos))
				return;

			auto it_szName = mDataMap.find(xorstr_(L"Name"));
			if (it_szName != mDataMap.end())
				wcsncpy_s(driverInfos->wszName, it_szName->second.c_str(), sizeof(driverInfos->wszName));

			auto it_szPath = mDataMap.find(xorstr_(L"PathName"));
			if (it_szPath != mDataMap.end())
				wcsncpy_s(driverInfos->wszPath, it_szPath->second.c_str(), sizeof(driverInfos->wszPath));

			auto it_szState = mDataMap.find(xorstr_(L"State"));
			if (it_szState != mDataMap.end())
				wcsncpy_s(driverInfos->wszState, it_szState->second.c_str(), sizeof(driverInfos->wszState));

			auto it_szServiceType = mDataMap.find(xorstr_(L"ServiceType"));
			if (it_szServiceType != mDataMap.end())
				wcsncpy_s(driverInfos->wszType, it_szServiceType->second.c_str(), sizeof(driverInfos->wszType));

			auto it_bStarted = mDataMap.find(xorstr_(L"Started"));
			if (it_bStarted != mDataMap.end())
				driverInfos->bStarted = std::stol(it_bStarted->second) ? true : false;

			OnDriverLoad(driverInfos);
		} break;

		default:
			break;
		}
	}
};
