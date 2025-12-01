#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiEmulation.hpp"
#include "../../../Common/SimpleTimer.hpp"





namespace NoMercy
{
#pragma region GeneralEmulationCheck
	__forceinline bool IsMsDefenderEmulationPresent()
	{
		if (IsWindows7OrGreater())
			return g_winAPIs->NtIsProcessInJob(NtCurrentProcess(), UlongToHandle(10)) == 0x125;
		return false;
	}

	__forceinline bool RandomApiCheck()
	{
		const auto uTime = (unsigned int)std::time(nullptr);
		std::srand(uTime);

		const auto stFakeFunctionName = stdext::to_ansi(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetRandomString(8));
		if (g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, stFakeFunctionName.c_str()))
		{
			return false;
		}
		return true;
	}

	__forceinline bool CheckErrorMode()
	{
		const auto dwRealCode = g_winAPIs->SetErrorMode(0);
		const auto dwCode = 1024UL;

		g_winAPIs->SetErrorMode(1024);
		if (g_winAPIs->SetErrorMode(0) != 1024)
		{
			return false;
		}

		if ((dwCode + 313) != 1337)
		{
			return false;
		}

		g_winAPIs->SetErrorMode(dwRealCode);
		return true;
	}

	__forceinline bool LoadNtOsKrnl()
	{
		if (IsWindows8OrGreater() == true)
			return true;

		const CHAR __ntoskrnlexe[] = { 'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e', 0x0 }; // ntoskrnl.exe

		auto hModule = g_winAPIs->LoadLibraryA(__ntoskrnlexe);
		if (!hModule)
			return false;

		g_winAPIs->FreeLibrary(hModule);
		return true;
	}

	__forceinline bool IsWindowsGenuine()
	{
		if (!IsWindowsVistaOrGreater())
			return true;

		GUID spUID{ 0 };
		RPC_WSTR spRPC = (RPC_WSTR)xorstr_(L"55c92734-d682-4d71-983e-d6ec3f16059f");
		
		const auto nStatus = g_winAPIs->UuidFromStringW(spRPC, &spUID);
		if (nStatus != RPC_S_OK)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to convert string to GUID (%d)", nStatus);
			return false;
		}

		SL_GENUINE_STATE slState{};
		const auto hr = g_winAPIs->SLIsGenuineLocal(&spUID, &slState, NULL);
		if (hr != S_OK)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to check if Windows is genuine (%p)", hr);
			return FALSE;
		}

		return slState == SL_GEN_STATE_IS_GENUINE;
	}

	__forceinline bool IsRemoteSession()
	{
		const auto session_metrics = g_winAPIs->GetSystemMetrics(SM_REMOTESESSION);
		return session_metrics != 0;
	}

	__forceinline bool IsNativeVhdBoot()
	{
		BOOL isnative = FALSE;
		if (g_winAPIs->IsNativeVhdBoot)
			g_winAPIs->IsNativeVhdBoot(&isnative);

		return !!isnative;
	}

	bool CheckRegistry_SandboxProductIDs(LPDWORD pdwErrorCode)
	{
		wchar_t wszRegKey[MAX_PATH]{ L'\0' };
		DWORD dwBufSize = MAX_PATH;
		DWORD dwDataType = REG_SZ;

		HKEY hKey = nullptr;
		auto lStatus = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ProductID"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lStatus == ERROR_SUCCESS)
		{
			lStatus = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"0") /* column */, NULL, &dwDataType, (LPBYTE)&wszRegKey, &dwBufSize);
			if (lStatus == ERROR_SUCCESS)
			{
				std::wstring stRegKey = wszRegKey;

				APP_TRACE_LOG(LL_SYS, L"Product ID: %s", stRegKey.c_str());

				const wchar_t __key1[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '1', '4', '5', '7', '2', '3', '6', '-', '2', '3', '8', '3', '7', 0x0 }; // 76487-640-1457236-23837
				const wchar_t __key2[] = { '7', '6', '4', '8', '7', '-', '3', '3', '7', '-', '8', '4', '2', '9', '9', '5', '5', '-', '2', '2', '6', '1', '4', 0x0 }; // 76487-337-8429955-22614
				const wchar_t __key3[] = { '7', '6', '4', '8', '7', '-', '6', '4', '4', '-', '3', '1', '7', '7', '0', '3', '7', '-', '2', '3', '5', '1', '0', 0x0 }; // 76487-644-3177037-23510
				const wchar_t __key4[] = { '7', '6', '4', '9', '7', '-', '6', '4', '0', '-', '6', '3', '0', '8', '8', '7', '3', '-', '2', '3', '8', '3', '5', 0x0 }; // 76497-640-6308873-23835
				const wchar_t __key5[] = { '5', '5', '2', '7', '4', '-', '6', '4', '0', '-', '2', '6', '7', '3', '0', '6', '4', '-', '2', '3', '9', '5', '0', 0x0 }; // 55274-640-2673064-23950
				const wchar_t __key6[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '8', '8', '3', '4', '0', '0', '5', '-', '2', '3', '1', '9', '5', 0x0 }; // 76487-640-8834005-23195
				const wchar_t __key7[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '0', '7', '1', '6', '6', '6', '2', '-', '2', '3', '5', '3', '5', 0x0 }; // 76487-640-0716662-23535
				const wchar_t __key8[] = { '7', '6', '4', '8', '7', '-', '6', '4', '4', '-', '8', '6', '4', '8', '4', '6', '6', '-', '2', '3', '1', '0', '6', 0x0 }; // 76487-644-8648466-23106
				const wchar_t __key9[] = { '0', '0', '4', '2', '6', '-', '2', '9', '3', '-', '8', '1', '7', '0', '0', '3', '2', '-', '8', '5', '1', '4', '6', 0x0 }; // 00426-293-8170032-85146
				const wchar_t __key10[] = { '7', '6', '4', '8', '7', '-', '3', '4', '1', '-', '5', '8', '8', '3', '8', '1', '2', '-', '2', '2', '4', '2', '0', 0x0 }; // 76487-341-5883812-22420
				const wchar_t __key11[] = { '7', '6', '4', '8', '7', '-', 'O', 'E', 'M', '-', '0', '0', '2', '7', '4', '5', '3', '-', '6', '3', '7', '9', '6', 0x0 }; // 76487-OEM-0027453-63796

				if (stRegKey == __key1)
				{
					if (pdwErrorCode) *pdwErrorCode = 100;
					return false;
				}
				else if (stRegKey == __key2)
				{
					if (pdwErrorCode) *pdwErrorCode = 101;
					return false;
				}
				else if (stRegKey == __key3)
				{
					if (pdwErrorCode) *pdwErrorCode = 102;
					return false;
				}
				else if (stRegKey == __key4)
				{
					if (pdwErrorCode) *pdwErrorCode = 103;
					return false;
				}
				else if (stRegKey == __key5)
				{
					if (pdwErrorCode) *pdwErrorCode = 104;
					return false;
				}
				else if (stRegKey == __key6)
				{
					if (pdwErrorCode) *pdwErrorCode = 105;
					return false;
				}
				else if (stRegKey == __key7)
				{
					if (pdwErrorCode) *pdwErrorCode = 106;
					return false;
				}
				else if (stRegKey == __key8)
				{
					if (pdwErrorCode) *pdwErrorCode = 107;
					return false;
				}
				else if (stRegKey == __key9)
				{
					if (pdwErrorCode) *pdwErrorCode = 108;
					return false;
				}
				else if (stRegKey == __key10)
				{
					if (pdwErrorCode) *pdwErrorCode = 109;
					return false;
				}
				else if (stRegKey == __key11)
				{
					if (pdwErrorCode) *pdwErrorCode = 110;
					return false;
				}
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return true;
	}
#pragma endregion GeneralEmulationCheck

#pragma region TimeDurationCheck
	inline bool __CheckGetTickCount()
	{
		auto __CheckGetTickCountEx = [] {
			const auto tStart = g_winAPIs->GetTickCount();

			g_winAPIs->Sleep(1000);

			__try {
				int* p = 0; // access violation
				*p = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			g_winAPIs->Sleep(1000);

			auto tEnd = g_winAPIs->GetTickCount();
			return (tEnd - tStart);
		};

		const auto dwDiff = __CheckGetTickCountEx();
		APP_TRACE_LOG(LL_SYS, L"dwDiff: %u", dwDiff);

		if (dwDiff > 3000)
		{
			return false;
		}
		return true;
	}

	inline bool __CheckStdChrono()
	{
		auto __CheckStdChronoEx = [] {
			CStopWatch <std::chrono::milliseconds> checkTimer;

			g_winAPIs->Sleep(1000);

			__try {
				int* p = 0; // access violation
				*p = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			g_winAPIs->Sleep(1000);

			return checkTimer.diff();
		};

		const auto llDiff = __CheckStdChronoEx();
		APP_TRACE_LOG(LL_SYS, L"Diff: %lld", llDiff);

		if (llDiff > 3000)
		{
			return false;
		}
		return true;
	}
#pragma endregion TimeDurationCheck

	bool CAntiEmulation::InitTimeChecks(LPDWORD pdwErrorStep)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti emulation InitTimeChecks has been started");

#ifdef _DEBUG
		if (g_winAPIs->IsDebuggerPresent()) // pass it for debug build and if have a attached debugger
			return true;
#endif

		if (__CheckGetTickCount() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 1;
			return false;
		}

		if (__CheckStdChrono() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 2;
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti emulation InitTimeChecks completed");
		return true;
	}

	bool CAntiEmulation::InitAntiEmulation(LPDWORD pdwErrorStep)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti emulation has been started");

		auto dwSandboxRet = 0UL;

		if (IsMsDefenderEmulationPresent())
		{
			if (pdwErrorStep) *pdwErrorStep = 1;
			return false;
		}

		if (RandomApiCheck() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 2;
			return false;
		}

		if (CheckErrorMode() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 3;
			return false;
		}
		
		if (LoadNtOsKrnl() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 4;
			return false;
		}
		
#ifdef __EXPERIMENTAL__
		if (IsWindowsGenuine() == false)
		{
			if (pdwErrorStep) *pdwErrorStep = 5;
			return false;
		}
#endif

		if (IsRemoteSession())
		{
			if (pdwErrorStep) *pdwErrorStep = 6;
			return false;
		}

		if (IsNativeVhdBoot())
		{
			if (pdwErrorStep) *pdwErrorStep = 7;
			return false;
		}
		
		if (CheckRegistry_SandboxProductIDs(&dwSandboxRet) == false)
		{
			if (pdwErrorStep) *pdwErrorStep = dwSandboxRet;
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti emulation completed");
		return true;
	}
};
