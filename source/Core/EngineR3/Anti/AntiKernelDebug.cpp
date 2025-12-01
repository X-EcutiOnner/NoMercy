#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiDebug.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../../Common/StdExtended.hpp"
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

// Block symbolic links; kldbgdrv  \Device\kldbgdrv

    // win11
    // BOOLEAN b{};
   // RtlGetSystemGlobalData(GlobalDataIdKdDebuggerEnabled, &b, sizeof(b));

namespace NoMercy
{
	bool KernelDebugInformationCheckTriggered()
	{
		SYSTEM_KERNEL_DEBUGGER_INFORMATION pSKDI = { 0 };
		if (NT_SUCCESS(g_winAPIs->NtQuerySystemInformation(SystemKernelDebuggerInformation, &pSKDI, sizeof(pSKDI), NULL)))
		{
			if (pSKDI.KernelDebuggerEnabled && !pSKDI.KernelDebuggerNotPresent)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: SystemKernelDebuggerInformation");
				return true;
			}
		}

		return false;
	}

	bool CheckSharedUserData()
	{
		// ignore in win11 > https://twitter.com/33y0re/status/1496504379351916547
		if (IsWindows11OrGreater())
			return false;

		static const auto pUserSharedData = (KUSER_SHARED_DATA*)0x7FFE0000; // The fixed user mode address of KUSER_SHARED_DATA

		const auto KdDebuggerEnabled = (pUserSharedData->KdDebuggerEnabled & 0x1) == 0x1;
		const auto KdDebuggerNotPresent = (pUserSharedData->KdDebuggerEnabled & 0x2) == 0x0;

		if (KdDebuggerEnabled || !KdDebuggerNotPresent)
			return true;

		return false;
	}

	bool CheckDebugBoot()
	{
		auto hKey = HKEY(nullptr);
		auto dwRegOpenRet = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"System\\CurrentControlSet\\Control"), 0, KEY_QUERY_VALUE | KEY_READ, &hKey);
		if (dwRegOpenRet != ERROR_SUCCESS)
			return false;
		
		wchar_t wszRegKey[_MAX_PATH]{ L'\0' };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;
		auto dwRegGetRet = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemStartOptions"), NULL, &dataType, (LPBYTE)&wszRegKey, &BufSize);
		if (dwRegGetRet != ERROR_SUCCESS)
		{
			g_winAPIs->RegCloseKey(hKey);
			return false;
		}

		const auto stLowerOptions = stdext::to_lower_wide(wszRegKey);
		const auto bRet =
			stLowerOptions.find(xorstr_(L"debug=1")) != std::wstring::npos ||
			stLowerOptions.find(xorstr_(L"debug=on")) != std::wstring::npos;

		g_winAPIs->RegCloseKey(hKey);
		return bRet;
	}

	bool CheckKernelDebugInformationEx()
	{
		if (!IsWindows8Point1OrGreater())
			return false;

		SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX pSKDIex = { 0 };
		if (NT_SUCCESS(g_winAPIs->NtQuerySystemInformation(SystemKernelDebuggerInformationEx, &pSKDIex, sizeof(pSKDIex), NULL)))
		{
			if (pSKDIex.DebuggerAllowed || pSKDIex.DebuggerEnabled || pSKDIex.DebuggerPresent)
			{
				APP_TRACE_LOG(LL_ERR, L"Debugger detected via: SystemKernelDebuggerInformationEx");
				return true;
			}
		}
		return false;
	}

	bool CheckKernelDebugFlags()
	{
		if (!IsWindows10OrGreater())
			return false;

		SYSTEM_KERNEL_DEBUGGER_FLAGS pSKDF = { 0 };
		const auto ntStatus = g_winAPIs->NtQuerySystemInformation(SystemKernelDebuggerFlags, &pSKDF, sizeof(pSKDF), NULL);
		if (NT_SUCCESS(ntStatus))
			return true;

		return false;
	}

	uint8_t CheckDebuggerProcesses()
	{
		std::vector <std::wstring> vecProcesses = {
			xorstr_(L"cdb.exe"), xorstr_(L"dbghost.exe"), xorstr_(L"kd.exe"), xorstr_(L"ntkd.exe"),
			xorstr_(L"ntsd.exe"), xorstr_(L"windbg.exe"), xorstr_(L"dbgx.shell.exe")
			// POSSIBLE FALSE-POSITIVES: xorstr_(L"dbgsvc.exe"),
		};

		const auto idx = CProcessFunctions::FindAnyProcess(vecProcesses);
		const auto wstProcName = std::distance(vecProcesses.begin(), vecProcesses.begin() + idx) < vecProcesses.size() ? vecProcesses[idx] : xorstr_(L"Unknown");
		if (idx)
		{
			APP_TRACE_LOG(LL_ERR, L"Debugger detected via: CheckDebuggerProcesses - %s", wstProcName.c_str());
			return idx;
		}

		return 0;
	}

	bool CAntiDebug::InitAntiKernelDebug(LPDWORD pdwErrorStep)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti kernel debug initialization has been started!");

		std::vector <std::tuple <uint32_t, std::function <bool()>, EFlags, uint32_t>> vecInfoHelpers = {
			{1, std::bind(&KernelDebugInformationCheckTriggered), EFlags::NONE, 0},
			{2, std::bind(&CheckSharedUserData), EFlags::NONE, 0},
			{3, std::bind(&CheckDebugBoot), EFlags::NONE, 0},
			{4, std::bind(&CheckKernelDebugInformationEx), EFlags::NONE, 0},
			{5, std::bind(&CheckKernelDebugFlags), EFlags::DISABLED, 0}, // false positive?
			{0, std::bind(&CheckDebuggerProcesses), EFlags::NONE, 100},
		};

		auto dwDetectIdx = 0UL;

		for (const auto& [idx, fn, flags, base] : vecInfoHelpers)
		{
			APP_TRACE_LOG(LL_SYS, L"Anti kernel debug step %u+%u checking... Flags: %d", base, idx, flags);

			if (flags == EFlags::DISABLED)
			{
				APP_TRACE_LOG(LL_SYS, L"Anti kernel debug step %u is disabled!", idx);
				continue;
			}
			else if (flags == EFlags::TEST && !stdext::is_debug_env())
			{
				APP_TRACE_LOG(LL_SYS, L"Anti kernel debug step %u is disabled in release mode!", idx);
				continue;
			}

			const auto bRet = fn();
			if (bRet)
			{
				APP_TRACE_LOG(LL_SYS, L"Kernel debugger %u detected!", idx);

				if (flags != EFlags::OPTIONAL)
				{
					dwDetectIdx = base + idx;
#ifndef _DEBUG
					break;
#endif
				}
			}

			APP_TRACE_LOG(LL_SYS, L"Anti kernel debug step %u completed!", idx);
		}

		APP_TRACE_LOG(dwDetectIdx == 0 ? LL_SYS : LL_CRI, L"Kernel debug check routine completed! Result: %u", dwDetectIdx);

		if (pdwErrorStep) *pdwErrorStep = dwDetectIdx;
		return dwDetectIdx == 0;
	}
};
