#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	inline bool __CreateServiceEntry(const std::wstring& stDriverPath, const std::wstring& stServiceName)
	{
		auto stRegistryKey = std::wstring(xorstr_(L"System\\CurrentControlSet\\Services\\"));
		stRegistryKey += stServiceName;

		HKEY hKey{};
		auto result = g_winAPIs->RegCreateKeyW(HKEY_LOCAL_MACHINE, stRegistryKey.c_str(), &hKey);
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegCreateKeyA failed with error: %d", result);
			return false;
		}

		// set type to 1 (kernel)
		constexpr std::uint8_t type_value = 1;
		result = g_winAPIs->RegSetValueExW(hKey, xorstr_(L"Type"), NULL, REG_DWORD, &type_value, 4u);
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegSetValueExA(Type) failed with error: %d", result);
			return false;
		}

		// set error control to 3
		constexpr std::uint8_t error_control_value = 3;
		result = g_winAPIs->RegSetValueExW(hKey, xorstr_(L"ErrorControl"), NULL, REG_DWORD, &error_control_value, 4u);
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegSetValueExA(ErrorControl) failed with error: %d", result);
			return false;
		}

		// set start to 3
		constexpr std::uint8_t start_value = 3;
		result = g_winAPIs->RegSetValueExW(hKey, xorstr_(L"Start"), NULL, REG_DWORD, &start_value, 4u);
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegSetValueExA(Start) failed with error: %d", result);
			return false;
		}

		// set image path to the driver on disk
		result = g_winAPIs->RegSetValueExW(hKey, xorstr_(L"ImagePath"), NULL, REG_SZ, (std::uint8_t*)stDriverPath.c_str(), stDriverPath.size());
		if (result != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"RegSetValueExA(ImagePath) failed with error: %d", result);
			return false;
		}

		g_winAPIs->RegCloseKey(hKey);
		return true;
	}

	inline bool __LoadDriver(const std::wstring& stDriverPath, const std::wstring& stServiceName)
	{
		if (NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->RequestPrivilege(SE_LOAD_DRIVER_PRIVILEGE) == false)
		{
			APP_TRACE_LOG(LL_SYS, L"Request driver load priv failed!");
			return false;
		}

		if (!__CreateServiceEntry(xorstr_(L"\\??\\") + std::filesystem::absolute(std::filesystem::path(stDriverPath)).wstring(), stServiceName))
		{
			APP_TRACE_LOG(LL_SYS, L"CreateServiceEntry failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto stRegPath = fmt::format(xorstr_("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{0}"), stdext::to_ansi(stServiceName));

		ANSI_STRING asDriverPath;
		g_winAPIs->RtlInitAnsiString(&asDriverPath, stRegPath.c_str());

		UNICODE_STRING usDriverRegPath;
		auto ntStatus = g_winAPIs->RtlAnsiStringToUnicodeString(&usDriverRegPath, &asDriverPath, true);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_SYS, L"RtlAnsiStringToUnicodeString failed with status: %p", ntStatus);
			return false;
		}

		ntStatus = g_winAPIs->NtLoadDriver(&usDriverRegPath);
		if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_IMAGE_ALREADY_LOADED && ntStatus != STATUS_INVALID_FILE_FOR_SECTION)
		{
			APP_TRACE_LOG(LL_SYS, L"NtLoadDriver failed with status: %p", ntStatus);
			return false;
		}

		g_winAPIs->NtUnloadDriver(&usDriverRegPath);
		return true;
	}


	inline bool CheckTestSign_Debug()
	{
		SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
		sci.Length = sizeof(sci);

		auto dwcbSz = 0UL;
		const auto ntStat = g_winAPIs->NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), &dwcbSz);
		if (!NT_SUCCESS(ntStat) || dwcbSz != sizeof(sci))
			return false;

		const auto bDebugmodeEnabled = !!(sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
		return bDebugmodeEnabled;
	}

	inline bool CheckTestSign_Type1()
	{
		SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
		sci.Length = sizeof(sci);

		auto dwcbSz = 0UL;
		const auto ntStat = g_winAPIs->NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), &dwcbSz);
		if (!NT_SUCCESS(ntStat) || dwcbSz != sizeof(sci))
			return false;

		const auto bTestsigningEnabled = !!(sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN);
		return bTestsigningEnabled;
	}

	inline bool CheckTestSign_Type2()
	{
		bool bRet = false;
		char RegKey[_MAX_PATH] = { 0 };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_DWORD;

		HKEY hKey;
		auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\CI"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"DebugFlags"), NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				if (!strcmp(RegKey, xorstr_("1")))
					bRet = true;
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return bRet;
	}

	inline bool CheckTestSign_Type3()
	{
		bool bRet = false;
		char RegKey[_MAX_PATH] = { 0 };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;

		HKEY hKey;
		auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemStartOptions"), NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				if (strstr(RegKey, xorstr_("TESTSIGNING")))
					bRet = true;
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return bRet;
	}

	inline bool CheckTestSign_Type4()
	{
		bool bRet = false;
		char RegKey[_MAX_PATH]{ '\0' };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;

		HKEY hKey;
		auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"SystemStartOptions"), NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				if (strstr(RegKey, xorstr_("DISABLE_INTEGRITY_CHECKS")))
					bRet = true;
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return bRet;
	}

	inline bool CheckTestSign_Type5()
	{
		HKEY hTestKey;
		if (g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"BCD00000000\\Objects"), 0, KEY_READ, &hTestKey) != ERROR_SUCCESS)
			return false;

		wchar_t     achKey[255]{ L'\0' };;
		DWORD    cbName;
		wchar_t  achClass[MAX_PATH] = L"";
		DWORD    cchClassName = MAX_PATH;
		DWORD    cSubKeys = 0;
		DWORD    cbMaxSubKey;
		DWORD    cchMaxClass;
		DWORD    cValues;
		DWORD    cchMaxValue;
		DWORD    cbMaxValueData;
		DWORD    cbSecurityDescriptor;
		FILETIME ftLastWriteTime;

		bool bRet = false;

		DWORD dwReturn[1000];
		DWORD dwBufSize = sizeof(dwReturn);

		auto dwApiRetCode = g_winAPIs->RegQueryInfoKeyW(
			hTestKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass,
			&cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime
		);

		if (dwApiRetCode == ERROR_SUCCESS && cSubKeys)
		{
			for (DWORD i = 0; i < cSubKeys; i++)
			{
				cbName = 255;
				dwApiRetCode = g_winAPIs->RegEnumKeyExW(hTestKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
				if (dwApiRetCode == ERROR_SUCCESS)
				{
					wchar_t wszNewWay[4096]{ L'\0' };
					wsprintf(wszNewWay, xorstr_(L"BCD00000000\\Objects\\%s\\Elements\\16000049"), achKey); // TODO: 12000002, 22000011

					HKEY hnewKey;
					auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, wszNewWay, NULL, KEY_QUERY_VALUE, &hnewKey);
					if (lError == ERROR_SUCCESS)
					{
						auto lVal = g_winAPIs->RegQueryValueExW(hnewKey, xorstr_(L"Element"), NULL, 0, (LPBYTE)dwReturn, &dwBufSize);
						if (lVal == ERROR_SUCCESS)
						{
							if (dwReturn[0] == 1UL)
								bRet = true;
						}
						g_winAPIs->RegCloseKey(hnewKey);
					}

				}
			}
		}

		g_winAPIs->RegCloseKey(hTestKey);
		return bRet;
	}

	inline bool CheckTestSign_Type6()
	{
		bool bRet = false;

		HKEY hKey;
		auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Driver Signing"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			BYTE Result;
			DWORD BufSize = sizeof(Result);
			DWORD dataType = REG_BINARY;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"Policy"), NULL, &dataType, &Result, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				if (Result == 0x02)
					bRet = true;
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return bRet;
	}

	inline bool CheckTestSign_Type7()
	{
		const auto c_stSystemPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->SystemPath();
		const auto c_stDriverPath = fmt::format(xorstr_(L"{0}\\Drivers\\flpydisk.sys"), c_stSystemPath.c_str());
		const auto c_szDriverName = xorstr_(L"flpydisk");

		if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(c_stDriverPath))
			return false;

		const auto bRet = __LoadDriver(c_stDriverPath, c_szDriverName);

		return bRet;
	}


	inline bool CheckKernelDebug_Type1()
	{
		bool bRet = false;

		HKEY hKey;
		auto lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session manager\\Debug Print Filter"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			BYTE Result;
			DWORD BufSize = sizeof(Result);
			DWORD dataType = REG_DWORD;

			auto lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"DEFAULT"), NULL, &dataType, &Result, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				if (Result == 0xF)
					bRet = true;
			}
			g_winAPIs->RegCloseKey(hKey);
		}
		return bRet;
	}


	bool IScanner::IsCustomKernelSignersAllowed()
	{
		auto IsPolicyEnabled = [](const std::wstring& wstPolicyName) {
			UNICODE_STRING usLicenseValue;
			g_winAPIs->RtlInitUnicodeString(&usLicenseValue, wstPolicyName.c_str());

			ULONG PolicyValueType = 0, CiAcpCks = 0, ReturnLength = 0;
			const auto ntStatus = g_winAPIs->NtQueryLicenseValue(&usLicenseValue, &PolicyValueType, (PVOID)&CiAcpCks, sizeof(CiAcpCks), &ReturnLength);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryLicenseValue failed with status: %p", ntStatus);
				return false;
			}

			if (PolicyValueType != REG_DWORD || ReturnLength != sizeof(ULONG))
			{
				APP_TRACE_LOG(LL_ERR, L"Object type mismatch: %u != %u Return length: %u != %u", PolicyValueType, REG_DWORD, ReturnLength, sizeof(ULONG));
				return false;
			}

			return CiAcpCks != 0;
		};

		if (IsPolicyEnabled(xorstr_(L"CodeIntegrity-AllowConfigurablePolicy")))
		{
			APP_TRACE_LOG(LL_ERR, L"Policy: 1 is enabled!");
			return true;
		}
		else if (IsPolicyEnabled(xorstr_(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners")))
		{
			APP_TRACE_LOG(LL_ERR, L"Policy: 2 is enabled!");
			return true;
		}

		return false;
	}


	bool IScanner::IsTestSignEnabled(LPDWORD pdwReturnCode)
	{
		auto dwTestSignRet = 0UL;
		do
		{
			if (CheckTestSign_Type1())
			{
				dwTestSignRet = 1;
				break;
			}

			if (CheckTestSign_Type2())
			{
				dwTestSignRet = 2;
				break;
			}

			if (CheckTestSign_Type3())
			{
				dwTestSignRet = 3;
				break;
			}

			if (CheckTestSign_Type4())
			{
				dwTestSignRet = 4;
				break;
			}

			if (CheckTestSign_Type5())
			{
				dwTestSignRet = 5;
				break;
			}

			if (CheckTestSign_Type6())
			{
				dwTestSignRet = 6;
				break;
			}

			/*
			* CHECKME
			if (CheckTestSign_Type7())
			{
				dwTestSignRet = 7;
				break;
			}
			*/

			if (CheckKernelDebug_Type1())
			{
				dwTestSignRet = 101;
				break;
			}

		} while (false);

		if (pdwReturnCode) *pdwReturnCode = dwTestSignRet;
		return dwTestSignRet != 0;
	}


	bool IScanner::IsSecureBootEnabled()
	{
		auto dwcbSz = 0UL;

		SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei = { 0 };
		auto ntStat = g_winAPIs->NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &dwcbSz);
		if (NT_SUCCESS(ntStat))
		{
			if (sbei.FirmwareType != FirmwareTypeUefi)
			{
				APP_TRACE_LOG(LL_ERR, L"System firmware type: %u is not uefi, secure boot check skipped.", sbei.FirmwareType);
				return true; // ignore for now
			}
		}

		SYSTEM_SECUREBOOT_INFORMATION ssbi = { 0 };
		ntStat = g_winAPIs->NtQuerySystemInformation(SystemSecureBootInformation, &ssbi, sizeof(ssbi), &dwcbSz);
		if (!NT_SUCCESS(ntStat) || dwcbSz != sizeof(ssbi))
		{
			APP_TRACE_LOG(LL_ERR, L"SystemSecureBootInformation query fail! Ntstatus: %p Return size: %u Ctx size: %u", ntStat, dwcbSz, sizeof(ssbi));
			return true;
		}

		if (ssbi.SecureBootCapable && !ssbi.SecureBootEnabled)
			return false;

		return true;
	}
};
