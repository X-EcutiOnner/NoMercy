/******************************************************************
*                                                                 *
*  VersionHelpers.h -- This module defines helper functions to    *
*                      promote version check with proper          *
*                      comparisons.                               *
*                                                                 *
*  Copyright (c) Microsoft Corp.  All rights reserved.            *
*                                                                 *
******************************************************************/
#ifndef _versionhelpers_H_INCLUDED_
#define _versionhelpers_H_INCLUDED_

#define WINAPI_FAMILY_PARTITION(Partitions)     (Partitions)
#define WINAPI_PARTITION_DESKTOP   (WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
#define _WIN32_WINNT_WINXP                  0x0501
#define _WIN32_WINNT_VISTA                  0x0600
#define _WIN32_WINNT_WIN7                   0x0601
#define _WIN32_WINNT_WIN8                   0x0602
#define _WIN32_WINNT_WINBLUE                0x0603
//#define _WIN32_WINNT_WIN10					0x0604

#include <phnt_windows.h>
#include <phnt.h>
#pragma once

#pragma region Application Family

#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#include <specstrings.h> // for _In_, etc.
#if !defined(__midl) && !defined(SORTPP_PASS)
#if (NTDDI_VERSION >= NTDDI_WINXP)
#ifdef __cplusplus
#define VERSIONHELPERAPI __forceinline bool
#else // __cplusplus
#define VERSIONHELPERAPI FORCEINLINE BOOL
#endif // __cplusplus

#include <lazy_importer.hpp>

using NoMercyCore::g_winAPIs;

VERSIONHELPERAPI IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0 };
	DWORDLONG const dwlConditionMask = g_winAPIs->VerSetConditionMask(
		g_winAPIs->VerSetConditionMask(
			g_winAPIs->VerSetConditionMask(
				0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;
	return g_winAPIs->VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}

inline std::wstring GetWindowsInfoString()
{
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	const auto ntStatus = IS_VALID_SMART_PTR(g_winAPIs) ? g_winAPIs->RtlGetVersion(&verInfo) : RtlGetVersion(&verInfo);
	if (ntStatus == STATUS_SUCCESS)
	{
		return fmt::format(xorstr_(L"{0}.{1} Build {2} SP {3}.{4} Platform {5}"),
			verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber, verInfo.wServicePackMajor, verInfo.wServicePackMajor, verInfo.dwPlatformId
		);
	}
	return {};
}

inline DWORD GetWindowsBuildNumber()
{
	DWORD dwResult = 0;
	
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	const auto ntStatus = IS_VALID_SMART_PTR(g_winAPIs) ? g_winAPIs->RtlGetVersion(&verInfo) : RtlGetVersion(&verInfo);
	if (ntStatus == STATUS_SUCCESS)
		dwResult = verInfo.dwBuildNumber;
	return dwResult;
}

inline DWORD GetWindowsMajorVersion()
{
	DWORD dwResult = 0;
	
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	if (g_winAPIs->RtlGetVersion(&verInfo) == STATUS_SUCCESS)
		dwResult = verInfo.dwMajorVersion;

	return dwResult;
}

inline DWORD GetWindowsMinorVersion()
{
	DWORD dwResult = 0;

	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	if (g_winAPIs->RtlGetVersion(&verInfo) == STATUS_SUCCESS)
		dwResult = verInfo.dwMinorVersion;
	return dwResult;
}

inline DWORD GetWindowsServicePackVersion()
{
	DWORD dwResult = 0;
	
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	if (g_winAPIs->RtlGetVersion(&verInfo) == STATUS_SUCCESS)
		dwResult = verInfo.wServicePackMajor;

	return dwResult;
}

inline BOOL IsFakeConditionalVersion()
{
	OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	if (!g_winAPIs->GetVersionExW((POSVERSIONINFOW)&verInfo))
		return FALSE;

	if (verInfo.dwMajorVersion > 0xf1)
		return TRUE;

	RTL_OSVERSIONINFOEXW verInfoRtl = { 0 };
	verInfoRtl.dwOSVersionInfoSize = sizeof(verInfoRtl);
	if (g_winAPIs->RtlGetVersion(&verInfoRtl))
		return FALSE;

	if (verInfoRtl.dwMajorVersion > 0xf1)
		return TRUE;

	return FALSE;
}


VERSIONHELPERAPI IsWindowsXPOrGreater() 
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
}
VERSIONHELPERAPI IsWindowsXPSP1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 1);
}
VERSIONHELPERAPI IsWindowsXPSP2OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 2);
}
VERSIONHELPERAPI IsWindowsXPSP3OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3);
}

VERSIONHELPERAPI IsWindowsVistaOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0);
}
VERSIONHELPERAPI IsWindowsVistaSP1OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 1);
}
VERSIONHELPERAPI IsWindowsVistaSP2OrGreater() 
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 2);
}

VERSIONHELPERAPI IsWindows7OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 0);
}
VERSIONHELPERAPI IsWindows7SP1OrGreater() 
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 1);
}

VERSIONHELPERAPI IsWindows8OrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN8), LOBYTE(_WIN32_WINNT_WIN8), 0);
}

VERSIONHELPERAPI IsWindows8Point1OrGreater() 
{
	return (GetWindowsMajorVersion() == 8 && GetWindowsMinorVersion() >= 1) || GetWindowsMajorVersion() > 8;
}

VERSIONHELPERAPI IsWindows10OrGreater() 
{
	return GetWindowsMajorVersion() >= 10;
}

VERSIONHELPERAPI IsWindows11OrGreater()
{
	return GetWindowsBuildNumber() >= 21996;
}

VERSIONHELPERAPI IsWindowsServer()
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0, 0, VER_NT_WORKSTATION };

	auto dwlConditionMask = g_winAPIs->VerSetConditionMask(0, VER_PRODUCT_TYPE, (BYTE)VER_EQUAL);
	return !g_winAPIs->VerifyVersionInfoW(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
}


#endif // NTDDI_VERSION

#endif // defined(__midl)

#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */

#pragma endregion

#endif // _VERSIONHELPERS_H_INCLUDED_
