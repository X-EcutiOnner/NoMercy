#include "../../include/PCH.hpp"
#include "../../include/WinAPIManager.hpp"

namespace NoMercyCore
{
	void CWinAPIManager::BindAPIs_11()
	{
		g_winAPIs->GUIDFromStringW = (WinAPI::TGUIDFromString)(g_winAPIs->GetProcAddress_o(g_winModules->hShell32, (LPCSTR)704));
		g_winAPIs->HeapCreate = decltype(g_winAPIs->HeapCreate)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("HeapCreate")));
		g_winAPIs->HeapDestroy = decltype(g_winAPIs->HeapDestroy)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("HeapDestroy")));
		g_winAPIs->HeapReAlloc = decltype(g_winAPIs->HeapReAlloc)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("HeapReAlloc")));
		g_winAPIs->MiniDumpWriteDump = decltype(g_winAPIs->MiniDumpWriteDump)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("MiniDumpWriteDump")));
		g_winAPIs->GetSystemTimeAsFileTime = decltype(g_winAPIs->GetSystemTimeAsFileTime)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetSystemTimeAsFileTime")));
		g_winAPIs->QueryThreadCycleTime = decltype(g_winAPIs->QueryThreadCycleTime)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("QueryThreadCycleTime")));
		g_winAPIs->LookupPrivilegeNameW = decltype(g_winAPIs->LookupPrivilegeNameW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LookupPrivilegeNameW")));
		g_winAPIs->LookupPrivilegeDisplayNameW = decltype(g_winAPIs->LookupPrivilegeDisplayNameW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LookupPrivilegeDisplayNameW")));
		g_winAPIs->GetUserProfileDirectoryW = decltype(g_winAPIs->GetUserProfileDirectoryW)(g_winAPIs->GetProcAddress(g_winModules->hUserEnv, xorstr_("GetUserProfileDirectoryW")));
		g_winAPIs->GetSystemDefaultLocaleName = decltype(g_winAPIs->GetSystemDefaultLocaleName)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetSystemDefaultLocaleName")));
		g_winAPIs->SHQueryUserNotificationState = decltype(g_winAPIs->SHQueryUserNotificationState)(g_winAPIs->GetProcAddress(g_winModules->hShell32, xorstr_("SHQueryUserNotificationState")));
		g_winAPIs->SetMenuItemInfoW = decltype(g_winAPIs->SetMenuItemInfoW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("SetMenuItemInfoW")));
		g_winAPIs->IsUserAnAdmin = decltype(g_winAPIs->IsUserAnAdmin)(g_winAPIs->GetProcAddress(g_winModules->hShell32, xorstr_("IsUserAnAdmin")));
		g_winAPIs->CertVerifyRevocation = decltype(g_winAPIs->CertVerifyRevocation)(g_winAPIs->GetProcAddress(g_winModules->hCrypt32, xorstr_("CertVerifyRevocation")));
		g_winAPIs->NtQuerySecurityObject = decltype(g_winAPIs->NtQuerySecurityObject)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQuerySecurityObject")));
		g_winAPIs->RtlGetSaclSecurityDescriptor = decltype(g_winAPIs->RtlGetSaclSecurityDescriptor)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlGetSaclSecurityDescriptor")));
		g_winAPIs->RtlGetAce = decltype(g_winAPIs->RtlGetAce)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlGetAce")));
		g_winAPIs->EnumClipboardFormats = decltype(g_winAPIs->EnumClipboardFormats)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("EnumClipboardFormats")));
		g_winAPIs->GetClipboardFormatNameW = decltype(g_winAPIs->GetClipboardFormatNameW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetClipboardFormatNameW")));
		g_winAPIs->RtlImageNtHeaderEx = decltype(g_winAPIs->RtlImageNtHeaderEx)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlImageNtHeaderEx")));
		g_winAPIs->SetSuspendState = (WinAPI::TSetSuspendState)(g_winAPIs->GetProcAddress(g_winModules->hPowrProf, xorstr_("SetSuspendState")));
		g_winAPIs->GdiplusStartup = decltype(g_winAPIs->GdiplusStartup)(g_winAPIs->GetProcAddress(g_winModules->hGdiplus, xorstr_("GdiplusStartup")));
		g_winAPIs->GdiplusShutdown = decltype(g_winAPIs->GdiplusShutdown)(g_winAPIs->GetProcAddress(g_winModules->hGdiplus, xorstr_("GdiplusShutdown")));
		g_winAPIs->SHGetFileInfoW = decltype(g_winAPIs->SHGetFileInfoW)(g_winAPIs->GetProcAddress(g_winModules->hShell32, xorstr_("SHGetFileInfoW")));
		g_winAPIs->GetIconInfo = decltype(g_winAPIs->GetIconInfo)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetIconInfo")));
		g_winAPIs->WNetOpenEnumW = decltype(g_winAPIs->WNetOpenEnumW)(g_winAPIs->GetProcAddress(g_winModules->hMpr, xorstr_("WNetOpenEnumW")));
		g_winAPIs->WNetEnumResourceW = decltype(g_winAPIs->WNetEnumResourceW)(g_winAPIs->GetProcAddress(g_winModules->hMpr, xorstr_("WNetEnumResourceW")));
		g_winAPIs->WNetCloseEnum = decltype(g_winAPIs->WNetCloseEnum)(g_winAPIs->GetProcAddress(g_winModules->hMpr, xorstr_("WNetCloseEnum")));

		// Test
		auto x = decltype(&Beep)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("Beep")));
		g_winAPIs->Beep.set(x);
		__nop();
	}
}