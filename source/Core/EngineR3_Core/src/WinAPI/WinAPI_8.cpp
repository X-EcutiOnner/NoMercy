#include "../../include/PCH.hpp"
#include "../../include/WinAPIManager.hpp"

namespace NoMercyCore
{
	void CWinAPIManager::BindAPIs_8()
	{
		g_winAPIs->ImageEnumerateCertificates = (WinAPI::TImageEnumerateCertificates)(g_winAPIs->GetProcAddress(g_winModules->hImagehlp, xorstr_("ImageEnumerateCertificates")));
		g_winAPIs->ImageGetCertificateHeader = (WinAPI::TImageGetCertificateHeader)(g_winAPIs->GetProcAddress(g_winModules->hImagehlp, xorstr_("ImageGetCertificateHeader")));
		g_winAPIs->ImageGetCertificateData = (WinAPI::TImageGetCertificateData)(g_winAPIs->GetProcAddress(g_winModules->hImagehlp, xorstr_("ImageGetCertificateData")));
		g_winAPIs->ControlServiceExW = decltype(g_winAPIs->ControlServiceExW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("ControlServiceExW")));
		g_winAPIs->SymGetLineFromAddr64 = decltype(g_winAPIs->SymGetLineFromAddr64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetLineFromAddr64")));
		g_winAPIs->StackWalk64 = decltype(g_winAPIs->StackWalk64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("StackWalk64")));
		g_winAPIs->StringFromGUID2 = decltype(g_winAPIs->StringFromGUID2)(g_winAPIs->GetProcAddress(g_winModules->hOle32, xorstr_("StringFromGUID2")));
		g_winAPIs->SymGetModuleInfoW64 = decltype(g_winAPIs->SymGetModuleInfoW64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetModuleInfoW64")));
		g_winAPIs->SymFromAddr = decltype(g_winAPIs->SymFromAddr)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymFromAddr")));
		g_winAPIs->CreatePipe = decltype(g_winAPIs->CreatePipe)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("CreatePipe")));
		g_winAPIs->GetStdHandle = decltype(g_winAPIs->GetStdHandle)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetStdHandle")));
		g_winAPIs->GetFileAttributesExW = decltype(g_winAPIs->GetFileAttributesExW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetFileAttributesExW")));
		g_winAPIs->GetUserGeoID = decltype(g_winAPIs->GetUserGeoID)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetUserGeoID")));
		g_winAPIs->GetGeoInfoW = decltype(g_winAPIs->GetGeoInfoW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetGeoInfoW")));
		g_winAPIs->GetProcessHandleCount = decltype(g_winAPIs->GetProcessHandleCount)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetProcessHandleCount")));
		g_winAPIs->GetGuiResources = decltype(g_winAPIs->GetGuiResources)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetGuiResources")));
		g_winAPIs->GetTimeZoneInformation = decltype(g_winAPIs->GetTimeZoneInformation)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetTimeZoneInformation")));
		g_winAPIs->NtQueryLicenseValue = decltype(g_winAPIs->NtQueryLicenseValue)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueryLicenseValue")));
		g_winAPIs->NtLoadDriver = decltype(g_winAPIs->NtLoadDriver)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtLoadDriver")));
		g_winAPIs->RtlAnsiStringToUnicodeString = decltype(g_winAPIs->RtlAnsiStringToUnicodeString)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlAnsiStringToUnicodeString")));
		g_winAPIs->SysStringLen = decltype(g_winAPIs->SysStringLen)(g_winAPIs->GetProcAddress(g_winModules->hOleAut32, xorstr_("SysStringLen")));
		g_winAPIs->TdhGetEventInformation = decltype(g_winAPIs->TdhGetEventInformation)(g_winAPIs->GetProcAddress(g_winModules->hTDH, xorstr_("TdhGetEventInformation")));
		g_winAPIs->TdhGetPropertySize = decltype(g_winAPIs->TdhGetPropertySize)(g_winAPIs->GetProcAddress(g_winModules->hTDH, xorstr_("TdhGetPropertySize")));
		g_winAPIs->TdhGetProperty = decltype(g_winAPIs->TdhGetProperty)(g_winAPIs->GetProcAddress(g_winModules->hTDH, xorstr_("TdhGetProperty")));
		g_winAPIs->TdhEnumerateProviders = decltype(g_winAPIs->TdhEnumerateProviders)(g_winAPIs->GetProcAddress(g_winModules->hTDH, xorstr_("TdhEnumerateProviders")));
		g_winAPIs->SymFunctionTableAccess64 = decltype(g_winAPIs->SymFunctionTableAccess64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymFunctionTableAccess64")));
		g_winAPIs->SymGetModuleBase64 = decltype(g_winAPIs->SymGetModuleBase64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetModuleBase64")));
		g_winAPIs->SymSetOptions = decltype(g_winAPIs->SymSetOptions)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymSetOptions")));
		g_winAPIs->FilterConnectCommunicationPort = decltype(g_winAPIs->FilterConnectCommunicationPort)(g_winAPIs->GetProcAddress(g_winModules->hFltlib, xorstr_("FilterConnectCommunicationPort")));
		g_winAPIs->FilterSendMessage = decltype(g_winAPIs->FilterSendMessage)(g_winAPIs->GetProcAddress(g_winModules->hFltlib, xorstr_("FilterSendMessage")));
		g_winAPIs->FilterGetMessage = decltype(g_winAPIs->FilterGetMessage)(g_winAPIs->GetProcAddress(g_winModules->hFltlib, xorstr_("FilterGetMessage")));
		g_winAPIs->FilterReplyMessage = decltype(g_winAPIs->FilterReplyMessage)(g_winAPIs->GetProcAddress(g_winModules->hFltlib, xorstr_("FilterReplyMessage")));
		g_winAPIs->SetFileInformationByHandle = decltype(g_winAPIs->SetFileInformationByHandle)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SetFileInformationByHandle")));
		g_winAPIs->PathFileExistsW = decltype(g_winAPIs->PathFileExistsW)(g_winAPIs->GetProcAddress(g_winModules->hShlwapi, xorstr_("PathFileExistsW")));
		g_winAPIs->SymGetModuleInfo64 = decltype(g_winAPIs->SymGetModuleInfo64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetModuleInfo64")));
		g_winAPIs->GetTimestampForLoadedLibrary = decltype(g_winAPIs->GetTimestampForLoadedLibrary)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("GetTimestampForLoadedLibrary")));
		g_winAPIs->RegSetValueExW = decltype(g_winAPIs->RegSetValueExW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("RegSetValueExW")));
		g_winAPIs->CreateProcessW = decltype(g_winAPIs->CreateProcessW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("CreateProcessW")));
		g_winAPIs->LsaNtStatusToWinError = decltype(g_winAPIs->LsaNtStatusToWinError)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LsaNtStatusToWinError")));
		g_winAPIs->ImpersonateLoggedOnUser = decltype(g_winAPIs->ImpersonateLoggedOnUser)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("ImpersonateLoggedOnUser")));
		g_winAPIs->RevertToSelf = decltype(g_winAPIs->RevertToSelf)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("RevertToSelf")));
		g_winAPIs->EmptyWorkingSet = decltype(g_winAPIs->EmptyWorkingSet)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("EmptyWorkingSet")));
		g_winAPIs->ReleaseMutex = decltype(g_winAPIs->ReleaseMutex)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("ReleaseMutex")));
		g_winAPIs->RegDeleteKeyExW = decltype(g_winAPIs->RegDeleteKeyExW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("RegDeleteKeyExW")));
		g_winAPIs->RegDeleteTreeW = decltype(g_winAPIs->RegDeleteTreeW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("RegDeleteTreeW")));
		g_winAPIs->NetUserGetLocalGroups = decltype(g_winAPIs->NetUserGetLocalGroups)(g_winAPIs->GetProcAddress(g_winModules->hNetapi32, xorstr_("NetUserGetLocalGroups")));
		g_winAPIs->GetACP = decltype(g_winAPIs->GetACP)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetACP")));
		g_winAPIs->IsHungAppWindow = decltype(g_winAPIs->IsHungAppWindow)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("IsHungAppWindow")));
		g_winAPIs->RtlFlushSecureMemoryCache = decltype(g_winAPIs->RtlFlushSecureMemoryCache)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlFlushSecureMemoryCache")));
		g_winAPIs->StartTraceW = decltype(g_winAPIs->StartTraceW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("StartTraceW")));
		g_winAPIs->ControlTraceW = decltype(g_winAPIs->ControlTraceW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("ControlTraceW")));
		g_winAPIs->OpenTraceW = decltype(g_winAPIs->OpenTraceW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("OpenTraceW")));
		g_winAPIs->ProcessTrace = decltype(g_winAPIs->ProcessTrace)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("ProcessTrace")));
		g_winAPIs->GetThreadTimes = decltype(g_winAPIs->GetThreadTimes)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetThreadTimes")));
		g_winAPIs->QueryServiceObjectSecurity = decltype(g_winAPIs->QueryServiceObjectSecurity)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("QueryServiceObjectSecurity")));
		g_winAPIs->GetSecurityDescriptorDacl = decltype(g_winAPIs->GetSecurityDescriptorDacl)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("GetSecurityDescriptorDacl")));
		g_winAPIs->SetServiceObjectSecurity = decltype(g_winAPIs->SetServiceObjectSecurity)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("SetServiceObjectSecurity")));
		g_winAPIs->GetSecurityInfo = decltype(g_winAPIs->GetSecurityInfo)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("GetSecurityInfo")));
		g_winAPIs->CLSIDFromString = decltype(g_winAPIs->CLSIDFromString)(g_winAPIs->GetProcAddress(g_winModules->hOle32, xorstr_("CLSIDFromString")));
		g_winAPIs->StringFromCLSID = decltype(g_winAPIs->StringFromCLSID)(g_winAPIs->GetProcAddress(g_winModules->hOle32, xorstr_("StringFromCLSID")));
		g_winAPIs->CoTaskMemFree = decltype(g_winAPIs->CoTaskMemFree)(g_winAPIs->GetProcAddress(g_winModules->hOle32, xorstr_("CoTaskMemFree")));
		g_winAPIs->NtUnloadDriver = decltype(g_winAPIs->NtUnloadDriver)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtUnloadDriver")));
		g_winAPIs->WaitForMultipleObjects = decltype(g_winAPIs->WaitForMultipleObjects)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("WaitForMultipleObjects")));
		g_winAPIs->GetUserDefaultLocaleName = decltype(g_winAPIs->GetUserDefaultLocaleName)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetUserDefaultLocaleName")));
		g_winAPIs->GetThreadLocale = decltype(g_winAPIs->GetThreadLocale)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetThreadLocale")));
		g_winAPIs->LCIDToLocaleName = decltype(g_winAPIs->LCIDToLocaleName)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("LCIDToLocaleName")));
		g_winAPIs->GetLocaleInfoEx = decltype(g_winAPIs->GetLocaleInfoEx)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetLocaleInfoEx")));
		g_winAPIs->GetSystemWow64DirectoryW = decltype(g_winAPIs->GetSystemWow64DirectoryW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetSystemWow64DirectoryW")));
		g_winAPIs->SymGetSymFromAddr64 = decltype(g_winAPIs->SymGetSymFromAddr64)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetSymFromAddr64")));
#ifndef _WIN64
		g_winAPIs->SymGetSymFromAddr = decltype(g_winAPIs->SymGetSymFromAddr)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetSymFromAddr")));
#endif
		g_winAPIs->SymGetOptions = decltype(g_winAPIs->SymGetOptions)(g_winAPIs->GetProcAddress(g_winModules->hDbghelp, xorstr_("SymGetOptions")));
		g_winAPIs->MapViewOfFileEx = decltype(g_winAPIs->MapViewOfFileEx)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("MapViewOfFileEx")));
		g_winAPIs->DnsQuery_W = decltype(g_winAPIs->DnsQuery_W)(g_winAPIs->GetProcAddress(g_winModules->hDnsapi, xorstr_("DnsQuery_W")));
		g_winAPIs->DnsRecordListFree = (WinAPI::TDnsRecordListFree)(g_winAPIs->GetProcAddress(g_winModules->hDnsapi, xorstr_("DnsRecordListFree")));
		g_winAPIs->GetFirmwareEnvironmentVariableW = decltype(g_winAPIs->GetFirmwareEnvironmentVariableW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetFirmwareEnvironmentVariableW")));
		g_winAPIs->UuidFromStringW = decltype(g_winAPIs->UuidFromStringW)(g_winAPIs->GetProcAddress(g_winModules->hRpcrt4, xorstr_("UuidFromStringW")));
		g_winAPIs->InternetGetConnectedState = decltype(g_winAPIs->InternetGetConnectedState)(g_winAPIs->GetProcAddress(g_winModules->hWininet, xorstr_("InternetGetConnectedState")));
		g_winAPIs->InternetAttemptConnect = decltype(g_winAPIs->InternetAttemptConnect)(g_winAPIs->GetProcAddress(g_winModules->hWininet, xorstr_("InternetAttemptConnect")));
		g_winAPIs->InternetCheckConnectionW = decltype(g_winAPIs->InternetCheckConnectionW)(g_winAPIs->GetProcAddress(g_winModules->hWininet, xorstr_("InternetCheckConnectionW")));
		g_winAPIs->MsiEnumProductsW = decltype(g_winAPIs->MsiEnumProductsW)(g_winAPIs->GetProcAddress(g_winModules->hMsi, xorstr_("MsiEnumProductsW")));
		g_winAPIs->MsiGetProductInfoW = decltype(g_winAPIs->MsiGetProductInfoW)(g_winAPIs->GetProcAddress(g_winModules->hMsi, xorstr_("MsiGetProductInfoW")));
		g_winAPIs->GetComputerNameExW = decltype(g_winAPIs->GetComputerNameExW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetComputerNameExW")));
		g_winAPIs->GetSystemPowerStatus = decltype(g_winAPIs->GetSystemPowerStatus)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetSystemPowerStatus")));
		g_winAPIs->GetDiskFreeSpaceExW = decltype(g_winAPIs->GetDiskFreeSpaceExW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetDiskFreeSpaceExW")));
		g_winAPIs->SHGetKnownFolderPath = decltype(g_winAPIs->SHGetKnownFolderPath)(g_winAPIs->GetProcAddress(g_winModules->hShell32, xorstr_("SHGetKnownFolderPath")));
		g_winAPIs->WTSEnumerateSessionsW = decltype(g_winAPIs->WTSEnumerateSessionsW)(g_winAPIs->GetProcAddress(g_winModules->hWtsapi32, xorstr_("WTSEnumerateSessionsW")));
		g_winAPIs->WTSQuerySessionInformationW = decltype(g_winAPIs->WTSQuerySessionInformationW)(g_winAPIs->GetProcAddress(g_winModules->hWtsapi32, xorstr_("WTSQuerySessionInformationW")));
		g_winAPIs->WTSFreeMemory = decltype(g_winAPIs->WTSFreeMemory)(g_winAPIs->GetProcAddress(g_winModules->hWtsapi32, xorstr_("WTSFreeMemory")));
		g_winAPIs->NetUserEnum = decltype(g_winAPIs->NetUserEnum)(g_winAPIs->GetProcAddress(g_winModules->hNetapi32, xorstr_("NetUserEnum")));
		g_winAPIs->LsaOpenPolicy = decltype(g_winAPIs->LsaOpenPolicy)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LsaOpenPolicy")));
		g_winAPIs->LsaEnumerateAccountRights = decltype(g_winAPIs->LsaEnumerateAccountRights)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LsaEnumerateAccountRights")));
		g_winAPIs->LsaFreeMemory = decltype(g_winAPIs->LsaFreeMemory)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LsaFreeMemory")));
		g_winAPIs->LsaClose = decltype(g_winAPIs->LsaClose)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LsaClose")));	
	}
};
