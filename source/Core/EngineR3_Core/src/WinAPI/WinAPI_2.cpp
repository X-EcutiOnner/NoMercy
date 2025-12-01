#include "../../include/PCH.hpp"
#include "../../include/WinAPIManager.hpp"

namespace NoMercyCore
{
	void CWinAPIManager::BindAPIs_2()
	{
		g_winAPIs->OpenThread= decltype(g_winAPIs->OpenThread)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("OpenThread")));
		g_winAPIs->NtDuplicateObject= decltype(g_winAPIs->NtDuplicateObject)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtDuplicateObject")));
		g_winAPIs->NtQueryObject= decltype(g_winAPIs->NtQueryObject)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueryObject")));
		g_winAPIs->GetFileSize= decltype(g_winAPIs->GetFileSize)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetFileSize")));
		g_winAPIs->FindFirstFileW = decltype(g_winAPIs->FindFirstFileW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("FindFirstFileW")));
		g_winAPIs->FindNextFileW = decltype(g_winAPIs->FindNextFileW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("FindNextFileW")));
		g_winAPIs->SetFileAttributesW = decltype(g_winAPIs->SetFileAttributesW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SetFileAttributesW")));
		g_winAPIs->RemoveDirectoryW = decltype(g_winAPIs->RemoveDirectoryW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("RemoveDirectoryW")));
		g_winAPIs->DeleteFileW = decltype(g_winAPIs->DeleteFileW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("DeleteFileW")));
		g_winAPIs->GetFileAttributesW = decltype(g_winAPIs->GetFileAttributesW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetFileAttributesW")));
		g_winAPIs->FindClose= decltype(g_winAPIs->FindClose)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("FindClose")));
		g_winAPIs->LookupPrivilegeValueW = decltype(g_winAPIs->LookupPrivilegeValueW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LookupPrivilegeValueW")));
		g_winAPIs->LookupPrivilegeValueW= decltype(g_winAPIs->LookupPrivilegeValueW)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("LookupPrivilegeValueW")));
		g_winAPIs->AdjustTokenPrivileges= decltype(g_winAPIs->AdjustTokenPrivileges)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("AdjustTokenPrivileges")));
		g_winAPIs->OpenProcessToken= decltype(g_winAPIs->OpenProcessToken)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("OpenProcessToken")));
		g_winAPIs->NtSetDebugFilterState= decltype(g_winAPIs->NtSetDebugFilterState)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtSetDebugFilterState")));
		g_winAPIs->WNetGetProviderNameW = decltype(g_winAPIs->WNetGetProviderNameW)(g_winAPIs->GetProcAddress(g_winModules->hMpr, xorstr_("WNetGetProviderNameW")));
		g_winAPIs->NtTerminateProcess= decltype(g_winAPIs->NtTerminateProcess)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtTerminateProcess")));
		g_winAPIs->GetSystemInfo= decltype(g_winAPIs->GetSystemInfo)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetSystemInfo")));
		g_winAPIs->CreateFileMappingW = decltype(g_winAPIs->CreateFileMappingW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("CreateFileMappingW")));
		g_winAPIs->MapViewOfFile= decltype(g_winAPIs->MapViewOfFile)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("MapViewOfFile")));
		g_winAPIs->UnmapViewOfFile= decltype(g_winAPIs->UnmapViewOfFile)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("UnmapViewOfFile")));
		g_winAPIs->ReadProcessMemory= decltype(g_winAPIs->ReadProcessMemory)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("ReadProcessMemory")));
		g_winAPIs->AllocateAndInitializeSid= decltype(g_winAPIs->AllocateAndInitializeSid)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("AllocateAndInitializeSid")));
		g_winAPIs->GetTokenInformation= decltype(g_winAPIs->GetTokenInformation)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("GetTokenInformation")));
		g_winAPIs->GlobalAlloc= decltype(g_winAPIs->GlobalAlloc)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GlobalAlloc")));
		g_winAPIs->InitializeAcl= decltype(g_winAPIs->InitializeAcl)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("InitializeAcl")));
		g_winAPIs->AddAccessDeniedAce= decltype(g_winAPIs->AddAccessDeniedAce)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("AddAccessDeniedAce")));
		g_winAPIs->AddAccessAllowedAce= decltype(g_winAPIs->AddAccessAllowedAce)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("AddAccessAllowedAce")));
		g_winAPIs->SetSecurityInfo= decltype(g_winAPIs->SetSecurityInfo)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("SetSecurityInfo")));
		g_winAPIs->FreeSid= decltype(g_winAPIs->FreeSid)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("FreeSid")));
		g_winAPIs->GetForegroundWindow= decltype(g_winAPIs->GetForegroundWindow)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetForegroundWindow")));
		g_winAPIs->TerminateThread= decltype(g_winAPIs->TerminateThread)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("TerminateThread")));
		g_winAPIs->SendMessageW = decltype(g_winAPIs->SendMessageW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("SendMessageW")));
		g_winAPIs->SetThreadContext= decltype(g_winAPIs->SetThreadContext)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SetThreadContext")));
		g_winAPIs->SuspendThread= decltype(g_winAPIs->SuspendThread)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SuspendThread")));
		g_winAPIs->BlockInput= decltype(g_winAPIs->BlockInput)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("BlockInput")));
		g_winAPIs->GetWindowModuleFileNameW = decltype(g_winAPIs->GetWindowModuleFileNameW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetWindowModuleFileNameW")));
		g_winAPIs->RemoveVectoredExceptionHandler= decltype(g_winAPIs->RemoveVectoredExceptionHandler)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("RemoveVectoredExceptionHandler")));
		g_winAPIs->NtQueryVirtualMemory= decltype(g_winAPIs->NtQueryVirtualMemory)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueryVirtualMemory")));
		g_winAPIs->PeekMessageW = decltype(g_winAPIs->PeekMessageW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("PeekMessageW")));
		g_winAPIs->GetMessageW = decltype(g_winAPIs->GetMessageW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetMessageW")));
		g_winAPIs->TranslateMessage= decltype(g_winAPIs->TranslateMessage)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("TranslateMessage")));
		g_winAPIs->DispatchMessageW = decltype(g_winAPIs->DispatchMessageW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("DispatchMessageW")));
		g_winAPIs->UnhookWindowsHookEx= decltype(g_winAPIs->UnhookWindowsHookEx)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("UnhookWindowsHookEx")));
		g_winAPIs->SHGetSpecialFolderPathW = decltype(g_winAPIs->SHGetSpecialFolderPathW)(g_winAPIs->GetProcAddress(g_winModules->hShell32, xorstr_("SHGetSpecialFolderPathW")));
		g_winAPIs->FreeLibraryAndExitThread= decltype(g_winAPIs->FreeLibraryAndExitThread)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("FreeLibraryAndExitThread")));
		g_winAPIs->NtUnmapViewOfSection= decltype(g_winAPIs->NtUnmapViewOfSection)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtUnmapViewOfSection")));
		g_winAPIs->EndTask= decltype(g_winAPIs->EndTask)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("EndTask")));
		g_winAPIs->VirtualAlloc= decltype(g_winAPIs->VirtualAlloc)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("VirtualAlloc")));
		g_winAPIs->DebugBreak= decltype(g_winAPIs->DebugBreak)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("DebugBreak")));
		g_winAPIs->GetModuleHandleExW = decltype(g_winAPIs->GetModuleHandleExW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetModuleHandleExW")));
		g_winAPIs->ReadFile= decltype(g_winAPIs->ReadFile)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("ReadFile")));
		g_winAPIs->NtSetInformationProcess= decltype(g_winAPIs->NtSetInformationProcess)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtSetInformationProcess")));
		g_winAPIs->NtAllocateVirtualMemory= decltype(g_winAPIs->NtAllocateVirtualMemory)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtAllocateVirtualMemory")));
		g_winAPIs->GetShellWindow= decltype(g_winAPIs->GetShellWindow)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetShellWindow")));
		g_winAPIs->CreateFileW= decltype(g_winAPIs->CreateFileW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("CreateFileW")));
		g_winAPIs->CryptCATAdminCalcHashFromFileHandle= decltype(g_winAPIs->CryptCATAdminCalcHashFromFileHandle)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminCalcHashFromFileHandle")));
		g_winAPIs->CryptCATAdminAcquireContext= decltype(g_winAPIs->CryptCATAdminAcquireContext)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminAcquireContext")));
		g_winAPIs->CryptCATAdminEnumCatalogFromHash= decltype(g_winAPIs->CryptCATAdminEnumCatalogFromHash)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminEnumCatalogFromHash")));
		g_winAPIs->CryptCATAdminReleaseContext= decltype(g_winAPIs->CryptCATAdminReleaseContext)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminReleaseContext")));
		g_winAPIs->CryptCATCatalogInfoFromContext= decltype(g_winAPIs->CryptCATCatalogInfoFromContext)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATCatalogInfoFromContext")));
		g_winAPIs->EnumProcessModules= decltype(g_winAPIs->EnumProcessModules)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("EnumProcessModules")));
		g_winAPIs->GetModuleFileNameExW = decltype(g_winAPIs->GetModuleFileNameExW)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("GetModuleFileNameExW")));
		g_winAPIs->GetModuleFileNameExW = decltype(g_winAPIs->GetModuleFileNameExW)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("GetModuleFileNameExW")));
		g_winAPIs->RtlGetVersion= decltype(g_winAPIs->RtlGetVersion)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlGetVersion")));
		g_winAPIs->VerifyVersionInfoW= decltype(g_winAPIs->VerifyVersionInfoW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("VerifyVersionInfoW")));
		g_winAPIs->VerSetConditionMask= decltype(g_winAPIs->VerSetConditionMask)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("VerSetConditionMask")));
		g_winAPIs->GetWindowLongW = decltype(g_winAPIs->GetWindowLongW)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetWindowLongW")));
		g_winAPIs->InitializeCriticalSection= decltype(g_winAPIs->InitializeCriticalSection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("InitializeCriticalSection")));
		g_winAPIs->EnterCriticalSection= decltype(g_winAPIs->EnterCriticalSection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("EnterCriticalSection")));
		g_winAPIs->LeaveCriticalSection= decltype(g_winAPIs->LeaveCriticalSection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("LeaveCriticalSection")));
		g_winAPIs->DeleteCriticalSection= decltype(g_winAPIs->DeleteCriticalSection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("DeleteCriticalSection")));
		g_winAPIs->GetProcessImageFileNameW = decltype(g_winAPIs->GetProcessImageFileNameW)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("GetProcessImageFileNameW")));
		g_winAPIs->GetLogicalDriveStringsW = decltype(g_winAPIs->GetLogicalDriveStringsW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetLogicalDriveStringsW")));
		g_winAPIs->GetSystemMetrics= decltype(g_winAPIs->GetSystemMetrics)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetSystemMetrics")));
		g_winAPIs->RtlAdjustPrivilege= decltype(g_winAPIs->RtlAdjustPrivilege)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlAdjustPrivilege")));

		g_winAPIs->EnumProcesses= decltype(g_winAPIs->EnumProcesses)(g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("EnumProcesses")));
		if (!g_winAPIs->EnumProcesses)
			g_winAPIs->EnumProcesses= decltype(g_winAPIs->EnumProcesses)(g_winAPIs->GetProcAddress_o(g_winModules->hPsapi, xorstr_("EnumProcesses")));
	}
};
