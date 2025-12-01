#include "../PCH.hpp"
#include "RestorePointHelper.hpp"
#include <srrestoreptapi.h>

namespace NoMercy
{
	BOOL InitializeCOMSecurity()
	{
		BOOL fRet = FALSE;
		ACL* pAcl = NULL;

		do
		{
			// Initialize the security descriptor.
			SECURITY_DESCRIPTOR securityDesc{ 0 };
			fRet = g_winAPIs->InitializeSecurityDescriptor(&securityDesc, SECURITY_DESCRIPTOR_REVISION);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"InitializeSecurityDescriptor failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Create an administrator group security identifier (SID).
			ULONGLONG  rgSidBA[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			DWORD cbSid = sizeof(rgSidBA);
			fRet = g_winAPIs->CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, rgSidBA, &cbSid);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateWellKnownSid(WinBuiltinAdministratorsSid) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Create a local service security identifier (SID).
			ULONGLONG  rgSidLS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidLS);
			fRet = g_winAPIs->CreateWellKnownSid(WinLocalServiceSid, NULL, rgSidLS, &cbSid);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateWellKnownSid(WinLocalServiceSid) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Create a network service security identifier (SID).
			ULONGLONG  rgSidNS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidNS);
			fRet = g_winAPIs->CreateWellKnownSid(WinNetworkServiceSid, NULL, rgSidNS, &cbSid);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateWellKnownSid(WinNetworkServiceSid) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Create a personal account security identifier (SID).
			ULONGLONG  rgSidPS[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidPS);
			fRet = g_winAPIs->CreateWellKnownSid(WinSelfSid, NULL, rgSidPS, &cbSid);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateWellKnownSid(WinSelfSid) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Create a local service security identifier (SID).
			ULONGLONG  rgSidSY[(SECURITY_MAX_SID_SIZE + sizeof(ULONGLONG) - 1) / sizeof(ULONGLONG)] = { 0 };
			cbSid = sizeof(rgSidSY);
			fRet = g_winAPIs->CreateWellKnownSid(WinLocalSystemSid, NULL, rgSidSY, &cbSid);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateWellKnownSid(WinLocalSystemSid) failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Setup the access control entries (ACE) for COM. You may need to modify 
			// the access permissions for your application. COM_RIGHTS_EXECUTE and
			// COM_RIGHTS_EXECUTE_LOCAL are the minimum access rights required.

			EXPLICIT_ACCESS ea[5] = { 0 };
			ea[0].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[0].grfAccessMode = SET_ACCESS;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.pMultipleTrustee = NULL;
			ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[0].Trustee.ptstrName = (LPTSTR)rgSidBA;

			ea[1].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[1].grfAccessMode = SET_ACCESS;
			ea[1].grfInheritance = NO_INHERITANCE;
			ea[1].Trustee.pMultipleTrustee = NULL;
			ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[1].Trustee.ptstrName = (LPTSTR)rgSidLS;

			ea[2].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[2].grfAccessMode = SET_ACCESS;
			ea[2].grfInheritance = NO_INHERITANCE;
			ea[2].Trustee.pMultipleTrustee = NULL;
			ea[2].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[2].Trustee.ptstrName = (LPTSTR)rgSidNS;

			ea[3].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[3].grfAccessMode = SET_ACCESS;
			ea[3].grfInheritance = NO_INHERITANCE;
			ea[3].Trustee.pMultipleTrustee = NULL;
			ea[3].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[3].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[3].Trustee.ptstrName = (LPTSTR)rgSidPS;

			ea[4].grfAccessPermissions = COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL;
			ea[4].grfAccessMode = SET_ACCESS;
			ea[4].grfInheritance = NO_INHERITANCE;
			ea[4].Trustee.pMultipleTrustee = NULL;
			ea[4].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[4].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[4].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[4].Trustee.ptstrName = (LPTSTR)rgSidSY;

			// Create an access control list (ACL) using this ACE list.
			const auto dwRet = g_winAPIs->SetEntriesInAclW(ARRAYSIZE(ea), ea, NULL, &pAcl);
			if (dwRet != ERROR_SUCCESS || pAcl == NULL)
			{
				APP_TRACE_LOG(LL_ERR, L"SetEntriesInAclA failed with status: %u error: %u", dwRet, g_winAPIs->GetLastError());
				fRet = FALSE;
				break;
			}

			// Set the security descriptor owner to Administrators.
			fRet = g_winAPIs->SetSecurityDescriptorOwner(&securityDesc, rgSidBA, FALSE);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"SetSecurityDescriptorOwner failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Set the security descriptor group to Administrators.
			fRet = g_winAPIs->SetSecurityDescriptorGroup(&securityDesc, rgSidBA, FALSE);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"SetSecurityDescriptorGroup failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Set the discretionary access control list (DACL) to the ACL.
			fRet = g_winAPIs->SetSecurityDescriptorDacl(&securityDesc, TRUE, pAcl, FALSE);
			if (!fRet)
			{
				APP_TRACE_LOG(LL_ERR, L"SetSecurityDescriptorDacl failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Initialize COM. You may need to modify the parameters of
			// CoInitializeSecurity() for your application. Note that an
			// explicit security descriptor is being passed down.
			const auto hrRet = g_winAPIs->CoInitializeSecurity(&securityDesc,
				-1,
				NULL,
				NULL,
				RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
				RPC_C_IMP_LEVEL_IDENTIFY,
				NULL,
				EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL,
				NULL
			);
			if (FAILED(hrRet))
			{
				APP_TRACE_LOG(LL_ERR, L"CoInitializeSecurity failed with status: %p error: %u", hrRet, g_winAPIs->GetLastError());
				fRet = FALSE;
				break;
			}

			fRet = TRUE;
		} while (FALSE);

		if (pAcl)
			g_winAPIs->LocalFree(pAcl);

		return fRet;
	}

	bool CreateRestorePoint()
	{
		if (!g_winAPIs->SRSetRestorePointW)
			return false;
		
		const auto hr = g_winAPIs->CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			APP_TRACE_LOG(LL_ERR, L"CoInitializeEx failed with status: %p", hr);
			return false;
		}

		// Initialize COM security to enable NetworkService,
		// LocalService and System to make callbacks to the process 
		// calling  System Restore. This is required for any process
		// that calls SRSetRestorePoint.
		auto fRet = InitializeCOMSecurity();
		if (!fRet)
		{
			APP_TRACE_LOG(LL_ERR, L"InitializeCOMSecurity failed. Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Initialize the RESTOREPOINTINFO structure
		RESTOREPOINTINFOW RestorePtInfo;
		RestorePtInfo.dwEventType = BEGIN_SYSTEM_CHANGE;
		RestorePtInfo.dwRestorePtType = APPLICATION_INSTALL;	
		RestorePtInfo.llSequenceNumber = 0; // RestPtInfo.llSequenceNumber must be 0 when creating a restore point.
		StringCbCopyW(RestorePtInfo.szDescription, sizeof(RestorePtInfo.szDescription), xorstr_(L"NoMercy System Restore Point"));

		STATEMGRSTATUS SMgrStatus;
		fRet = g_winAPIs->SRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
		if (!fRet)
		{
			const auto dwErr = SMgrStatus.nStatus;
			if (dwErr == ERROR_SERVICE_DISABLED)
			{
				APP_TRACE_LOG(LL_ERR, L"System restore is turned off!");
				return false;
			}

			APP_TRACE_LOG(LL_ERR, L"System restore point create failed with error: %u", dwErr);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Restore point created; number=%I64d.", SMgrStatus.llSequenceNumber);

		// The application performs some installation operations here.

		// It is not necessary to call SrSetRestorePoint to indicate that the 
		// installation is complete except in the case of ending a nested 
		// restore point. Every BEGIN_NESTED_SYSTEM_CHANGE must have a 
		// corresponding END_NESTED_SYSTEM_CHANGE or the application cannot 
		// create new restore points.

		// Update the RESTOREPOINTINFO structure to notify the 
		// system that the operation is finished.
		RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;

		// End the system change by using the sequence number 
		// received from the first call to SRSetRestorePoint.
		RestorePtInfo.llSequenceNumber = SMgrStatus.llSequenceNumber;

		// Notify the system that the operation is done and that this
		// is the end of the restore point.
		fRet = g_winAPIs->SRSetRestorePointW(&RestorePtInfo, &SMgrStatus);
		if (!fRet)
		{
			APP_TRACE_LOG(LL_ERR, L"Failure to end the restore point error: %u", SMgrStatus.nStatus);
			return false;
		}

		return true;
	}
};
