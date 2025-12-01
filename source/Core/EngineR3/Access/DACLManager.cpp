#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Access.hpp"
#include "../../EngineR3_Core/include/Elevation.hpp"

// FIXME random exceptions in GetThreadFromThreadCode thread >> 0xDDDDDDD
// #define ENABLE_EXPERIMENTAL_DACL_RULES

#define TOKEN_POISONED_ACCESS					\
	TOKEN_ADJUST_PRIVILEGES						| \
	TOKEN_DUPLICATE								| \
	TOKEN_ASSIGN_PRIMARY

#define THREAD_POISONED_ACCESS					\
	WRITE_DAC									| \
	THREAD_SUSPEND_RESUME						| \
	THREAD_SET_CONTEXT							| \
	THREAD_SET_INFORMATION						| \
	THREAD_SET_THREAD_TOKEN						| \
	THREAD_TERMINATE

#define PROCESS_POISONED_ACCESS					\
	WRITE_DAC									| \
	PROCESS_CREATE_THREAD						| \
	PROCESS_VM_WRITE							| \
	PROCESS_VM_OPERATION						| \
	PROCESS_SET_INFORMATION						| \
	PROCESS_SET_SESSIONID						| \
	PROCESS_SUSPEND_RESUME

namespace NoMercy
{
	bool CAccess::BlockAccess(HANDLE hTarget)
	{
		std::wstring szSD =
			xorstr_(L"D:P"
				"(D;OICI;GA;;;BG)"  /* Deny access to built-in guests */
				"(D;OICI;GA;;;AN)"  /*		  ^		  anonymous logon */
				"(D;OICI;GA;;;AU)"  /*		  ^		  authenticated users */
				"(D;OICI;GA;;;BA)"  /*		  ^		  administrators */
				"(D;OICI;GA;;;LA)"  /*		  ^		  Built-in Administrator */
			);

		SECURITY_ATTRIBUTES sa{ 0 };
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = FALSE;

		if (!g_winAPIs->ConvertStringSecurityDescriptorToSecurityDescriptorW(szSD.c_str(), SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
		{
			APP_TRACE_LOG(LL_ERR, L"ConvertStringSecurityDescriptorToSecurityDescriptorA fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->SetKernelObjectSecurity(hTarget, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
		{
			APP_TRACE_LOG(LL_ERR, L"SetKernelObjectSecurity fail! Error: %u", g_winAPIs->GetLastError());
			g_winAPIs->LocalFree(sa.lpSecurityDescriptor);
			return false;
		}

		g_winAPIs->LocalFree(sa.lpSecurityDescriptor);
		return true;
	}

	bool GetWellKnownSids(std::vector<PSID>& vecSids)
	{
		// Structure to hold SID creation info
		struct SidInfo
		{
			SID_IDENTIFIER_AUTHORITY authority;
			std::vector<DWORD> subAuthorities;
		};

		// List of well-known SIDs we want to deny access to
		const std::vector<SidInfo> wellKnownSids = {
			// World SID (Everyone)
			{ SECURITY_WORLD_SID_AUTHORITY, {SECURITY_WORLD_RID} },

			// Local System
			{ SECURITY_NT_AUTHORITY, {SECURITY_LOCAL_SYSTEM_RID} },

			// Administrators
			{ SECURITY_NT_AUTHORITY, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS} },

			// Users
			{ SECURITY_NT_AUTHORITY, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS} },

			// Authenticated Users
			{ SECURITY_NT_AUTHORITY, {SECURITY_AUTHENTICATED_USER_RID} },

			// Restricted Code
			{ SECURITY_NT_AUTHORITY, {SECURITY_RESTRICTED_CODE_RID} }
		};

		for (const auto& sidInfo : wellKnownSids)
		{
			PSID sid = nullptr;
			if (g_winAPIs->AllocateAndInitializeSid(
				const_cast<PSID_IDENTIFIER_AUTHORITY>(&sidInfo.authority),
				static_cast<BYTE>(sidInfo.subAuthorities.size()),
				sidInfo.subAuthorities.size() > 0 ? sidInfo.subAuthorities[0] : 0,
				sidInfo.subAuthorities.size() > 1 ? sidInfo.subAuthorities[1] : 0,
				sidInfo.subAuthorities.size() > 2 ? sidInfo.subAuthorities[2] : 0,
				sidInfo.subAuthorities.size() > 3 ? sidInfo.subAuthorities[3] : 0,
				sidInfo.subAuthorities.size() > 4 ? sidInfo.subAuthorities[4] : 0,
				sidInfo.subAuthorities.size() > 5 ? sidInfo.subAuthorities[5] : 0,
				sidInfo.subAuthorities.size() > 6 ? sidInfo.subAuthorities[6] : 0,
				sidInfo.subAuthorities.size() > 7 ? sidInfo.subAuthorities[7] : 0,
				&sid))
			{
				if (g_winAPIs->IsValidSid(sid))
					vecSids.push_back(sid);
				else
					g_winAPIs->FreeSid(sid);
			}
		}

		return !vecSids.empty();
	}

	bool CAccess::ChangeAccessRights(HANDLE hTarget, EACLTargetType eTargetType)
	{
		std::vector<PSID> vecSids;
		if (!GetWellKnownSids(vecSids))
		{
			APP_TRACE_LOG(LL_ERR, L"GetWellKnownSids fail, last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		DWORD dwPoisonedRights = 0;
		switch (eTargetType)
		{
		case EACLTargetType::PROCESS:
			dwPoisonedRights = PROCESS_POISONED_ACCESS;
			break;
		case EACLTargetType::THREAD:
			dwPoisonedRights = THREAD_POISONED_ACCESS;
			break;
		case EACLTargetType::TOKEN:
			dwPoisonedRights = TOKEN_POISONED_ACCESS;
			break;
		};

		const auto nACLBufferSize = 0x400 * vecSids.size();
		if (nACLBufferSize > std::numeric_limits<WORD>::max())
		{
			APP_TRACE_LOG(LL_ERR, L"ACL buffer size is too large: %u", nACLBufferSize);

			for (auto sid : vecSids)
			{
				g_winAPIs->FreeSid(sid);
			}
			return false;
		}

		auto pACLBuffer = CMemHelper::Allocate(nACLBufferSize);
		if (!pACLBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for ACL buffer with size: %u", nACLBufferSize);

			for (auto sid : vecSids)
			{
				g_winAPIs->FreeSid(sid);
			}
			return false;
		}

		auto pACL = (PACL)pACLBuffer;
		pACL->AclRevision = ACL_REVISION;
		pACL->AclSize = static_cast<WORD>(nACLBufferSize);
		pACL->AceCount = 0;

		bool success = true;
		for (auto sid : vecSids)
		{
			const auto ntStatus = g_winAPIs->RtlAddAccessDeniedAce(pACL, ACL_REVISION, dwPoisonedRights, sid);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"RtlAddAccessDeniedAce failed with NTSTATUS: 0x%p for SID: 0x%p", ntStatus, sid);

				success = false;
				break;
			}
		}

		if (success)
		{
			success = (g_winAPIs->SetSecurityInfo(hTarget, SE_KERNEL_OBJECT,
				PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
				0, 0, pACL, 0) == ERROR_SUCCESS
			);

			if (!success)
			{
				APP_TRACE_LOG(LL_ERR, L"SetSecurityInfo failed with error: %u", g_winAPIs->GetLastError());
			}
		}

		// Cleanup
		for (auto sid : vecSids)
		{
			FreeSid(sid);
		}
		CMemHelper::Free(pACLBuffer);

		return success;
	}

	bool CAccess::DenyTokenAccess()
	{
		HANDLE hToken = nullptr;
		if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenProcessToken fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto bRet = this->ChangeAccessRights(hToken, EACLTargetType::TOKEN);

		g_winAPIs->CloseHandle(hToken);
		return bRet;
	}
}
