#include "../../include/PCH.hpp"
#include "../../include/Elevation.hpp"

namespace NoMercyCore
{
	std::optional <bool> CElevationHelper::IsApplicationRequiredUAC(const std::wstring& wstApplication)
	{
		DWORD dwRunLevel = 0;
		DWORD dwFlags = 0;
		DWORD dwReason = 0;
		const auto dwRetCode = g_winAPIs->CheckElevation(wstApplication.c_str(), &dwFlags, nullptr, &dwRunLevel, &dwReason);
		if (dwRetCode != 0)
		{
			APP_TRACE_LOG(LL_ERR, L"CheckElevation failed with return: %u error: %u", dwRetCode, g_winAPIs->GetLastError());
			return std::nullopt;
		}

		APP_TRACE_LOG(LL_SYS, L"Application: %ls Run level: %u Flags: %u Reason: %u", wstApplication.c_str(), dwRunLevel, dwFlags, dwReason);
		return std::make_optional<bool>(dwRunLevel > 0);
	}

	bool CElevationHelper::HasEnoughRights()
	{
		const auto lstRequiredRights = {
			xorstr_(L"SeDebugPrivilege"), // SE_DEBUG_PRIVILEGE
//			xorstr_(L"SeLoadDriverPrivilege"), // SE_LOAD_DRIVER_PRIVILEGE
//			xorstr_(L"SeIncreaseQuotaPrivilege"), // SE_INCREASE_QUOTA_PRIVILEGE
//			xorstr_(L"SeAssignPrimaryTokenPrivilege"), // SE_ASSIGNPRIMARYTOKEN_PRIVILEGE
//			xorstr_(L"SeTcbPrivilege") // SE_TCB_PRIVILEGE
		};
		const auto nRequiredRightCount = lstRequiredRights.size();
		
		auto ParseUserInfo = [&lstRequiredRights, &nRequiredRightCount](const USER_INFO_3* user) {
			if (!user)
			{
				APP_TRACE_LOG(LL_WARN, L"Null user name!");
				return false;
			}

			const auto groups = CElevationHelper::GetGroupsOfUser(user->usri3_name);
			for (const auto& group : groups)
			{
				auto psid = CElevationHelper::GetPSIDFromName(group);
				if (psid.get())
				{
					LSA_OBJECT_ATTRIBUTES unused{ 0 };
					ZeroMemory(&unused, sizeof(unused));

					LSA_HANDLE handle = nullptr;
					if (g_winAPIs->LsaOpenPolicy(nullptr, &unused, GENERIC_EXECUTE, &handle) == STATUS_SUCCESS)
					{
						PLSA_UNICODE_STRING rights;
						ULONG count = 0;
						const auto status = g_winAPIs->LsaEnumerateAccountRights(handle, psid.get(), (::LSA_UNICODE_STRING**)&rights, &count);
						if (status == STATUS_SUCCESS)
						{
							std::wstring wstRights;
							
							auto found_right_count = 0u;
							for (std::size_t i = 0; i < count; ++i)
							{
								const auto right = std::wstring(rights[i].Buffer, rights[i].Length / sizeof(*rights[i].Buffer));
								wstRights += right + xorstr_(L", ");

								for (const auto& required_right : lstRequiredRights)
								{
									if (right == required_right)
									{
										++found_right_count;
										break;
									}
								}
							}

							if (wstRights.size() > 2)
								wstRights.erase(wstRights.size() - 2);
							
							APP_TRACE_LOG(LL_SYS, L"User %s has rights: %s", group.c_str(), wstRights.c_str());

							g_winAPIs->LsaFreeMemory(rights);

							if (found_right_count == nRequiredRightCount)
							{
								g_winAPIs->LsaClose(handle);
								return true;
							}
						}
						else
						{
							if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetSystemErrorFromLSAStatus(status) == ERROR_FILE_NOT_FOUND)
							{
								APP_TRACE_LOG(LL_WARN, L"User %ls has no rights", user->usri3_name);
							}
							else
							{
								APP_TRACE_LOG(LL_ERR, L"LsaEnumerateAccountRights failed with error: %u - status: %p", g_winAPIs->GetLastError(), status);
							}
						}
						g_winAPIs->LsaClose(handle);
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"LsaOpenPolicy failed with error: %u", g_winAPIs->GetLastError());
					}
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Null pSID for: %s-%s", user->usri3_name, group.c_str());
				}
			}

			if (groups.empty())
			{
				const auto wstLowerGroupName = stdext::to_lower_wide(user->usri3_name);
				const std::wstring wstAvastSandbox = xorstr_(L"wdagutilityaccount");
				if (wstAvastSandbox == wstLowerGroupName)
				{
					APP_TRACE_LOG(LL_WARN, L"Sandbox account skipped");
					return true; // ...
				}

				APP_TRACE_LOG(LL_ERR, L"Groups empty for: %s", user->usri3_name);
			}

			return false;
		};

		// Iterate users
		auto bHasRights = false;
		LPUSER_INFO_3 buffer = nullptr;
		NET_API_STATUS status;
		DWORD total = 0;
		DWORD handler = 0;
		
		do
		{
			DWORD count = 0;
			status = g_winAPIs->NetUserEnum(nullptr, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&buffer, MAX_PREFERRED_LENGTH, &count, &total, &handler);
			if (status == NERR_Success || status == ERROR_MORE_DATA)
			{
				if (auto ptr = buffer; ptr != nullptr)
				{
					for (std::size_t i = 0; i < count; ++i)
					{
						if (ptr)
						{
							if (ParseUserInfo(ptr))
							{
								bHasRights = true;
								break;
							}

							++ptr;
						}
					}
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"NetUserEnum failed with error: %u - status: %u", g_winAPIs->GetLastError(), status);
			}

			if (buffer)
			{
				g_winAPIs->NetApiBufferFree(buffer);
				buffer = nullptr;
			}
		} while (status == ERROR_MORE_DATA);

		if (!total && !handler)
		{
			APP_TRACE_LOG(LL_WARN, L"Priv enum failed with error: %u - status: %u", g_winAPIs->GetLastError(), status);
		}

		if (buffer)
		{
			g_winAPIs->NetApiBufferFree(buffer);
			buffer = nullptr;
		}

		return bHasRights;
	}

	bool CElevationHelper::IsUserAdmin()
	{
		struct SContext
		{
			PACL   pACL;
			PSID   psidAdmin;
			HANDLE hToken;
			HANDLE hImpersonationToken;
			PSECURITY_DESCRIPTOR psdAdmin;

			SContext() :
				pACL(nullptr), psidAdmin(nullptr), hToken(nullptr), hImpersonationToken(nullptr), psdAdmin(nullptr)
			{
			}

			~SContext()
			{
				if (pACL)
				{
					g_winAPIs->LocalFree(pACL);
					pACL = nullptr;
				}
				if (psdAdmin)
				{
					g_winAPIs->LocalFree(psdAdmin);
					psdAdmin = nullptr;
				}
				if (psidAdmin)
				{
					g_winAPIs->FreeSid(psidAdmin);
					psidAdmin = nullptr;
				}
				if (hImpersonationToken)
				{
					g_winAPIs->CloseHandle(hImpersonationToken);
					hImpersonationToken = nullptr;
				}
				if (hToken)
				{
					g_winAPIs->CloseHandle(hToken);
					hToken = nullptr;
				}
			}
		} ctx;

		BOOL   fReturn = FALSE;
		DWORD  dwStatus;
		DWORD  dwAccessMask;
		DWORD  dwAccessDesired;
		DWORD  dwACLSize;
		DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);

		PRIVILEGE_SET   ps;
		GENERIC_MAPPING GenericMapping;
		SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
		
		if (!g_winAPIs->OpenThreadToken(NtCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &ctx.hToken))
		{
			if (g_winAPIs->GetLastError() != ERROR_NO_TOKEN)
			{
				APP_TRACE_LOG(LL_ERR, L"OpenThreadToken failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &ctx.hToken))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}

		if (!g_winAPIs->DuplicateToken(ctx.hToken, SecurityImpersonation, &ctx.hImpersonationToken))
		{
			APP_TRACE_LOG(LL_ERR, L"DuplicateToken failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->AllocateAndInitializeSid(&SystemSidAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &ctx.psidAdmin))
		{
			APP_TRACE_LOG(LL_ERR, L"AllocateAndInitializeSid failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		ctx.psdAdmin = g_winAPIs->LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (!ctx.psdAdmin)
		{
			APP_TRACE_LOG(LL_ERR, L"LocalAlloc (psdAdmin) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->InitializeSecurityDescriptor(ctx.psdAdmin, SECURITY_DESCRIPTOR_REVISION))
		{
			APP_TRACE_LOG(LL_ERR, L"InitializeSecurityDescriptor failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Compute size needed for the ACL.
		dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + g_winAPIs->GetLengthSid(ctx.psidAdmin) - sizeof(DWORD);

		ctx.pACL = (PACL)g_winAPIs->LocalAlloc(LPTR, dwACLSize);
		if (!ctx.pACL)
		{
			APP_TRACE_LOG(LL_ERR, L"LocalAlloc (pACL) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->InitializeAcl(ctx.pACL, dwACLSize, ACL_REVISION2))
		{
			APP_TRACE_LOG(LL_ERR, L"InitializeAcl failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		dwAccessMask = ACCESS_READ | ACCESS_WRITE;

		if (!g_winAPIs->AddAccessAllowedAce(ctx.pACL, ACL_REVISION2, dwAccessMask, ctx.psidAdmin))
		{
			APP_TRACE_LOG(LL_ERR, L"AddAccessAllowedAce failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->SetSecurityDescriptorDacl(ctx.psdAdmin, TRUE, ctx.pACL, FALSE))
		{
			APP_TRACE_LOG(LL_ERR, L"SetSecurityDescriptorDacl failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// AccessCheck validates a security descriptor somewhat; set the group
		// and owner so that enough of the security descriptor is filled out 
		// to make AccessCheck happy.

		g_winAPIs->SetSecurityDescriptorGroup(ctx.psdAdmin, ctx.psidAdmin, FALSE);
		g_winAPIs->SetSecurityDescriptorOwner(ctx.psdAdmin, ctx.psidAdmin, FALSE);

		if (!g_winAPIs->IsValidSecurityDescriptor(ctx.psdAdmin))
		{
			APP_TRACE_LOG(LL_ERR, L"IsValidSecurityDescriptor failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		dwAccessDesired = ACCESS_READ;

		GenericMapping.GenericRead = ACCESS_READ;
		GenericMapping.GenericWrite = ACCESS_WRITE;
		GenericMapping.GenericExecute = 0;
		GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

		if (!g_winAPIs->AccessCheck(ctx.psdAdmin, ctx.hImpersonationToken, dwAccessDesired, &GenericMapping, &ps, &dwStructureSize, &dwStatus, &fReturn))
		{
			APP_TRACE_LOG(LL_ERR, L"AccessCheck failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(fReturn ? LL_SYS : LL_ERR, L"AccessCheck returned value: %d", fReturn);
		return !!fReturn;
	}

	bool CElevationHelper::IsRunAsAdmin()
	{
		bool bIsRunAsAdmin = false;
		PSID pAdministratorsGroup = nullptr;

		do
		{
			SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
			if (!g_winAPIs->AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
			{
				APP_TRACE_LOG(LL_ERR, L"AllocateAndInitializeSid failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			BOOL bRet = FALSE;
			if (!g_winAPIs->CheckTokenMembership(nullptr, pAdministratorsGroup, &bRet))
			{
				APP_TRACE_LOG(LL_ERR, L"CheckTokenMembership failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			bIsRunAsAdmin = !!bRet;
		} while (false);
		
		if (pAdministratorsGroup)
		{
			g_winAPIs->FreeSid(pAdministratorsGroup);
			pAdministratorsGroup = nullptr;
		}

		return bIsRunAsAdmin;
	}

	bool CElevationHelper::IsProcessElevated(HANDLE hProcess)
	{
		bool bIsElevated = false;
		HANDLE hToken = nullptr;

		do
		{
			if (!g_winAPIs->OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			DWORD dwSize;
			TOKEN_ELEVATION elevation;
			if (!g_winAPIs->GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
			{
				APP_TRACE_LOG(LL_ERR, L"GetTokenInformation failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			bIsElevated = elevation.TokenIsElevated;
		} while (false);

		if (hToken)
		{
			g_winAPIs->CloseHandle(hToken);
			hToken = nullptr;
		}

		return bIsElevated;
	}

	DWORD CElevationHelper::GetIntegrityLevel(HANDLE hTarget)
	{
		DWORD dwIntegrityLevel = 0;
		HANDLE hToken = nullptr;
		PTOKEN_MANDATORY_LABEL pTokenIL = nullptr;

		do
		{
			if (!g_winAPIs->OpenProcessToken(hTarget, TOKEN_QUERY, &hToken))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenProcessToken fail! Handle: %p Error: %u", hTarget, g_winAPIs->GetLastError());
				break;
			}
			
			DWORD cbTokenIL = 0;
			if (!g_winAPIs->GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &cbTokenIL))
			{
				const auto dwError = g_winAPIs->GetLastError();
				if (ERROR_INSUFFICIENT_BUFFER != dwError)
				{
					APP_TRACE_LOG(LL_ERR, L"GetTokenInformation(1) fail! Handle: %p Error: %u", hTarget, dwError);
					break;
				}
			}			
			
			pTokenIL = (TOKEN_MANDATORY_LABEL*)g_winAPIs->LocalAlloc(LPTR, cbTokenIL);
			if (!pTokenIL)
			{
				APP_TRACE_LOG(LL_ERR, L"LocalAlloc fail! Error: %u", g_winAPIs->GetLastError());
				break;
			}			

			if (!g_winAPIs->GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL))
			{
				APP_TRACE_LOG(LL_ERR, L"GetTokenInformation(2) fail! Handle: %p Error: %u", hTarget, g_winAPIs->GetLastError());
				break;
			}

			if (!g_winAPIs->IsValidSid(pTokenIL->Label.Sid))
			{
				APP_TRACE_LOG(LL_ERR, L"IsValidSid fail! Handle: %p Error: %u", hTarget, g_winAPIs->GetLastError());
				break;
			}

			const auto pdwAuthCount = g_winAPIs->GetSidSubAuthorityCount(pTokenIL->Label.Sid);
			if (!pdwAuthCount)
			{
				APP_TRACE_LOG(LL_ERR, L"GetSidSubAuthorityCount fail! Handle: %p Error: %u", hTarget, g_winAPIs->GetLastError());
				break;
			}

			const auto dwAuthCount = static_cast<DWORD>(*pdwAuthCount - 1);
			if (dwAuthCount == 0)
			{
				const auto dwError = g_winAPIs->GetLastError();
				APP_TRACE_LOG(dwError ? LL_ERR : LL_TRACE, L"dwAuthCount is null! Handle: %p Error: %u", hTarget, dwError);
				// break;
			}

			const auto pdwIntegrityRet = g_winAPIs->GetSidSubAuthority(pTokenIL->Label.Sid, dwAuthCount);
			if (!pdwIntegrityRet)
			{
				APP_TRACE_LOG(LL_ERR, L"GetSidSubAuthority fail! Handle: %p Error: %u", hTarget, g_winAPIs->GetLastError());
				break;
			}
			
			dwIntegrityLevel = *pdwIntegrityRet;
		} while (false);

		if (hToken)
		{
			g_winAPIs->CloseHandle(hToken);
			hToken = nullptr;
		}
		if (pTokenIL)
		{
			g_winAPIs->LocalFree(pTokenIL);
			pTokenIL = nullptr;
		}

		return dwIntegrityLevel;
	}

	bool CElevationHelper::GetCurrentUserAndDomain(LPWSTR szUser, PDWORD pcchUser, LPWSTR szDomain, PDWORD pcchDomain)
	{
		bool bRet = false;
		HANDLE hToken = nullptr;
		PTOKEN_USER ptiUser = nullptr;

		do
		{
			// Get the calling thread's access token.
			if (!g_winAPIs->OpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
			{
				const auto dwErrorCode = g_winAPIs->GetLastError();
				if (dwErrorCode != ERROR_NO_TOKEN)
				{
					APP_TRACE_LOG(LL_ERR, L"OpenThreadToken failed with error: %u", dwErrorCode);
					break;
				}

				// Retry against process token if no thread token exists.
				if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
				{
					APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
					break;
				}
			}

			// Obtain the size of the user information in the token.
			DWORD cbti = 0;
			if (g_winAPIs->GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti))
			{
				// Call should have failed due to zero-length buffer.
				break;
			}
			else
			{
				// Call should have failed due to zero-length buffer.
				const auto dwErrorCode = g_winAPIs->GetLastError();
				if (dwErrorCode != ERROR_INSUFFICIENT_BUFFER)
				{
					APP_TRACE_LOG(LL_ERR, L"GetTokenInformation failed with error: %u", dwErrorCode);
					break;
				}
			}

			// Allocate buffer for user information in the token.
			ptiUser = (PTOKEN_USER)g_winAPIs->HeapAlloc(g_winAPIs->GetProcessHeap(), 0, cbti);
			if (!ptiUser)
			{
				APP_TRACE_LOG(LL_ERR, L"HeapAlloc failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Retrieve the user information from the token.
			if (!g_winAPIs->GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
			{
				APP_TRACE_LOG(LL_ERR, L"GetTokenInformation failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Validate the user SID.
			if (!g_winAPIs->IsValidSid(ptiUser->User.Sid))
			{
				APP_TRACE_LOG(LL_ERR, L"IsValidSid failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			// Retrieve user name and domain name based on user's SID.
			SID_NAME_USE snu{};
			if (!g_winAPIs->LookupAccountSidW(0, ptiUser->User.Sid, szUser, pcchUser, szDomain, pcchDomain, &snu))
			{
				APP_TRACE_LOG(LL_ERR, L"LookupAccountSidW failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			bRet = true;
		} while (FALSE);

		if (hToken)
		{
			g_winAPIs->CloseHandle(hToken);
			hToken = nullptr;
		}
		if (ptiUser)
		{
			g_winAPIs->HeapFree(g_winAPIs->GetProcessHeap(), 0, ptiUser);
			ptiUser = nullptr;
		}

		return bRet;
	}

	DWORD CElevationHelper::GetCurrentSessionID()
	{
		auto dwSessionID = static_cast<DWORD>(-1);
		g_winAPIs->ProcessIdToSessionId(
			g_winAPIs->GetCurrentProcessId(),
			&dwSessionID
		);
		return dwSessionID;
	}

	std::wstring CElevationHelper::GetCurrentDomain()
	{
		DWORD dwLevel = 100;
		LPWKSTA_INFO_100 pBuf = NULL;
		const auto nStatus = g_winAPIs->NetWkstaGetInfo(NULL, dwLevel, (LPBYTE*)&pBuf);
		if (nStatus == NERR_Success)
		{
			const auto wstBuffer = std::wstring(pBuf->wki100_langroup);

			g_winAPIs->NetApiBufferFree(pBuf);
			return wstBuffer;
		}
		return {};
	}

	std::wstring CElevationHelper::GetAccountSID()
	{
		DWORD cbUserNameSize = MAX_PATH;
		wchar_t wszUserName[MAX_PATH]{ L'\0' };

		if (!g_winAPIs->GetUserNameW(wszUserName, &cbUserNameSize))
		{
			APP_TRACE_LOG(LL_ERR, L"GetUserNameW failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		//======================================

		SID_NAME_USE SidNameUse{};

		DWORD dwDMSize = MAX_PATH * sizeof(wchar_t);
		wchar_t wszDomain[MAX_PATH]{ L'\0' };

		DWORD cbSIDSize = MAX_PATH;;
		wchar_t wszSID[MAX_PATH]{ L'\0' };

		if (!g_winAPIs->LookupAccountNameW(NULL, wszUserName, (PSID)wszSID, &cbSIDSize, wszDomain, &dwDMSize, &SidNameUse))
		{
			APP_TRACE_LOG(LL_ERR, L"LookupAccountNameA failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		if (!g_winAPIs->IsValidSid((PSID)wszSID))
		{
			APP_TRACE_LOG(LL_ERR, L"IsValidSid failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		//======================================

		const auto pSIDAuthority = g_winAPIs->GetSidIdentifierAuthority((PSID)wszSID);
		if (!pSIDAuthority)
		{
			APP_TRACE_LOG(LL_ERR, L"GetSidIdentifierAuthority failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		wchar_t wszBuffer[512]{ L'\0' };
		int nIPos = _snwprintf(wszBuffer, 512, xorstr_(L"S-%u-%u"), SID_REVISION, pSIDAuthority->Value[5]);
		if (nIPos >= 512)
		{
			APP_TRACE_LOG(LL_ERR, L"_snwprintf failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		auto nSubs = *g_winAPIs->GetSidSubAuthorityCount((PSID)wszSID);
		for (auto nIter = 0; nIter < nSubs; ++nIter)
		{
			nIPos += _snwprintf(wszBuffer + nIPos, nIPos, xorstr_(L"-%u"), *g_winAPIs->GetSidSubAuthority((PSID)wszSID, nIter));
			if (nIPos >= 512)
			{
				APP_TRACE_LOG(LL_ERR, L"sprintf_s failed with error: %u", g_winAPIs->GetLastError());
				return {};
			}
		}

		//======================================

		return wszBuffer;
	}

	bool CElevationHelper::SetProcessPrivilege(HANDLE hToken, const std::wstring& stPrivilege, bool bEnable)
	{
		LUID luid{ 0 };
		if (!g_winAPIs->LookupPrivilegeValueW(nullptr, stPrivilege.c_str(), &luid))
		{
			APP_TRACE_LOG(LL_ERR, L"LookupPrivilegeValueW failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		TOKEN_PRIVILEGES tp{ 0 };
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (bEnable)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		// Enable the privilege or disable all privileges.
		if (!g_winAPIs->AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
		{
			APP_TRACE_LOG(LL_ERR, L"AdjustTokenPrivileges failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (g_winAPIs->GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			return false;
		}

		return true;
	}

	std::wstring CElevationHelper::GetStringSIDFromPSID(PSID pSID)
	{
		LPWSTR lpwszBuffer = nullptr; 
		if (!g_winAPIs->ConvertSidToStringSidW(pSID, &lpwszBuffer))
		{
			APP_TRACE_LOG(LL_ERR, L"ConvertSidToStringSidA failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		std::wstring stSID(lpwszBuffer);

		g_winAPIs->LocalFree(lpwszBuffer);
		return stSID;
	}

	std::unique_ptr <SID> CElevationHelper::GetPSIDFromName(const std::wstring& wstName)
	{
		std::unique_ptr <SID> upSID(nullptr);

		if (!wstName.empty())
		{
			DWORD dwSize = 0;
			DWORD dwDummy = 0;

			if (!g_winAPIs->LookupAccountNameW(nullptr, wstName.c_str(), upSID.get(), &dwSize, nullptr, &dwDummy, nullptr))
			{
				if (g_winAPIs->GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					upSID = std::unique_ptr<SID>(reinterpret_cast<SID*>(new (std::nothrow) BYTE[dwSize]));
					if (!upSID || !upSID.get())
						return {};

					wchar_t wszDummy[512]{ L'\0' };
					SID_NAME_USE snuDummy{};
					if (g_winAPIs->LookupAccountNameW(nullptr, wstName.c_str(), upSID.get(), &dwSize, wszDummy, &dwDummy, &snuDummy))
					{
						if (!g_winAPIs->IsValidSid(upSID.get()))
							return {};
					}
				}
			}
		}

		return upSID;
	}

	std::vector <std::wstring> CElevationHelper::GetGroupsOfUser(const std::wstring& wstName)
	{
		std::vector <std::wstring> vGroups;

		if (!wstName.empty()) 
		{
			LPLOCALGROUP_USERS_INFO_0 lpBuffer = nullptr;
			DWORD dwCount, dwTotal = 0;
			const auto dwStatus = g_winAPIs->NetUserGetLocalGroups(nullptr, wstName.c_str(), 0, LG_INCLUDE_INDIRECT, (LPBYTE*)&lpBuffer, MAX_PREFERRED_LENGTH, &dwCount, &dwTotal);
			
			if (dwStatus == NERR_Success)
			{
				if (auto ptr = lpBuffer; !!ptr)
				{
					for (auto i = 0u; i < dwCount; ++i)
					{
						if (ptr)
						{
							vGroups.push_back(ptr->lgrui0_name);
							++ptr;
						}
					}
				}
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"NetUserGetLocalGroups failed with error: %u", dwStatus);
			}

			if (lpBuffer)
			{
				g_winAPIs->NetApiBufferFree(lpBuffer);
				lpBuffer = nullptr;
			}
		}

		return vGroups;
	}
};
