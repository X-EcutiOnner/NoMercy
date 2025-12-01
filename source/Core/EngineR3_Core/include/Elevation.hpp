#pragma once

namespace NoMercyCore
{
    class CElevationHelper
    {
        public:
            static std::optional <bool> IsApplicationRequiredUAC(const std::wstring& wstApplication);
            static bool HasEnoughRights();
            static bool IsUserAdmin();
            static bool IsRunAsAdmin();
            static bool IsProcessElevated(HANDLE hProcess);
            static DWORD GetIntegrityLevel(HANDLE hTarget);
            static bool GetCurrentUserAndDomain(PTSTR szUser, PDWORD pcchUser, PTSTR szDomain, PDWORD pcchDomain);
            static DWORD GetCurrentSessionID();
            static std::wstring GetCurrentDomain();
            static std::wstring GetAccountSID();
            static bool SetProcessPrivilege(HANDLE hToken, const std::wstring& stPrivilege, bool bEnable);
            static std::wstring GetStringSIDFromPSID(PSID pSID);
            static std::unique_ptr <SID> CElevationHelper::GetPSIDFromName(const std::wstring& stName);
            static std::vector <std::wstring> GetGroupsOfUser(const std::wstring& wstName);
    };
};
