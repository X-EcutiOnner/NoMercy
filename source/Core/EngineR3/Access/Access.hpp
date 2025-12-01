#pragma once

namespace NoMercy
{
	enum class EACLTargetType : uint8_t
	{
		PROCESS,
		THREAD,
		TOKEN
	};
	
	class CAccess : public std::enable_shared_from_this <CAccess>
	{
		public:
			CAccess() = default;
			virtual ~CAccess() = default;

			bool BlockAccess(HANDLE hTarget);
			bool ChangeAccessRights(HANDLE hTarget, EACLTargetType eTargetType);
			bool DenyTokenAccess();
			bool SetMitigationPolicys();

			bool RemoveProcessDebugPriv(DWORD dwProcessId, HANDLE hProcess);
			bool DecreasePrivilege(HANDLE hProcess);

			bool EnablePermanentDep();
			bool EnableNullPageProtection();

			bool EnableDebugPrivileges();

		private:
			std::vector <DWORD> m_vBlockedProcessIds;
	};
};

