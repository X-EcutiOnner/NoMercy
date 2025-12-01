#pragma once

namespace NoMercy
{
	struct SPageEntry
	{
		LPVOID BaseAddress{ nullptr };
		SIZE_T RegionSize{ 0 };
		DWORD Protection{ 0 };
	};
	struct SHookEntry
	{
		bool bActive{ false };
		LPVOID pTarget{ nullptr };
		LPVOID pDetour{ nullptr };
	};

	class CPageGuardHook : std::enable_shared_from_this <CPageGuardHook>
	{
	public:
		CPageGuardHook();
		virtual ~CPageGuardHook();

		bool Initialize();
		bool Uninitialize();

		bool CreateHook(LPVOID pTarget, LPVOID pDetour);
		bool EnableHook(LPVOID pTarget);
		bool DisableHook(LPVOID pTarget);
		void RefreshHook(LPVOID pTarget);

		bool EnableALLHooks(bool bEnable);
		void RefreshALLHooks();

		LPVOID HandlePageGuard(LPVOID pAddress);

		void CreateTestHook();

	protected:
		bool EnableHookEx(LPVOID pTarget, bool bEnable);
		bool EnableHookEx(UINT pos, bool enable);

		void RefreshHookEx(UINT pos);

		bool GuardEntry(SHookEntry* pEntry);
		bool IsPageGuarded(LPVOID pTarget);

		bool ProtectPage(PVOID address, DWORD protection, PDWORD oldProtect);
		bool GetPageProtection(LPVOID pTarget, PDWORD pProtection);
		bool QueryPage(LPVOID pTarget, SPageEntry* pEntry);

		SHookEntry* AddHookEntry();
		UINT FindHookEntry(LPVOID pTarget);

	private:
		HANDLE m_hHeap;
		HANDLE m_hExceptionHandler;
	};
};
