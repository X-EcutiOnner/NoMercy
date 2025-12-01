#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include "ApcFilter.hpp"
#include "HotPatch.hpp"
#include "PageGuardHook.hpp"
#include "../../../Common/Locks.hpp"

namespace NoMercy
{
	enum EHookBlacklistedShellCodeTypes : uint32_t
	{
		ShellCodeNull,
		LdrLoadShellCode1,
		ManualMapShellCode1,
		ManualMapShellCode2,
		ManualMapShellCode3,
		ReflectiveShellCode1,
		ManualLoadShellCode1,
		ThreadHijackShellCode1,
		ThreadHijackShellCode2,
		ThreadHijackShellCode3,
		CreateRemoteThreadExShellCode1,
		CodeInjectionShellCode1,
		AutoInjectorLalakerShellCode,
		LalakerMetin2HackV110,
		SHELLCODEMAXITEM
	};

	enum EHookBlacklistedInjectionTypes : uint32_t
	{
		HookApiNull = 100,
		EaxLoadLibraryA,
		EaxLoadLibraryW,
		EaxLoadLibraryExA,
		EaxLoadLibraryExW,
		EaxLoadLibraryA_KBase,
		EaxLoadLibraryW_KBase,
		EaxLoadLibraryExA_KBase,
		EaxLoadLibraryExW_KBase,
		EaxFreeLibrary,
		EaxLdrLoadDll,
		EaxLdrUnloadDll,
		EaxSetWindowHookEx,
		EaxPython,
		EaxRtlUserThreadStart,
		EaxSetWindowHookEx2,
		EaxNtCreateThread,
		EaxNtCreateThreadEx,
		EaxRtlCreateUserThread,
		EaxCodeInjectionType,
		EaxUnknownState,
		EaxBadPointerType,
		EaxBadAllocatedProtectType,
		EaxBadProtectType,
		QueryWorkingSetExFail,
		QueryWorkingSetExNotValid,
		EaxMainProcess,
		EaxMappedCode,
		EaxMappedCode2,
		NullCharacteristics,
		HOOKBLACKLISTMAXITEM
	};

	enum EHookBlacklistedFailTypes : uint32_t
	{
		HOOK_CHECK_GETMODULEINFO_FAIL = 1000,
		HOOK_CHECK_GETMODULEINFO_PYTHON_FAIL,
		HOOK_CHECK_VIRTUALQUERY_FAIL,
		HOOK_CHECK_GETMAPPEDFILENAME_FAIL
	};

	enum EHookBlockTypes
	{
		RET_HOOK = 1,
		NOP_HOOK,
	};

	// ---------------

	struct SHookContext
	{
		std::wstring func{ L"" };
		PVOID target{ nullptr };
		PVOID detour{ nullptr };
		BYTE backup[5]{ 0 };
		PVOID original{ nullptr };

		SHookContext() {}
		SHookContext(std::wstring func_, PVOID target_, PVOID detour_)
		{
			func = func_;
			target = target_;
			detour = detour_;
		}
	};

	template <typename T>
	struct SHookInfo
	{
		T original;
		// CScopedLock lock;
		mutable std::recursive_mutex mtx;
	};

	struct SFilterData
	{
		PVOID ClientLoadLibrary;
		std::vector <PVOID> Callbacks;
		bool Initialized;
	};

	struct SPatchBackup
	{
		std::wstring FuncName;
		DWORD_PTR Address;
		PVOID Backup;
		DWORD BackupSize;
	};

	// --------------------------------

	class CSelfApiHooks : public std::enable_shared_from_this <CSelfApiHooks>
	{
	public:
		CSelfApiHooks();
		virtual ~CSelfApiHooks() = default;

	public:
		bool InitializeSelfAPIHooks();
		bool InitDllNotificationCallback();
		void InstallInstrumentationCallback(HANDLE hProcess);
		bool InitializeApfnFilter();
		bool InitializeSingleStepWatcher();
		
		auto IsInitializing() const { return m_bHooksIsInitializing; };
		bool IsInitialized();
		bool IsPatchedFunction(const std::wstring& stName);

		bool PatchFunction(const std::string& stName, DWORD_PTR lpFunc, uint8_t type);

		bool IsHookedAPI(const std::wstring& stFunction);
		auto GetHooks() const { return m_vHooks; };
		SHookContext GetHook(const std::wstring& stFunction);

		void CleanupHooks();
		void ReleaseSelfAPIHooks();
		void ReleaseDllNotificationCallback();
		void ReleasePatchs();
		void RemoveInstrumentationCallback(HANDLE hProcess);
		void RemoveSingleStepWatcher();

		bool IsHookIntegrityCorrupted();
		bool IsWinHookOrigin(PVOID FramePtr);

		bool SyscallHook(const std::string& name, const uint32_t id, void* dest, NoMercy::NtDirect*& ref_ptr);
		bool RemoveSyscallHook(const std::string& target);
		bool RemoveSyscallHooks();

		void CheckEPTHook();

		auto GetPageGuardHookHelper() { return m_spPageGuardHookHelper; };

	protected:
		bool __BlockAPI(const std::wstring& module, const std::string& func, uint8_t type);

		bool __InitializePatchs();
		bool __InitializeDetours();
		bool __SetInstrumentationCallbackHook(HANDLE ProcessHandle, BOOL Enable);

	private:
		std::vector <SHookContext>										m_vHooks;
		bool															m_bHooksIsInitializing;
		bool															m_bHooksIsInitialized;
		LPVOID															m_lpDllNotificationCookie;
		std::unique_ptr <CApcRoutinesStorage>							m_upApcStorages;
		std::vector <std::tuple <std::string, NtDirect*, HotPatch*>>	m_vecSyscallHookedFuncs;
		std::unique_ptr <SFilterData>									m_upFilterData;
		std::vector < std::shared_ptr <SPatchBackup>>					m_vecPatchs;
		LPVOID															m_pvSingleStepWatcher;
		std::shared_ptr <CPageGuardHook>								m_spPageGuardHookHelper;
	};
};
