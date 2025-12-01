#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <atomic>

#undef OPTIONAL

namespace NoMercy
{		
	enum EBootkitReturnValues
	{
		BOOTKIT_NONE,
		BOOTKIT_LIB_UNKNOWN_APP_PATH,
		BOOTKIT_LIB_UNKNOWN_LOAD_OPTS,
		BOOTKIT_LIB_UNKNOWN_CI_POLICY,
		BOOTKIT_LIB_UNKNOWN_APP_DEV,
		BOOTKIT_LIB_UNKNOWN_APP_DEV_PATH,
		BOOTKIT_LIB_DEBUGGER_ENABLED,
		BOOTKIT_LIB_DISABLED_INTEGRITY_CHECKS,
		BOOTKIT_LIB_ALLOWED_FLIGHT_SIGNATURES,
		BOOTKIT_LIB_ALLOWED_PRERELEASE_SIGNATURES,
		BOOTKIT_OSL_NX_ALWAYS_OFF,
		BOOTKIT_OSL_KERNEL_DEBUGGER_ENABLED,
		BOOTKIT_OSL_DISABLED_CODE_INTEGRITY_CHECKS,
		BOOTKIT_OSL_ALLOWED_PRERELEASE_SIGNATURES,
		BOOTKIT_OSL_HYPERVISOR_DEBUGGER_ENABLED,
		BOOTKIT_OSL_SYSTEM_ROOT_NOT_WINDOWS,
		BOOTKIT_OSL_UEFI_BOOT_DEVICE,
		BOOTKIT_UNKNOWN_BOOT_ENTRY,
		BOOTKIT_BOOT_SECTOR_INTEGRITY_CORRUPTED,
		BOOTKIT_MBR_SIGN_INTEGRITY_CORRUPTED,
		BOOTKIT_MBR_INTEGRITY_CORRUPTED,
		BOOTKIT_NVRAM_INTEGRITY_CORRUPTED,
		BOOTKIT_SYS_FILE_INTEGRITY_CORRUPTED,
		BOOTKIT_OSL_WINPE_MODE,
	};

	class CAntiDebug
	{
		enum class EFlags : uint8_t
		{
			NONE,
			DISABLED,
			OPTIONAL,
			TEST
		};
		
	public:
		static bool SeDebugPrivTriggered();

		static bool InitAntiDebug(LPDWORD pdwErrorStep);
		static bool InitAntiKernelDebug(LPDWORD pdwErrorStep);
		static bool IsHypervisorPresent(LPDWORD pdwDetectType);
		static bool LowLevelHypervisorChecksPassed(LPDWORD pdwReturnCode);
		static bool CheckRuntimeAntiDebug(LPDWORD pdwDetectType);
		static bool CheckPreAntiDebug();
		static bool ParentCheck(const std::wstring& c_stPatcherName, const std::wstring& c_stPatcherHash);
		static bool IsImageSumCorrupted(LPVOID pvBaseImage, uint64_t unCorrectSum);
		static bool CheckStartupTime();

		static bool AntiVirtualize(LPDWORD pdwReturnCode);
		static bool AntiBootkit(LPDWORD pdwDetectType);
	};
};
