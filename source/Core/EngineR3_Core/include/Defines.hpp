#pragma once
#include "BasicLog.hpp"
#include "LogHelper.hpp"
#include "../../../Common/StdExtended.hpp"
#include <xorstr.hpp>
#include <fmt/format.h>
#include <ProtectionMacros.h>

#define ENABLE_JUNK_MACROS
//#define ENABLE_SCAN_ENVIRONMENT

#define MAX_SCREENSHOT_COUNT 3 // 1

#define CRASHPAD_NAME			fmt::format(xorstr_(L"NoMercy\\NoMercy_Crash_Handler_x{0}.exe"), NM_PLATFORM)
#define CLIENT_MUTEX			xorstr_(L"Global\\{G3ATBC35-7348-450a-GDCL-CVL5XBE14X3D}")
#define API_SERVER_URI			xorstr_(L"api-beta.nomercy.ac")
// #define API_SERVER_URI			xorstr_(L"localhost")
#define ERROR_POST_URL			xorstr_(L"https://api-beta.nomercy.ac/v1/error_report")
#define SENTRY_DSN				xorstr_(L"https://2791fac55c7d0024bbf0b31ecb033eeb@o920931.ingest.sentry.io/4505895396179968")
//#define SENTRY_DSN				xorstr_(L"https://2791fac55c7d0024bbf0b31ecb033eeb@sentry.nomercy.ac/4505895396179968")
#define DEFAULT_I18N_FILENAME	xorstr_(L"en.json")
#define GAME_DATA_FILENAME		xorstr_(L"NoMercy\\NoMercy_Game.dat")
#define FILE_DB_FILENAME		xorstr_(L"NoMercy\\NoMercy_Game.fdb")
#define HB_PUB_KEY_FILENAME		xorstr_(L"NoMercy\\NoMercy_Game.key")
#define CHEAT_DB_FILENAME		xorstr_(L"NoMercy\\NoMercy.cdb")
#define SCAN_CACHE_FILENAME		xorstr_(L"NoMercy\\NoMercy.scdb")
#ifdef _RELEASE_DEBUG_MODE_
#define REST_CERT_FILENAME		xorstr_("F:\\Git\\.ac\\NoMercy\\NoMercyClient\\Bin_public\\.debug\\NoMercy\\NoMercy.crt")
#define REST_CERT_KEY_FILENAME	xorstr_("F:\\Git\\.ac\\NoMercy\\NoMercyClient\\Bin_public\\.debug\\NoMercy\\NoMercy.key")
#else
#define REST_CERT_FILENAME		xorstr_("NoMercy\\NoMercy.crt")
#define REST_CERT_KEY_FILENAME	xorstr_("NoMercy\\NoMercy.key")
#endif
#define KEEP_OLD_LOG_FILES		false

// using ptr_t = uint64_t;
using ptr_t = const void* __ptr64;

enum class EBarrier : uint8_t
{
	none,
	wow_32_32,  // Both processes are WoW64 
	wow_64_64,  // Both processes are x64
	wow_32_64,  // Managing x64 process from WoW64 process
	wow_64_32  // Managing WOW64 process from x64 process
};

enum ENoMercyCoreStage : uint8_t
{
	STATE_DEV	= 0x01,
	STATE_BETA	= 0x02,
	STATE_RC	= 0x03,
	STATE_RTM	= 0x04
};

enum ELogLevels : uint8_t
{
	LL_SYS,
	LL_ERR,
	LL_CRI,
	LL_WARN,
	LL_DEV,
	LL_TRACE
};

enum ELogTypes : uint8_t
{
	LT_NONE,
	LT_RING3_CORE,
	LT_RING3,
	LT_LOADER,
	LT_MAX
};

enum ELogCategories : uint8_t
{
	LOG_GENERAL = 0x01,
	LOG_HOOK = 0x02,
	LOG_SCANNER = 0x03,
	LOG_SDK = 0x04,
	LOG_WMI = 0x05,
	LOG_NETWORK = 0x06,
	LOG_KERNEL = 0x07,
	LOG_PYTHON = 0x08,
};

enum class EPhase : uint8_t
{
	PHASE_PRE = 1,
	PHASE_INIT = 2,
	PHASE_POST = 3,
	PHASE_CHEAT = 4,
	PHASE_NETWORK = 5,
	PHASE_TELEMETRY = 99
};

enum EAppTypes : uint8_t
{
	NM_NONE,
	NM_CLIENT,
	NM_STANDALONE,
	NM_MAX
};

static inline void CheckAppIntegrity()
{
#ifndef _DEBUG
#if USE_THEMIDA_SDK == 1
#define CORRUPT_STACK while(NtCurrentTeb()->NtTib.StackBase > NtCurrentTeb()->NtTib.StackLimit) \
    { \
        NtCurrentTeb()->NtTib.StackBase = (PVOID)((DWORD_PTR)NtCurrentTeb()->NtTib.StackBase - 4); \
        NtCurrentTeb()->NtTib.StackBase = nullptr; \
    }

	VM_TIGER_BLACK_START;

	bool bClean{};
	int dwDummy = 0;
	CHECK_CODE_INTEGRITY(dwDummy, 0xB9C0173E);

	if (dwDummy != 0xB9C0173E)
	{
		CORRUPT_STACK;
	}

	bClean = true;

	VM_TIGER_BLACK_END;

	// then at the end of the function, they do this to prevent you from just skipping after bClean is set to true
	VM_TIGER_BLACK_START;

	if (!bClean)
	{
		CORRUPT_STACK;
	}

	VM_TIGER_BLACK_END;
#endif
#endif
}

static std::wstring GetLogTypeName(uint8_t nLogType)
{
	static std::map <uint8_t, std::wstring> s_mLogTypes =
	{
		{ LT_RING3_CORE,	xorstr_(L"NM_C_RING3_CORE")	},
		{ LT_RING3,			xorstr_(L"NM_C_RING3")		},
		{ LT_LOADER,		xorstr_(L"NM_C_LOADER")		},
	};

	if (nLogType <= LT_NONE || nLogType >= LT_MAX)
		return L"";

	auto it = s_mLogTypes.find(nLogType);
	if (it == s_mLogTypes.end())
		return xorstr_(L"UNKNOWN_LOG:") + nLogType;

	return it->second;
}

static std::wstring GetAppTypeNameW(uint8_t nAppType)
{
	static std::map <uint8_t, std::wstring> s_mAppTypes =
	{
		{ NM_CLIENT,		xorstr_(L"NM_CLIENT")		},
		{ NM_STANDALONE,	xorstr_(L"NM_STANDALONE")	},
	};

	if (nAppType <= NM_NONE || nAppType >= NM_MAX)
		return L"";

	auto it = s_mAppTypes.find(nAppType);
	if (it == s_mAppTypes.end())
		return xorstr_(L"Undefined app type: ") + nAppType;

	return it->second;
}
static std::string GetAppTypeNameA(uint8_t bAppType)
{
	return stdext::to_ansi(GetAppTypeNameW(bAppType));
}

#ifdef _DEBUG
	#define __EXPERIMENTAL__
#endif

#ifndef APP_TRACE_LOG
	#define APP_TRACE_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr()) {\
			NoMercyCore::CLogHelper::Instance().Log(LOG_GENERAL, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);\
		} else {\
			NoMercyCore::LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(log), __VA_ARGS__);\
		}
#endif

#ifndef HOOK_LOG
	#define HOOK_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_HOOK, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef SCANNER_LOG
	#define SCANNER_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_SCANNER, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef SDK_LOG
	#define SDK_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_SDK, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef WMI_LOG
	#define WMI_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_WMI, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef NET_LOG
#define NET_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_NETWORK, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef KERNEL_LOG
#define KERNEL_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_KERNEL, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif
#ifndef PYTHON_LOG
#define PYTHON_LOG(level, log, ...)\
		if (NoMercyCore::CLogHelper::InstancePtr())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_PYTHON, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef TLS_LOG
	#define TLS_LOG(log, ...)\
		NoMercyTLS::TLS_Logf(xorstr_(__FUNCTION__), xorstr_(log), __VA_ARGS__);
#endif

#ifndef ADMIN_DEBUG_LOG
	#define ADMIN_DEBUG_LOG(level, log, ...)\
		if (NoMercyCore::CApplication::InstancePtr() && NoMercyCore::CLogHelper::InstancePtr() &&\
			IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().DataInstance()) &&\
			NoMercyCore::CApplication::Instance().DataInstance()->IsAdminEnvironment())\
			NoMercyCore::CLogHelper::Instance().Log(LOG_GENERAL, xorstr_(__FUNCTION__), level, xorstr_(log), __VA_ARGS__);
#endif

#ifndef DEBUG_POSTFIX
	#ifdef _DEBUG
		#define DEBUG_POSTFIX L"_d"
	#else
		#define DEBUG_POSTFIX L""
	#endif
#endif

#ifndef IS_X64_APP
	#if (NM_PLATFORM == 86)
		#define IS_X64_APP FALSE
	#else
		#define IS_X64_APP TRUE
	#endif
#endif

#ifdef or
	#undef or
#endif

#ifdef and
	#undef and
#endif

#ifdef xor
	#undef xor
#endif

#undef GetModuleHandle
#undef HeapEnableTerminationOnCorruption

#define PROCESS_ALL_ACCESS_XP (SYNCHRONIZE | 0xFFF)

#define NM_CREATEMAGIC(b0, b1, b2, b3) \
	(uint32_t(uint8_t(b0)) | (uint32_t(uint8_t(b1)) << 8) | \
	(uint32_t(uint8_t(b2)) << 16) | (uint32_t(uint8_t(b3)) << 24))

#define DEBUG_LOG_FILENAME				xorstr_(L"Log\\AppTrace_{}_{}_{}.log")
#define CUSTOM_LOG_FILENAME_A			xorstr_("NoMercy.log")
#define CUSTOM_LOG_FILENAME_W			xorstr_(L"NoMercy.log")
#define CUSTOM_TLS_LOG_FILENAME			xorstr_("NoMercyTLS.log")

#define IS_VALID_HANDLE(handle)		(handle && handle != INVALID_HANDLE_VALUE)
#define IS_VALID_SMART_PTR(ptr)		(ptr && ptr.get())

#ifndef GWL_WNDPROC
	#define GWL_WNDPROC         (-4)
#endif

#ifndef GetAbsolutePtr
	#define GetAbsolutePtr(pBase, dwOffset) (*(PVOID*)((PBYTE)pBase + (dwOffset)))
#endif
#ifndef Relative2Absolute
	#define Relative2Absolute(pBase, dwOffset, dwLength) (PVOID)((SIZE_T)pBase + (*(PLONG)((PBYTE)pBase + dwOffset)) + dwLength)
#endif

#ifndef CERT_SECTION_TYPE_ANY
	#define CERT_SECTION_TYPE_ANY                   0xFF      // Any Certificate type
#endif

#ifndef IS_SET
	#define IS_SET(flag, bit)                ((flag) & (bit))
#endif

#ifndef SET_BIT
	#define SET_BIT(var, bit)                ((var) |= (bit))
#endif

#ifndef REMOVE_BIT
	#define REMOVE_BIT(var, bit)             ((var) &= ~(bit))
#endif

#ifndef TOGGLE_BIT
	#define TOGGLE_BIT(var, bit)             ((var) = (var) ^ (bit))
#endif

#ifndef STATUS_SERVICE_NOTIFICATION
	#define STATUS_SERVICE_NOTIFICATION		0x40000018
#endif

#ifndef ENUM_PROCESS_MODULES_LIMIT
	#define ENUM_PROCESS_MODULES_LIMIT 0x800
#endif

#ifndef THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE
	#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040
#endif

#ifndef FILE_SHARE_VALID_FLAGS
	#define FILE_SHARE_VALID_FLAGS 0x00000007
#endif

#ifndef NT_GLOBAL_FLAG_DEBUGGED
	#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#endif

#ifndef PROCESS_CALLBACK_FILTER_ENABLED
	#define PROCESS_CALLBACK_FILTER_ENABLED 0x1
#endif

#ifndef MakePtr
	#define MakePtr(Type, Base, Offset) ((Type)(DWORD_PTR(Base) + (DWORD_PTR)(Offset)))
#endif

#ifndef padding
	#define padding(x) struct { unsigned char __padding##x[(x)]; };
#endif

#ifndef padding_add
	#define padding_add(x, y) struct { unsigned char __padding##x[(x) + (y)]; };
#endif

#ifndef padding_sub
	#define padding_sub(x, y) struct { unsigned char __padding##x[(x) - (y)]; };
#endif

#ifndef static_assert_size
	#define static_assert_size(actual, expected) \
		static_assert((actual) == (expected), "Size assertion failed: " #actual " != " #expected ".");
#endif

#ifndef static_assert_offset
	#define static_assert_offset(type, member, expected) \
		static_assert(offsetof((type), (member)) == (expected), "Offset assertion failed: " offsetof((type), (member)) " != " #expected ".");
#endif

#define ALIGN_UP_BY(Address, Align)   (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#define ALIGN_UP_POINTER_BY(Pointer, Align)   ((PVOID)ALIGN_UP_BY(Pointer, Align))
#define ALIGN_UP(Address, Type)   ALIGN_UP_BY(Address, sizeof(Type))

#define PTR_ADD_OFFSET(Pointer, Offset)   ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

#define PH_FIRST_OBJECT_TYPE(ObjectTypes) \
	PTR_ADD_OFFSET(ObjectTypes, ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR))

#define PH_NEXT_OBJECT_TYPE(ObjectType) \
	PTR_ADD_OFFSET(ObjectType, sizeof(OBJECT_TYPE_INFORMATION) + \
	ALIGN_UP(ObjectType->TypeName.MaximumLength, ULONG_PTR))

#define VM_LOCK_1                0x0001   // This is used, when calling KERNEL32.DLL VirtualLock routine
#define VM_LOCK_2                0x0002   // This require SE_LOCK_MEMORY_NAME privilege
