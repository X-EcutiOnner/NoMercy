#include <memory>
#include <filesystem>
#include <xorstr.hpp>
#include <lazy_importer.hpp>
#include <fmt/format.h>
#include <JunkMacros.h>
#include "../include/Index.h"
#include "../include/tls_callback.h"
#include "../../../Common/StdExtended.hpp"
#include "../../../Common/SimpleTimer.hpp"
#include "../../../Core/EngineR3_Core/include/ErrorIDs.hpp"
#include "../../../Core/EngineR3_Core/include/ExitHelper.hpp"
#include "../../../Core/EngineR3_Core/include/Defines.hpp"
#include "../../../Core/EngineR3/Index.hpp"
#include "../../../Core/EngineTLS/include/Index.hpp"

// #define USE_APC_BASED_INIT

// Additional linker options
#pragma comment(linker, "/ALIGN:0x10000")

// Global variables
static const auto gsc_stModuleVersion = std::to_string(__NOMERCY_VERSION__);

volatile bool g_vbTlsRan = false;

static auto gs_hModule = static_cast<HMODULE>(nullptr);
static auto gs_pModuleData = static_cast<LDR_DATA_TABLE_ENTRY*>(nullptr);

// Helper functions
inline LDR_DATA_TABLE_ENTRY* __CreateInfoData(HMODULE hModule)
{
#ifdef _M_X64
	auto pPEB = (PPEB)__readgsqword(0x60);
#elif _M_IX86
	auto pPEB = (PPEB)__readfsdword(0x30);
#else
#error "architecture unsupported"
#endif

	auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	auto Current = PLDR_DATA_TABLE_ENTRY{ nullptr };
	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (static_cast<PVOID>(hModule) == Current->DllBase)
		{
			return Current;
		}
		CurrentEntry = CurrentEntry->Flink;
	}
	return Current;
}

#ifdef USE_APC_BASED_INIT
VOID __ApcCallback(PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
{
	NoMercy::CNoMercyIndex::InitCore((uint8_t)ApcArgument1, ApcArgument2, ApcArgument3);
}
#endif

// Exported functions
#pragma optimize("", off) // flow in or out of inline asm code suppresses global optimization
bool NM_Initialize(const uint32_t c_u32GameCode, const uint8_t c_u8NmVersion, const NoMercy::TNMCallback c_kMessageHandler)
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_1
#endif

#ifdef USE_APC_BASED_INIT
	// Fire initialization with APC for save time
	auto ntStatus = NtQueueApcThread(NtCurrentThread(), __ApcCallback, (PVOID)c_u8NgVersion, (PVOID)c_kMessageHandler, (PVOID)gs_pModuleData);
	if (!NT_SUCCESS(ntStatus))
	{
		NoMercyCore::OnPreFail(0, CORE_ERROR_APC_INIT_FAIL, ntStatus);
		return false;
	}

	// Send alert to the thread for trigger APC
	ntStatus = NtAlertThread(NtCurrentThread());
	if (!NT_SUCCESS(ntStatus))
	{
		NoMercyCore::OnPreFail(0, CORE_ERROR_APC_TRIGGER_FAIL, ntStatus);
		return false;
	}
#else
	return NoMercy::CNoMercyIndex::InitCore(c_u8NmVersion, c_kMessageHandler, gs_pModuleData);
#endif

	return true;
}

bool NM_Finalize()
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_2
#endif

	return NoMercy::CNoMercyIndex::Release();
}

bool NM_ForwardMessage(const int32_t c_s32Code, const void* c_lpMessage)
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_1
#endif

	return NoMercy::CNoMercyIndex::SendNMMessage(c_s32Code, c_lpMessage);
}

uint32_t NM_GetVersionNumber() 
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_1
#endif

	return std::atol(gsc_stModuleVersion.c_str());
}


// TLS processor function
void NTAPI __TlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_1
#endif

	if (!g_vbTlsRan)
	{
		g_vbTlsRan = true;

		NoMercyTLS::CTLSIndex::TlsRedirector(hModule, dwReason, pContext);
	}
}

// Static entrypoint processor functions
static BOOL __OnProcessAttach(HMODULE hModule)
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_2
#endif

	// Is already attached module?
	if (gs_hModule)
	{
		NoMercyCore::OnPreFail(0, CORE_ERROR_ALREADY_ATTACHED_MODULE);
		return FALSE;
	}
	gs_hModule = hModule;

	// Does module exist in list?
	gs_pModuleData = __CreateInfoData(gs_hModule);
	if (!gs_pModuleData)
	{
		NoMercyCore::OnPreFail(0, CORE_ERROR_MODULE_DETAIL_QUERY_FAIL);
		return FALSE;
	}

	return NoMercy::CNoMercyIndex::Enter();
}

static BOOL __OnProcessDetach()
{
#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_2
#endif

	NoMercy::CNoMercyIndex::Exit();
	return TRUE;
}

static BOOL __OnThreadAttach(DWORD dwThreadId)
{
	NoMercy::CNoMercyIndex::OnThreadAttach(dwThreadId);
	return TRUE;
}

// Entrypoint function
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID)
{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	// Print debug data
	char szModule[MAX_PATH]{ '\0' };
	GetModuleFileNameA(hModule, szModule, MAX_PATH);

	char szExecutable[MAX_PATH]{ '\0' };
	GetModuleFileNameA(nullptr, szExecutable, MAX_PATH);

	const auto stLogBuffer = fmt::format("DLL({0}) Entrypoint call: '{1}' for Module: '{2}' Executable: '{3}'", fmt::ptr(hModule), dwReason, szModule, szExecutable);
	OutputDebugStringA(stLogBuffer.c_str());
#endif

#ifdef ENABLE_JUNK_MACROS
	KARMA_MACRO_1
#endif

	BOOL bDLLMainRet = TRUE;
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			bDLLMainRet = __OnProcessAttach(hModule);
		} break;
		case DLL_PROCESS_DETACH:
		{
			bDLLMainRet = __OnProcessDetach();
		} break;
		case DLL_THREAD_ATTACH:
		{
			bDLLMainRet = __OnThreadAttach(HandleToUlong(NtCurrentThreadId()));
		} break;
		default:
			break;
	}
	
	return bDLLMainRet;
}

#pragma optimize("", on)
