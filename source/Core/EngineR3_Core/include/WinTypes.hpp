#pragma once
#include <WinSock2.h>
#include <IPTypes.h>
#include <phnt_windows.h>
#include <phnt.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <ProcessSnapshot.h>
#include <WinInet.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <WinTrust.h>
#include <mscat.h>
#include <Softpub.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <combaseapi.h>
#include <WinSock2.h>
#include <winsta.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <sddl.h>
#include <timeapi.h>
#include <WinDNS.h>
#include <Shlwapi.h>
#include <LM.h>
#include <nb30.h>
#include <mscoree.h>
#include <strsafe.h>
#include <CommCtrl.h>
#include <winevt.h>
#include <WtsApi32.h>
#include <wincodecsdk.h>
#include <SetupAPI.h>
#include <Snmp.h>
#include <srrestoreptapi.h>
#include <DbgHelp.h>
#include <rtcapi.h>
#include <tdh.h>
#include <fltUser.h>
#include <tbs.h>
#include <WS2tcpip.h>
#include <slpublic.h>
#include <Msi.h>
#include <ShlGuid.h>
#include <powerbase.h>
#include <cfgmgr32.h>
#include <d3d11.h>
#include <dbt.h>
#include <Uxtheme.h>
#include <dwmapi.h>
#include <userenv.h>

using std::min;
using std::max;

#pragma warning(push) 
#pragma warning(disable: 4458)
#include <GdiPlus.h>
#pragma warning(pop) 

using namespace Gdiplus;

namespace NoMercyCore::WinAPI
{
	typedef DWORD LFTYPE;

	typedef enum HardErrorResponseButton {
		ResponseButtonOK,
		ResponseButtonOKCancel,
		ResponseButtonAbortRetryIgnore,
		ResponseButtonYesNoCancel,
		ResponseButtonYesNo,
		ResponseButtonRetryCancel,
		ResponseButtonCancelTryAgainContinue
	} HardErrorResponseButton;

	enum EPDITypes
	{
		PDI_MODULES = 0x01,
		PDI_BACKTRACE = 0x02,
		PDI_HEAPS = 0x04,
		PDI_HEAP_TAGS = 0x08,
		PDI_HEAP_BLOCKS = 0x10,
		PDI_LOCKS = 0x20
	};

	enum ETimeSyncFlags
	{
		TimeSyncFlag_SoftResync = 0x00,
		TimeSyncFlag_HardResync = 0x01,
		TimeSyncFlag_ReturnResult = 0x02,
		TimeSyncFlag_Rediscover = 0x04,
		TimeSyncFlag_UpdateAndResync = 0x08
	};

#ifndef _M_X64
	typedef struct _RUNTIME_FUNCTION
	{
		ULONG BeginAddress;
		ULONG EndAddress;
		ULONG UnwindData;
	} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;
#endif
	typedef HANDLE EVT_HANDLE, *PEVT_HANDLE;

	typedef struct _DNS_CACHE_ENTRY
	{
		struct _DNS_CACHE_ENTRY* Next;  // Pointer to next entry
		PCWSTR Name;                    // DNS Record Name
		USHORT Type;                    // DNS Record Type
		USHORT DataLength;              // Not referenced
		ULONG Flags;                    // DNS Record Flags
	} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

	typedef struct _MEMORY_SECTION_NAME
	{
		UNICODE_STRING	SectionFileName;
	} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

	typedef struct _LARGE_STRING
	{
		ULONG Length;
		ULONG MaximumLength : 31;
		ULONG bAnsi : 1;
		PVOID Buffer;
	} LARGE_STRING, *PLARGE_STRING;

	typedef struct _DEBUG_HEAP_INFORMATION
	{
		ULONG Base;			// 0x00
		ULONG Flags;		// 0x04
		USHORT Granularity; // 0x08
		USHORT Unknown;		// 0x0A
		ULONG Allocated;	// 0x0C
		ULONG Committed;	// 0x10
		ULONG TagCount;		// 0x14
		ULONG BlockCount;	// 0x18
		ULONG Reserved[7];	// 0x1C
		PVOID Tags;			// 0x38
		PVOID Blocks;		// 0x3C Heap block pointer for this node.
	} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

	typedef struct _ASTAT_
	{
		ADAPTER_STATUS adapt;
		NAME_BUFFER NameBuff[30];
	} ASTAT, *PASTAT;

	typedef enum _WINDOWCOMPOSITIONATTRIB
	{
		WCA_UNDEFINED = 0,
		WCA_NCRENDERING_ENABLED = 1,
		WCA_NCRENDERING_POLICY = 2,
		WCA_TRANSITIONS_FORCEDISABLED = 3,
		WCA_ALLOW_NCPAINT = 4,
		WCA_CAPTION_BUTTON_BOUNDS = 5,
		WCA_NONCLIENT_RTL_LAYOUT = 6,
		WCA_FORCE_ICONIC_REPRESENTATION = 7,
		WCA_EXTENDED_FRAME_BOUNDS = 8,
		WCA_HAS_ICONIC_BITMAP = 9,
		WCA_THEME_ATTRIBUTES = 10,
		WCA_NCRENDERING_EXILED = 11,
		WCA_NCADORNMENTINFO = 12,
		WCA_EXCLUDED_FROM_LIVEPREVIEW = 13,
		WCA_VIDEO_OVERLAY_ACTIVE = 14,
		WCA_FORCE_ACTIVEWINDOW_APPEARANCE = 15,
		WCA_DISALLOW_PEEK = 16,
		WCA_CLOAK = 17,
		WCA_CLOAKED = 18,
		WCA_ACCENT_POLICY = 19,
		WCA_FREEZE_REPRESENTATION = 20,
		WCA_EVER_UNCLOAKED = 21,
		WCA_VISUAL_OWNER = 22,
		WCA_HOLOGRAPHIC = 23,
		WCA_EXCLUDED_FROM_DDA = 24,
		WCA_PASSIVEUPDATEMODE = 25,
		WCA_USEDARKMODECOLORS = 26,
		WCA_CORNER_STYLE = 27,
		WCA_PART_COLOR = 28,
		WCA_DISABLE_MOVESIZE_FEEDBACK = 29,
		WCA_LAST = 30
	} WINDOWCOMPOSITIONATTRIB;

	typedef struct _WINDOWCOMPOSITIONATTRIBDATA
	{
		WINDOWCOMPOSITIONATTRIB Attrib;
		PVOID pvData;
		SIZE_T cbData;
	} WINDOWCOMPOSITIONATTRIBDATA;

	typedef enum _ACCENT_STATE
	{
		ACCENT_DISABLED = 0,
		ACCENT_ENABLE_GRADIENT = 1,
		ACCENT_ENABLE_TRANSPARENTGRADIENT = 2,
		ACCENT_ENABLE_BLURBEHIND = 3,
		ACCENT_ENABLE_ACRYLICBLURBEHIND = 4, // RS4 1803
		ACCENT_ENABLE_HOSTBACKDROP = 5, // RS5 1809
		ACCENT_INVALID_STATE = 6
	} ACCENT_STATE;

	typedef enum _SYSTEM_ENVIRONMENT_INFORMATION_CLASS
	{
		SystemEnvironmentUnknownInformation,
		SystemEnvironmentNameInformation, // q: VARIABLE_NAME
		SystemEnvironmentValueInformation, // q: VARIABLE_NAME_AND_VALUE
		MaxSystemEnvironmentInfoClass
	} SYSTEM_ENVIRONMENT_INFORMATION_CLASS;

	typedef struct _ACCENT_POLICY
	{
		ACCENT_STATE AccentState;
		DWORD AccentFlags;
		DWORD GradientColor;
		DWORD AnimationId;
	} ACCENT_POLICY;

	typedef struct _MIB_IPNET_ROW2 {
		//
		// Key Struture.
		//
		SOCKADDR_INET Address;
		NET_IFINDEX InterfaceIndex;
		NET_LUID InterfaceLuid;

		//
		// Read-Write.
		//
		UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];

		//
		// Read-Only.
		//
		ULONG PhysicalAddressLength;
		NL_NEIGHBOR_STATE State;

		union {
			struct {
				BOOLEAN IsRouter : 1;
				BOOLEAN IsUnreachable : 1;
			};
			UCHAR Flags;
		};

		union {
			ULONG LastReachable;
			ULONG LastUnreachable;
		} ReachabilityTime;
	} MIB_IPNET_ROW2, * PMIB_IPNET_ROW2;

	typedef struct _MIB_IPNET_TABLE2 {
		ULONG NumEntries;
		MIB_IPNET_ROW2 Table[ANY_SIZE];
	} MIB_IPNET_TABLE2, * PMIB_IPNET_TABLE2;

#pragma pack(push, 1)
	typedef struct _SL_CACHE_VALUE_DESCRIPTOR {
		USHORT Size;
		USHORT NameLength;
		USHORT Type;
		USHORT DataLength;
		ULONG Attributes;
		ULONG Reserved;
		WCHAR Name[ANYSIZE_ARRAY];
	} SL_CACHE_VALUE_DESCRIPTOR, * PSL_CACHE_VALUE_DESCRIPTOR;
	typedef SL_CACHE_VALUE_DESCRIPTOR SL_KMEM_CACHE_VALUE_DESCRIPTOR;
#pragma pack(pop)

	typedef struct _SL_CACHE {
		ULONG TotalSize;
		ULONG SizeOfData;
		ULONG SignatureSize;
		ULONG Flags;
		ULONG Version;
		SL_KMEM_CACHE_VALUE_DESCRIPTOR Descriptors[ANYSIZE_ARRAY];
	} SL_CACHE, * PSL_CACHE;
	typedef SL_CACHE SL_KMEM_CACHE;

	typedef struct _RTL_UNLOAD_EVENT_TRACE
	{
		PVOID BaseAddress; // Base address of dll
		SIZE_T SizeOfImage; // Size of image
		ULONG Sequence; // Sequence number for this event
		ULONG TimeDateStamp; // Time and date of image
		ULONG CheckSum; // Image checksum
		WCHAR ImageName[32]; // Image name
	} RTL_UNLOAD_EVENT_TRACE, * PRTL_UNLOAD_EVENT_TRACE;
	
	typedef struct _EXT_PARAMS
	{
		DWORD64 Type; // enum 1-5
		PVOID Addr;
	} EXT_PARAMS, * PEXT_PARAMS;

	// ------------------

	typedef BOOL(WINAPI* TDLLMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
	typedef int(WINAPI* TMessageBoxTimeout)(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);
	typedef int(WINAPI* TMessageBoxTimeoutW)(IN HWND hWnd, IN LPCWSTR lpText, IN LPCWSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);
	typedef NTSTATUS(NTAPI* TNtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG CreateFlags, ULONG_PTR StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve,
		LPVOID AttributeList
	);
	typedef BOOL(WINAPI* TEndTask)(HWND hWnd, BOOL fShutDown, BOOL fForce);
	typedef DWORD(NTAPI* TCsrGetProcessId)();
	typedef NTSTATUS(NTAPI* TNtGetNextThread)(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
	typedef NTSTATUS(NTAPI* TNtGetNextProcess)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
	typedef NTSTATUS(NTAPI* TRtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath,
		PUNICODE_STRING CurrentDirectory, UNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo,
		PUNICODE_STRING RuntimeData, ULONG Flags);
	typedef NTSTATUS(NTAPI* TNtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 Size, PULONG64 NumberOfBytesRead);
	typedef NTSTATUS(NTAPI* TNtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength,
		PULONG ReturnLength);
	typedef NTSTATUS(NTAPI* TNtWow64WriteVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PULONG64 ReturnLength);
	typedef BOOL(WINAPI* TCreateEnvironmentBlock)(LPVOID* lpEnvironment, HANDLE hToken, BOOL bInherit);
	typedef BOOL(WINAPI* TDestroyEnvironmentBlock)(LPVOID lpEnvironment);
	typedef NTSTATUS(NTAPI* TLdrGetProcedureAddressForCaller)(_In_ PVOID DllHandle, _In_opt_ PANSI_STRING ProcedureName, _In_opt_ ULONG ProcedureNumber,
		_Out_ PVOID* ProcedureAddress, _In_ ULONG Flags, _In_ PVOID* Callback
	);
	typedef DNS_STATUS(WINAPI* TDnsGetCacheDataTable)(_Inout_ PDNS_CACHE_ENTRY* DnsCacheEntry);
	typedef BOOL(WINAPI* TClientThreadSetup)(VOID);
	typedef VOID(NTAPI* TLdrInitializeThunk)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
	typedef VOID(NTAPI* TKiUserApcDispatcher)(PVOID Unused1, PVOID Unused2, PVOID Unused3, PVOID ContextStart, PVOID ContextBody);
	typedef VOID(NTAPI* TKiUserCallbackDispatcher)(ULONG Index, PVOID Argument, ULONG ArgumentLength);
	typedef SHORT(NTAPI* TNtUserGetAsyncKeyState)(INT Key);
	typedef LONG(NTAPI* TNtUserSetWindowLong)(HWND hWnd, DWORD Index, LONG NewValue, BOOL Ansi);
	typedef LONG_PTR(NTAPI* TNtUserSetWindowLongPtr)(HWND hWnd, DWORD Index, LONG_PTR NewValue, BOOL Ansi);
	typedef UINT_PTR(NTAPI* TNtUserSetTimer)(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc);
	typedef HWND(NTAPI* TNtUserCreateWindowEx)(DWORD dwExStyle, PLARGE_STRING plstrClassName, PLARGE_STRING plstrClsVersion, PLARGE_STRING plstrWindowName,
		DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam, DWORD dwFlags, PVOID acbiBuffer
	);
	typedef HFONT(NTAPI* TNtGdiHfontCreate)(PENUMLOGFONTEXDVW pelfw, ULONG cjElfw, LFTYPE lft, FLONG fl, PVOID pvCliData);
	typedef VOID(__cdecl* TRtlRestoreContext)(PCONTEXT ContextRecord,struct _EXCEPTION_RECORD* ExceptionRecord);
	typedef PIMAGE_NT_HEADERS(WINAPI* TCheckSumMappedFile)(_In_ PVOID BaseAddress, _In_ DWORD FileLength, _Out_ PDWORD HeaderSum, _Out_ PDWORD CheckSum);
	typedef void(NTAPI* TLdrInitializeThunk)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
	typedef NTSTATUS(NTAPI* TLdrRegisterDllNotification)(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, PVOID Context, PVOID* Cookie);
	typedef NTSTATUS(NTAPI* TLdrUnregisterDllNotification)(PVOID Cookie);
	typedef BOOL(WINAPI* TSfcIsFileProtected)(HANDLE RpcHandle, LPCWSTR Path);
	typedef ULONG(NTAPI* TNtGetTickCount)();
	typedef BOOL(__stdcall* TImageEnumerateCertificates)(HANDLE FileHandle, WORD TypeFilter, PDWORD CertificateCount, PDWORD Indices, DWORD IndexCount);
	typedef BOOL(__stdcall* TImageGetCertificateHeader)(_In_ HANDLE FileHandle, _In_ DWORD CertificateIndex, _Inout_ LPWIN_CERTIFICATE Certificateheader);
	typedef BOOL(__stdcall* TImageGetCertificateData)(HANDLE FileHandle, DWORD CertificateIndex, LPWIN_CERTIFICATE Certificate, PDWORD RequiredLength);
	typedef BOOL(WINAPI* TSetProcessUserModeExceptionPolicy)(DWORD dwFlags);
	typedef BOOL(WINAPI* TGetProcessUserModeExceptionPolicy)(LPDWORD lpFlags);
	typedef BOOL(WINAPI* TGetWindowCompositionAttribute)(HWND, WINDOWCOMPOSITIONATTRIBDATA*);
	typedef BOOL(WINAPI* TSetWindowCompositionAttribute)(HWND, WINDOWCOMPOSITIONATTRIBDATA*);
	typedef VOID(WINAPI* TDnsRecordListFree)(PDNS_RECORD pRecordList, DNS_FREE_TYPE FreeType);
	typedef NTSTATUS(NTAPI* TGetIpNetTable2)(ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2* Table);
	typedef VOID(NTAPI* TFreeMibTable)(PVOID Memory);
	typedef BOOLEAN(NTAPI* TRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
	typedef NTSTATUS(NTAPI* TRtlDosApplyFileIsolationRedirection_Ustr)(ULONG Flags, PUNICODE_STRING OriginalName, PUNICODE_STRING Extension, PUNICODE_STRING StaticString,
		PUNICODE_STRING DynamicString, PUNICODE_STRING* NewName, PULONG NewFlags, PSIZE_T FileNameSize, PSIZE_T RequiredLength
	);
	typedef BOOL(WINAPI* TImmGetHotKey)(DWORD dwHotKeyID, LPUINT lpuModifiers, LPUINT lpuVKey, LPHKL lphKL);
	typedef int(WINAPI* TImmActivateLayout)(LPARAM pa);
	typedef VOID(WINAPI* TLoadAppInitDlls)();
	typedef NTSTATUS(NTAPI* TNtCreateWorkerFactory)(
		PHANDLE WorkerFactoryHandleReturn, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE CompletionPortHandle,
		HANDLE WorkerProcessHandle, PVOID StartRoutine, PVOID StartParameter, ULONG MaxThreadCount, SIZE_T StackReserve, SIZE_T StackCommit
	);
	typedef int(WINAPI* TRtlRetrieveNtUserPfn)(void** clientA, void** clientW, void** Unk);
	typedef ULONG_PTR(NTAPI* TNtUserSetClassLongPtr)(HWND hwnd, INT offset, LONG_PTR newval, BOOL ansi);
	typedef HHOOK(NTAPI* TNtUserSetWindowsHookEx)(HINSTANCE Mod, PUNICODE_STRING ModuleName, DWORD ThreadId, int HookId, HOOKPROC HookProc, BOOL Ansi);
	typedef VOID(WINAPI* TRtlGetUnloadEventTraceEx)(PULONG* ElementSize, PULONG* ElementCount, PVOID* EventTrace);
	typedef DWORD(WINAPI* TCheckElevation)(LPCWSTR lpApplicationName, LPDWORD pdwFlags, HANDLE hChildToken, LPDWORD pdwRunLevel, LPDWORD pdwReason);
	typedef int(WINAPI* TW32TimeSyncNow)(const wchar_t* pwszComputer, unsigned int blocking, unsigned int flags);
	typedef NTSTATUS(NTAPI* TNtAllocateVirtualMemoryEx)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection,
		PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount
	);
	typedef NTSTATUS(NTAPI* TNtMapViewOfSectionEx)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
		ULONG AllocationType, ULONG Win32Protect, PEXT_PARAMS ExtParameters, ULONG ExtParametersCount
	);
	typedef VOID(NTAPI* TKiUserCallbackDispatcher)(ULONG Index, PVOID Argument, ULONG ArgumentLength);
	typedef BOOL(WINAPI* TGUIDFromString)(LPCTSTR psz, LPGUID pguid);
	typedef NTSTATUS(NTAPI* TNtCreateProcessStateChange)(PHANDLE ProcessStateChangeHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ProcessHandle, INT Reserved
	);
	typedef NTSTATUS(NTAPI* TNtChangeProcessState)(HANDLE ProcessStateChangeHandle, HANDLE ProcessHandle, PROCESS_STATE_CHANGE_TYPE StateChangeType,
		PVOID ExtendedInformation, SIZE_T ExtendedInformationLength, INT Reserved
	);
	typedef NTSTATUS(NTAPI* TNtQueryWnfStateData)(PWNF_STATE_NAME StateName, PWNF_TYPE_ID TypeId, const VOID* ExplicitScope,
		PWNF_CHANGE_STAMP ChangeStamp, PVOID Buffer, PULONG BufferSize
	);
	typedef BOOLEAN(WINAPI* TSetSuspendState)(BOOLEAN bHibernate, BOOLEAN bForce, BOOLEAN bWakeupEventsDisabled);
	
#ifdef _M_X64
	typedef PRUNTIME_FUNCTION(NTAPI* TRtlLookupFunctionEntry)(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);
#endif
};
