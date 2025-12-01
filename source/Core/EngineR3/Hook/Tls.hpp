#pragma once

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

typedef struct _TEB_tls_only
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
	PVOID SystemReserved1[30];
#else
	PVOID SystemReserved1[26];
#endif
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderReserved[11];
	ULONG ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK ActivationStack;

	UCHAR WorkingOnBehalfTicket[8];
	NTSTATUS ExceptionCode;

	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	ULONG_PTR InstrumentationCallbackSp;
	ULONG_PTR InstrumentationCallbackPreviousPc;
	ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
	ULONG TxFsContext;
#endif
	BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
	UCHAR SpareBytes[23];
	ULONG TxFsContext;
#endif
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID PerflibData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		} s1;
	} u1;

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR ReservedForCodeCoverage;
	PVOID ThreadPoolData;
	PVOID* TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	USHORT HeapVirtualAffinity;
	USHORT LowFragHeapDataSlot;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	} u2;
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT LoadOwner : 1;
			USHORT LoaderWorker : 1;
			USHORT SkipLoaderInit : 1;
			USHORT SpareSameTebBits : 1;
		} s2;
	} u3;

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	LONG WowTebOffset;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
	ULONGLONG ReservedForCrt;
	GUID EffectiveContainerId;
} TEB_tls_only, *PTEB_tls_only;

// Hackplementation of thread local storage without using the CRT or LdrpAllocateTls

static constexpr ULONG_PTR TebAllocationSize = (sizeof(TEB_tls_only) + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1));

#ifdef _WIN64
// On x64 we can freely write past the end of the TEB since 2 zeroed pages are allocated for it. Leave some headroom for the TEB to grow in future Windows versions
static constexpr LONG_PTR TebPadding = 0x200; // +512
#else
// On x86 and Wow64 we have a problem because sizeof(TEB) == PAGE_SIZE == TebAllocationSize, i.e. there are no spare zeroes past the end of the TEB, at least on Win 10.
// Instead abuse the SpareBytes field for this. Because (1) this field has a slightly different offset on different versions of Windows (+1AC for 7 vs +1B9 for 10),
// and (2) this field is not pointer-aligned, round the address up to pointer alignment. The offset is negative from the end since we are writing to the TEB, not past it
static constexpr LONG_PTR TebPaddingFromEnd = (static_cast<LONG_PTR>(TebAllocationSize) - FIELD_OFFSET(TEB_tls_only, SpareBytes)); // 4096 - 441 = 3655
static constexpr LONG_PTR TebPadding = ((-1 * TebPaddingFromEnd) + static_cast<LONG_PTR>(alignof(PVOID)) - 1) & (~(static_cast<LONG_PTR>(alignof(PVOID)) - 1)); // ALIGN_UP(-1 * 3655, PVOID) = -3652
static_assert(TebPadding == -3652, "You touched ntdll.h didn't you?");
#endif

// To create a TLS variable, declare it here
enum class TlsVariable : ULONG_PTR
{
	InstrumentationCallbackDisabled, // The only TLS variable we currently actually use...
	MaxTlsVariable // Must be last
};

template <TlsVariable Variable>
struct TebOffset
{
	constexpr static ULONG_PTR Value = (static_cast<LONG_PTR>(sizeof(TEB_tls_only)) + TebPadding) + (static_cast<ULONG_PTR>(Variable) * alignof(PVOID));
};

static_assert(TebOffset<TlsVariable::MaxTlsVariable>::Value <= TebAllocationSize - sizeof(PVOID), "TLS variable offsets exceed TEB allocation size");
static_assert(static_cast<ULONG_PTR>(TlsVariable::MaxTlsVariable) - 1 <= 5, "All out of TEB SpareBytes, find some new field to abuse"); // Only really applies to x86, but check on both

FORCEINLINE volatile LONG* TlsGetInstrumentationCallbackDisabled()
{
	return reinterpret_cast<volatile LONG*>(reinterpret_cast<ULONG_PTR>(reinterpret_cast<TEB_tls_only*>(NtCurrentTeb())) + TebOffset<TlsVariable::InstrumentationCallbackDisabled>::Value);
}
