#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	std::wstring ConvertTimestampToReadableDateTime(ULONG ulTimestamp)
	{
		LARGE_INTEGER time{};
		g_winAPIs->RtlSecondsSince1970ToTime(ulTimestamp, &time);

		FILETIME fileTime{};
		FILETIME newFileTime{};

		fileTime.dwLowDateTime = time.LowPart;
		fileTime.dwHighDateTime = time.HighPart;
		g_winAPIs->FileTimeToLocalFileTime(&fileTime, &newFileTime);

		SYSTEMTIME SystemTime{};
		g_winAPIs->FileTimeToSystemTime(&newFileTime, &SystemTime);

		wchar_t wszBuffer[128]{ L'\0' };
		_snwprintf(wszBuffer, 128,
			xorstr_(L"%04u-%02u-%02u %02u:%02u:%02u"),
			SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond
		);

		return std::wstring(wszBuffer);
	}

	void IScanner::CheckUnloadedModules()
	{
#ifdef _DEBUG
		// Test
		auto lib = LoadLibraryA("msidntld.dll");
		FreeLibrary(lib);
#endif

		NTSTATUS status;
		PULONG elementSize;
		PULONG elementCount;
		PVOID eventTrace;
		ULONG eventTraceSize;
		ULONG capturedElementSize;
		ULONG capturedElementCount;
		PVOID capturedEventTracePointer;
		PVOID capturedEventTrace = NULL;
		ULONG i;
		PVOID currentEvent;
	
		g_winAPIs->RtlGetUnloadEventTraceEx(&elementSize, &elementCount, &eventTrace);

		if (!NT_SUCCESS(status = g_winAPIs->NtReadVirtualMemory(
			NtCurrentProcess(),
			elementSize,
			&capturedElementSize,
			sizeof(ULONG),
			NULL
		)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtReadVirtualMemory (elementSize) failed with status: %p", status);
			goto __complete;
		}
		
		if (!NT_SUCCESS(status = g_winAPIs->NtReadVirtualMemory(
			NtCurrentProcess(),
			elementCount,
			&capturedElementCount,
			sizeof(ULONG),
			NULL
		)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtReadVirtualMemory (elementCount) failed with status: %p", elementCount);
			goto __complete;
		}
		
		if (!NT_SUCCESS(status = g_winAPIs->NtReadVirtualMemory(
			NtCurrentProcess(),
			eventTrace,
			&capturedEventTracePointer,
			sizeof(PVOID),
			NULL
		)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtReadVirtualMemory (eventTrace) failed with status: %p", eventTrace);
			goto __complete;
		}
		
		if (!capturedEventTracePointer)
		{
			APP_TRACE_LOG(LL_WARN, L"No unloaded module found!");
			goto __complete; // no events
		}
		
		if (capturedElementCount > 0x4000)
			capturedElementCount = 0x4000;

		eventTraceSize = capturedElementSize * capturedElementCount;

		capturedEventTrace = CMemHelper::Allocate(eventTraceSize);

		if (!capturedEventTrace)
		{
			APP_TRACE_LOG(LL_WARN, L"Memory allocation with size: %u failed with error: %u", eventTraceSize, g_winAPIs->GetLastError());
			status = STATUS_NO_MEMORY;
			goto __complete;
		}

		if (!NT_SUCCESS(status = g_winAPIs->NtReadVirtualMemory(
			NtCurrentProcess(),
			capturedEventTracePointer,
			capturedEventTrace,
			eventTraceSize,
			NULL
		)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtReadVirtualMemory (capturedEventTrace) failed with status: %p", eventTrace);
			goto __complete;
		}
		
		currentEvent = capturedEventTrace;

		APP_TRACE_LOG(LL_TRACE, L"%d unloaded module found!", capturedElementCount);

		for (i = 0; i < capturedElementCount; i++)
		{
			auto rtlEvent = (PRTL_UNLOAD_EVENT_TRACE)currentEvent;
			if (rtlEvent->BaseAddress)
			{
				wchar_t wszName[32]{ L'\0' };
				wcscpy_s(wszName, rtlEvent->ImageName);
				const auto stName = stdext::to_ansi(wszName);

				const auto stDateTime = ConvertTimestampToReadableDateTime(rtlEvent->TimeDateStamp);

				APP_TRACE_LOG(LL_TRACE, L"[%d] [%lu] %s >> Base (%p) Size (%p) Time: %s (%p) Sum: %p Version: %lu/%lu",
					i, rtlEvent->Sequence, stName.c_str(), rtlEvent->BaseAddress, rtlEvent->SizeOfImage, stDateTime.c_str(), rtlEvent->TimeDateStamp,
					rtlEvent->CheckSum, rtlEvent->Version[0], rtlEvent->Version[1]
				);

				// TODO: Scan
			}
			
			currentEvent = PTR_ADD_OFFSET(currentEvent, capturedElementSize);
		}

__complete:
		if (capturedEventTrace)
		{
			CMemHelper::Free(capturedEventTrace);
			capturedEventTrace = nullptr;
		}
		
		return;
	}
};
