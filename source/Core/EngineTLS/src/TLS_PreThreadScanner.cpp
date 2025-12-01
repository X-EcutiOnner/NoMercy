#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"

namespace NoMercyTLS
{
	static DWORD s_dwThreadCount = 0;
	static DWORD s_dwCurrentTID = 0;

	void TLS_ScanThreads()
	{
		s_dwCurrentTID = HandleToULong(NtCurrentThreadId());
#ifdef ENABLE_TLS_LOGS
		TLS_LOG("Current Thread: %u", s_dwCurrentTID);
#endif

		TLS_EnumerateThreads(nullptr, [](DWORD dwThreadID, LPVOID) {
			auto fnOpenThread = [](DWORD dwDesiredAccess, DWORD dwThreadID) -> HANDLE{
				OBJECT_ATTRIBUTES oa;
				InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

				HANDLE hThread = nullptr;
				CLIENT_ID cid = { nullptr, reinterpret_cast<HANDLE>(dwThreadID) };

				const auto ntStatus = NT::NtOpenThread(&hThread, dwDesiredAccess, &oa, &cid);
				if (!NT_SUCCESS(ntStatus))
				{
#ifdef ENABLE_TLS_LOGS
					TLS_LOG("NtOpenThread (%u) failed with status: %p", dwThreadID, ntStatus);
#endif
					return nullptr;
				}

				return hThread;
			};
			auto fnGetThreadStartAddress = [](HANDLE hThread) -> DWORD {
				DWORD dwCurrentThreadAddress = 0;
				const auto ntStatus = NT::NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), nullptr);
				if (!NT_SUCCESS(ntStatus))
				{
#ifdef ENABLE_TLS_LOGS
					TLS_LOG("GetThreadStartAddress fail! Thread: %p Status: %p", hThread, ntStatus);
#endif
					return 0;
				}
				return dwCurrentThreadAddress;
			};


			s_dwThreadCount++;
#ifdef ENABLE_TLS_LOGS
			TLS_LOG("[%u] Thread: %u", s_dwThreadCount, dwThreadID);
#endif

			auto hThread = fnOpenThread(THREAD_ALL_ACCESS, dwThreadID);
			if (!IS_VALID_HANDLE(hThread))
			{
				return;
			}

			const auto dwStartAddress = fnGetThreadStartAddress(hThread);
			if (!dwStartAddress)
			{
				return;
			}
#ifdef ENABLE_TLS_LOGS
			TLS_LOG("[%u] Thread: %u Start address: %p", s_dwThreadCount, dwThreadID, dwStartAddress);
#endif

			const auto bIsMainThread = s_dwCurrentTID == dwThreadID || TLS_IsIninModule(dwStartAddress);
			if (bIsMainThread)
			{
				CONTEXT ctx{ 0 };
				ctx.ContextFlags = CONTEXT_CONTROL;
				const auto ntStatus = NT::NtGetContextThread(hThread, &ctx);
				if (!NT_SUCCESS(ntStatus))
				{
#ifdef ENABLE_TLS_LOGS
					TLS_LOG("NtGetContextThread fail! Thread: %u Status: %p", dwThreadID, ntStatus);
#endif
				}
				else
				{
					if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
					{
						TLS_MessageBox(xorstr_(L"NoMercy core protector"), xorstr_(L"Thread modification detected!"));

						std::abort();
						return;
					}
				}
			}
			else
			{
				TLS_LOG("Unknown thread: %u started by: %p will be terminated!", dwThreadID, dwStartAddress);
				const auto ntStatus = NT::NtTerminateThread(hThread, STATUS_SUCCESS);
				TLS_LOG("Thread: %u terminate completed with status: %p", dwThreadID, ntStatus);

				if (NT_SUCCESS(ntStatus))
				{
					s_dwThreadCount--;
				}
			}

			NT::NtClose(hThread);
		});

		if (!s_dwThreadCount)
		{
			TLS_LOG("No thread found!");

			TLS_MessageBox(xorstr_(L"NoMercy core protector"), xorstr_(L"Thread enumeration failed!"));

			std::abort();
			return;
		}
		else if (s_dwThreadCount > 1)
		{
			TLS_LOG("%u thread found!", s_dwThreadCount);

			wchar_t wszBuffer[0x100]{ L'\0' };
			wsprintfW(wszBuffer, xorstr_(L"[%u] Unknown threads found in process!"), s_dwThreadCount);

			TLS_MessageBox(xorstr_(L"NoMercy core protector"), wszBuffer);

			std::abort();
			return;
		}
	}
}
