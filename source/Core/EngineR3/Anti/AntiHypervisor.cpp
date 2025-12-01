#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiDebug.hpp"





#ifdef _M_X64
extern "C" void asm_pg_KiErrata361Present();
extern "C" bool asm_pg_single_step();
#endif

extern "C" void asm_single_step_cpuid();
extern "C" void asm_single_step_rdtsc();

namespace NoMercy
{
	inline bool HasRdtscpSupport()
	{
		int CPUInfo[4] = { -1 };
		__cpuid(CPUInfo, 0x80000001);
		return ((CPUInfo[3] >> 27) & 1);
	}
	
	inline bool CheckRdtscCpu()
	{
		DWORD tsc1 = 0;
		DWORD tsc2 = 0;
		DWORD avg = 0;
		INT cpuInfo[4] = {};
		for (INT i = 0; i < 10; i++)
		{
			tsc1 = __rdtsc();
			__cpuid(cpuInfo, 0);
			tsc2 = __rdtsc();
			avg += (tsc2 - tsc1);
		}
		avg = avg / 10;

		APP_TRACE_LOG(LL_SYS, L"RDTSC CPU: %u", avg);
		
		if (avg > 25 && avg < 500)
			return false;
		return true;
	}

	inline bool CheckRdtscp()
	{
		unsigned int  val = 0;
		DWORD tscp1 = 0;
		DWORD tscp2 = 0;
		DWORD avg = 0;
		INT cpuid[4] = {};

		if (HasRdtscpSupport())
		{
			APP_TRACE_LOG(LL_SYS, L"RDTSCP support detected");
			
			for (INT j = 0; j < 10; j++)
			{
				tscp1 = __rdtscp(&val);
				//call 3 cpuid for normal detect
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				tscp2 = __rdtscp(&val);
				avg += tscp2 - tscp1;

				if (avg > 25 && avg < 500)
				{
					APP_TRACE_LOG(LL_ERR, L"RDTSCP: %u", avg);
					return false;
				}
				else
					avg = 0;
			}
			return true;
		}
		return false; 
	}

	inline bool CheckRdtscHeap()
	{
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG tsc3 = 0;

		for (DWORD i = 0; i < 10; i++)
		{
			tsc1 = __rdtsc();

			g_winAPIs->GetProcessHeap();

			tsc2 = __rdtsc();

			g_winAPIs->CloseHandle(0);

			tsc3 = __rdtsc();

			if ((tsc3 - tsc2) / (tsc2 - tsc1) >= 10)
			{
				APP_TRACE_LOG(LL_ERR, L"RDTSC Heap: %u", (tsc3 - tsc2) / (tsc2 - tsc1));
				return false;
			}
		}

		return true;
	}

	__declspec(noinline) bool SingleStepCheck()
	{
		uint8_t byte_step = 0;
		
		__try
		{
			asm_single_step_cpuid();
		}
		__except (byte_step = *(uint8_t*)(GetExceptionInformation())->ExceptionRecord->ExceptionAddress)
		{
			if (byte_step != 0x90)
				return true;
		}

		__try
		{
			asm_single_step_rdtsc();
		}
		__except (byte_step = *(uint8_t*)(GetExceptionInformation())->ExceptionRecord->ExceptionAddress)
		{
			if (byte_step != 0x90)
				return true;
		}
		
		return false;
	}
	
	inline int SSTrapFilter(unsigned int code, struct _EXCEPTION_POINTERS* ep, bool& bDetected, int& singleStepCount)
	{
		if (code != EXCEPTION_SINGLE_STEP)
		{
			bDetected = true;
			return EXCEPTION_CONTINUE_SEARCH;
		}

		singleStepCount++;

		if ((size_t)ep->ExceptionRecord->ExceptionAddress != (size_t)asm_single_step_cpuid + 11)
		{
			bDetected = true;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		bool bIsRaisedBySingleStep = ep->ContextRecord->Dr6 & (1 << 14);
		bool bIsRaisedByDr0 = ep->ContextRecord->Dr6 & 1;
		if (!bIsRaisedBySingleStep || !bIsRaisedByDr0)
		{
			bDetected = true;
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}
	inline bool CheckSSTrapFlag()
	{
		bool bDetected = false;
		int singleStepCount = 0;
		
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		g_winAPIs->GetThreadContext(NtCurrentThread(), &ctx);
		
		ctx.Dr0 = (size_t)asm_single_step_cpuid + 11;
		ctx.Dr7 = 1;
		g_winAPIs->SetThreadContext(NtCurrentThread(), &ctx);
		
		__try
		{
			asm_single_step_cpuid();
		}
		__except (SSTrapFilter(GetExceptionCode(), GetExceptionInformation(), bDetected, singleStepCount))
		{
			if (singleStepCount != 1)
			{
				bDetected = true;
			}
		}
		return bDetected;
	}

	bool CheckCPUID()
	{
		// Force ignore all hypervisor types, worth?
#if 0
		int CPUInfo[4] = { -1 };

		// Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX
		__cpuid(CPUInfo, 1);
		return ((CPUInfo[2] >> 31) & 1);
#else
		return false;
#endif
	}

	bool IsRdtscpCorrupt()
	{
		unsigned int val = 0;
		DWORD tscp1 = 0;
		DWORD tscp2 = 0;
		DWORD avg = 0;
		INT cpuid[4] = {};

		if (HasRdtscpSupport())
		{
			for (INT j = 0; j < 0x13337; j++)
			{
				tscp1 = __rdtscp(&val);
				__cpuid(cpuid, 0);

				tscp2 = __rdtscp(&val);
				avg += tscp2 - tscp1;
				if (avg > 3000 && avg < 150000)
				{
					APP_TRACE_LOG(LL_SYS, L"RDTSCP: %u", avg);
					return false;
				}
				
				avg = 0;
			}
			return true;
		}
		
		return false;
	}

	bool HypervisorCheckTriggered()
	{
		auto bRet = FALSE;
#ifndef _M_X64
		__asm
		{
			pushad
			pushfd
			pop eax
			or eax, 0x00200000
			push eax
			popfd
			pushfd
			pop eax
			and eax, 0x00200000
			jz CPUID_NOT_SUPPORTED
			xor eax, eax
			xor edx, edx
			xor ecx, ecx
			xor ebx, ebx
			inc eax
			cpuid
			test ecx, 0x80000000
			jnz Hypervisor
			mov bRet, 0
			jmp bye
			Hypervisor :
			mov bRet, 1
				jmp bye
				CPUID_NOT_SUPPORTED :
			mov bRet, 2
				bye :
				popad
		}
#endif
		return (bRet == TRUE);
	}

	bool CheckUdpPorts()
	{
		auto bRet = false;
		auto pUdpTable = (PMIB_UDPTABLE)CMemHelper::Allocate(sizeof(PMIB_UDPTABLE));

		auto dwNeedSize = 0UL;
		auto dwUdpRet = g_winAPIs->GetUdpTable(pUdpTable, &dwNeedSize, TRUE);

		if (dwUdpRet == ERROR_INSUFFICIENT_BUFFER)
		{
			pUdpTable = (PMIB_UDPTABLE)CMemHelper::ReAlloc(pUdpTable, dwNeedSize);
			dwUdpRet = g_winAPIs->GetUdpTable(pUdpTable, &dwNeedSize, TRUE);
		}

		if (dwUdpRet == NO_ERROR)
		{
			if (pUdpTable->dwNumEntries > 0)
			{
				auto iPortCount = 0UL;
				for (auto i = 0UL; i < pUdpTable->dwNumEntries; i++)
				{
					switch (pUdpTable->table[i].dwLocalPort)
					{
						case 67: // DHCP
						case 68: // DHCP
						case 69: // TFTP
						case 4011: // PXE
							iPortCount++;
							break;
					}
				}

				if (iPortCount >= 3)
				{
					bRet = true;
				}
			}
		}

		CMemHelper::Free(pUdpTable);
		return bRet;
	}

	bool CAntiDebug::LowLevelHypervisorChecksPassed(LPDWORD pdwReturnCode)
	{
		auto check_by_invalid_cpuid = []() {
			struct _cpuid
			{
				UINT data[4];
			};
			
			auto fn_check = [](_cpuid a, _cpuid b) -> bool {
				return (a.data[0] && a.data[0] != b.data[0]) &&
					(a.data[1] && a.data[1] != b.data[1]) &&
					(a.data[2] && a.data[2] != b.data[2]) &&
					(a.data[3] && a.data[3] != b.data[3]);
			};

			unsigned int invalid_leaf = 0x13371337;
			unsigned int valid_leaf = 0x40000000;

			_cpuid cpuid_first = { 0 };
			_cpuid cpuid_sec = { 0 };

			__cpuid((int*)&cpuid_first, invalid_leaf);
			__cpuid((int*)&cpuid_sec, valid_leaf);

			APP_TRACE_LOG(LL_SYS, L"check_by_invalid_cpuid :: first: %u %u %u %u", cpuid_first.data[0], cpuid_first.data[1], cpuid_first.data[2], cpuid_first.data[3]);
			APP_TRACE_LOG(LL_SYS, L"check_by_invalid_cpuid :: sec: %u %u %u %u", cpuid_sec.data[0], cpuid_sec.data[1], cpuid_sec.data[2], cpuid_sec.data[3]);

			if (fn_check(cpuid_first, cpuid_sec))
			{
				APP_TRACE_LOG(LL_ERR, L"cpuid manipulation detected");
				return false;
			}
			return true;
		};
		

		__try
		{
			if (!check_by_invalid_cpuid())
			{
				if (pdwReturnCode) *pdwReturnCode = 1;
				return false;
			}
		}
		__except (GetExceptionCode() == EXCEPTION_SINGLE_STEP ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH)
		{
			if (pdwReturnCode) *pdwReturnCode = 11;
			return false;
		}
		
#ifdef _M_X64
		__try
		{
			if (!asm_pg_single_step())
			{
				if (pdwReturnCode) *pdwReturnCode = 2;
				return false;
			}
		}
		__except (GetExceptionCode() == EXCEPTION_SINGLE_STEP ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH)
		{
			if (pdwReturnCode) *pdwReturnCode = 12;
			return false;
		}
		
		__try
		{
			asm_pg_KiErrata361Present();
		}
		__except (GetExceptionCode() == EXCEPTION_SINGLE_STEP ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH)
		{
			if (pdwReturnCode) *pdwReturnCode = 13;
			return false;
		}

		return true;
#else
		return true;
#endif
	}

	bool CAntiDebug::IsHypervisorPresent(LPDWORD pdwDetectType)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti hypervisor initialization has been started!");

		std::vector <std::tuple <uint32_t, std::function <bool()>, EFlags, uint32_t>> vecInfoHelpers = {
			{1, std::bind(&CheckRdtscCpu), EFlags::OPTIONAL, 0}, // false positive?
			{2, std::bind(&CheckRdtscp), EFlags::OPTIONAL, 0},
			{3, std::bind(&CheckRdtscHeap), EFlags::DISABLED, 0}, // false positive?
			{4, std::bind(&SingleStepCheck), EFlags::DISABLED, 0}, // false positive?
			{5, std::bind(&CheckSSTrapFlag), EFlags::DISABLED, 0}, // false positive?
			{6, std::bind(&CheckCPUID), EFlags::NONE, 0},
			{7, std::bind(&IsRdtscpCorrupt), EFlags::DISABLED, 0}, // false positive?
			{8, std::bind(&HypervisorCheckTriggered), EFlags::DISABLED, 0},
			{9, std::bind(&CheckUdpPorts), EFlags::NONE, 0}
		};

		auto dwDetectIdx = 0UL;

		for (const auto& [idx, fn, flags, base] : vecInfoHelpers)
		{
			APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step %u+%u checking... Flags: %d", base, idx, flags);

			if (flags == EFlags::DISABLED)
			{
				APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step %u is disabled!", idx);
				continue;
			}
			else if (flags == EFlags::TEST && !stdext::is_debug_env())
			{
				APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step %u is disabled in release mode!", idx);
				continue;
			}

			const auto bRet = fn();
			if (bRet)
			{
				APP_TRACE_LOG(LL_SYS, L"Hypervisor %u detected!", idx);

				if (flags != EFlags::OPTIONAL)
				{
					dwDetectIdx = base + idx;
#ifndef _DEBUG
					break;
#endif
				}
			}

			APP_TRACE_LOG(LL_SYS, L"Anti hypervisor step %u completed!", idx);
		}

		APP_TRACE_LOG(dwDetectIdx == 0 ? LL_SYS : LL_CRI, L"Hypervisor check routine completed! Result: %u", dwDetectIdx);

		if (pdwDetectType) *pdwDetectType = dwDetectIdx;
		return dwDetectIdx != 0;
	}
};
