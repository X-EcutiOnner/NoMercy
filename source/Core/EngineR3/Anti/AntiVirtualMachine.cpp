#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiDebug.hpp"
#include "../../../Common/StdExtended.hpp"


#define PUserKData        ((LPBYTE)0x00005800)
#define CURTLSPTR_OFFSET 0x000
#define UTlsPtr() (*(LPDWORD *)(PUserKData+CURTLSPTR_OFFSET))

#define TLSSLOT_MSGQUEUE    0
#define TLSSLOT_RUNTIME     1
#define TLSSLOT_KERNEL      2

#define TLSKERN_NOFAULT         0x00000002
#define TLSKERN_NOFAULTMSG      0x00000010

namespace NoMercy
{
#ifndef _M_X64

	// IsInsideVPC's exception filter
	DWORD __forceinline IsInsideVPC_exceptionFilter(LPEXCEPTION_POINTERS ep)
	{
		PCONTEXT ctx = ep->ContextRecord;

		ctx->Ebx = static_cast<DWORD>(-1); // Not running VPC
		ctx->Eip += 4; // skip past the "call VPC" opcodes
		return static_cast<DWORD>(EXCEPTION_CONTINUE_EXECUTION);
		// we can safely resume execution since we skipped faulty instruction
	}

	// High level language friendly version of IsInsideVPC()
	inline bool IsInsideVPC()
	{
		bool rc = false;
		__try
		{
			_asm push ebx
			_asm mov  ebx, 0 // It will stay ZERO if VPC is running
			_asm mov  eax, 1 // VPC function number

							 // call VPC
			_asm __emit 0Fh
			_asm __emit 3Fh
			_asm __emit 07h
			_asm __emit 0Bh

			_asm test ebx, ebx
			_asm setz[rc]
				_asm pop ebx
		}
		// The except block shouldn't get triggered if VPC is running!!
		__except (IsInsideVPC_exceptionFilter(GetExceptionInformation()))
		{
		}
		return rc;
	}

	inline bool IsInsideVMWare()
	{
		bool rc = true;
		__try
		{
			__asm
			{
				push   edx
				push   ecx
				push   ebx

				mov    eax, 'VMXh'
				mov    ebx, 0 // any value but not the MAGIC VALUE
				mov    ecx, 10 // get VMWare version
				mov    edx, 'VX' // port number

				in     eax, dx // read port
							   // on return EAX returns the VERSION
							   cmp    ebx, 'VMXh' // is it a reply from VMWare?
							   setz[rc] // set return value

							   pop    ebx
							   pop    ecx
							   pop    edx
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			rc = false;
		}
		return rc;
	}

	inline bool AntiVPC()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti virtual pc check has been started!");

		if (IsInsideVPC() || g_winAPIs->GetModuleHandleW_o(xorstr_(L"vmcheck.dll")))
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti virtual pc check completed!");
		return true;
	}

	inline bool AntiVMware()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti vmware check has been started!");

		if (IsInsideVMWare())
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti vmware check completed!");
		return true;
	}

	bool IsRunningOnVirtualMachineEx()
	{
		BOOL fRetVal = TRUE;
		DWORD OldPtr = UTlsPtr()[TLSSLOT_KERNEL];
		UTlsPtr()[TLSSLOT_KERNEL] |= TLSKERN_NOFAULT | TLSKERN_NOFAULTMSG;

		__try
		{
			__asm
			{
				// Execute a synthetic VMCPUID instruction.
				__emit  0x0F
				__emit  0xC7
				__emit  0xC8
				__emit  0x01
				__emit  0x00
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// this should be EXCEPTION_ILLEGAL_INSTRUCTION
			fRetVal = FALSE;
		}

		UTlsPtr()[TLSSLOT_KERNEL] = OldPtr;
		return fRetVal;
	}

	bool IsRunningOnVirtualMachine()
	{
		if (IsRunningOnVirtualMachineEx())
		{
			APP_TRACE_LOG(LL_ERR, L"IsRunningOnVirtualMachine detected!");
			return true;
		}
		return false;
	}
#endif

	inline bool AntiSandBoxie()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti sandboxie check has been started!");

		if (g_winAPIs->GetModuleHandleW_o(xorstr_(L"SbieDll.dll")) ||
			g_winAPIs->GetModuleHandleW_o(xorstr_(L"SbieDllX.dll")))
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti sandboxie check completed!");
		return true;
	}

	inline bool AntiSandbox()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti sandbox check has been started!");

		auto hwSandbox = g_winAPIs->FindWindowExW(0, 0, xorstr_(L"Progman"), xorstr_(L"Program Manager"));
		if (!hwSandbox)
			return false;

		// Normal sandbox uygulaması pcde aktifse
#if 0
		auto hwSandbox2 = g_winAPIs->FindWindowExW(0, 0, xorstr_(L"SandboxieControlWndClass"), 0);
		if (hwSandbox2)
			return false;
#endif

		APP_TRACE_LOG(LL_SYS, L"Anti sandbox check completed!");
		return true;
	}

	inline bool AntiVirtualMachine()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti virtual machine check has been started!");
#ifndef _M_X64
		unsigned int reax = 0;
		__asm
		{
			mov eax, 0xCCCCCCCC;
			smsw eax;
			mov DWORD PTR[reax], eax;
		}

		if ((((reax >> 24) & 0xFF) == 0xcc) && (((reax >> 16) & 0xFF) == 0xcc))
		{
			return false;
		}
#endif

		APP_TRACE_LOG(LL_SYS, L"Anti virtual machine check completed!");
		return true;
	}

	inline bool AntiVirtualBox()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti virtual box check has been started!");

		auto bRet = true;

		unsigned long pnsize = 0x1000;
		auto provider = (wchar_t*)g_winAPIs->LocalAlloc(LMEM_ZEROINIT, pnsize * sizeof(wchar_t));
		if (provider)
		{
			int retv = g_winAPIs->WNetGetProviderNameW(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
			if (retv == NO_ERROR)
			{
				if (g_winAPIs->lstrcmpW(provider, xorstr_(L"VirtualBox Shared Folders!")) == 0)
				{
					bRet = false;
				}
			}
			
			g_winAPIs->LocalFree(provider);
		}

		if (!bRet)
			return false;


		auto lstDevices = {
			xorstr_(L"\\\\.\\VBoxMiniRdrDN"), xorstr_(L"\\\\.\\pipe\\VBoxMiniRdDN"),
			xorstr_(L"\\\\.\\VBoxTrayIPC")
		};

		for (const auto& device : lstDevices)
		{
			auto hDevice = g_winAPIs->CreateFileW(device, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			if (IS_VALID_HANDLE(hDevice))
			{
				g_winAPIs->CloseHandle(hDevice);
				return false;
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Anti virtual box check completed!");
		return true;
	}

	inline bool AntiSunbeltSandBox()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti sunbelt sandbox check has been started!");

		wchar_t wszFileName[MAX_PATH]{ L'\0' };
		g_winAPIs->GetModuleFileNameW(NULL, wszFileName, MAX_PATH);

		if (!wcscmp(wszFileName, xorstr_(L"C:\\file.exe")) || g_winAPIs->GetModuleHandleW_o(xorstr_(L"pstorec.dll")))
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti sunbelt sandbox check completed!");
		return true;
	}

	inline bool AntiWPEPro()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti wpe check has been started!");

		if (g_winAPIs->GetModuleHandleW_o(xorstr_(L"wpespy.dll")))
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti wpe check completed!");
		return true;
	}

	inline bool AntiWine()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti wine check has been started!");

		if (g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("wine_get_unix_file_name")))
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti wine check completed!");
		return true;
	}

	inline bool Anticuckoomon()
	{
		APP_TRACE_LOG(LL_SYS, L"Anti cuckoomon check has been started!");

		if (g_winAPIs->GetModuleHandleW_o(xorstr_(L"cuckoomon.dll")))
		{
			return false;
		}

		if (g_winAPIs->CreateFileW(xorstr_(L"\\\\.\\pipe\\cuckoo"), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE)
		{
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Anti cuckoomon check completed!");
		return true;
	}

	inline bool CheckRdtsc()
	{
		auto time1 = __rdtsc();
		auto time2 = __rdtsc();

		const auto diff = time2 - time1;
		APP_TRACE_LOG(LL_WARN, L"Diff: %llu", diff);

		if (diff > 250)
			return false;
		return true;
	}

	inline bool CheckRegistry_DiskEnum(LPDWORD pdwReturnCode)
	{
		APP_TRACE_LOG(LL_SYS, L"Registry Disk Enum check has been started!");

		char wszRegKey[_MAX_PATH]{ L'\0' };
		DWORD BufSize = _MAX_PATH;
		DWORD dataType = REG_SZ;

		HKEY hKey;
		long lError = g_winAPIs->RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"), NULL, KEY_QUERY_VALUE, &hKey);
		if (lError == ERROR_SUCCESS)
		{
			long lVal = g_winAPIs->RegQueryValueExW(hKey, xorstr_(L"0"), NULL, &dataType, (LPBYTE)&wszRegKey, &BufSize);
			if (lVal == ERROR_SUCCESS)
			{
				const auto wstRegKey = stdext::to_lower_wide(wszRegKey);
				if (wstRegKey.find(xorstr_(L"vmware")) != std::string::npos)
				{
					if (pdwReturnCode) *pdwReturnCode = 1;
					return false;
				}
				if (wstRegKey.find(xorstr_(L"virtual")) != std::string::npos)
				{
					if (pdwReturnCode) *pdwReturnCode = 2;
					return false;
				}
				if (wstRegKey.find(xorstr_(L"vbox")) != std::string::npos)
				{
					if (pdwReturnCode) *pdwReturnCode = 3;
					return false;
				}
				if (wstRegKey.find(xorstr_(L"qemu")) != std::string::npos)
				{
					if (pdwReturnCode) *pdwReturnCode = 4;
					return false;
				}
				if (wstRegKey.find(xorstr_(L"xen")) != std::string::npos)
				{
					if (pdwReturnCode) *pdwReturnCode = 5;
					return false;
				}
			}
			g_winAPIs->RegCloseKey(hKey);
		}

		APP_TRACE_LOG(LL_SYS, L"Registry Disk Enum check completed!");
		return true;
	}

	inline void CrashMachine()
	{
		__try
		{
			__sidt(nullptr);
		}
		__except (1)
		{
		}
	}

	inline bool CheckCpuID(LPDWORD pdwReturnCode)
	{
		APP_TRACE_LOG(LL_SYS, L"CPU ID check has been started!");

		auto GetHyperVendorID = []() -> std::wstring {
			int cpuInfo[4];
			__cpuid(cpuInfo, 0x40000000);

			char szHyperVendorID[13]{ 0 };
			memcpy(szHyperVendorID + 0, &cpuInfo[1], sizeof(int)); // ebx
			memcpy(szHyperVendorID + 4, &cpuInfo[2], sizeof(int)); // ecx
			memcpy(szHyperVendorID + 8, &cpuInfo[3], sizeof(int)); // edx

			szHyperVendorID[12] = '\0';

			return stdext::to_wide(szHyperVendorID);
		};

		const auto lstBlacklistCPUIds = {
			xorstr_(L"VBox"),xorstr_(L"VirtualBox"),xorstr_(L"XenVM"),xorstr_(L"KVMKVMKVM"),xorstr_(L"VMware"),
			xorstr_(L"QEMU"),xorstr_(L"TCGTCGTCGTCG"),xorstr_(L"bhyve bhyve"),
			xorstr_(L"QNXQVMBSQG"),xorstr_(L"ACRNACRNACRN"),xorstr_(L"lrpepyh vr"),xorstr_(L"prl hyperv"),
			xorstr_(L"Virtual Machine"),xorstr_(L"Virtual HD"),xorstr_(L"Virtual CD"), xorstr_(L"hypervisor")
			// xorstr_(L"Microsoft Hv") (False positive)
		};

		static const auto stID = GetHyperVendorID();
		APP_TRACE_LOG(LL_SYS, L"Vendor ID: %s", stID.c_str());

		uint32_t idx = 0;
		for (const auto& stCurrentBlacklistedId : lstBlacklistCPUIds)
		{
			idx++;

			if (stID.find(stCurrentBlacklistedId) != std::wstring::npos)
			{
				if (pdwReturnCode) *pdwReturnCode = idx;
				return false;
			}
		}

		APP_TRACE_LOG(LL_SYS, L"CPU ID check completed!");
		return true;
	}

	bool CAntiDebug::AntiVirtualize(LPDWORD pdwReturnCode)
	{
		APP_TRACE_LOG(LL_SYS, L"Anti virtualize event has been started!");

		auto dwDiskRet = 0UL;
		auto dwCpuIDRet = 0UL;

		// FIXME: crash
#ifndef _M_X64
		//	AntiVPC();
		//	AntiVMware();
		//	IsRunningOnVirtualMachine();
#endif

		if (AntiSandBoxie() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 1;
			return false;
		}
		if (AntiSandbox() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 2;
			return false;
		}

		if (AntiVirtualMachine() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 3;
			return false;
		}
		if (AntiVirtualBox() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 4;
			return false;
		}
		if (AntiSunbeltSandBox() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 5;
			return false;
		}
		if (AntiWPEPro() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 6;
			return false;
		}
		if (AntiWine() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 7;
			return false;
		}
		if (Anticuckoomon() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 8;
			return false;
		}
		if (CheckRdtsc() == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 9;
			return false;
		}
		if (CheckRegistry_DiskEnum(&dwDiskRet) == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 100 + dwDiskRet;
			return false;
		}
		if (CheckCpuID(&dwCpuIDRet) == false)
		{
			if (pdwReturnCode) *pdwReturnCode = 200 + dwCpuIDRet;
			return false;
		}

		/*
#ifdef __EXPERIMENTAL__
		CrashMachine();
#endif
		*/

		APP_TRACE_LOG(LL_SYS, L"Anti virtualize event completed!");
		return true;
	}
};
