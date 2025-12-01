#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../../../Common/StdExtended.hpp"
#include "../../../Common/GameCodes.hpp"

namespace NoMercy
{
	inline int FilterShellcode(LPVOID lpTargetAddress)
	{
		HOOK_LOG(LL_SYS, L"Shellcode filter has been started!");

#ifdef _DEBUG
		BYTE bBytes[16]{ 0 };
		memcpy(bBytes, lpTargetAddress, sizeof(bBytes));

		HOOK_LOG(LL_SYS, L"Shellcode Info -> Address: %p Bytes: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x",
			lpTargetAddress, bBytes[0], bBytes[1], bBytes[2], bBytes[3], bBytes[4], bBytes[5], bBytes[6], bBytes[7], bBytes[8], bBytes[9], bBytes[10], bBytes[11]);

		wchar_t wszFileName[2048]{ L'\0' };
		g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpTargetAddress, wszFileName, 2048);
		HOOK_LOG(LL_SYS, L"Shellcode mapped module name: %s", wszFileName ? wszFileName : xorstr_(L"*UNKNOWN*"));
#endif

		auto pMemory = (BYTE*)lpTargetAddress;
		BYTE shellLdrLoad[5] = { 0x55, 0x8B, 0xEC, 0x8D, 0x5 };
		BYTE shellManualMp[6] = { 0x55, 0x8B, 0xEC, 0x51, 0x53, 0x8B };
		BYTE shellReflective[8] = { 0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x54, 0x8B };
		BYTE shellMLoad[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x53, 0x56 };
		BYTE shellhijack[10] = { 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x60, 0x9C, 0xBB, 0xCC, 0xCC };
		BYTE shellhijack2[10] = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06 };
		BYTE shellhijack3[10] = { 0x56, 0x8B, 0x35, 0x00, 0xC0, 0x27, 0x6A, 0x57, 0x8B, 0x3D };
		BYTE shellcreateremotethreadex[10] = { 0xE8, 0x1D, 0x00, 0x00, 0x00, 0x50, 0x68, 0x58, 0x58, 0xC3 };
		BYTE shellcodeinjectrosdevil[8] = { 0x68, 0xAC, 0xCE, 0xEA, 0xAC, 0x9C, 0x60, 0x68 };
		BYTE shellcodeLalakerAuto[8] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x5D, 0xFF, 0x25 };

		// LdrLoadDll, LdrpLoadDll, ManualMap1
		if (memcmp(lpTargetAddress, &shellLdrLoad, 5) == 0)
			return LdrLoadShellCode1;

		// ManualMap2
		if (memcmp(lpTargetAddress, &shellManualMp, 6) == 0)
			return ManualMapShellCode1;

		// ManualMap3 ++
		if (*pMemory == 0x68 && *(pMemory + 5) == 0x68)
		{
			if (*(pMemory + 10) == 0xB8)
				return ManualMapShellCode2;
			else if (*(pMemory + 10) == 0x68)
				return ManualMapShellCode3;
		}

		// Reflective
		if (memcmp(lpTargetAddress, &shellReflective, sizeof(shellReflective)) == 0)
			return ReflectiveShellCode1;

		// Manual Load
		if (memcmp(lpTargetAddress, &shellMLoad, sizeof(shellMLoad)) == 0)
			return ManualLoadShellCode1;

		// Thread hijack 1
		if (memcmp(lpTargetAddress, &shellhijack, sizeof(shellhijack)) == 0)
			return ThreadHijackShellCode1;

		// Thread hijack 2
		if (memcmp(lpTargetAddress, &shellhijack2, sizeof(shellhijack2)) == 0)
			return ThreadHijackShellCode2;

		// Thread hijack 3
		if (memcmp(lpTargetAddress, &shellhijack3, sizeof(shellhijack3)) == 0)
			return ThreadHijackShellCode3;

		// Createremotethreadex 1
		if (memcmp(lpTargetAddress, &shellcreateremotethreadex, sizeof(shellcreateremotethreadex)) == 0)
			return CreateRemoteThreadExShellCode1;

		// Code injection 1
		if (memcmp(lpTargetAddress, &shellcodeinjectrosdevil, sizeof(shellcodeinjectrosdevil)) == 0)
			return CodeInjectionShellCode1;

		// Lalaker auto injector
		if (memcmp(lpTargetAddress, &shellcodeLalakerAuto, sizeof(shellcodeLalakerAuto)) == 0)
			return AutoInjectorLalakerShellCode;

		// Lalaker v110 external hack
		if (pMemory[0] == 0x68 && pMemory[1] == 0x0 && pMemory[2] == 0x0 && pMemory[5] == 0xe8 && pMemory[7] == 0xcd && pMemory[10] == 0x68)
			return LalakerMetin2HackV110;

		HOOK_LOG(LL_SYS, L"Shellcode filter completed!");
		return ShellCodeNull;
	}

	uint32_t CAnalyser::AnalyseShellcode(LPVOID lpCaller, EAnalyseTypes nAnalyseType, const std::wstring& stModuleName)
	{
		HOOK_LOG(LL_SYS, L"Caller Address checker has been started! Caller: %p Type: %u Name: %s", lpCaller, nAnalyseType, stModuleName.c_str());

		uint32_t dwDetectedType = ShellCodeNull;
		auto pbCaller = (LPBYTE)lpCaller;

		//
		do
		{
			MODULEINFO user32ModInfo{ 0 };
			if (!g_winAPIs->GetModuleInformation(NtCurrentProcess(), g_winModules->hUser32, &user32ModInfo, sizeof(user32ModInfo)))
			{
				HOOK_LOG(LL_ERR, L"GetModuleInformation fail! Last error: %u", g_winAPIs->GetLastError());
				dwDetectedType = HOOK_CHECK_GETMODULEINFO_FAIL;
				break;
			}

			const auto dwUser32Low = (DWORD_PTR)user32ModInfo.lpBaseOfDll;
			const auto dwUser32Hi = (DWORD_PTR)user32ModInfo.lpBaseOfDll + user32ModInfo.SizeOfImage;
			if ((DWORD_PTR)lpCaller >= dwUser32Low && (DWORD_PTR)lpCaller <= dwUser32Hi)
			{
				HOOK_LOG(LL_ERR, L"Caller inside in user32.dll");
				dwDetectedType = EaxSetWindowHookEx;
				break;
			}

			if (g_winModules->hPython && NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() == GAME_CODE_METIN2)
			{
				MODULEINFO pythonModInfo{ 0 };
				if (!g_winAPIs->GetModuleInformation(NtCurrentProcess(), g_winModules->hPython, &pythonModInfo, sizeof(pythonModInfo)))
				{
					HOOK_LOG(LL_ERR, L"GetModuleInformation(python) fail! Last error: %u", g_winAPIs->GetLastError());
					dwDetectedType = HOOK_CHECK_GETMODULEINFO_PYTHON_FAIL;
					break;
				}

				const auto dwPythonLow = (DWORD_PTR)pythonModInfo.lpBaseOfDll;
				const auto dwPythonHi = (DWORD_PTR)pythonModInfo.lpBaseOfDll + pythonModInfo.SizeOfImage;
				if ((DWORD_PTR)lpCaller >= dwPythonLow && (DWORD_PTR)lpCaller <= dwPythonHi)
				{
					HOOK_LOG(LL_ERR, L"Caller inside in python dll");
					dwDetectedType = EaxPython;
					break;
				}
			}

			MEMORY_BASIC_INFORMATION mbiCaller{ 0 };
			if (!g_winAPIs->VirtualQuery(lpCaller, &mbiCaller, sizeof(mbiCaller)))
			{
				HOOK_LOG(LL_ERR, L"VirtualQuery fail! Last error: %u", g_winAPIs->GetLastError());
				dwDetectedType = HOOK_CHECK_VIRTUALQUERY_FAIL;
				break;
			}

			wchar_t wszFileName[2048]{ L'\0' };
			if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpCaller, wszFileName, 2048))
			{
				HOOK_LOG(LL_ERR, L"GetMappedFileNameA fail! Last error: %u", g_winAPIs->GetLastError());
				//dwDetectedType = HOOK_CHECK_GETMAPPEDFILENAME_FAIL;
				//break;
			}

			HOOK_LOG(LL_SYS, L"Caller Address checker completed! Address: %p Name: %s", lpCaller, wszFileName[0] != L'\0' ? wszFileName : xorstr_(L"***Unknown***"));

			const auto iShellInjectionRet = FilterShellcode(lpCaller);
			if (iShellInjectionRet)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode: %u detected", iShellInjectionRet);
				dwDetectedType = iShellInjectionRet;
				break;
			}

			static const auto dwLoadLibraryA = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("LoadLibraryA"));
			if (dwLoadLibraryA && lpCaller == dwLoadLibraryA)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryA");
				dwDetectedType = EaxLoadLibraryA;
				break;
			}

			static const auto dwLoadLibraryW = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("LoadLibraryW"));
			if (dwLoadLibraryW && lpCaller == dwLoadLibraryW)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryW");
				dwDetectedType = EaxLoadLibraryW;
				break;
			}

			static const auto dwLoadLibraryExA = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("LoadLibraryExA"));
			if (dwLoadLibraryExA && lpCaller == dwLoadLibraryExA)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryExA");
				dwDetectedType = EaxLoadLibraryExA;
				break;
			}

			static const auto dwLoadLibraryExW = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("LoadLibraryExW"));
			if (dwLoadLibraryExW && lpCaller == dwLoadLibraryExW)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryExW");
				dwDetectedType = EaxLoadLibraryExW;
				break;
			}

			static const auto dwFreeLibrary = g_winAPIs->GetProcAddress_o(g_winModules->hKernel32, xorstr_("FreeLibrary"));
			if (dwFreeLibrary && lpCaller == dwFreeLibrary)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: FreeLibrary");
				dwDetectedType = EaxFreeLibrary;
				break;
			}

			static const auto dwLdrLoadDll = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("LdrLoadDll"));
			if (dwLdrLoadDll && lpCaller == dwLdrLoadDll)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LdrLoadDll");
				dwDetectedType = EaxLdrLoadDll;
				break;
			}

			static const auto dwLdrUnloadDll = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("LdrUnloadDll"));
			if (dwLdrUnloadDll && lpCaller == dwLdrUnloadDll)
			{
				HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LdrUnloadDll");
				dwDetectedType = EaxLdrUnloadDll;
				break;
			}

			if (IsWindowsVistaOrGreater())
			{
				static const auto dwRtlUserThreadStart = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("RtlUserThreadStart"));
				if (dwRtlUserThreadStart && lpCaller == dwRtlUserThreadStart)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: RtlUserThreadStart");
					dwDetectedType = EaxRtlUserThreadStart;
					break;
				}

				static const auto dwNtCreateThread = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("NtCreateThread"));
				if (dwNtCreateThread && lpCaller == dwNtCreateThread)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: NtCreateThread");
					dwDetectedType = EaxNtCreateThread;
					break;
				}

				static const auto dwNtCreateThreadEx = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("NtCreateThreadEx"));
				if (dwNtCreateThreadEx && lpCaller == dwNtCreateThreadEx)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: NtCreateThreadEx");
					dwDetectedType = EaxNtCreateThreadEx;
					break;
				}

				static const auto dwRtlCreateUserThread = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, xorstr_("RtlCreateUserThread"));
				if (dwRtlCreateUserThread && lpCaller == dwRtlCreateUserThread)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: RtlCreateUserThread");
					dwDetectedType = EaxRtlCreateUserThread;
					break;
				}
			}

			if (g_winModules->hKernelbase)
			{
				static const auto dwLoadLibraryA_KBase = g_winAPIs->GetProcAddress_o(g_winModules->hKernelbase, xorstr_("LoadLibraryA"));
				if (dwLoadLibraryA_KBase && lpCaller == dwLoadLibraryA_KBase)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryA(kernelbase)");
					dwDetectedType = EaxLoadLibraryA_KBase;
					break;
				}

				static const auto dwLoadLibraryW_KBase = g_winAPIs->GetProcAddress_o(g_winModules->hKernelbase, xorstr_("LoadLibraryW"));
				if (dwLoadLibraryW_KBase && lpCaller == dwLoadLibraryW_KBase)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryW(kernelbase)");
					dwDetectedType = EaxLoadLibraryW_KBase;
					break;
				}

				static const auto dwLoadLibraryExA_KBase = g_winAPIs->GetProcAddress_o(g_winModules->hKernelbase, xorstr_("LoadLibraryExA"));
				if (dwLoadLibraryExA_KBase && lpCaller == dwLoadLibraryExA_KBase)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryExA(kernelbase)");
					dwDetectedType = EaxLoadLibraryExA_KBase;
					break;
				}

				static const auto dwLoadLibraryExW_KBase = g_winAPIs->GetProcAddress_o(g_winModules->hKernelbase, xorstr_("LoadLibraryExW"));
				if (dwLoadLibraryExW_KBase && lpCaller == dwLoadLibraryExW_KBase)
				{
					HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: LoadLibraryExW(kernelbase)");
					dwDetectedType = EaxLoadLibraryExW_KBase;
					break;
				}
			}

			if (!stModuleName.empty() && NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(stModuleName) == false)
			{
				std::wstring arrWhiteList[] = {
					xorstr_(L"wintrust.dll"), xorstr_(L"d3d9"), xorstr_(L"kernel32"), xorstr_(L"windowscodecs.dll")
				};

				bool bIsWhitelisted = false;
				for (const auto& stCurrentItem : arrWhiteList)
				{
					if (wcsstr(stModuleName.c_str(), stCurrentItem.c_str()))
					{
						HOOK_LOG(LL_SYS, L"Whitelisted module name: %s", stModuleName.c_str());
						bIsWhitelisted = true;
					}
				}

				if (!bIsWhitelisted)
				{
					if (*(pbCaller - 7) == 0x1C)
					{
						HOOK_LOG(LL_ERR, L"Blacklisted shellcode loader: SetWindowHookEx(2)");
						dwDetectedType = EaxSetWindowHookEx2;
						break;
					}
				}
			}
			
			if (nAnalyseType == EAnalyseTypes::ANALYSE_THREAD)
			{
				if (mbiCaller.Type != MEM_IMAGE)
				{
					HOOK_LOG(LL_ERR, L"Not allowed memory type: %p", mbiCaller.Type);
					dwDetectedType = EaxCodeInjectionType;
					break;
				}

				else if (mbiCaller.State != MEM_COMMIT)
				{
					HOOK_LOG(LL_ERR, L"Not allowed memory state: %p", mbiCaller.State);
					dwDetectedType = EaxUnknownState;
					break;
				}
			}

			if (mbiCaller.AllocationProtect == PAGE_EXECUTE_READWRITE)
			{
				HOOK_LOG(LL_ERR, L"Not allowed allocation protect: %p", mbiCaller.AllocationProtect);
				dwDetectedType = EaxBadAllocatedProtectType;
				break;
			}

			if (mbiCaller.Protect == PAGE_EXECUTE_READWRITE)
			{
				HOOK_LOG(LL_ERR, L"Not allowed protect: %p", mbiCaller.Protect);
				dwDetectedType = EaxBadProtectType;
				break;
			}

			if (IsWindowsVistaOrGreater())
			{
				PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { 0 };
				pworkingSetExInformation.VirtualAddress = lpCaller;

				if (!g_winAPIs->QueryWorkingSetEx(NtCurrentProcess(), &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
				{
					HOOK_LOG(LL_ERR, L"QueryWorkingSetEx failed with error: %u", g_winAPIs->GetLastError());
					dwDetectedType = QueryWorkingSetExFail;
					break;
				}

				if (!pworkingSetExInformation.VirtualAttributes.Valid)
				{
					HOOK_LOG(LL_ERR, L"Not valid VA memory");
					dwDetectedType = QueryWorkingSetExNotValid;
					break;
				}
			}

			if (wszFileName[0] != L'\0' &&
				NoMercyCore::CApplication::Instance().DataInstance()->GetGameCode() == GAME_CODE_METIN2 &&
				nAnalyseType == EAnalyseTypes::ANALYSE_THREAD)
			{
				auto szLowerFileName = stdext::to_lower_wide(wszFileName);

				auto szExecutablePath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
				auto szLowerExecutable = stdext::to_lower_wide(szExecutablePath);

				if (szLowerFileName == szLowerExecutable)
				{
					HOOK_LOG(LL_ERR, L"Thread executed from main process space");
					dwDetectedType = EaxMainProcess;
					break;
				}

				if (szLowerFileName.empty() && mbiCaller.Type == MEM_PRIVATE && mbiCaller.RegionSize == 0x1000)
				{
					HOOK_LOG(LL_ERR, L"Special mapped code");
					dwDetectedType = EaxMappedCode;
					break;
				}

				/*
				if (szLowerFileName.empty() && mbiCaller.State == 0x1000)
				{
					dwDetectedType = EaxMappedCode2;
					goto _complete;
				}
				*/
			}

			/*
			auto pCurrentSecHdr = (IMAGE_SECTION_HEADER*)lpCaller;
			if (pCurrentSecHdr && !pCurrentSecHdr->Characteristics)
			{
				dwDetectedType = NullCharacteristics;
				goto _complete;
			}
			*/

		} while (false);

		if (dwDetectedType) {
			HOOK_LOG(LL_ERR, L"Detection triggered with: %u code.", dwDetectedType);
		} else {
			HOOK_LOG(LL_SYS, L"Caller Address checker passed! Address: %p", lpCaller);
		}
		return dwDetectedType;
	}
};
