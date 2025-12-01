#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ManualMapScanner.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"

#ifdef _WIN64
	#define START_ADDRESS (PVOID)0x00000000010000
	#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
	#define START_ADDRESS (PVOID)0x10000
	#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif

namespace NoMercy
{
	CManualMapScanner::CManualMapScanner()
	{
	}
	CManualMapScanner::~CManualMapScanner()
	{
	}

	std::map <LPVOID, DWORD> BuildModuledMemoryMap()
	{
		std::map <LPVOID, DWORD> memoryMap;
		
		HMODULE hMods[1024]{ 0 };
		DWORD cbNeeded = 0;
		if (!g_winAPIs->EnumProcessModules(NtCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
		{
			APP_TRACE_LOG(LL_ERR, L"EnumProcessModules failed with error: %u", g_winAPIs->GetLastError());
			return memoryMap;
		}

		for (std::size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modinfo{ 0 };
			if (g_winAPIs->GetModuleInformation(NtCurrentProcess(), hMods[i], &modinfo, sizeof(modinfo)))
			{
				memoryMap.insert(memoryMap.begin(), std::pair <LPVOID, DWORD>(modinfo.lpBaseOfDll, modinfo.SizeOfImage));
			}
		}

		return memoryMap;
	}
	bool IsMemoryInModuledRange(LPVOID target_base)
	{
		const auto modules = BuildModuledMemoryMap();

		for (const auto& [base, size] : modules)
		{
			if (target_base >= base && target_base <= (LPVOID)((DWORD_PTR)base + size))
				return true;
		}

		return false;
	}
	
	void CManualMapScanner::WatchMemoryAllocations(SScanData* scanData, const void* ptr, size_t length)
	{
		if (!scanData || !ptr)
			return;

		const void* end = (const void*)((const char*)ptr + length);
		do
		{
			MEMORY_BASIC_INFORMATION mbi{ 0 };
			if (!g_winAPIs->VirtualQuery(ptr, &mbi, sizeof(mbi)))
			{
				APP_TRACE_LOG(LL_ERR, L"VirtualQuery failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			if ((mbi.State != MEM_FREE || mbi.State != MEM_RELEASE) && mbi.Type & (MEM_IMAGE | MEM_PRIVATE) && mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))
			{
				if (!IsMemoryInModuledRange((LPVOID)ptr))
				{
					for (DWORD_PTR z = (DWORD_PTR)ptr; z < ((DWORD_PTR)ptr + mbi.RegionSize); z++)
					{
						if (scanData->scanType == EManualMapScanTypes::MMAP_IMPORT_TABLE)
						{
							auto fnSeqCheck = [&z]() {
								bool complete_sequence = false;

								__try
								{
									for (DWORD x = 0; x < (10 * 6); x += 0x6)
									{
										if (*(byte*)(z + x) == 0xFF && *(byte*)(x + z + 0x1) == 0x25)
										{
											complete_sequence = true;
										}
										else
										{
											complete_sequence = false;
										}
									}
								}
								__except (EXCEPTION_EXECUTE_HANDLER)
								{
								}

								return complete_sequence;
							};

							auto complete_sequence = fnSeqCheck();

							if (complete_sequence)
							{
								SManualMapScanCtx mmap;
								mmap.base_address = (LPVOID)ptr;
								mmap.AllocatedBase = mbi.AllocationBase;
								mmap.AllocatedProtect = mbi.AllocationProtect;
								mmap.AllocatedSize = mbi.RegionSize;
								mmap.detectionType = MMAP_IMPORT_TABLE;
								scanData->notifyCallback(&mmap);
								break;
							}
						}
						else if (scanData->scanType == EManualMapScanTypes::MMAP_CRT_STUB)
						{
#ifdef _WIN64
							const auto pattern = xorstr_(L"\x48\x8B\xC4\x48\x89\x58\x20\x4C\x89\x40\x18\x89\x50\x10\x48\x89\x48\x08\x56\x57\x41\x56\x48\x83\xEC\x40\x49\x8B\xF0\x8B\xFA\x4C\x8B\xF1\x85\xD2\x75\x0F\x39\x15\x00\x00\x00\x00\x7F\x07\x33\xC0\xE9\x00\x00\x00\x00");
							const auto wildcard = xorstr_(L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxx????");
#else
							const auto pattern = xorstr_(L"\x6A\x10\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x6A\x00\xE8\x00\x00\x00\x00\x59\x84\xC0\x75\x07");
							const auto wildcard = xorstr_(L"xxx????x????xxx????xxxxx");
#endif

							auto fnPatternCheck = [&z, &pattern, &wildcard]() {
								bool found = false;

								auto dwLength = (DWORD)wcslen(wildcard);
								__try
								{
									for (DWORD j = 0; j < dwLength; j++)
									{
										found &= wildcard[j] == '?' || pattern[j] == *(char*)(z + j);
									}
								}
								__except (EXCEPTION_EXECUTE_HANDLER)
								{
								}

								return found;
							};

							auto found = fnPatternCheck();

							if (found)
							{
								SManualMapScanCtx mmap;
								mmap.base_address = (LPVOID)ptr;
								mmap.AllocatedBase = mbi.AllocationBase;
								mmap.AllocatedProtect = mbi.AllocationProtect;
								mmap.AllocatedSize = mbi.RegionSize;
								mmap.detectionType = MMAP_CRT_STUB;
								scanData->notifyCallback(&mmap);
								break;
							}
						}
						else if (scanData->scanType == EManualMapScanTypes::MMAP_DLL_HEADERS)
						{
							PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(LPVOID)z;
							if (dosHeader && dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
							{
								PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)z + dosHeader->e_lfanew);
								if (NtHeader && NtHeader->Signature == IMAGE_NT_SIGNATURE)
								{
									if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
									{
										SManualMapScanCtx mmap;
										mmap.base_address = (LPVOID)ptr;
										mmap.AllocatedBase = mbi.AllocationBase;
										mmap.AllocatedProtect = mbi.AllocationProtect;
										mmap.AllocatedSize = mbi.RegionSize;
										mmap.detectionType = MMAP_DLL_HEADERS;
										scanData->notifyCallback(&mmap);
										break;
									}
								}
							}
						}
					}
				}
			}
			ptr = (const void*)((const char*)(mbi.BaseAddress) + mbi.RegionSize);

			g_winAPIs->Sleep(10);
		} while (ptr < end);
	}

	void CManualMapScanner::ScanForDllThread(SScanData* scanData)
	{
		auto hSnapshot = g_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!IS_VALID_HANDLE(hSnapshot))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateToolhelp32Snapshot failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		THREADENTRY32 th32{ 0 };
		th32.dwSize = sizeof(th32);

		if (g_winAPIs->Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == g_winAPIs->GetCurrentProcessId() && th32.th32ThreadID != g_winAPIs->GetCurrentThreadId())
				{
					auto targetThread = g_winAPIs->OpenThread(THREAD_QUERY_INFORMATION, FALSE, th32.th32ThreadID);
					if (targetThread)
					{
						DWORD_PTR dwStartAddress = 0x0;
						const auto ntStatus = g_winAPIs->NtQueryInformationThread(targetThread, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(dwStartAddress), nullptr);
						
						if (NT_SUCCESS(ntStatus))
						{
							if (!IsMemoryInModuledRange((LPVOID)dwStartAddress))
							{
								MEMORY_BASIC_INFORMATION mbi{ 0 };
								if (g_winAPIs->VirtualQueryEx(NtCurrentProcess(), (LPCVOID)dwStartAddress, &mbi, sizeof(mbi)))
								{
									SManualMapScanCtx mmap;
									mmap.base_address = (LPVOID)dwStartAddress;
									mmap.AllocatedBase = mbi.AllocationBase;
									mmap.AllocatedProtect = mbi.AllocationProtect;
									mmap.AllocatedSize = mbi.RegionSize;
									mmap.detectionType = MMAP_DLL_THREAD;
									scanData->notifyCallback(&mmap);

									break;
								}
							}
						}

						g_winAPIs->CloseHandle(targetThread);
					}
				}

				g_winAPIs->Sleep(10);
			} while (g_winAPIs->Thread32Next(hSnapshot, &th32));
		}

		g_winAPIs->CloseHandle(hSnapshot);
	}
	void CManualMapScanner::ScanForCheats(SScanData* scanData)
	{
		WatchMemoryAllocations(scanData, START_ADDRESS, END_ADDRESS);
	}
	
	static void CallbackMDE(SManualMapScanCtx* mmap)
	{
		if (!CApplication::InstancePtr() || CApplication::Instance().AppCloseTriggered() || CApplication::Instance().AppIsFinalized())
			return;
		if (!NoMercyCore::CApplication::InstancePtr() || NoMercyCore::CApplication::Instance().IsShuttingDown())
			return;
		if (!IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()) ||
			!IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()))
			return;

		std::wstring strDetectionType;

		switch (mmap->detectionType)
		{
		case MMAP_DLL_HEADERS:
			strDetectionType = xorstr_(L"DLL headers");
			break;
		case MMAP_DLL_THREAD:
			strDetectionType = xorstr_(L"DLL thread");
			break;
		case MMAP_CRT_STUB:
			strDetectionType = xorstr_(L"CRT stub");
			break;
		case MMAP_IMPORT_TABLE:
			strDetectionType = xorstr_(L"Import table");
			break;

		default:
			break;
		}

		wchar_t wszTargetName[MAX_PATH * 2]{ L'\0' };
		g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), mmap->base_address, wszTargetName, MAX_PATH);

//		APP_TRACE_LOG(LL_WARN, L"Mapped module: %p Owner: %s Last error: %u", mmap->base_address, wszTargetName, g_winAPIs->GetLastError());

		const auto stNormalizedName = stdext::to_lower_wide(CProcessFunctions::DosDevicePath2LogicalPath(wszTargetName));
		if (stNormalizedName.empty())
			return;

		if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(stNormalizedName))
		{
			APP_TRACE_LOG(LL_TRACE, L"Ignored system module: %s", stNormalizedName.c_str());
			return;
		}

		std::vector <std::wstring> vecKnownMappedModule;
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()->GetLoadedModuleList(vecKnownMappedModule);

		if (!stdext::in_vector(vecKnownMappedModule, stNormalizedName))
		{
			APP_TRACE_LOG(LL_WARN, L"Mapped module: %p Owner: %s Last error: %u", mmap->base_address, wszTargetName, g_winAPIs->GetLastError());
			
			const auto wstNormalizedName = CProcessFunctions::DosDevicePath2LogicalPath(wszTargetName);
			if (!wstNormalizedName.empty())
			{
				const auto wstLowerExecutable = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath());
				const auto wstLowerNormalizedName = stdext::to_lower_wide(wstNormalizedName);

				if (wstLowerExecutable == wstLowerNormalizedName && mmap->detectionType == MMAP_IMPORT_TABLE)
				{
					APP_TRACE_LOG(LL_WARN, L"Ignored import table of the main executable: %s", wstNormalizedName.c_str());
					return;
				}
			}

			const std::vector <std::wstring> lstWhitelistedModules = {
				xorstr_(L"klhkum."), // kaspersky
				xorstr_(L"\\Config.Msi\\"), // msi *.rbf
				xorstr_(L"Security:x86"), // ucbrowser
				xorstr_(L"pancafe pro client") // net kafe

				// cef.pak
				// cef\GPUCache\index
			};
			
			auto bIsWhitelisted = false;
			for (const auto& stModule : lstWhitelistedModules)
			{
				if (stNormalizedName.find(stModule) != std::wstring::npos)
				{
					APP_TRACE_LOG(LL_SYS, L"Ignored whitelisted module: %s", stNormalizedName.c_str());
					bIsWhitelisted = true;
					break;
				}
			}
			
			if (!bIsWhitelisted)
			{
				APP_TRACE_LOG(LL_ERR, L"Detected manual map at address : 0x%p(%s) | Determined by: %s", mmap->base_address, wszTargetName, strDetectionType.c_str());
			
				auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>();
				if (IS_VALID_SMART_PTR(upProcEnumerator))
				{
					const auto& vecProcList = upProcEnumerator->EnumerateProcesses();
					for (auto& hProcess : vecProcList)
					{
						const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);
						const auto dwParentPID = CProcessFunctions::GetProcessParentProcessId(dwProcessID);
						const auto wstParentName = CProcessFunctions::GetParentProcessName(dwProcessID, true);
						const auto wstProcessName = CProcessFunctions::GetProcessName(hProcess);

						APP_TRACE_LOG(LL_SYS, L"Process: %s(%u) | Parent: %s(%u)", wstProcessName.c_str(), dwProcessID, wstParentName.c_str(), dwParentPID);
					}
					upProcEnumerator.reset();
				}
				
				const auto wstRefID = CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MAPPED_MODULE, mmap->detectionType, wszTargetName);
				if (!wstRefID.empty())
				{
					if (wstNormalizedName.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Failed to normalize path: %s", wszTargetName);
						return;
					}
					CApplication::Instance().OnCheatProcessDetect(wstRefID, NtCurrentProcess(), wstNormalizedName);
				}
			}
		}
	};
	
	DWORD CManualMapScanner::ManualMapScannerThreadProcessor(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Manual map scanner event has been started!");

		const auto lstScanMethods = {
//			MMAP_DLL_HEADERS,
			MMAP_DLL_THREAD,
//			MMAP_CRT_STUB,
			MMAP_IMPORT_TABLE
		};
		
		while (true)
		{
			for (const auto& scanMethod : lstScanMethods)
			{
				SScanData scn{ 0 };
				scn.notifyCallback = std::bind(&CallbackMDE, std::placeholders::_1);
				scn.scanType = scanMethod;

				if (scanMethod == EManualMapScanTypes::MMAP_DLL_THREAD)
					ScanForDllThread(&scn);
				else
					ScanForCheats(&scn);		

				g_winAPIs->Sleep(10);
			}
			
			g_winAPIs->Sleep(30000);
		}

		return 0;
	}

	DWORD WINAPI CManualMapScanner::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CManualMapScanner*>(lpParam);
		return This->ManualMapScannerThreadProcessor();
	}

	bool CManualMapScanner::InitializeThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_MANUAL_MAP_SCANNER, StartThreadRoutine, (void*)this, 0, true);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
	void CManualMapScanner::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_MANUAL_MAP_SCANNER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
