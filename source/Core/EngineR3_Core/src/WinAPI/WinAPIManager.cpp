#include "../../include/PCH.hpp"
#include "../../include/WinAPIManager.hpp"
#include "../../include/SyscallHelper.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/PEHelper.hpp"
#include "../../include/Pe.hpp"
#include "../../include/ApiSetMap.hpp"
#include "../../include/ExitHelper.hpp"
#include "../../include/PEHelper.hpp"
#include "../../include/DirFunctions.hpp"
#include "../../include/AutoFSRedirection.hpp"
#include "../../include/PeSignatureVerifier.hpp"
#include "../../include/FileVersion.hpp"
#include "../../../../Common/StdExtended.hpp"
#include "../../../../Common/GameCodes.hpp"
#include "../../../../Common/BasicCrypt.hpp"
#include <DbgHelp.h>

#define DECLARE_WINMODULE(to, name)\
	g_winModules->to = g_winAPIs->GetModuleHandleW(xorstr_(name));\
	if (!g_winModules->to) {\
		APP_TRACE_LOG(LL_CRI, L"Module (%s) bind fail!", #name);\
		return false;\
	}\
	APP_TRACE_LOG(LL_TRACE, L"Module (%s) bind success! (%p)", #name, g_winModules->to);

#define DECLARE_WINAPI(api)\
	g_winAPIs->api = LI_FN(api).forwarded_safe();\
	if (!g_winAPIs->api) {\
		APP_TRACE_LOG(LL_CRI, L"%s WinAPI could not found.", #api);\
		return false;\
	}\
	APP_TRACE_LOG(LL_TRACE, L"WinAPI (%s) declared succesfully. (%p)", #api, api);

namespace NoMercyCore
{
	extern bool __CheckIATHooks(HMODULE hModule);
	extern bool __CheckEATHooks(HMODULE hModule);
	
	std::shared_ptr <SWinModuleTable>	g_winModules;
	std::shared_ptr <SWinAPITable>		g_winAPIs;

	inline std::wstring __DosDevicePath2LogicalPath(LPCWSTR lpwszDosPath)
	{
		std::wstring wstrResult;
		wchar_t wszTemp[MAX_PATH];
		wszTemp[0] = L'\0';

		if (!lpwszDosPath || !wcslen(lpwszDosPath) || !g_winAPIs->GetLogicalDriveStringsW(_countof(wszTemp) - 1, wszTemp))
			return wstrResult;

		wchar_t wszName[MAX_PATH];
		wchar_t wszDrive[3] = L" :";
		BOOL bFound = FALSE;
		wchar_t* p = wszTemp;

		do {
			// Copy the drive letter to the template string
			*wszDrive = *p;

			// Look up each device name
			if (g_winAPIs->QueryDosDeviceW(wszDrive, wszName, _countof(wszName)))
			{
				UINT uNameLen = (UINT)stdext::CRT::string::_strlen_w(wszName);

				if (uNameLen < MAX_PATH)
				{
					bFound = wcsncmp(lpwszDosPath, wszName, uNameLen) == 0;

					if (bFound)
					{
						// Reconstruct pszFilename using szTemp
						// Replace device path with DOS path
						wchar_t wszTempFile[MAX_PATH]{ L'\0' };
						_snwprintf(wszTempFile, sizeof(wszTempFile), xorstr_(L"%s%s"), wszDrive, lpwszDosPath + uNameLen);
						wstrResult = wszTempFile;
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		} while (!bFound && *p); // end of string

		return wstrResult;
	}

	inline std::wstring ProbeSxSRedirect(std::wstring original_name)
	{
		std::wstring output_name;

		UNICODE_STRING OriginalName{ 0 };
		g_winAPIs->RtlInitUnicodeString(&OriginalName, original_name.c_str());

		wchar_t wszBuf[MAX_PATH * 3]{ L'\0' };
		UNICODE_STRING DllName1{ 0 };
		DllName1.Buffer = wszBuf;
		DllName1.Length = sizeof(wszBuf) / 2;
		DllName1.MaximumLength = sizeof(wszBuf);

		UNICODE_STRING DllName2{ 0 };
		PUNICODE_STRING pPath = nullptr;
		const auto status = g_winAPIs->RtlDosApplyFileIsolationRedirection_Ustr(
			TRUE, &OriginalName, nullptr, &DllName1, &DllName2, &pPath, nullptr, nullptr, nullptr
		);

		if (status == STATUS_SUCCESS)
		{
			output_name = pPath->Buffer;
		}
		else
		{
			// FIXME: STATUS_SXS_KEY_NOT_FOUND 
			APP_TRACE_LOG(LL_ERR, L"RtlDosApplyFileIsolationRedirection_Ustr failed. (%08X)", status);
			g_winAPIs->RtlFreeUnicodeString(&DllName2);
		}

		return output_name;
	}
	inline bool IsGlobalizationNls(const std::wstring& stPath)
	{
		static const auto sc_stNLS = xorstr_(L"\\Windows\\Globalization\\Sorting\\SortDefault.nls");
		return stPath.find(sc_stNLS) != std::wstring::npos;
	}
	static bool IsLibraryFromMalformedPath(HMODULE hModule, std::wstring wstModuleExecutable)
	{
		auto GetPathFromProcessName = [](std::wstring wstBuffer) {
			const auto wstCopyBuffer = wstBuffer;
			const auto nPos = wstCopyBuffer.find_last_of(xorstr_(L"\\/"));
			return wstCopyBuffer.substr(0, nPos);
		};
		auto GetModuleOwnerName = [](LPVOID lpModuleBase) -> std::wstring {
			wchar_t wszFileName[2048]{ L'\0' };
			if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpModuleBase, wszFileName, sizeof(wszFileName) / sizeof(*wszFileName)))
				return {};

			const auto wstDosName = __DosDevicePath2LogicalPath(wszFileName);
			if (wstDosName.empty())
				return {};

			const auto wstLowerDosName = stdext::to_lower_wide(wstDosName);
			return wstLowerDosName;
		};


		if (!hModule || wstModuleExecutable.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Sanity failed!");
			return false;
		}

		if (IsGlobalizationNls(wstModuleExecutable))
		{
			APP_TRACE_LOG(LL_SYS, L"NLS detected and skipped!");
			return false;
		}

		const auto wstModulePath = stdext::to_lower_wide(GetPathFromProcessName(wstModuleExecutable));
		if (wstModulePath.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Module executable path split failed!");
			return false;
		}

		wchar_t wszWindowsPath[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->GetWindowsDirectoryW(wszWindowsPath, MAX_PATH))
		{
			APP_TRACE_LOG(LL_ERR, L"GetWindowsDirectoryW failed. Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		const auto wstLowerWindowsPath = stdext::to_lower_wide(wszWindowsPath);
		const auto wstLowerWinSxsPath = fmt::format(xorstr_(L"{0}\\winsxs\\"), wstLowerWindowsPath);

		wchar_t wszSystemPath[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->GetSystemDirectoryW(wszSystemPath, MAX_PATH))
		{
			APP_TRACE_LOG(LL_ERR, L"GetSystemDirectoryW failed. Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		const auto wstLowerSystemPath = stdext::to_lower_wide(wszSystemPath);

#ifdef _X86_
		std::wstring wstLowerWow64Path;
		if (stdext::is_wow64())
		{
			wchar_t wszWow64Path[MAX_PATH * 2]{ L'\0' };
			const auto hr = g_winAPIs->SHGetFolderPathW(nullptr, CSIDL_SYSTEMX86, nullptr, 0, wszWow64Path);
			if (FAILED(hr))
			{
				APP_TRACE_LOG(LL_ERR, L"SHGetFolderPathW failed. Error: %p", hr);
				return false;
			}
			wstLowerWow64Path = stdext::to_lower_wide(wszWow64Path);
		}
#endif

		wchar_t wszExePath[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->GetProcessImageFileNameW(NtCurrentProcess(), wszExePath, MAX_PATH))
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcessImageFileName failed. Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		const auto wstLowerExePath = stdext::to_lower_wide(wszExePath);

		wchar_t wszSystemDriver[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->GetEnvironmentVariableW(xorstr_(L"SystemDrive"), wszSystemDriver, MAX_PATH))
		{
			APP_TRACE_LOG(LL_ERR, L"GetEnvironmentVariableA failed. Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		const auto wstLowerSystemDriver = stdext::to_lower_wide(wszSystemDriver);

		wchar_t wszSystemDriverDevice[MAX_PATH * 2]{ L'\0' };
		if (!g_winAPIs->QueryDosDeviceW(wszSystemDriver, wszSystemDriverDevice, MAX_PATH))
		{
			APP_TRACE_LOG(LL_ERR, L"QueryDosDeviceA failed. Error: %u", g_winAPIs->GetLastError());
			return false;
		}
		const auto wstLowerSystemDriverDevice = stdext::to_lower_wide(wszSystemDriverDevice);

		const auto wstSystem32Path = fmt::format(xorstr_(L"{0}{1}"), wszSystemDriverDevice, xorstr_(L"\\Windows\\System32\\"));
		const auto wstLowerSystem32Path = stdext::to_lower_wide(wstSystem32Path);

		const auto wstMappedExecutable = GetModuleOwnerName(hModule);
		if (wstMappedExecutable.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Mapped memory detection failed. Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto wstMappedPath = stdext::to_lower_wide(GetPathFromProcessName(wstMappedExecutable));
		if (wstMappedPath.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Mapped memory path split failed!");
			return false;
		}

		// Module memory path validation
		if (wstModuleExecutable.substr(0, wstLowerWinSxsPath.size()) == wstLowerWinSxsPath)
		{
			APP_TRACE_LOG(LL_SYS, L"Target module path matched with SxS path: %s", wstLowerWinSxsPath.c_str());
			
			const auto wstResolvedPath = ProbeSxSRedirect(wstModuleExecutable);
			if (wstResolvedPath.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"SxS redirect probing failed!");
				return false;
			}

			APP_TRACE_LOG(LL_SYS, L"SxS redirect probing succeeded! Resolved path: %ls", wstResolvedPath.c_str());
			wstModuleExecutable = stdext::to_lower_wide(wstResolvedPath);
		}

		if (wstModuleExecutable.substr(0, wstLowerSystem32Path.size()) == wstLowerSystem32Path)
		{
			APP_TRACE_LOG(LL_SYS, L"Target module path matched with NT module path: %s", wstSystem32Path.c_str());
			return false;
		}

		if (wstModuleExecutable.substr(0, wstLowerSystemPath.size()) == wstLowerSystemPath)
		{
			APP_TRACE_LOG(LL_SYS, L"Target module path matched with regular system path: %s", wstLowerSystemPath.c_str());
			return false;
		}

#ifdef _X86_
		if (stdext::is_wow64() &&
			wstModuleExecutable.substr(0, wstLowerWow64Path.size()) == wstLowerWow64Path)
		{
			APP_TRACE_LOG(LL_SYS, L"Target module path matched with wow64 system path: %s", wstLowerWow64Path.c_str());
			return false;
		}
#endif

		if (wstLowerExePath == wstModuleExecutable)
		{
			APP_TRACE_LOG(LL_SYS, L"Target module path matched with executable path: %s", wstLowerExePath.c_str());
			return false;
		}

		// Mapped memory owner path validation
		if (wstMappedPath != wstModulePath)
		{
			if (wstLowerSystemPath != wstMappedPath
#ifdef _X86_
				&& (!wstLowerWow64Path.empty() && wstLowerWow64Path != wstMappedPath)
#endif
				)
			{
				APP_TRACE_LOG(LL_ERR, L"Target mapped memory path is malformed: %s (%s)", wstMappedExecutable.c_str(), wstMappedPath.c_str());
				return true;
			}
		}

		APP_TRACE_LOG(LL_ERR, L"Target module path is malformed: %s (%s)", wstModuleExecutable.c_str(), wstModulePath.c_str());
		return true;
	}

	CWinAPIManager::CWinAPIManager() :
		m_bHasInitialized(false)
	{
		const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe();
		assert(fnGetLastError != nullptr);

		m_spNtAPIHelper = stdext::make_shared_nothrow<CNtAPI>();
		if (!IS_VALID_SMART_PTR(m_spNtAPIHelper))
		{
			APP_TRACE_LOG(LL_ERR, L"m_spNtAPIHelper allocation fail! Error code: %u", fnGetLastError());
			assert(m_spNtAPIHelper != nullptr);
		}
		m_spSyscallHelper = stdext::make_shared_nothrow<CSyscall>();
		if (!IS_VALID_SMART_PTR(m_spSyscallHelper))
		{
			APP_TRACE_LOG(LL_ERR, L"m_spSyscallHelper allocation fail! Error code: %u", fnGetLastError());
			assert(m_spSyscallHelper != nullptr);
		}
	}
	CWinAPIManager::~CWinAPIManager()
	{
		m_bHasInitialized = false;
	}

	bool CWinAPIManager::IsValidHandle(HANDLE hTarget)
	{
		if (hTarget == NtCurrentProcess())
			return true;
		
		auto dwInfo = 0UL;
		if (!hTarget || !g_winAPIs->GetHandleInformation(hTarget, &dwInfo))
			return false;
		return true;
	}
	bool CWinAPIManager::SafeCloseHandle(HANDLE hTarget, bool bIgnoreSanity)
	{
		if (!hTarget)
			return false;

		auto dwInfo = 0UL;
		__try
		{
			if (!bIgnoreSanity)
			{
				if (!g_winAPIs->GetHandleInformation(hTarget, &dwInfo))
					return false;
				if (dwInfo & HANDLE_FLAG_PROTECT_FROM_CLOSE)
					return false;
			}
			
			return g_winAPIs->CloseHandle(hTarget);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	PVOID CWinAPIManager::GetModuleAddressFromName(const std::wstring& wstModuleName, bool bIsCompleteCheck)
	{
		auto IsExistString = [&](const std::wstring& lhs, const std::wstring& rhs, bool bIsCompleteCheck) {
			if (lhs.empty() || rhs.empty())
				return false;

			if (bIsCompleteCheck && rhs == lhs)
				return true;

			if (!bIsCompleteCheck && lhs.find(rhs) != std::wstring::npos)
				return true;

			return false;
		};

		const auto wstLowerModuleName = stdext::to_lower_wide(wstModuleName);

		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			const auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			const auto stCurrModuleName = stdext::to_lower_wide(Current->FullDllName.Buffer);
			if (IsExistString(stCurrModuleName, wstLowerModuleName, bIsCompleteCheck))
				return Current->DllBase;

			CurrentEntry = CurrentEntry->Flink;
		}
		return nullptr;
	}
	std::wstring CWinAPIManager::GetModuleNameFromAddress(DWORD_PTR dwAddress, bool bFullName)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (dwAddress >= (DWORD_PTR)Current->DllBase && dwAddress <= ((DWORD_PTR)Current->DllBase + Current->SizeOfImage))
			{
				return bFullName ?
					std::wstring(Current->FullDllName.Buffer, Current->FullDllName.Length / sizeof(wchar_t)) :
					std::wstring(Current->BaseDllName.Buffer, Current->BaseDllName.Length / sizeof(wchar_t));
			}

			CurrentEntry = CurrentEntry->Flink;
		}
		return {};
	}
	bool CWinAPIManager::IsLoadedModuleBase(DWORD_PTR dwAddress)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (dwAddress == reinterpret_cast<DWORD_PTR>(Current->DllBase))
				return true;

			CurrentEntry = CurrentEntry->Flink;
		}
		return false;
	}
	bool CWinAPIManager::DestroyEntrypoint(DWORD_PTR dwAddress)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (dwAddress == reinterpret_cast<DWORD_PTR>(Current->DllBase))
			{
				Current->EntryPoint = nullptr;
				return true;
			}

			CurrentEntry = CurrentEntry->Flink;
		}
		return false;
	}
	LPVOID CWinAPIManager::GetLdrModule(DWORD_PTR dwAddress)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (dwAddress == reinterpret_cast<DWORD_PTR>(Current->DllBase))
			{
				return Current;
			}

			CurrentEntry = CurrentEntry->Flink;
		}
		return nullptr;
	}
	LPVOID CWinAPIManager::FindOwnModuleFromAddress(DWORD_PTR dwAddress)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (dwAddress >= reinterpret_cast<DWORD_PTR>(Current->DllBase) && dwAddress <= (reinterpret_cast<DWORD_PTR>(Current->DllBase) + Current->SizeOfImage))
			{
				return Current;
			}

			CurrentEntry = CurrentEntry->Flink;
		}
		return nullptr;
	}
	void CWinAPIManager::EnumerateModules(std::function<void(LDR_DATA_TABLE_ENTRY*)> cb)
	{
		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (Current)
				cb(Current);

			CurrentEntry = CurrentEntry->Flink;
		}
	}

	DWORD CWinAPIManager::ModuleCountByAddress(HMODULE hModule)
	{
		DWORD ret = 0;

		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (hModule && hModule == Current->DllBase)
				ret++;

			CurrentEntry = CurrentEntry->Flink;
		}

		return ret;
	}
	std::vector <SDllEntry> CWinAPIManager::DumpModules()
	{
		std::vector <SDllEntry> vecModules;

		DWORD dwBaseAddress = 0, dwPrevBase = 0;

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		while (g_winAPIs->VirtualQuery((void*)dwBaseAddress, &mbi, sizeof(mbi)))
		{
			if (mbi.State != MEM_COMMIT)
				mbi.AllocationBase = 0;

			if (mbi.Type != MEM_IMAGE)
				mbi.AllocationBase = 0;

			if ((DWORD)mbi.AllocationBase == dwPrevBase)
				mbi.AllocationBase = 0;

			if (mbi.AllocationBase && ((DWORD)mbi.AllocationBase == dwBaseAddress))
			{
				wchar_t wszModName[MAX_PATH]{ L'\0' };
				if (g_winAPIs->GetModuleFileNameW((HMODULE)mbi.AllocationBase, wszModName, _countof(wszModName)))
				{
					SDllEntry current;
					current.hModule = (HMODULE)mbi.BaseAddress;
					current.wstModuleName = wszModName;
					vecModules.emplace_back(current);

					dwPrevBase = (DWORD)mbi.AllocationBase;
				}
			}

			dwBaseAddress += mbi.RegionSize;
		}

		return vecModules;
	}
	HMODULE CWinAPIManager::GetBaseAddressFromAddress(LPVOID pvAddress)
	{
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (g_winAPIs->VirtualQuery(pvAddress, &mbi, sizeof(mbi)))
			return reinterpret_cast<HMODULE>(mbi.AllocationBase);
		return nullptr;
	}
	std::wstring CWinAPIManager::GetMappedNameNative(HANDLE hProcess, HMODULE hModule)
	{
		wchar_t wszMappedName[MAX_PATH * 2]{ L'\0' }; // * 2 extra space for dos device path addition
		if (g_winAPIs->GetMappedFileNameW(hProcess, hModule, wszMappedName, MAX_PATH))
			return __DosDevicePath2LogicalPath(wszMappedName);;
		return {};
	}


	static HMODULE __SafeLoadSystemLibrary(const std::wstring& wstFileName)
	{
		static const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe_cached();
		if (!fnGetLastError)
		{
			APP_TRACE_LOG(LL_CRI, L"GetLastError function not found in exported API list!");
			return nullptr;
		}

		static const auto fnGetModuleHandleW = LI_FN(GetModuleHandleW).forwarded_safe_cached();
		if (!fnGetModuleHandleW)
		{
			APP_TRACE_LOG(LL_CRI, L"GetModuleHandleW function not found in exported API list!");
			return nullptr;
		}

		static const auto fnGetProcAddress = LI_FN(GetProcAddress).forwarded_safe_cached();
		if (!fnGetProcAddress)
		{
			APP_TRACE_LOG(LL_CRI, L"GetProcAddress function not found in exported API list!");
			return nullptr;
		}

		static const auto fnLoadLibraryExW = LI_FN(LoadLibraryExW).forwarded_safe_cached();
		if (!fnLoadLibraryExW)
		{
			APP_TRACE_LOG(LL_CRI, L"LoadLibraryExW function not found in exported API list!");
			return nullptr;
		}

		static const auto fnGetSystemDirectoryW = LI_FN(GetSystemDirectoryW).forwarded_safe_cached();
		if (!fnGetSystemDirectoryW)
		{
			APP_TRACE_LOG(LL_CRI, L"GetSystemDirectoryW function not found in exported API list!");
			return nullptr;
		}

		static const auto hKernel32 = fnGetModuleHandleW(xorstr_(L"kernel32.dll"));
		if (!hKernel32)
		{
			APP_TRACE_LOG(LL_CRI, L"Get Kernel32.dll handle failed with error: %u", fnGetLastError());
			return nullptr;
		}

		// Check for the presence of AddDllDirectory as a proxy for checking whether
		// the LoadLibraryEx LOAD_LIBARY_SEARCH_SYSTEM32 flag is supported.
		// On Windows 8+, support is built-in.
		// On Windows 7, Windows Server 2008 R2, Windows Vista and Windows Server 2008,
		// support is available if KB2533623 is installed.
		if (fnGetProcAddress(hKernel32, xorstr_("AddDllDirectory")))
		{
			// LOAD_LIBARY_SEARCH_SYSTEM32 is available
			return fnLoadLibraryExW(wstFileName.c_str(), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		}
		else
		{
			// LOAD_LIBARY_SEARCH_SYSTEM32 is unavailable - attempt to create full path to system folder
			wchar_t wszSysDir[MAX_PATH * 2]{ L'\0' };
			if (!fnGetSystemDirectoryW(wszSysDir, MAX_PATH))
			{
				APP_TRACE_LOG(LL_CRI, L"fnGetSystemDirectoryA(2) failed with error: %u", fnGetLastError());
				return nullptr;
			}

			const auto wstModulePath = fmt::format(xorstr_(L"{0}\\{1}"), wszSysDir, wstFileName);
			const auto hModule = fnLoadLibraryExW(wstModulePath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
			APP_TRACE_LOG(hModule ? LL_SYS : LL_ERR, L"Module: %s Ptr: %p Last error: %u", wstModulePath.c_str(), hModule, fnGetLastError());

			return hModule;
		}
	}

	static HMODULE WINAPI __MyGetModuleHandle(_In_ LPCWSTR lpModuleName)
	{
		static const auto GetModuleByPeb = [&](const std::wstring& wstModuleName) -> HMODULE
		{
			const auto wstLowerName = stdext::to_lower_wide(wstModuleName);
			if (wstLowerName.size())
			{
				const auto pPEB = NtCurrentPeb();
				if (pPEB)
				{
					auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
					while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
					{
						const auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (Current)
						{
							const auto wstCurrentName = stdext::to_lower_wide(Current->BaseDllName.Buffer);
							if (wstCurrentName == wstLowerName)
							{
								return reinterpret_cast<HMODULE>(Current->DllBase);
							}
						}
						CurrentEntry = CurrentEntry->Flink;
					}
				}
			}
			return nullptr;
		};

		APP_TRACE_LOG(LL_TRACE, L"__MyGetModuleHandle called for: %s", lpModuleName ? lpModuleName : xorstr_(L"<NULL>"));

		auto hTmpModule = g_winAPIs->GetModuleHandleW_o(lpModuleName);
		if (!hTmpModule)
		{
			const auto dwLastError = g_winAPIs->GetLastError();
			const auto bIsKnownError = dwLastError == ERROR_MOD_NOT_FOUND;
			APP_TRACE_LOG(bIsKnownError ? LL_WARN : LL_ERR, L"GetModuleHandleA fail! Module: %s Return code: %u", lpModuleName, dwLastError);

			hTmpModule = __SafeLoadSystemLibrary(lpModuleName);
			if (!hTmpModule)
			{
				APP_TRACE_LOG(LL_ERR, L"LoadLibraryExA Step 1 fail! Module: %s Error code: %u", lpModuleName, g_winAPIs->GetLastError());
			}
			else
			{
				CApplication::Instance().WinAPIManagerInstance()->AddModuleToSelfLoadedModuleList(hTmpModule);
			}
		}

		// hTmpModule = g_winAPIs->LoadLibraryExW(lpModuleName, nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
		if (!hTmpModule)
		{
			// APP_TRACE_LOG(LL_ERR, L"LoadLibraryExA Step 2 fail! Module: %s Error code: %u", lpModuleName, g_winAPIs->GetLastError());
			std::vector <std::wstring> vecOptionalModules = {
				xorstr_(L"w32time.dll"),
				xorstr_(L"srclient.dll"),
				xorstr_(L"ucrtbase.dll"),
				xorstr_(L"tbs.dll")
			};

			const auto wstLowerModuleName = stdext::to_lower_wide(lpModuleName);

			if (wcsstr(wstLowerModuleName.c_str(), xorstr_(L"python")))
			{
				APP_TRACE_LOG(LL_WARN, L"Python module could not found!");
				return nullptr;
			}
			else if (stdext::in_vector(vecOptionalModules, wstLowerModuleName))
			{
				APP_TRACE_LOG(LL_WARN, L"Optional module: %s could not found!", lpModuleName);
				return nullptr;
			}

			APP_TRACE_LOG(LL_ERR, L"Module: %s not found!", lpModuleName);
			OnPreFail(0, CORE_ERROR_WIN_MODULE_NOT_FOUND, g_winAPIs->GetLastError(), lpModuleName);
			return nullptr;
		}

		// Add current module to module list
		if (hTmpModule && !CApplication::Instance().WinAPIManagerInstance()->IsModuleExistOnModuleList(hTmpModule))
			CApplication::Instance().WinAPIManagerInstance()->AddModuleToModuleList(hTmpModule);

		// Check routine
		const auto lpMemoryCachePtr = GetModuleByPeb(lpModuleName);
		if (lpMemoryCachePtr && lpMemoryCachePtr != hTmpModule)
		{
			APP_TRACE_LOG(LL_ERR, L"Module manipulation detected: %s | %p-%p", lpModuleName, lpMemoryCachePtr, hTmpModule);

			OnPreFail(0, CORE_ERROR_WIN_MODULE_MANIPULATION_DETECTED, g_winAPIs->GetLastError(), lpModuleName);
			return nullptr;
		}
		// Store text section
		LPVOID lpTextBase = nullptr;
		SIZE_T cbTextSize = 0;
		if (!CPEFunctions::GetTextSectionInformation(hTmpModule, &lpTextBase, &cbTextSize))
		{
			const auto wstLowerModuleName = stdext::to_lower_wide(lpModuleName);

			const std::vector <std::wstring> vecTextSectionWhiteList = {
				xorstr_(L"sfc.dll")
			};
			auto bIsWhiteListed = false;
			for (const auto& wstWhiteList : vecTextSectionWhiteList)
			{
				if (wstLowerModuleName.find(wstWhiteList) != std::wstring::npos)
				{
					bIsWhiteListed = true;
					break;
				}
			}

			if (!bIsWhiteListed)
			{
				APP_TRACE_LOG(LL_ERR, L"ERROR! Module: %s text section is not found!", lpModuleName);

				OnPreFail(0, CORE_ERROR_WIN_MODULE_TEXT_SECTION_NOT_FOUND, g_winAPIs->GetLastError(), lpModuleName);
				return nullptr;
			}
		}
		CApplication::Instance().WinAPIManagerInstance()->RegisterModuleTextSection(hTmpModule, lpTextBase, cbTextSize);

		APP_TRACE_LOG(LL_TRACE, L"__MyGetModuleHandle %s -> %p", lpModuleName, hTmpModule);
		return hTmpModule;
	}


	PVOID CWinAPIManager::GetRealAddress(PVOID pAddress)
	{
#ifdef _M_IX86
		if (*(PBYTE)pAddress == 0xE9 || *(PBYTE)pAddress == 0xE8)
			return Relative2Absolute(pAddress, 1, 5);

		if (*(PBYTE)pAddress == 0x68 && *((PBYTE)pAddress + 5) == 0xC3)
			return GetAbsolutePtr(pAddress, 1);

		if (*(PBYTE)pAddress == 0xB8 && *(PWORD)((PBYTE)pAddress + 5) == 0xE0FF)
			return GetAbsolutePtr(pAddress, 1);

		if (*(PWORD)pAddress == 0xFF2E)
			return GetAbsolutePtr(pAddress, 2);

#elif _M_X64

		if (*(PBYTE)pAddress == 0xE9)
			return Relative2Absolute(pAddress, 1, 5);

		if (*(PWORD)pAddress == 0xB849 && *(PWORD)((PBYTE)pAddress + 10) == 0xE0FF)
			return GetAbsolutePtr(pAddress, 2);

		if (*(PWORD)pAddress == 0x25FF && *(PULONG)((PBYTE)pAddress + 2) == 0x00000000)
			return GetAbsolutePtr(pAddress, 6);

		if (*(PWORD)pAddress == 0xB848 && *(PWORD)((PBYTE)pAddress + 10) == 0xC350)
			return GetAbsolutePtr(pAddress, 2);
#endif

		return pAddress;
	}

	bool CWinAPIManager::InModuleRange(HMODULE hModule, DWORD_PTR dwAddress)
	{
		auto bRet = false;

		const auto fnGetModuleInformation = LI_FN(GetModuleInformation).forwarded_safe_cached();
		if (!fnGetModuleInformation)
			return bRet;

		MODULEINFO mi = { 0 };
		if (fnGetModuleInformation(NtCurrentProcess(), hModule, &mi, static_cast<DWORD>(sizeof(mi))))
		{
			const auto dwBase = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll);
			const auto dwHi = reinterpret_cast<DWORD_PTR>(mi.lpBaseOfDll) + mi.SizeOfImage;

			bRet = (dwAddress >= dwBase && dwAddress <= dwHi);
		}
		return bRet;
	}

	static FARPROC WINAPI __MyGetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
	{
		static auto __GetProcAddressEx = [](_In_ HMODULE hModule, _In_ LPCSTR lpProcName) {
			auto pvAPIptr = static_cast<FARPROC>(CApplication::Instance().WinAPIManagerInstance()->NTHelper()->GetProcAddress(hModule, lpProcName));
			if (!pvAPIptr)
				pvAPIptr = static_cast<FARPROC>(CPEFunctions::GetExportEntry(hModule, lpProcName));

			return pvAPIptr;
		};

		APP_TRACE_LOG(LL_TRACE, L"__MyGetProcAddress called for: %p!%hs", hModule, lpProcName);

		// At the first try load kernel32 APIs from kernelbase
		auto bKernel32Switched = false;
		if (hModule == g_winModules->hKernel32 && g_winModules->hKernelbase)
		{
			hModule = g_winModules->hKernelbase;
			bKernel32Switched = true;
		}

		// Try load
		auto pvAPIptr = __GetProcAddressEx(hModule, lpProcName);

		// Seems like API doesn't exist in kernelbase, revert to kernel32
		if (!pvAPIptr && bKernel32Switched)
		{
			hModule = g_winModules->hKernel32;
			pvAPIptr = __GetProcAddressEx(hModule, lpProcName);
		}
		
		// query name
		const auto stModuleName = CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)hModule);

		// check load ret
		const auto wstAPIName = stdext::to_wide(lpProcName);
		if (!pvAPIptr)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! %s!%hs Windows API not initialized!", stModuleName.c_str(), lpProcName);

			// optional
			if (!strcmp(lpProcName, xorstr_("BcdSetLogging")))
				return nullptr;

			OnPreFail(0, CORE_ERROR_WIN_API_INIT_FAIL, g_winAPIs->GetLastError(), wstAPIName);
			return nullptr;
		}

		// sanitize check
		if (CApplication::Instance().WinAPIManagerInstance()->HasInitialized() == false)
		{
			const auto wstModuleName = CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)hModule);
			APP_TRACE_LOG(LL_TRACE, L"Getprocaddress called for: %s!%hs Address: %p", wstModuleName.c_str(), lpProcName, pvAPIptr);

			// out of bound module
			auto iStep = 0;
			while (CApplication::Instance().WinAPIManagerInstance()->InModuleRange(hModule, reinterpret_cast<DWORD_PTR>(pvAPIptr)) == false)
			{
				const auto pRedirectPtr = (FARPROC)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetRealAddress(pvAPIptr);
				if (pRedirectPtr == pvAPIptr)
					break;

				auto szRealOwner = CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress(reinterpret_cast<DWORD_PTR>(pRedirectPtr));
				APP_TRACE_LOG(LL_WARN, L"[1] Hook detected! API: %hs Hooked address: %p Real Address: %p Owner: %s Step: %d", lpProcName, pvAPIptr, pRedirectPtr, szRealOwner.c_str(), iStep++);
				pvAPIptr = pRedirectPtr;
			}

			// instruction based hook
			auto iStep2 = 0;
			auto fpRealAddress = (FARPROC)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetRealAddress(pvAPIptr);
			while (fpRealAddress != pvAPIptr)
			{
				auto szRealOwner = CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress(reinterpret_cast<DWORD_PTR>(fpRealAddress));
				APP_TRACE_LOG(LL_WARN, L"[2] Hook detected! API: %hs Hooked address: %p Real Address: %p Owner: %s Step: %d", lpProcName, pvAPIptr, fpRealAddress, szRealOwner.c_str(), iStep2++);
				pvAPIptr = fpRealAddress;
				fpRealAddress = (FARPROC)NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetRealAddress(pvAPIptr);
			}

			// text section
			if (CApplication::Instance().WinAPIManagerInstance()->HasModuleTextSectionInfo(hModule))
			{
				const auto spTextCtx = CApplication::Instance().WinAPIManagerInstance()->GetModuleTextSectionInfo(hModule);
				if (IS_VALID_SMART_PTR(spTextCtx))
				{
					const auto dwApiAddr = reinterpret_cast<DWORD_PTR>(pvAPIptr);
					const auto dwTextAddr = reinterpret_cast<DWORD_PTR>(spTextCtx->lpBase);
					const auto dwTextSize = spTextCtx->cbSize;

					if (!(dwApiAddr >= dwTextAddr && dwApiAddr < dwTextAddr + dwTextSize))
					{
						APP_TRACE_LOG(LL_ERR, L"API: %hs Address: %p Owner: %s Text: %p/%p (%u)",
							lpProcName, pvAPIptr, stModuleName.c_str(), dwTextAddr, dwTextAddr + dwTextSize, dwTextSize
						);
						
						OnPreFail(0, CORE_ERROR_WIN_API_INTEGRITY_FAIL, 1, wstAPIName);
						return nullptr;
					}
				}
			}
		}

		if (!CApplication::Instance().WinAPIManagerInstance()->IsCheckedWinAPI(wstAPIName))
		{
			constexpr auto BACKUP_SIZE = 5;
			auto lpBackup = new(std::nothrow) BYTE[BACKUP_SIZE];
			if (!lpBackup)
			{
				APP_TRACE_LOG(LL_ERR, L"ERROR! Failed to allocate memory for backup!");
				return pvAPIptr;
			}

			memcpy(lpBackup, pvAPIptr, BACKUP_SIZE);

			auto pNullByte = { 0x0 };
			if (!memcmp(lpBackup, &pNullByte, BACKUP_SIZE))
			{
				APP_TRACE_LOG(LL_ERR, L"ERROR! %s!%hs Windows API backup can not created!", stModuleName.c_str(), lpProcName);
			}
			else
			{
				const auto wstBackup = stdext::dump_hex(lpBackup, BACKUP_SIZE);

				const auto pkAPIData = new (std::nothrow) SWinAPIEntry{ pvAPIptr , wstAPIName };
				if (pkAPIData)
				{
					CApplication::Instance().WinAPIManagerInstance()->AddWinAPIBackup(pkAPIData, lpBackup);
					APP_TRACE_LOG(LL_TRACE, L"%hs WinAPI Backup created: %s", lpProcName, wstBackup.c_str());
				}
			}
		}

		return pvAPIptr;
	}

	FARPROC CWinAPIManager::GetProcAddressSafe(LPCWSTR lpszModuleName, LPCWSTR lpszProcName)
	{
		if (!m_bHasInitialized)
			return nullptr;

		const auto hModule = m_spSecureLoadLibrary->Find(lpszModuleName);
		if (!hModule)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! Module %s secure copy does not exist!", lpszModuleName);
			return nullptr;
		}
		
		const auto pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"[DOS] Module %s is not a valid PE file!", lpszModuleName);
			return nullptr;
		}

		const auto pINH32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<LPBYTE>(hModule) + pIDH->e_lfanew);
		const auto pINH64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<LPBYTE>(hModule) + pIDH->e_lfanew);
		if (pINH32->Signature != IMAGE_NT_SIGNATURE && pINH64->Signature != IMAGE_NT_SIGNATURE)
		{
			APP_TRACE_LOG(LL_ERR, L"[NT] Module %s is not a valid PE file! Signature: %u / %u", lpszModuleName, pINH32->Signature, pINH64->Signature);
			return nullptr;
		}

		PIMAGE_EXPORT_DIRECTORY pIED = nullptr;
		if (pINH32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			pIED = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<LPBYTE>(hModule) +
				pINH32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			);
		}
		else
		{
			pIED = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<LPBYTE>(hModule) +
				pINH64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			);
		}

		const auto pFunctionTable = reinterpret_cast<LPDWORD>(reinterpret_cast<LPBYTE>(hModule) + pIED->AddressOfFunctions);
		const auto pNameTable = reinterpret_cast<LPDWORD>(reinterpret_cast<LPBYTE>(hModule) + pIED->AddressOfNames);
		const auto pOrdinalTable = reinterpret_cast<LPWORD>(reinterpret_cast<LPBYTE>(hModule) + pIED->AddressOfNameOrdinals);

		if (!pFunctionTable || !pNameTable || !pOrdinalTable)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! Module %s PE import table is corrupted!", lpszModuleName);
			return nullptr;
		}

		for (SIZE_T i = 0; i < pIED->NumberOfNames; ++i)
		{
			const auto function_name = reinterpret_cast<PCCH>(hModule) + static_cast<DWORD_PTR>(pNameTable[i]);
			if (stdext::hash(function_name) == stdext::hash(lpszProcName))
				return reinterpret_cast<FARPROC>(reinterpret_cast<LPBYTE>(hModule) + pFunctionTable[pOrdinalTable[i]]);
		}

		return nullptr;
	}

	bool CWinAPIManager::PatchModuleHook(LPCWSTR lpszModuleName, LPCWSTR lpszProcName)
	{
		auto __PatchModuleName = [](const std::wstring& wstModuleName) -> std::wstring {
			const auto wstSysPath		= stdext::to_lower_wide(CApplication::Instance().DirFunctionsInstance()->SystemPath());
			const auto wstSysWow64Path	= stdext::to_lower_wide(CApplication::Instance().DirFunctionsInstance()->SystemPath2());

			auto wstFixedModuleName = stdext::to_lower_wide(wstModuleName);
			if (stdext::starts_with(wstFixedModuleName, wstSysPath))
			{
				wstFixedModuleName = stdext::replace(wstFixedModuleName, wstSysPath, wstSysWow64Path);
				APP_TRACE_LOG(LL_TRACE, L"Patched module name: '%s' >> '%s'", wstModuleName.c_str(), wstFixedModuleName.c_str());
			}
			else
			{
				APP_TRACE_LOG(LL_WARN, L"Module: '%s' is not suitable for patch! Sys paths: '%s'/'%s'", wstFixedModuleName.c_str(), wstSysPath.c_str(), wstSysWow64Path.c_str());
			}

			return wstFixedModuleName;
		};

		auto __GetFuncSize = [](HMODULE hModule, FARPROC pFunc) -> DWORD
		{
#if defined _M_IX86
			return CPEFunctions::GetFunctionSize(pFunc);
#else
			const auto func_data = g_winAPIs->RtlLookupFunctionEntry((DWORD64)pFunc, (DWORD64*)hModule, nullptr);
			if (func_data)
			{
				return func_data->EndAddress - func_data->BeginAddress;
			}
			return 5;
#endif
		};

		if (!lpszModuleName || !*lpszModuleName || !lpszProcName || !*lpszProcName)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Patching hook %s:%s", lpszModuleName, lpszProcName);
	
		if (stdext::starts_with(std::wstring(lpszProcName), std::wstring(xorstr_(L"0x"))))
			return false;

		if (!m_bHasInitialized)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! WinAPIManager is not initialized!");
			return false;
		}

		const auto hModule = g_winAPIs->GetModuleHandleW_o(lpszModuleName);
		if (!hModule)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! Module %s does not exist!", lpszModuleName);
			return false;
		}
		
		const auto stAPIName = stdext::to_ansi(lpszProcName);
		const auto pUnsafeFunc = g_winAPIs->GetProcAddress_o(hModule, stAPIName.c_str());
		if (!pUnsafeFunc)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! API %s:%s does not exist!", lpszModuleName, lpszProcName);
			return false;
		}

		const auto wstFixedModuleName = __PatchModuleName(lpszModuleName);
		APP_TRACE_LOG(LL_SYS, L"Original function %s(%s):%s at %p", lpszModuleName, wstFixedModuleName.c_str(), lpszProcName, pUnsafeFunc);

		const auto pSafeFunc = this->GetProcAddressSafe(wstFixedModuleName.c_str(), lpszProcName);
		if (!pSafeFunc)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! API %s:%s real address can not found!", wstFixedModuleName.c_str(), lpszProcName);
			return false;
		}
		
		const auto pFuncSize = __GetFuncSize(hModule, pSafeFunc);
		if (!pFuncSize || pFuncSize > 16)
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! API %s:%s size: %u can not validated!", lpszModuleName, lpszProcName, pFuncSize);
			return false; 
		}

		APP_TRACE_LOG(LL_TRACE, L"Safe function %s:%s at %p with size: %u", lpszModuleName, lpszProcName, pSafeFunc, pFuncSize);

		MEMORY_BASIC_INFORMATION mbi{ 0 };
		if (!g_winAPIs->VirtualQuery(pUnsafeFunc, &mbi, sizeof(mbi)))
		{
			APP_TRACE_LOG(LL_ERR, L"ERROR! API %s:%s memory can not queried! Error: %u", lpszModuleName, lpszProcName, g_winAPIs->GetLastError());
			return false;
		}

		auto bProtectionChanged = false;
		DWORD dwOldProtect = 0;
		if (mbi.Protect & PAGE_GUARD || mbi.Protect == PAGE_NOACCESS)
		{
			APP_TRACE_LOG(LL_WARN, L"Suspicious protection for %s!%s (%p) >> %p", lpszModuleName, lpszProcName, pUnsafeFunc, mbi.Protect);

			if (!g_winAPIs->VirtualProtect(pUnsafeFunc, pFuncSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				APP_TRACE_LOG(LL_ERR, L"ERROR! API %s:%s memory protection can not changed! Error: %u", lpszModuleName, lpszProcName, g_winAPIs->GetLastError());
				return false;
			}

			bProtectionChanged = true;
		}
		
		auto result = g_winAPIs->RtlCompareMemory(pUnsafeFunc, pSafeFunc, pFuncSize);
		if (result != pFuncSize) // hooked
		{
			const auto wstSafeDump = stdext::dump_hex((const uint8_t*)pSafeFunc, pFuncSize);
			const auto wstUnsafeDump = stdext::dump_hex((const uint8_t*)pUnsafeFunc, pFuncSize);

			APP_TRACE_LOG(LL_WARN, L"API %s:%s is hooked! Correct: %s Current: %s", lpszModuleName, lpszProcName, wstSafeDump.c_str(), wstUnsafeDump.c_str());
			
			if (!bProtectionChanged)
			{
				if (!g_winAPIs->VirtualProtect(pUnsafeFunc, pFuncSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					APP_TRACE_LOG(LL_ERR, L"VirtualProtect (1) failed for: %s:%s with error: %u", lpszModuleName, lpszProcName, g_winAPIs->GetLastError());
					return false;
				}

				bProtectionChanged = true;
			}
			
			SIZE_T cbWrittenSize = 0;
			if (!g_winAPIs->WriteProcessMemory(NtCurrentProcess(), pUnsafeFunc, pSafeFunc, pFuncSize, &cbWrittenSize) || cbWrittenSize != pFuncSize)
			{
				APP_TRACE_LOG(LL_ERR, L"WriteProcessMemory failed for: %s:%s with error: %u, Written size: %u Func size: %u",
					lpszModuleName, lpszProcName, g_winAPIs->GetLastError(), cbWrittenSize, pFuncSize
				);
				return false;
			}
			
			result = g_winAPIs->RtlCompareMemory(pUnsafeFunc, pSafeFunc, pFuncSize);
			const auto bCompleted = result == pFuncSize;
			
			if (bProtectionChanged)
			{
				if (!g_winAPIs->VirtualProtect(pUnsafeFunc, pFuncSize, dwOldProtect, &dwOldProtect))
				{
					APP_TRACE_LOG(LL_ERR, L"VirtualProtect (2) failed for: %s:%s with error: %u", lpszModuleName, lpszProcName, g_winAPIs->GetLastError());
					return false;
				}

				bProtectionChanged = false;
			}
			
			if (bCompleted)
			{
				APP_TRACE_LOG(LL_TRACE, L"API %s:%s hook is patched!", lpszModuleName, lpszProcName);
				return true;
			}
			
			APP_TRACE_LOG(LL_ERR, L"API %s:%s hook could not patched!", lpszModuleName, lpszProcName);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Module %s function %s is not hooked!", lpszModuleName, lpszProcName);
		return true;
	}
	
	bool CWinAPIManager::IsBadReadPtr(const void* lpTargetAddr, std::size_t cbCheckSize)
	{ 
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		g_winAPIs->VirtualQuery(lpTargetAddr, &mbi, sizeof(mbi));
		
		return
			!!g_winAPIs->GetLastError() ||
			!(mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE);
	}

	ULONG_PTR CWinAPIManager::GetFunctionAddressPDB(const HMODULE c_hModule, const WCHAR* c_wszApiName)
	{
		if (!c_hModule)
			return 0;

		if (!c_wszApiName || !*c_wszApiName)
			return 0;

		const auto fnSymName = LI_FN(SymFromNameW).forwarded_safe_cached();
		if (!fnSymName)
			return 0;

		BYTE memory[0x2000]{ 0 };
		SYMBOL_INFOW* syminfo = (SYMBOL_INFOW*)memory;
		syminfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
		syminfo->MaxNameLen = MAX_SYM_NAME;
		syminfo->ModBase = (ULONG_PTR)c_hModule;

		if (!fnSymName(NtCurrentProcess(), c_wszApiName, syminfo))
		{
			APP_TRACE_LOG(LL_ERR, L"SymFromName %ls returned error: %u", c_wszApiName, g_winAPIs->GetLastError());
			return 0;
		}

		return (ULONG_PTR)syminfo->Address;
	}
	bool CWinAPIManager::GetFunctionNameFromAddress(HANDLE hProcess, LPVOID pModuleBase, LPVOID pObject, std::wstring& stFuncName)
	{
		constexpr auto STACKWALK_MAX_NAMELEN = 1024;
		BOOL bRet = FALSE;

		const auto options = g_winAPIs->SymGetOptions();
		g_winAPIs->SymSetOptions(options & ~SYMOPT_UNDNAME);

		if (!g_winAPIs->SymInitialize(NtCurrentProcess(), nullptr, true))
		{
			APP_TRACE_LOG(LL_TRACE, L"SymInitialize fail! Error: %u", g_winAPIs->GetLastError());
			// return false;
		}
		
		auto pSym = (IMAGEHLP_SYMBOL64*)CMemHelper::Allocate(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN + 1);
		if (pSym)
		{
			pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
			pSym->MaxNameLength = 128;

			std::string stBuffer;

			auto dwDisplacement64 = 0ULL;
			bRet = g_winAPIs->SymGetSymFromAddr64(hProcess, (DWORD64)pObject, &dwDisplacement64, pSym);
			if (!bRet)
			{
				APP_TRACE_LOG(LL_TRACE, L"SymGetSymFromAddr64 returned error: %u", g_winAPIs->GetLastError());
				stBuffer = stdext::pointer_to_string_a((uintptr_t)pObject - (uintptr_t)pModuleBase);
			}
			else
			{
#ifdef _DEBUG
				APP_TRACE_LOG(LL_TRACE, L"SymGetSymFromAddr64 returned: %s", pSym->Name);
#endif
				stBuffer = dwDisplacement64 ? fmt::format(xorstr_("{0}+{1}"), pSym->Name, stdext::pointer_to_string_a(dwDisplacement64)) : pSym->Name;
			}

			stFuncName = stdext::to_wide(stBuffer);

			CMemHelper::Free(pSym);
			pSym = nullptr;
		}
		
		g_winAPIs->SymSetOptions(options);
		return bRet;
	};


	bool CWinAPIManager::BindBaseAPIs()
	{
		g_winAPIs->GetProcAddress = __MyGetProcAddress;
		if (!g_winAPIs->GetProcAddress)
		{
			APP_TRACE_LOG(LL_ERR, L"__MyGetProcAddress not found!");
			return false;
		}

		g_winAPIs->GetProcAddress_o = LI_FN(GetProcAddress).forwarded_safe();
		if (!g_winAPIs->GetProcAddress_o)
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcAddress_o not found!");
			return false;
		}

		g_winAPIs->GetModuleHandleW = __MyGetModuleHandle;
		if (!g_winAPIs->GetModuleHandleW)
		{
			APP_TRACE_LOG(LL_ERR, L"__MyGetModuleHandle not found!");
			return false;
		}

		g_winAPIs->GetModuleHandleW_o = LI_FN(GetModuleHandleW).forwarded_safe();
		if (!g_winAPIs->GetModuleHandleW_o)
		{
			APP_TRACE_LOG(LL_ERR, L"GetModuleHandleW_o not found!");
			return false;
		}

		g_winAPIs->LoadLibraryW = LI_FN(LoadLibraryW).forwarded_safe();
		if (!g_winAPIs->LoadLibraryW)
		{
			APP_TRACE_LOG(LL_ERR, L"LoadLibraryW not found!");
			return false;
		}

#pragma warning(push)
#pragma warning(disable: 4996) // warning C4996: 'GetVersionExA': was declared deprecated
		DECLARE_WINAPI(GetVersionExW);
#pragma warning(pop)
		DECLARE_WINAPI(GetLastError);
		DECLARE_WINAPI(GetHandleInformation);
		DECLARE_WINAPI(CloseHandle);
		DECLARE_WINAPI(VirtualQuery);
		DECLARE_WINAPI(GetModuleFileNameW);
		DECLARE_WINAPI(LoadLibraryExW);
		DECLARE_WINAPI(GetSystemDirectoryW);
		DECLARE_WINAPI(VerSetConditionMask);
		DECLARE_WINAPI(VerifyVersionInfoW);
		DECLARE_WINAPI(RtlGetVersion);
		DECLARE_WINAPI(RtlInitAnsiString);
		DECLARE_WINAPI(LdrGetProcedureAddress);
		DECLARE_WINAPI(RtlImageDirectoryEntryToData);

		if (stdext::is_wow64())
		{
			DECLARE_WINAPI(Wow64DisableWow64FsRedirection);
			DECLARE_WINAPI(Wow64RevertWow64FsRedirection);
		}
		
		return true;
	}
	
	bool CWinAPIManager::BindModules()
	{
		DECLARE_WINMODULE(hKernel32, L"kernel32.dll");
		DECLARE_WINMODULE(hNtdll, L"ntdll.dll");
		DECLARE_WINMODULE(hUser32, L"user32.dll");
		DECLARE_WINMODULE(hPsapi, L"psapi.dll");
		DECLARE_WINMODULE(hDbghelp, L"dbghelp.dll");
		DECLARE_WINMODULE(hAdvapi32, L"advapi32.dll");
		DECLARE_WINMODULE(hWininet, L"wininet.dll");
		DECLARE_WINMODULE(hWinsta, L"winsta.dll");
		DECLARE_WINMODULE(hShlwapi, L"shlwapi.dll");
		DECLARE_WINMODULE(hShell32, L"shell32.dll");
		DECLARE_WINMODULE(hCrypt32, L"crypt32.dll");
		DECLARE_WINMODULE(hWs2_32, L"ws2_32.dll");
		DECLARE_WINMODULE(hIphlpapi, L"iphlpapi.dll");
		DECLARE_WINMODULE(hMpr, L"mpr.dll");
		DECLARE_WINMODULE(hWintrust, L"wintrust.dll");
		DECLARE_WINMODULE(hDnsapi, L"DNSAPI.dll");
		DECLARE_WINMODULE(hOle32, L"ole32.dll");
		DECLARE_WINMODULE(hGdi32, L"gdi32.dll");
		DECLARE_WINMODULE(hUserEnv, L"Userenv.dll");
		DECLARE_WINMODULE(hWinmm, L"winmm.dll");
		DECLARE_WINMODULE(hImagehlp, L"Imagehlp.dll");
		DECLARE_WINMODULE(hImm32, L"Imm32.dll");
		DECLARE_WINMODULE(hSfc, L"Sfc.dll");
		DECLARE_WINMODULE(hNetapi32, L"Netapi32.dll");
		DECLARE_WINMODULE(hMsCoree, L"mscoree.dll");
		DECLARE_WINMODULE(hWindowsCodecs, L"Windowscodecs.dll");
		DECLARE_WINMODULE(hMsimg32, L"Msimg32.dll");
		DECLARE_WINMODULE(hWtsapi32, L"Wtsapi32.dll");
		DECLARE_WINMODULE(hSetupapi, L"Setupapi.dll");
		DECLARE_WINMODULE(hInetmib1, L"inetmib1.dll");
		DECLARE_WINMODULE(hSnmpapi, L"snmpapi.dll");
		DECLARE_WINMODULE(hVersion, L"version.dll");
		DECLARE_WINMODULE(hOleAut32, L"OleAut32.dll");
		DECLARE_WINMODULE(hTDH, L"tdh.dll");
		DECLARE_WINMODULE(hFltlib, L"FLTLIB.dll");
		DECLARE_WINMODULE(hRpcrt4, L"Rpcrt4.dll");
		DECLARE_WINMODULE(hMsi, L"Msi.dll");
		DECLARE_WINMODULE(hPowrProf, L"PowrProf.dll");
		DECLARE_WINMODULE(hMsvcrt, L"msvcrt.dll");
		DECLARE_WINMODULE(hGdiplus, L"gdiplus.dll");

		// Optional
		g_winModules->hW32time = g_winAPIs->GetModuleHandleW(xorstr_(L"w32time.dll"));
		if (!g_winModules->hW32time)
		{
			APP_TRACE_LOG(LL_WARN, L"Module (w32time.dll) bind fail!");
		}
		g_winModules->hSrclient = g_winAPIs->GetModuleHandleW(xorstr_(L"srclient.dll"));
		if (!g_winModules->hSrclient)
		{
			APP_TRACE_LOG(LL_WARN, L"Module (srclient.dll) bind fail!");
		}
		g_winModules->hUcrtbase = g_winAPIs->GetModuleHandleW(xorstr_(L"ucrtbase.dll"));
		if (!g_winModules->hUcrtbase)
		{
			APP_TRACE_LOG(LL_WARN, L"Module (ucrtbase.dll) bind fail!");
		}
		g_winModules->hTBS = g_winAPIs->GetModuleHandleW(xorstr_(L"tbs.dll"));
		if (!g_winModules->hTBS)
		{
			APP_TRACE_LOG(LL_WARN, L"Module (tbs.dll) bind fail!");
		}

		// Keep untouched version of ntdll
		g_winModules->hNtdll_o = g_winModules->hNtdll;

		// Version specific modules
		if (IsWindowsVistaOrGreater())
		{
			DECLARE_WINMODULE(hWevtapi, L"Wevtapi.dll");
			DECLARE_WINMODULE(hSlwga,	L"Slwga.dll");
			DECLARE_WINMODULE(hUxtheme, L"UxTheme.dll");
		}
		if (IsWindows7OrGreater())
		{
			DECLARE_WINMODULE(hKernelbase, L"kernelbase.dll");
		}
		if (IsWindows10OrGreater())
		{
			DECLARE_WINMODULE(hWin32u, L"win32u.dll");
			DECLARE_WINMODULE(hBCD, L"bcd.dll");
			DECLARE_WINMODULE(hDwmapi, L"dwmapi.dll");
		}

		// Process base
		g_winModules->hBaseModule = g_winAPIs->GetModuleHandleW_o(nullptr);
		if (!g_winModules->hBaseModule)
		{
			APP_TRACE_LOG(LL_CRI, L"Process base module bind fail!");
			return false;
		}
		APP_TRACE_LOG(LL_TRACE, L"Process base module bind success! (%p)", g_winModules->hBaseModule);

		// Game specific
		if (CApplication::Instance().DataInstance()->GetAppType() == NM_CLIENT)
		{
			const auto IsWhitelistedGameModuleHash = [&](const std::wstring& wstModuleName, const std::wstring& wstModuleHash) {
				for (const auto& [stCurrModuleName, stCurrModuleHash] : m_mapWhitelistedGameModules)
				{
					if (stCurrModuleName == wstModuleName && stCurrModuleHash == wstModuleHash)
						return true;
				}
				return false;
			};

			wchar_t wszCurrentPath[MAX_PATH * 2]{ '\0' };
			LI_FN(GetCurrentDirectoryW)(MAX_PATH, wszCurrentPath);

			const auto wstPython27ModuleName = fmt::format(xorstr_(L"{0}\\python27.dll"), wszCurrentPath);
			if (std::filesystem::exists(wstPython27ModuleName))
			{
				const auto wstModuleHash = CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(wstPython27ModuleName);
				const auto bIsWhitelisted = IsWhitelistedGameModuleHash(xorstr_(L"python27"), wstModuleHash);
				APP_TRACE_LOG(LL_SYS, L"Python27.dll file(%s) found! Hash: %s Whitelisted: %d",
					wstPython27ModuleName.c_str(), wstModuleHash.c_str(), bIsWhitelisted ? 1 : 0
				);

				if (!wstModuleHash.empty() && bIsWhitelisted)
				{
					g_winModules->hPython = g_winAPIs->LoadLibraryW(wstPython27ModuleName.c_str());
					APP_TRACE_LOG(LL_WARN, L"Python27.dll handle: %p Last error: %u", g_winModules->hPython, g_winAPIs->GetLastError());
				}
			}
		}

		return true;
	}

	bool CWinAPIManager::BindAPIs()
	{
		BindAPIs_1();
		BindAPIs_2();
		BindAPIs_3();
		BindAPIs_4();
		BindAPIs_5();
		BindAPIs_6();
		BindAPIs_7();
		BindAPIs_8();
		BindAPIs_9();
		BindAPIs_10();
		BindAPIs_11();

		if (IsWindowsXPSP1OrGreater())
		{
			g_winAPIs->GetProcessId = decltype(g_winAPIs->GetProcessId)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetProcessId")));
		}

		if (IsWindowsVistaOrGreater())
		{
			g_winAPIs->NtCreateThreadEx = decltype(g_winAPIs->NtCreateThreadEx)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtCreateThreadEx")));
			g_winAPIs->QueryFullProcessImageNameW = decltype(g_winAPIs->QueryFullProcessImageNameW)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("QueryFullProcessImageNameW")));
			g_winAPIs->GetThreadId = decltype(g_winAPIs->GetThreadId)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetThreadId")));
			g_winAPIs->CsrGetProcessId = decltype(g_winAPIs->CsrGetProcessId)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("CsrGetProcessId")));
			g_winAPIs->NtGetNextThread = decltype(g_winAPIs->NtGetNextThread)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtGetNextThread")));
			g_winAPIs->NtGetNextProcess = decltype(g_winAPIs->NtGetNextProcess)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtGetNextProcess")));
			g_winAPIs->ProcessIdToSessionId = decltype(g_winAPIs->ProcessIdToSessionId)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("ProcessIdToSessionId")));
			g_winAPIs->QueryWorkingSetEx = decltype(g_winAPIs->QueryWorkingSetEx)(g_winAPIs->GetProcAddress(g_winModules->hPsapi, xorstr_("QueryWorkingSetEx")));
			g_winAPIs->EvtCreateRenderContext = decltype(g_winAPIs->EvtCreateRenderContext)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtCreateRenderContext")));
			g_winAPIs->EvtQuery = decltype(g_winAPIs->EvtQuery)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtQuery")));
			g_winAPIs->EvtNext = decltype(g_winAPIs->EvtNext)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtNext")));
			g_winAPIs->EvtRender = decltype(g_winAPIs->EvtRender)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtRender")));
			g_winAPIs->EvtOpenPublisherMetadata = decltype(g_winAPIs->EvtOpenPublisherMetadata)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtOpenPublisherMetadata")));
			g_winAPIs->EvtClose = decltype(g_winAPIs->EvtClose)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtClose")));
			g_winAPIs->LdrRegisterDllNotification = (WinAPI::TLdrRegisterDllNotification)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrRegisterDllNotification")));
			g_winAPIs->LdrUnregisterDllNotification = (WinAPI::TLdrUnregisterDllNotification)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrUnregisterDllNotification")));
			g_winAPIs->EvtFormatMessage = decltype(g_winAPIs->EvtFormatMessage)(g_winAPIs->GetProcAddress(g_winModules->hWevtapi, xorstr_("EvtFormatMessage")));
			g_winAPIs->GetIpNetTable2 = (WinAPI::TGetIpNetTable2)(g_winAPIs->GetProcAddress(g_winModules->hIphlpapi, xorstr_("GetIpNetTable2")));
			g_winAPIs->inet_ntop = decltype(g_winAPIs->inet_ntop)(g_winAPIs->GetProcAddress(g_winModules->hWs2_32, xorstr_("inet_ntop")));
			g_winAPIs->FreeMibTable = (WinAPI::TFreeMibTable)(g_winAPIs->GetProcAddress(g_winModules->hIphlpapi, xorstr_("FreeMibTable")));
			g_winAPIs->SLIsGenuineLocal = decltype(g_winAPIs->SLIsGenuineLocal)(g_winAPIs->GetProcAddress(g_winModules->hSlwga, xorstr_("SLIsGenuineLocal")));
			g_winAPIs->GetTickCount64 = decltype(g_winAPIs->GetTickCount64)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetTickCount64")));
			g_winAPIs->SetWindowTheme = decltype(g_winAPIs->SetWindowTheme)(g_winAPIs->GetProcAddress(g_winModules->hUxtheme, xorstr_("SetWindowTheme")));
			g_winAPIs->GetPhysicallyInstalledSystemMemory = decltype(g_winAPIs->GetPhysicallyInstalledSystemMemory)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetPhysicallyInstalledSystemMemory")));
		}

		if (IsWindows7OrGreater())
		{
			g_winAPIs->DnsGetCacheDataTable = (WinAPI::TDnsGetCacheDataTable)g_winAPIs->GetProcAddress(g_winModules->hDnsapi, xorstr_("DnsGetCacheDataTable"));
			g_winAPIs->GetWindowDisplayAffinity = decltype(g_winAPIs->GetWindowDisplayAffinity)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetWindowDisplayAffinity")));
			g_winAPIs->SetWindowDisplayAffinity = decltype(g_winAPIs->SetWindowDisplayAffinity)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("SetWindowDisplayAffinity")));
			g_winAPIs->NtIsProcessInJob = decltype(g_winAPIs->NtIsProcessInJob)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtIsProcessInJob")));
			g_winAPIs->EnableTraceEx2 = decltype(g_winAPIs->EnableTraceEx2)(g_winAPIs->GetProcAddress(g_winModules->hAdvapi32, xorstr_("EnableTraceEx2")));
			g_winAPIs->GetActiveProcessorCount = decltype(g_winAPIs->GetActiveProcessorCount)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetActiveProcessorCount")));
			g_winAPIs->CheckElevation = (WinAPI::TCheckElevation)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("CheckElevation")));
		}

		if (IsWindows8OrGreater())
		{
			g_winAPIs->LdrGetProcedureAddressForCaller = decltype(g_winAPIs->LdrGetProcedureAddressForCaller)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("LdrGetProcedureAddressForCaller")));
			g_winAPIs->SetProcessMitigationPolicy = decltype(g_winAPIs->SetProcessMitigationPolicy)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SetProcessMitigationPolicy")));
			g_winAPIs->GetProcessMitigationPolicy = decltype(g_winAPIs->GetProcessMitigationPolicy)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("GetProcessMitigationPolicy")));
			g_winAPIs->IsNativeVhdBoot = decltype(g_winAPIs->IsNativeVhdBoot)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("IsNativeVhdBoot")));
			g_winAPIs->CryptCATAdminAcquireContext2 = decltype(g_winAPIs->CryptCATAdminAcquireContext2)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminAcquireContext2")));
			g_winAPIs->CryptCATAdminCalcHashFromFileHandle2 = decltype(g_winAPIs->CryptCATAdminCalcHashFromFileHandle2)(g_winAPIs->GetProcAddress(g_winModules->hWintrust, xorstr_("CryptCATAdminCalcHashFromFileHandle2")));
			g_winAPIs->GetCurrentInputMessageSource = decltype(g_winAPIs->GetCurrentInputMessageSource)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetCurrentInputMessageSource")));

			if (g_winModules->hTBS)
				g_winAPIs->Tbsi_GetDeviceInfo = decltype(g_winAPIs->Tbsi_GetDeviceInfo)(g_winAPIs->GetProcAddress(g_winModules->hTBS, xorstr_("Tbsi_GetDeviceInfo")));
		}

		if (IsWindows8Point1OrGreater())
		{
			g_winAPIs->PssCaptureSnapshot = decltype(g_winAPIs->PssCaptureSnapshot)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssCaptureSnapshot")));
			g_winAPIs->PssFreeSnapshot = decltype(g_winAPIs->PssFreeSnapshot)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssFreeSnapshot")));
			g_winAPIs->PssQuerySnapshot = decltype(g_winAPIs->PssQuerySnapshot)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssQuerySnapshot")));
			g_winAPIs->PssWalkMarkerCreate = decltype(g_winAPIs->PssWalkMarkerCreate)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssWalkMarkerCreate")));
			g_winAPIs->PssWalkMarkerFree = decltype(g_winAPIs->PssWalkMarkerFree)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssWalkMarkerFree")));
			g_winAPIs->PssWalkSnapshot = decltype(g_winAPIs->PssWalkSnapshot)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("PssWalkSnapshot")));
		}
		
		if (IsWindows10OrGreater())
		{
			g_winAPIs->SetThreadDescription = decltype(g_winAPIs->SetThreadDescription)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SetThreadDescription")));
			g_winAPIs->IsWow64Process2 = decltype(g_winAPIs->IsWow64Process2)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("IsWow64Process2")));
			g_winAPIs->GetWindowCompositionAttribute = (WinAPI::TGetWindowCompositionAttribute)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("GetWindowCompositionAttribute")));
			g_winAPIs->SetWindowCompositionAttribute = (WinAPI::TSetWindowCompositionAttribute)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("SetWindowCompositionAttribute")));
			g_winAPIs->BcdOpenSystemStore = decltype(g_winAPIs->BcdOpenSystemStore)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdOpenSystemStore")));
			g_winAPIs->BcdCloseStore = decltype(g_winAPIs->BcdCloseStore)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdCloseStore")));
			g_winAPIs->BcdOpenObject = decltype(g_winAPIs->BcdOpenObject)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdOpenObject")));
			g_winAPIs->BcdCloseObject = decltype(g_winAPIs->BcdCloseObject)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdCloseObject")));
			g_winAPIs->BcdGetElementData = decltype(g_winAPIs->BcdGetElementData)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdGetElementData")));
			g_winAPIs->BcdSetElementData = decltype(g_winAPIs->BcdSetElementData)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdSetElementData")));
			g_winAPIs->BcdEnumerateObjects = decltype(g_winAPIs->BcdEnumerateObjects)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdEnumerateObjects")));
			g_winAPIs->BcdEnumerateAndUnpackElements = decltype(g_winAPIs->BcdEnumerateAndUnpackElements)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdEnumerateAndUnpackElements")));
			g_winAPIs->BcdSetLogging = decltype(g_winAPIs->BcdSetLogging)(g_winAPIs->GetProcAddress(g_winModules->hBCD, xorstr_("BcdSetLogging")));
			g_winAPIs->RtlRetrieveNtUserPfn = (WinAPI::TRtlRetrieveNtUserPfn)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("RtlRetrieveNtUserPfn")));
			g_winAPIs->RtlPcToFileHeader = decltype(g_winAPIs->RtlPcToFileHeader)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("RtlPcToFileHeader")));
			g_winAPIs->DwmEnableBlurBehindWindow = decltype(g_winAPIs->DwmEnableBlurBehindWindow)(g_winAPIs->GetProcAddress(g_winModules->hDwmapi, xorstr_("DwmEnableBlurBehindWindow")));
			g_winAPIs->DwmExtendFrameIntoClientArea = decltype(g_winAPIs->DwmExtendFrameIntoClientArea)(g_winAPIs->GetProcAddress(g_winModules->hDwmapi, xorstr_("DwmExtendFrameIntoClientArea")));

			if (GetWindowsBuildNumber() >= 15063)
				g_winAPIs->SetProcessDpiAwarenessContext = decltype(g_winAPIs->SetProcessDpiAwarenessContext)(g_winAPIs->GetProcAddress(g_winModules->hUser32, xorstr_("SetProcessDpiAwarenessContext")));
			if (GetWindowsBuildNumber() >= 17063)
				g_winAPIs->NtQueryWnfStateData = (WinAPI::TNtQueryWnfStateData)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtQueryWnfStateData")));
		}

		if (IsWindows11OrGreater())
		{
			g_winAPIs->NtCreateProcessStateChange = (WinAPI::TNtCreateProcessStateChange)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtCreateProcessStateChange")));
			g_winAPIs->NtChangeProcessState = (WinAPI::TNtChangeProcessState)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtChangeProcessState")));
		}

		if (stdext::is_wow64())
		{
			g_winAPIs->Wow64DisableWow64FsRedirection = decltype(g_winAPIs->Wow64DisableWow64FsRedirection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("Wow64DisableWow64FsRedirection")));
			g_winAPIs->Wow64EnableWow64FsRedirection = decltype(g_winAPIs->Wow64EnableWow64FsRedirection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("Wow64EnableWow64FsRedirection")));
			g_winAPIs->Wow64RevertWow64FsRedirection = decltype(g_winAPIs->Wow64RevertWow64FsRedirection)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("Wow64RevertWow64FsRedirection")));
			g_winAPIs->NtWow64ReadVirtualMemory64 = decltype(g_winAPIs->NtWow64ReadVirtualMemory64)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtWow64ReadVirtualMemory64")));
			g_winAPIs->NtWow64QueryInformationProcess64 = decltype(g_winAPIs->NtWow64QueryInformationProcess64)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtWow64QueryInformationProcess64")));
			g_winAPIs->NtWow64WriteVirtualMemory64 = decltype(g_winAPIs->NtWow64WriteVirtualMemory64)(g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("NtWow64WriteVirtualMemory64")));
		}

#ifdef _M_X64
		g_winAPIs->RtlAddFunctionTable = (WinAPI::TRtlAddFunctionTable)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("RtlAddFunctionTable")));
		g_winAPIs->RtlLookupFunctionEntry = (WinAPI::TRtlLookupFunctionEntry)(g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("RtlLookupFunctionEntry")));
#endif

		const auto hD3D11 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d11.dll"));
		if (hD3D11)
		{
			g_winAPIs->D3D11CreateDeviceAndSwapChain = decltype(g_winAPIs->D3D11CreateDeviceAndSwapChain)(g_winAPIs->GetProcAddress(hD3D11, xorstr_("D3D11CreateDeviceAndSwapChain")));
		}

		if (g_winModules->hW32time)
		{
			g_winAPIs->W32TimeSyncNow = (WinAPI::TW32TimeSyncNow)(g_winAPIs->GetProcAddress(g_winModules->hW32time, xorstr_("W32TimeSyncNow")));
		}

		if (g_winModules->hSrclient)
		{
			g_winAPIs->SRSetRestorePointW = decltype(g_winAPIs->SRSetRestorePointW)(g_winAPIs->GetProcAddress(g_winModules->hSrclient, xorstr_("SRSetRestorePointW")));
		}
		
		return true;
	}

	bool CWinAPIManager::CheckModulesIntegrity(std::wstring* pszModuleName, LPDWORD pdwErrorStep)
	{
		const auto c_spAntiModule = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();

		const auto vecModules = GetSelfModuleList();
		for (const auto& hModule : vecModules)
		{
			if (g_winModules->hBaseModule == hModule)
				continue;

			if (c_spAntiModule && c_spAntiModule->DllBase == hModule)
				continue;

			wchar_t wszModuleExecutable[MAX_PATH * 2]{ L'\0' };
			if (!g_winAPIs->GetModuleFileNameW(hModule, wszModuleExecutable, sizeof(wszModuleExecutable) / sizeof(*wszModuleExecutable)) || wszModuleExecutable[0] == L'\0')
			{
				const auto wstNameFromPEB = GetModuleNameFromAddress(reinterpret_cast<DWORD_PTR>(hModule));
				APP_TRACE_LOG(LL_ERR, L"GetModuleFileNameW fail! Target Module: %p Error: %u Forced: %s", hModule, g_winAPIs->GetLastError(), wstNameFromPEB.c_str());
				
				if (pszModuleName)  *pszModuleName = wstNameFromPEB;
				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::NAME_QUERY_FAIL);
				return false;
			}

			if (!this->CheckModuleIntegrity(hModule, wszModuleExecutable, true, pdwErrorStep))
			{
				if (pszModuleName)  *pszModuleName = wszModuleExecutable;
				return false;
			}
		}
		return true;
	}

	bool CWinAPIManager::CheckModuleIntegrity(HMODULE hModule, const std::wstring& wstModuleName, bool bKnownModule, LPDWORD pdwErrorStep)
	{
		enum class EModuleHijackRet : uint8_t
		{
			NONE,
			OK,
			DOS,
			FH_1,
			FH_2,
			FH_3,
			FH_4,
			OH_1,
			OH_2,
			OH_3,
			OH_4,
			OH_5,
			OH_6,
			OH_7,
			SECTION_1,
			SECTION_2,
			SECTION_3,
			SECTION_4
		};

		static auto __ReadFile = [](const std::wstring& wstFileName) -> std::vector <BYTE> {
			auto vecOutput = std::vector <BYTE>();
			HANDLE hFile = nullptr;

			do
			{
				hFile = g_winAPIs->CreateFileW(wstFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				if (!IS_VALID_HANDLE(hFile))
				{
					APP_TRACE_LOG(LL_ERR, L"CreateFileW(%s) failed with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
					break;
				}

				const auto dwFileSize = g_winAPIs->GetFileSize(hFile, nullptr);
				if (dwFileSize == INVALID_FILE_SIZE || !dwFileSize)
				{
					APP_TRACE_LOG(LL_ERR, L"GetFileSize(%s) failed with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
					break;
				}
				vecOutput.resize(dwFileSize);

				DWORD dwRead = 0;
				if (!g_winAPIs->ReadFile(hFile, vecOutput.data(), dwFileSize, &dwRead, nullptr))
				{
					APP_TRACE_LOG(LL_ERR, L"ReadFile(%s) failed with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
					break;
				}
				else if (dwRead != dwFileSize)
				{
					APP_TRACE_LOG(LL_ERR, L"ReadFile(%s) could not read entire file, read %u of %u bytes", wstFileName.c_str(), dwRead, dwFileSize);
					break;
				}
			} while (false);

			if (IS_VALID_HANDLE(hFile))
			{
				g_winAPIs->CloseHandle(hFile);
				hFile = nullptr;
			}

			return vecOutput;
		};

		auto __IsModuleHijacked = [](const auto& module_pe, const auto& file_pe) {		
			// DOS
			if (module_pe.headers().dos()->e_lfanew != file_pe.headers().dos()->e_lfanew)
				return EModuleHijackRet::DOS;
			
			// File Header
			{
				if (module_pe.headers().nt()->FileHeader.TimeDateStamp != file_pe.headers().nt()->FileHeader.TimeDateStamp)
					return EModuleHijackRet::FH_1;
				
				if (module_pe.headers().nt()->FileHeader.SizeOfOptionalHeader != file_pe.headers().nt()->FileHeader.SizeOfOptionalHeader)
					return EModuleHijackRet::FH_2;
				
				if (module_pe.headers().nt()->FileHeader.NumberOfSections != file_pe.headers().nt()->FileHeader.NumberOfSections)
					return EModuleHijackRet::FH_3;

				if (module_pe.headers().nt()->FileHeader.Characteristics != file_pe.headers().nt()->FileHeader.Characteristics)
					return EModuleHijackRet::FH_4;
			}

			// Optional header
			{
				if (module_pe.headers().opt()->CheckSum != file_pe.headers().opt()->CheckSum)
					return EModuleHijackRet::OH_1;
				
				if (module_pe.headers().opt()->AddressOfEntryPoint != file_pe.headers().opt()->AddressOfEntryPoint)
					return EModuleHijackRet::OH_2;

				if (module_pe.headers().opt()->BaseOfCode != file_pe.headers().opt()->BaseOfCode)
					return EModuleHijackRet::OH_3;
				
//				if (module_pe.headers().opt()->BaseOfData != file_pe.headers().opt()->BaseOfData)
//					return EModuleHijackRet::OH_4;

				if (module_pe.headers().opt()->SizeOfInitializedData != file_pe.headers().opt()->SizeOfInitializedData)
					return EModuleHijackRet::OH_5;
					
				if (module_pe.headers().opt()->SizeOfImage != file_pe.headers().opt()->SizeOfImage)
					return EModuleHijackRet::OH_6;
			}

			// Section
			{
				struct SSectionHeader
				{
					DWORD   VirtualAddress;
					DWORD   SizeOfRawData;
					DWORD   Characteristics;
				};
				
				// Save memory sections
				std::map <std::string, std::shared_ptr <SSectionHeader> > mapSections;
				for (const auto& section : module_pe.sections())
				{
					auto stName = std::string((const char*)section.Name, sizeof(section.Name));
					if (stName.empty())
						continue;
					
					auto pSection = std::make_shared <SSectionHeader>();
					pSection->VirtualAddress = section.VirtualAddress;
					pSection->SizeOfRawData = section.SizeOfRawData;
					pSection->Characteristics = section.Characteristics;
					mapSections[stName] = pSection;
				}
				
				// FIXME: d3d10core.dll to whitelist
				/*
				// Compare with file sections
				for (const auto& section : file_pe.sections())
				{
					auto stName = std::wstring((const char*)section.Name, sizeof(section.Name));
					
					auto pSection = mapSections[stName];
					if (!pSection)
						return EModuleHijackRet::SECTION_1;
					
					if (pSection->VirtualAddress != section.VirtualAddress)
						return EModuleHijackRet::SECTION_2;
					
					if (pSection->SizeOfRawData != section.SizeOfRawData)
						return EModuleHijackRet::SECTION_3;
					
					if (pSection->Characteristics != section.Characteristics)
						return EModuleHijackRet::SECTION_4;
				}
				*/
			}
			
			return EModuleHijackRet::OK;
		};
		
		auto wstLowerModuleExecutable = stdext::to_lower_wide(wstModuleName);

		APP_TRACE_LOG(LL_SYS, L"Checking dll integrity! Target Module: %s Handle: %p", wstLowerModuleExecutable.c_str(), hModule);

		const auto vecFileBuffer = __ReadFile(wstLowerModuleExecutable);
		if (vecFileBuffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Target module: %s file read failed!", wstLowerModuleExecutable.c_str());

			if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::READ_FAIL);
			return false;
		}

		// 1: Check module path
		if (IsLibraryFromMalformedPath(hModule, wstLowerModuleExecutable))
		{
			APP_TRACE_LOG(LL_ERR, L"Target module path: %s is malformed!", wstLowerModuleExecutable.c_str());

			if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::MALFORMED_PATH);
			return false;
		}

		// Resolve SxS
		if (wstLowerModuleExecutable.find(xorstr_(L"\\winsxs\\")) != std::wstring::npos)
		{
			wstLowerModuleExecutable = ProbeSxSRedirect(wstLowerModuleExecutable);
			if (wstLowerModuleExecutable.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Target module: %s SxS redirect failed!", wstModuleName.c_str());

				/*
				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::SXS_REDIRECT_FAIL);
				return false;
				*/
				return true; // just ignore
			}

			APP_TRACE_LOG(LL_SYS, L"Target module SxS redirect to: %s", wstLowerModuleExecutable.c_str());
		}

		// saltanat#6260
#ifdef __EXPERIMENTAL__
		// 2: Validate module with SFC API
		if (g_winAPIs->SfcIsFileProtected && !IsBadCodePtr((FARPROC)g_winAPIs->SfcIsFileProtected) && !g_winAPIs->SfcIsFileProtected(nullptr, wstModuleName.c_str()))
		{
			auto bSkip = false;
			if (!bKnownModule && wstModuleName.find(xorstr_(L"d3d8.dll")) != std::string::npos)
				bSkip = true;
			
			APP_TRACE_LOG(LL_ERR, L"Target module: %s file is not protected!", wstLowerModuleExecutable.c_str());

			if (!bSkip)
			{
				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::SFC_FAIL);
				return false;
			}
		}
#endif

		// 3: Validate module with CheckSumMappedFile API
		DWORD dwHeaderSum = 0, dwChecksum = 0;
		if (g_winAPIs->CheckSumMappedFile((PVOID)vecFileBuffer.data(), vecFileBuffer.size(), &dwHeaderSum, &dwChecksum))
		{
			APP_TRACE_LOG(LL_SYS, L"File: %s Size: %u Checksum: %p/%p (%d)",
				wstLowerModuleExecutable.c_str(), vecFileBuffer.size(), dwHeaderSum, dwChecksum, dwHeaderSum == dwChecksum
			);

			if (dwHeaderSum && dwChecksum && dwHeaderSum != dwChecksum)
			{
				APP_TRACE_LOG(LL_ERR, L"Module: %s checksum mismatch", wstLowerModuleExecutable.c_str());

#ifdef __EXPERIMENTAL__
				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::CHECKSUM_MAPPED_FAIL);
				return false;
#endif
			}
		}
		// 4: Validate module against dll hijack
		const auto module_pe = Pe::PeNative::fromModule(hModule);
		if (!module_pe.valid())
		{
			APP_TRACE_LOG(LL_ERR, L"Target module: %s memory is not a valid PE!", wstLowerModuleExecutable.c_str());

			if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::MODULE_PE_NOT_VALID);
			return false;
		}
		const auto file_pe = Pe::PeNative::fromFile(vecFileBuffer.data());
		if (file_pe.valid())
		{
			const auto nHijackRet = __IsModuleHijacked(module_pe, file_pe);
			if (nHijackRet != EModuleHijackRet::OK)
			{
				APP_TRACE_LOG(LL_ERR, L"Target module: %s is hijacked! (%d)", wstLowerModuleExecutable.c_str(), nHijackRet);

				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::MODULE_HIJACKED);
				return false;
			}
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"Target module: %s disk file is not a valid PE!", wstLowerModuleExecutable.c_str());
		}

		// 5: Validate module against hooks
		if (__CheckIATHooks(hModule))
		{
			APP_TRACE_LOG(LL_ERR, L"Target module: %s has IAT hooks!", wstLowerModuleExecutable.c_str());

			if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::IAT_HOOKS);
			return false;
		}

		if (__CheckEATHooks(hModule))
		{
			APP_TRACE_LOG(LL_ERR, L"Target module: %s has EAT hooks!", wstLowerModuleExecutable.c_str());

			if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::EAT_HOOKS);
			return false;
		}

		// 5: Check module file digital signature
		if (IsWindows10OrGreater())
		{
			static auto vecWhitelistedModules = std::vector <HMODULE>{
				g_winModules->hMsCoree,
				g_winModules->hMsimg32,
				g_winModules->hInetmib1,
				g_winModules->hSnmpapi,
				g_winModules->hSrclient,
				g_winModules->hTDH,
				g_winModules->hMsi,
				g_winModules->hSlwga,
				g_winModules->hOleAut32
			};

			if (!stdext::in_vector(vecWhitelistedModules, hModule))
			{
				const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstLowerModuleExecutable);
				if (obHasCert.has_value())
				{
					APP_TRACE_LOG(LL_SYS, L"Cert query for: %ls completed with result: %d", wstLowerModuleExecutable.c_str(), obHasCert.value());

					if (!obHasCert.value())
					{
						APP_TRACE_LOG(LL_ERR, L"Digital signature does not exist in: %ls", wstLowerModuleExecutable.c_str());

						if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::FILE_NOT_SIGNED);
						return false;
					}
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to query certificate informations for file %ls", wstLowerModuleExecutable.c_str());
				}
			}

			// 6: Check LoadReason
			if (bKnownModule)
			{
				const auto lpModule = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(FindOwnModuleFromAddress((DWORD_PTR)hModule));
				if (lpModule)
				{
					const auto dwLoadReason = lpModule->LoadReason;
					if (dwLoadReason != LoadReasonStaticDependency &&
						dwLoadReason != LoadReasonStaticForwarderDependency &&
						dwLoadReason != LoadReasonDynamicLoad &&
						dwLoadReason != LoadReasonDynamicForwarderDependency &&
						dwLoadReason != LoadReasonDelayloadDependency)
					{
						APP_TRACE_LOG(LL_ERR, L"Target module: %s LoadReason: %u", wstLowerModuleExecutable.c_str(), dwLoadReason);

						if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::UNALLOWED_LOAD_REASON);
						return false;
					}

					if (dwLoadReason == LoadReasonDynamicLoad)
					{
						APP_TRACE_LOG(LL_WARN, L"Target module: %s loaded dynamically!", wstLowerModuleExecutable.c_str());

						auto bFound = false;
						for (const auto& hLoadedModule : m_vSelfLoadedModuleList)
						{
							if (hLoadedModule == hModule)
							{
								bFound = true;
								break;
							}
						}

						static auto vecKnownSystemModules = std::vector <HMODULE>{
							g_winModules->hKernel32,
							g_winModules->hImm32,
							g_winModules->hShell32,
							g_winModules->hIphlpapi,
							g_winModules->hSnmpapi
						};
						if (g_winModules->hKernelbase)
							vecKnownSystemModules.push_back(g_winModules->hKernelbase);

						if (bFound == false && !stdext::in_vector(vecKnownSystemModules, hModule))
						{
							APP_TRACE_LOG(LL_ERR, L"Target module: %s loaded dynamically from unknown source!", wstLowerModuleExecutable.c_str());

#ifdef __EXPERIMENTAL__
							if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::UNALLOWED_LOAD_REASON_DYN);
							return false;
#endif
						}
					}
				}
			}

			// 7. Check version info
			CFileVersion verInfo;
			if (!verInfo.QueryFile(wstLowerModuleExecutable))
			{
				APP_TRACE_LOG(LL_ERR, L"Target module: %s version info query failed with error: %u", wstLowerModuleExecutable.c_str(), g_winAPIs->GetLastError());

				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::VERSION_INFO_QUERY_FAIL);
				return false;
			}

			const auto stCurrentCompanyName = verInfo.GetCompanyName();
			if (stCurrentCompanyName != xorstr_(L"Microsoft Corporation") && stCurrentCompanyName != xorstr_(L"Microsoft"))
			{
				APP_TRACE_LOG(LL_ERR, L"Target module: %s company name: '%s' is not valid!", wstLowerModuleExecutable.c_str(), stCurrentCompanyName.c_str());

				if (pdwErrorStep)	*pdwErrorStep = static_cast<DWORD>(EModuleIntegrityRet::INVALID_COMPANY_NAME);
				return false;
			}
		}

		return true;
	}

	bool CWinAPIManager::IsCheckedWinAPI(const std::wstring& wstName)
	{
		for (const auto& [api, backup] : m_mapWinApiBackups)
		{
			if (api->wstName == wstName)
				return true;
		}
		return false;
	}

	bool CWinAPIManager::LoadSecureModules()
	{
		const auto vecModules = GetSelfModuleList();
		for (const auto& hModule : vecModules)
		{
			wchar_t wszModuleExecutable[MAX_PATH]{ '\0' };
			if (!g_winAPIs->GetModuleFileNameW(hModule, wszModuleExecutable, sizeof(wszModuleExecutable)) || !wcslen(wszModuleExecutable))
			{
				const auto wstNameFromPEB = GetModuleNameFromAddress(reinterpret_cast<DWORD_PTR>(hModule));
				APP_TRACE_LOG(LL_ERR, L"GetModuleFileNameA fail! Target Module: %p Error: %u Forced: %s", hModule, g_winAPIs->GetLastError(), wstNameFromPEB.c_str());
				continue;
			}
			
			if (!m_spSecureLoadLibrary->Load(wszModuleExecutable, ESLLLoadType::LOAD_FROM_MEMORY))
			{
				APP_TRACE_LOG(LL_WARN, L"LoadSecureModules: Module: %s load from memory failed with return: %u", wszModuleExecutable, g_winAPIs->GetLastError());
				
				if (!m_spSecureLoadLibrary->Load(wszModuleExecutable, ESLLLoadType::LOAD_FROM_FILE))
				{
					APP_TRACE_LOG(LL_ERR, L"LoadSecureModules: Module: %s load from file failed with error: %u", wszModuleExecutable, g_winAPIs->GetLastError());
					return false;
				}
			}

			const auto c_stModuleName = CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(wszModuleExecutable);
			const auto pvSecureModule = m_spSecureLoadLibrary->Get(c_stModuleName);
			if (!pvSecureModule)
			{
				APP_TRACE_LOG(LL_ERR, L"LoadSecureModules: Module: %s not found in secure module list", c_stModuleName.c_str());
				return false;
			}
		}

		return true;
	}

	bool CWinAPIManager::HasDuplicateModule()
	{
		using TContainer = std::vector <std::tuple <uint32_t, std::wstring, std::wstring>>;
		
		auto __DumpModules = [](TContainer& vecModules) {
			CApplication::Instance().WinAPIManagerInstance()->EnumerateModules([&vecModules](LDR_DATA_TABLE_ENTRY* pEntry) {
				static uint32_t idx = 0;
				
				if (!pEntry)
					return;

				std::wstring wszCurrentModuleFullName(pEntry->FullDllName.Buffer, pEntry->FullDllName.Length / 2);
				if (wszCurrentModuleFullName.empty())
					return;

				std::wstring wszCurrentModuleName(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / 2);
				if (wszCurrentModuleName.empty())
					return;
				
				vecModules.emplace_back(std::make_tuple(idx, stdext::to_lower_wide(wszCurrentModuleName), stdext::to_lower_wide(wszCurrentModuleFullName)));
				idx++;
			});
		};

		TContainer vecModules;
		__DumpModules(vecModules);

		for (const auto& [idx, stName, stFullName] : vecModules)
		{
			for (const auto& [idx2, stName2, stFullName2] : vecModules)
			{
				if (idx == idx2)
					continue;

				if (stFullName == stFullName2)
				{
					APP_TRACE_LOG(LL_ERR, L"Duplicate module: %s found at: %d/%d", stFullName.c_str(), idx, idx2);
					return true;
				}
			}
		}

		return false;
	}

	bool CWinAPIManager::Initialize()
	{
		if (m_bHasInitialized)
			return false;

		// TODO: Append whitelisted game modules SHA1 hash-es
		// m_mapWhitelistedGameModules.emplace(xorstr_(L"python27"), "1337");

		const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe();
		if (!fnGetLastError)
		{
			APP_TRACE_LOG(LL_CRI, L"fnGetLastError not found!");
			return false;
		}

		g_winModules = stdext::make_shared_nothrow<SWinModuleTable>();
		if (!IS_VALID_SMART_PTR(g_winModules))
		{
			APP_TRACE_LOG(LL_CRI, L"g_winModules allocation fail! Last error: %u", fnGetLastError());
			return false;
		}

		g_winAPIs = stdext::make_shared_nothrow<SWinAPITable>();
		if (!IS_VALID_SMART_PTR(g_winAPIs))
		{
			APP_TRACE_LOG(LL_CRI, L"g_winAPIs allocation fail! Last error: %u", fnGetLastError());
			return false;
		}

		m_spSecureLoadLibrary = stdext::make_shared_nothrow<CSecureLoadLibrary>();
		if (!IS_VALID_SMART_PTR(m_spSecureLoadLibrary))
		{
			APP_TRACE_LOG(LL_CRI, L"m_spSecureLoadLibrary allocation fail! Last error: %u", fnGetLastError());
			return false;
		}

		if (!BindBaseAPIs())
		{
			APP_TRACE_LOG(LL_CRI, L"BindBaseAPIs fail! Last error: %u", fnGetLastError());
			return false;
		}

		if (!BindModules())
		{
			APP_TRACE_LOG(LL_CRI, L"BindModules fail! Last error: %u", fnGetLastError());
			return false;
		}

		if (!BindAPIs())
		{
			APP_TRACE_LOG(LL_CRI, L"BindAPIs fail! Last error: %u", fnGetLastError());
			return false;
		}

		if (!m_spSyscallHelper->Initialize())
		{
			APP_TRACE_LOG(LL_CRI, L"Syscall helper initialize failed! Last error: %u", fnGetLastError());
			return false;
		}

		if (!LoadSecureModules())
		{
			APP_TRACE_LOG(LL_CRI, L"LoadSecureModules fail! Last error: %u", fnGetLastError());
			return false;
		}

		if (HasDuplicateModule())
		{
			APP_TRACE_LOG(LL_CRI, L"Duplicate modules detected!");
			return false;
		}
	
		APP_TRACE_LOG(LL_SYS, L"Dynamic winapi initilization completed!");
		m_bHasInitialized = true;
		return true;
	}

	void CWinAPIManager::Release()
	{
		if (!m_bHasInitialized)
			return;
		m_bHasInitialized = false;

		this->SecureLibraryHelper()->Release(L"");

		if (IS_VALID_SMART_PTR(g_winModules))
		{
			g_winModules.reset();
			g_winModules = nullptr;
		}
		/*
		if (IS_VALID_SMART_PTR(g_winAPIs))
		{
			g_winAPIs.reset();
			g_winAPIs = nullptr;
		}
		*/
	}

	bool CWinAPIManager::HasInitialized()
	{
		return m_bHasInitialized;
	}

	void CWinAPIManager::RegisterModuleTextSection(HMODULE hModule, LPVOID pvBase, std::size_t cbSize)
	{
		const auto spCtx = stdext::make_shared_nothrow<STextSectionCtx>();
		if (!IS_VALID_SMART_PTR(spCtx))
			return;
		
		spCtx->lpBase = pvBase;
		spCtx->cbSize = cbSize;
		m_mapModuleTextSections.emplace(hModule, spCtx);
	}
	std::shared_ptr <STextSectionCtx> CWinAPIManager::GetModuleTextSectionInfo(HMODULE hModule) const
	{
		std::shared_ptr <STextSectionCtx> ctx;
		if (stdext::get_map_value(m_mapModuleTextSections, hModule, ctx))
			return ctx;
		return {};
	}
	bool CWinAPIManager::HasModuleTextSectionInfo(HMODULE hModule) const
	{
		return m_mapModuleTextSections.find(hModule) != m_mapModuleTextSections.end();
	}
};
