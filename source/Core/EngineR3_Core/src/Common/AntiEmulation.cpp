#include "../../include/PCH.hpp"
#include "../../include/Application.hpp"
#include "../../include/SafeExecutor.hpp"



#undef APP_TRACE_LOG
#define APP_TRACE_LOG static_assert(0);
#define g_winAPIs 0

#define FIRM 'FIRM'
#define RSMB 'RSMB'

#ifdef __EXPERIMENTAL__
#define FATAL_EXIT true
#else
#define FATAL_EXIT false
#endif

#ifdef _DEBUG
#define DEBUG_MSG(x) __DebugMsg(x)
#else
#define DEBUG_MSG(x)
#endif

#define INIT_WINAPI(name) \
	s_winAPIs->name = LI_FN(name).forwarded_safe(); \
	if (!s_winAPIs->name) \
	{\
		DEBUG_MSG(fmt::format(xorstr_(L"[!] Failed to resolve {0}\n"), xorstr_(L#name))); \
		return false;\
	}

bool g_IsWow64 = false;
bool g_IsWin64 = false;
SYSTEM_INFO g_siSysInfo{ 0 };

namespace NoMercyCore
{
	struct SWinAPITable2
	{
		decltype(&IsProcessorFeaturePresent) IsProcessorFeaturePresent;
		decltype(&PostQuitMessage) PostQuitMessage;
		decltype(&LdrShutdownProcess) LdrShutdownProcess;
		decltype(&RaiseException) RaiseException;
		decltype(&TerminateProcess) TerminateProcess;
		decltype(&GetNativeSystemInfo) GetNativeSystemInfo;
		decltype(&GetSystemInfo) GetSystemInfo;
		decltype(&RtlNtStatusToDosError) RtlNtStatusToDosError;
		decltype(&RtlCompareMemory) RtlCompareMemory;
		decltype(&RtlInitUnicodeString) RtlInitUnicodeString;
		decltype(&NtOpenDirectoryObject) NtOpenDirectoryObject;
		decltype(&NtQueryDirectoryObject) NtQueryDirectoryObject;
		decltype(&NtQuerySystemInformation) NtQuerySystemInformation;
		decltype(&NtQueryInformationProcess) NtQueryInformationProcess;
		decltype(&NtQueryVirtualMemory) NtQueryVirtualMemory;
		decltype(&NtCreateFile) NtCreateFile;
		decltype(&NtQueryObject) NtQueryObject;
		decltype(&NtOpenKey) NtOpenKey;
		decltype(&NtClose) NtClose;
		decltype(&GetLastError) GetLastError;
		decltype(&CreateWaitableTimerW) CreateWaitableTimerW;
		decltype(&SetWaitableTimer) SetWaitableTimer;
		decltype(&CancelWaitableTimer) CancelWaitableTimer;
		decltype(&GetTickCount) GetTickCount;
		decltype(&NtQueryTimer) NtQueryTimer;
		decltype(&Sleep) Sleep;
		decltype(&NtDelayExecution) NtDelayExecution;
		decltype(&GetLastInputInfo) GetLastInputInfo;
		decltype(&GetExtendedTcpTable) GetExtendedTcpTable;
		decltype(&CreateToolhelp32Snapshot) CreateToolhelp32Snapshot;
		decltype(&Process32FirstW) Process32FirstW;
		decltype(&Process32NextW) Process32NextW;
		decltype(&GetUserNameW) GetUserNameW;
		decltype(&GetComputerNameW) GetComputerNameW;
		decltype(&GetComputerNameExW) GetComputerNameExW;
		decltype(&GetWindowsDirectoryW) GetWindowsDirectoryW;
		decltype(&GetFileAttributesW) GetFileAttributesW;
		decltype(&ExpandEnvironmentStringsW) ExpandEnvironmentStringsW;
		decltype(&RegOpenKeyExW) RegOpenKeyExW;
		decltype(&RegCloseKey) RegCloseKey;
		decltype(&Wow64DisableWow64FsRedirection) Wow64DisableWow64FsRedirection;
		decltype(&Wow64RevertWow64FsRedirection) Wow64RevertWow64FsRedirection;
	};
	static SWinAPITable2* s_winAPIs = nullptr;

	// -----------------------------------------------------------------------------------

	[[noreturn]] void __AbortProcess(const std::wstring& wstMessage)
	{
		ServiceMessageBox(xorstr_(L"NoMercy Fatal Error!"), wstMessage, MB_ICONERROR);

		if (s_winAPIs)
		{
			if (s_winAPIs->IsProcessorFeaturePresent && s_winAPIs->IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE))
				__fastfail(EXIT_FAILURE);

			if (s_winAPIs->PostQuitMessage)
				s_winAPIs->PostQuitMessage(EXIT_SUCCESS);

			if (s_winAPIs->LdrShutdownProcess)
				s_winAPIs->LdrShutdownProcess();

			if (s_winAPIs->RaiseException)
				s_winAPIs->RaiseException(static_cast<DWORD>(STATUS_INVALID_PARAMETER), EXCEPTION_NONCONTINUABLE, 0, nullptr);

			if (s_winAPIs->TerminateProcess)
				s_winAPIs->TerminateProcess(NtCurrentProcess(), EXIT_SUCCESS);
		}
		
		exit(0);
		*(int*)0 = 0;
	}

	void __DebugMsg(const std::wstring& wstMessage)
	{
#ifdef _DEBUG
		OutputDebugStringW(wstMessage.c_str());
		LogfW(CUSTOM_LOG_FILENAME_W, xorstr_(L"%s"), wstMessage.c_str()); // temp
#endif
	}

	bool __FillWinAPITable()
	{
		s_winAPIs = new (std::nothrow) SWinAPITable2();
		if (!s_winAPIs)
			__AbortProcess(xorstr_(L"AE :: Failed to allocate memory for WinAPI table."));

		auto fnLoadLibraryW = LI_FN(LoadLibraryW).forwarded_safe();
		if (!fnLoadLibraryW)
			__AbortProcess(xorstr_(L"AE :: Failed to resolve LoadLibraryW."));

		if (!fnLoadLibraryW(xorstr_(L"kernel32.dll")))
		{
			DEBUG_MSG(xorstr_(L"[!] Failed to load kernel32.dll\n"));
			return false;
		}
		if (!fnLoadLibraryW(xorstr_(L"kernelbase.dll")))
		{
			DEBUG_MSG(xorstr_(L"[!] Failed to load kernelbase.dll\n"));
			// return false;
		}
		if (!fnLoadLibraryW(xorstr_(L"ntdll.dll")))
		{
			DEBUG_MSG(xorstr_(L"[!] Failed to load ntdll.dll\n"));
			return false;
		}
		if (!fnLoadLibraryW(xorstr_(L"iphlpapi.dll")))
		{
			DEBUG_MSG(xorstr_(L"[!] Failed to load iphlpapi.dll\n"));
			return false;
		}

		INIT_WINAPI(IsProcessorFeaturePresent);
		INIT_WINAPI(PostQuitMessage);
		INIT_WINAPI(LdrShutdownProcess);
		INIT_WINAPI(RaiseException);
		INIT_WINAPI(TerminateProcess);
		INIT_WINAPI(GetNativeSystemInfo);
		INIT_WINAPI(GetSystemInfo);
		INIT_WINAPI(RtlNtStatusToDosError);
		INIT_WINAPI(RtlCompareMemory);
		INIT_WINAPI(RtlInitUnicodeString);
		INIT_WINAPI(NtOpenDirectoryObject);
		INIT_WINAPI(NtQueryDirectoryObject);
		INIT_WINAPI(NtQuerySystemInformation);
		INIT_WINAPI(NtQueryInformationProcess);
		INIT_WINAPI(NtQueryVirtualMemory);
		INIT_WINAPI(NtCreateFile);
		INIT_WINAPI(NtQueryObject);
		INIT_WINAPI(NtOpenKey);
		INIT_WINAPI(NtClose);
		INIT_WINAPI(GetLastError);
		INIT_WINAPI(CreateWaitableTimerW);
		INIT_WINAPI(SetWaitableTimer);
		INIT_WINAPI(CancelWaitableTimer);
		INIT_WINAPI(GetTickCount);
		INIT_WINAPI(NtQueryTimer);
		INIT_WINAPI(Sleep);
		INIT_WINAPI(NtDelayExecution);
		INIT_WINAPI(GetLastInputInfo);
		INIT_WINAPI(GetExtendedTcpTable);
		INIT_WINAPI(CreateToolhelp32Snapshot);
		INIT_WINAPI(Process32FirstW);
		INIT_WINAPI(Process32NextW);
		INIT_WINAPI(GetUserNameW);
		INIT_WINAPI(GetComputerNameW);
		INIT_WINAPI(GetComputerNameExW);
		INIT_WINAPI(GetWindowsDirectoryW);
		INIT_WINAPI(GetFileAttributesW);
		INIT_WINAPI(ExpandEnvironmentStringsW);
		INIT_WINAPI(RegOpenKeyExW);
		INIT_WINAPI(RegCloseKey);

		return true;
	}

	bool __FillWow64APITable()
	{
		if (!s_winAPIs)
			return false;

		if (g_IsWow64)
		{
			const auto fnGetProcAddress = LI_FN(GetProcAddress).safe();
			if (!fnGetProcAddress)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to resolve GetProcAddress\n"));
				return false;
			}
			const auto fnLoadLibraryW = LI_FN(LoadLibraryW).safe();
			if (!fnLoadLibraryW)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to resolve LoadLibraryW\n"));
				return false;
			}
			const auto hKernel32 = fnLoadLibraryW(xorstr_(L"kernel32.dll"));
			if (!hKernel32)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to load kernel32.dll\n"));
				return false;
			}

			s_winAPIs->Wow64DisableWow64FsRedirection = (decltype(&::Wow64DisableWow64FsRedirection))fnGetProcAddress(hKernel32, xorstr_("Wow64DisableWow64FsRedirection"));
			if (!s_winAPIs->Wow64DisableWow64FsRedirection)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to resolve Wow64DisableWow64FsRedirection\n"));
				return false;
			}

			s_winAPIs->Wow64RevertWow64FsRedirection = (decltype(&::Wow64RevertWow64FsRedirection))fnGetProcAddress(hKernel32, xorstr_("Wow64RevertWow64FsRedirection"));
			if (!s_winAPIs->Wow64RevertWow64FsRedirection)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to resolve Wow64RevertWow64FsRedirection\n"));
				return false;
			}
		}

		return true;
	}

	// -----------------------------------------------------------------------------------

	__forceinline bool __IsExecutableCode(ULONG Protection, ULONG State)
	{
		return (((Protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) &&
			((State & MEM_COMMIT) == MEM_COMMIT));
	}

	bool __IsRegKeyExists(HKEY hKey, const std::wstring wstSubKey)
	{
		HKEY hSubKey = NULL;
		if (s_winAPIs->RegOpenKeyExW(hKey, wstSubKey.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
		{
			s_winAPIs->RegCloseKey(hSubKey);
			return true;
		}

		return false;
	}
	bool __IsFileExists(const std::wstring wstSubKey)
	{
		const auto dwAttrib = s_winAPIs->GetFileAttributesW(wstSubKey.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
	}
	bool __IsDirectoryExists(const std::wstring wstSubKey)
	{
		const auto dwAttrib = s_winAPIs->GetFileAttributesW(wstSubKey.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
	}
	std::wstring __ReadFileContent(const std::wstring& stFileName)
	{
		std::wstring stContent;

		try
		{
			std::ifstream in(stFileName.c_str(), std::ios_base::binary);
			if (in.is_open())
			{
				in.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
				stContent = std::wstring(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
			}
		}
		catch (const std::bad_alloc&)
		{
			stContent.clear();
		}
		catch (const std::ios_base::failure&)
		{
			stContent.clear();
		}
		catch (...)
		{
			stContent.clear();
		}

		return stContent;
	}

	bool __IsProcess32bit(HANDLE hProcess)
	{
		if (!hProcess)
			return false;

		PROCESS_EXTENDED_BASIC_INFORMATION pebi;
		RtlSecureZeroMemory(&pebi, sizeof(pebi));
		pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

		const auto ntStatus = s_winAPIs->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
		if (NT_SUCCESS(ntStatus))
			return (pebi.IsWow64Process == 1);

		return false;
	}
	bool __Is64BitWindows(bool& brfIs64)
	{
#if defined(_WIN64)
		return true;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
		// 32-bit programs run on both 32-bit and 64-bit Windows
		brfIs64 = __IsProcess32bit(NtCurrentProcess());
		return brfIs64;
#else
		return false; // Win64 does not support Win16
#endif
	}

	bool __EnumerateObjectDirectory(const std::wstring& wstPath, std::function<bool(std::wstring)> fnCallback)
	{
		if (wstPath.empty() || !fnCallback)
			return false;

		UNICODE_STRING usPath = { 0 };
		usPath.Buffer = const_cast<wchar_t*>(wstPath.c_str());
		usPath.Length = static_cast<uint16_t>(wstPath.size() * sizeof(wchar_t));
		usPath.MaximumLength = usPath.Length;

		OBJECT_ATTRIBUTES oa{ 0 };
		InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hDirectory = 0;
		const auto ntStatus = s_winAPIs->NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oa);
		if (!NT_SUCCESS(ntStatus))
		{
			DEBUG_MSG(fmt::format(xorstr_(L"{0} :: NtOpenDirectoryObject failed with error: {1}"), __FUNCTIONW__, s_winAPIs->GetLastError()));
			return nullptr;
		}

		auto pObjDirInfo = static_cast<OBJECT_DIRECTORY_INFORMATION*>(calloc(0x800, 1));
		if (!pObjDirInfo)
		{
			DEBUG_MSG(fmt::format(xorstr_(L"{0} :: calloc failed with error: {1}"), __FUNCTIONW__, errno));
			return nullptr;
		}

		ULONG returnedLength = 0;
		ULONG context = 0;
		while (s_winAPIs->NtQueryDirectoryObject(hDirectory, pObjDirInfo, 0x800, TRUE, FALSE, &context, &returnedLength) == STATUS_SUCCESS && returnedLength > 0)
		{
			auto wszName = static_cast<wchar_t*>(calloc(pObjDirInfo->Name.Length + 1, sizeof(wchar_t)));
			if (wszName)
			{
				memcpy(wszName, pObjDirInfo->Name.Buffer, pObjDirInfo->Name.Length * sizeof(wchar_t));
				fnCallback(wszName);
				free(wszName);
			}
		}

		free(pObjDirInfo);
		return true;
	}

	bool __ScanDump(const uint8_t* c_lpData, const std::size_t dwDataSize, const uint8_t* c_lpFindData, const std::size_t dwFindDataSize)
	{
		if (!c_lpData || !c_lpFindData)
			return false;

		if (dwFindDataSize > dwDataSize)
			return false;

		for (std::size_t i = 0; i < dwDataSize - dwFindDataSize; i++)
		{
			if (s_winAPIs->RtlCompareMemory(c_lpData + i, c_lpFindData, dwFindDataSize) == dwFindDataSize)
			{
				return true;
			}
		}
		return false;
	}

	PVOID __GetFirmwareTable(PULONG pdwDataSize, DWORD dwSignature, DWORD dwTableID)
	{
		ULONG Length = 0x1000;
		auto sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)malloc(Length);
		if (!sfti)
		{
			DEBUG_MSG(fmt::format(xorstr_(L"{0} :: HeapAlloc failed with error: {1}"), __FUNCTIONW__, s_winAPIs->GetLastError()));
			return nullptr;
		}
		sfti->Action = SystemFirmwareTableGet;
		sfti->ProviderSignature = dwSignature;
		sfti->TableID = dwTableID;
		sfti->TableBufferLength = Length;

		// Query if info class available and if how many memory we need.
		auto ntStatus = s_winAPIs->NtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
		if (ntStatus == STATUS_INVALID_INFO_CLASS ||
			ntStatus == STATUS_INVALID_DEVICE_REQUEST ||
			ntStatus == STATUS_NOT_IMPLEMENTED ||
			Length == 0
			)
		{
			free(sfti);
			return nullptr;
		}

		if (!NT_SUCCESS(ntStatus) || ntStatus == STATUS_BUFFER_TOO_SMALL)
		{
			free(sfti);

			sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)malloc(Length);
			if (sfti)
			{
				sfti->Action = SystemFirmwareTableGet;
				sfti->ProviderSignature = dwSignature;
				sfti->TableID = dwTableID;
				sfti->TableBufferLength = Length;

				ntStatus = s_winAPIs->NtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
				if (!NT_SUCCESS(ntStatus))
				{
					free(sfti);
					return nullptr;
				}

				if (pdwDataSize)
					*pdwDataSize = Length;
			}
		}
		else
		{
			if (pdwDataSize)
				*pdwDataSize = Length;
		}

		return sfti;
	}

	bool __OpenDevice(LPWSTR lpDeviceName, ACCESS_MASK DesiredAccess, PHANDLE phDevice)
	{
		if (phDevice)
			*phDevice = nullptr;

		if (!lpDeviceName || !*lpDeviceName)
			return false;

		UNICODE_STRING uDevName;
		RtlSecureZeroMemory(&uDevName, sizeof(uDevName));
		RtlInitUnicodeString(&uDevName, lpDeviceName);

		OBJECT_ATTRIBUTES attr;
		InitializeObjectAttributes(&attr, &uDevName, OBJ_CASE_INSENSITIVE, 0, NULL);

		HANDLE hDevice = nullptr;
		IO_STATUS_BLOCK iost;
		const auto ntStatus = s_winAPIs->NtCreateFile(&hDevice, DesiredAccess, &attr, &iost, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
		if (NT_SUCCESS(ntStatus))
		{
			if (phDevice)
				*phDevice = hDevice;
		}

		return NT_SUCCESS(ntStatus);
	}

	PVOID __GetSystemInfo(SYSTEM_INFORMATION_CLASS InfoClass)
	{
		PVOID pvBuffer = nullptr;
		ULONG ulSize = 0x1000;
		std::size_t cbCounter = 0;
		NTSTATUS ntStatus = STATUS_INFO_LENGTH_MISMATCH;
		ULONG ulRetSize = 0;

		do {
			pvBuffer = malloc(ulSize);
			if (pvBuffer)
				ntStatus = s_winAPIs->NtQuerySystemInformation(InfoClass, pvBuffer, ulSize, &ulRetSize);
			else
				return nullptr;

			if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
			{
				free(pvBuffer);
				ulSize *= 2;
			}

			cbCounter++;
			if (cbCounter > 100)
			{
				ntStatus = STATUS_SECRET_TOO_LONG;
				break;
			}
		} while (ntStatus == STATUS_INFO_LENGTH_MISMATCH);

		if (NT_SUCCESS(ntStatus))
			return pvBuffer;

		if (pvBuffer)
			free(pvBuffer);
		return nullptr;
	}

	bool __QueryObjectName(HANDLE hValue, LPWSTR Buffer, ULONG BufferSize)
	{
		bool bRet = false;
		OBJECT_NAME_INFORMATION* pObjName = nullptr;

		do
		{
			ULONG ReturnLength = 0;
			s_winAPIs->NtQueryObject(hValue, ObjectNameInformation, NULL, ReturnLength, &ReturnLength);
			if (ReturnLength == 0L)
			{
				DEBUG_MSG(fmt::format(xorstr_(L"[!] NtQueryObject failed with {0}"), s_winAPIs->RtlNtStatusToDosError(ReturnLength)));
				break;
			}

			pObjName = (POBJECT_NAME_INFORMATION)malloc(ReturnLength);
			if (!pObjName)
			{
				DEBUG_MSG(fmt::format(xorstr_(L"[!] HeapAlloc failed with {0}"), s_winAPIs->GetLastError()));
				break;
			}

			const auto ntStatus = s_winAPIs->NtQueryObject(hValue, ObjectNameInformation, pObjName, ReturnLength, NULL);
			if (NT_SUCCESS(ntStatus))
			{
				if (pObjName->Name.Buffer && pObjName->Name.Length > 0)
				{
					bRet = true;
					wcsncpy_s(Buffer, BufferSize / sizeof(WCHAR), pObjName->Name.Buffer, pObjName->Name.Length / sizeof(WCHAR));
				}
			}
		} while (false);

		if (pObjName)
			free(pObjName);

		return bRet;
	}

	bool __IsSandboxieVirtualRegistryPresent()
	{
		bool bRet = false;

		const auto szRegstrUserKey = stdext::stack(L"\\REGISTRY\\USER");

		UNICODE_STRING ustrRegPath;
		RtlSecureZeroMemory(&ustrRegPath, sizeof(ustrRegPath));
		s_winAPIs->RtlInitUnicodeString(&ustrRegPath, szRegstrUserKey.data());

		OBJECT_ATTRIBUTES obja;
		InitializeObjectAttributes(&obja, &ustrRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hKey = nullptr;
		const auto ntStatus = s_winAPIs->NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja);
		if (NT_SUCCESS(ntStatus))
		{
			WCHAR szObjectName[MAX_PATH + 1];
			RtlSecureZeroMemory(szObjectName, sizeof(szObjectName));

			if (__QueryObjectName((HKEY)hKey, szObjectName, MAX_PATH * sizeof(WCHAR)))
			{
				if (wcscmp(szRegstrUserKey.data(), szObjectName) != 0)
				{
					bRet = true;
				}
			}
			s_winAPIs->NtClose(hKey);
		}

		return bRet;
	}

	// -----------------------------------------------------------------------------------

	bool __IsUnknownVM()
	{
		auto IsVM = false;

		ULONG dwDataSize = 0L;
		auto sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)__GetFirmwareTable(&dwDataSize, RSMB, 0);
		if (sfti)
		{
			const auto szUnknown = stdext::stack("Virtual");
			IsVM = __ScanDump((const uint8_t*)sfti, dwDataSize, (const uint8_t*)szUnknown.data(), szUnknown.size());
			free(sfti);
		}
		return IsVM;
	}

	bool __IsEmuTriggeredByTimer()
	{
		bool IsEmuTriggeredByTimer = false;
		LONG Timeout = 3000;

		auto hTimer = s_winAPIs->CreateWaitableTimerW(NULL, TRUE, NULL);
		if (!hTimer)
		{
			DEBUG_MSG(fmt::format(xorstr_(L"[!] CreateWaitableTimerW failed with {0}"), s_winAPIs->GetLastError()));
			return false;
		}

		LARGE_INTEGER DueTime;
		DueTime.QuadPart = Timeout * (-10000LL);

		auto StartingTick = s_winAPIs->GetTickCount();

		if (!s_winAPIs->SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, 0))
		{
			DEBUG_MSG(fmt::format(xorstr_(L"[!] SetWaitableTimer failed with {0}"), s_winAPIs->GetLastError()));
			s_winAPIs->NtClose(hTimer);
			return false;
		}

		TIMER_BASIC_INFORMATION TimerInformation;
		ULONG ReturnLength;
		do
		{
			s_winAPIs->Sleep(Timeout / 10);
			s_winAPIs->NtQueryTimer(hTimer, TimerBasicInformation, &TimerInformation, sizeof(TIMER_BASIC_INFORMATION), &ReturnLength);
		} while (!TimerInformation.TimerState);

		s_winAPIs->NtClose(hTimer);

		auto TimeElapsedMs = s_winAPIs->GetTickCount() - StartingTick;
		DEBUG_MSG(fmt::format(xorstr_(L"Requested delay: {0}, elapsed time: {1}"), Timeout, TimeElapsedMs));

		if (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2)
		{
			DEBUG_MSG(xorstr_(L"__IsEmuTriggeredByTimer :: Emulation detected!"));
			IsEmuTriggeredByTimer = true;
		}

		return IsEmuTriggeredByTimer;
	}

	bool __IsSleepHooked()
	{
		bool IsSleepHooked = false;
		if (s_winAPIs->NtDelayExecution(FALSE, (PLARGE_INTEGER)0) != STATUS_ACCESS_VIOLATION)
		{
			DEBUG_MSG(xorstr_(L"__IsSleepHooked :: Emulation detected!"));
			IsSleepHooked = true;
		}
		return IsSleepHooked;
	}

	bool __CheckInputDelay()
	{
		bool IsInputDelay = false;

		DWORD ticks = s_winAPIs->GetTickCount();

		LASTINPUTINFO li;
		li.cbSize = sizeof(LASTINPUTINFO);
		BOOL res = s_winAPIs->GetLastInputInfo(&li);

		if (ticks - li.dwTime > 10000)
		{
			DEBUG_MSG(xorstr_(L"__CheckInputDelay :: Emulation detected!"));
			IsInputDelay = true;
		}

		return IsInputDelay;
	}

	bool __IsValidEnvName()
	{
		auto IsValidEnvName = false;

		auto fnLoadLibraryW = LI_FN(LoadLibraryW).forwarded_safe();
		auto fnGetProcAddress = LI_FN(GetProcAddress).forwarded_safe();

		if (!fnLoadLibraryW || !fnGetProcAddress)
			return IsValidEnvName;

		auto hNetApi32 = fnLoadLibraryW(xorstr_(L"netapi32.dll"));
		if (!hNetApi32)
			return IsValidEnvName;

		auto NetValidateName = (decltype(&::NetValidateName))fnGetProcAddress(hNetApi32, xorstr_("NetValidateName"));
		const auto dwResult = NetValidateName(xorstr_(L"123"), L"", L"", L"", NetSetupMachine);
		const auto dwErroCode = s_winAPIs->GetLastError();

		if (dwResult == 0 && dwErroCode == ERROR_ENVVAR_NOT_FOUND)
		{
			DEBUG_MSG(xorstr_(L"__IsValidEnvName :: Emulation detected!"));
			IsValidEnvName = true;
		}

		return IsValidEnvName;
	}

	bool __HasWinnfsdLog()
	{
		std::vector <std::wstring> vecLogFiles;

		wchar_t wszWinDir[MAX_PATH]{ L'\0' };
		if (s_winAPIs->GetWindowsDirectoryW(wszWinDir, MAX_PATH))
		{
			const auto wstTargetPath = fmt::format(xorstr_(L"{0}\\INF"), wszWinDir);
			if (__IsDirectoryExists(wstTargetPath))
			{
				try
				{
					std::error_code ec{};
					for (const auto& entry : std::filesystem::directory_iterator(wstTargetPath, ec))
					{
						if (!entry.is_regular_file())
							continue;

						const auto& kFile = entry.path();
						const auto wstExtension = kFile.extension();
						const auto wstFileName = kFile.filename();
						if (wstExtension != xorstr_(L".log"))
							continue;

						if (!stdext::starts_with(std::wstring(wstFileName), std::wstring(xorstr_(L"setupapi.offline"))))
							continue;

						vecLogFiles.emplace_back(kFile.wstring());
					}
				}
				catch (const std::filesystem::filesystem_error& ex)
				{
					UNREFERENCED_PARAMETER(ex);
				}
				catch (...)
				{
				}
			}
		}

		for (const auto& wstLogFile : vecLogFiles)
		{
			if (wstLogFile.empty() || !__IsFileExists(wstLogFile))
				continue;

			const auto wstContent = __ReadFileContent(wstLogFile);
			if (wstContent.empty())
				continue;

			std::wstring wstWinnfsdStr = xorstr_(L"D:\\work\\mount\\");

			const auto bRet = wstContent.find(wstWinnfsdStr) != std::wstring::npos;
		
			wstWinnfsdStr.clear();

			if (bRet)
				return true;
		}

		return false;
	}
	// -----------------------------------------------------------------------------------

	bool __IsInSandboxEnvironment(uint8_t nRfType)
	{
		bool IsSB = false;
		SYSTEM_HANDLE_INFORMATION* HandleTable = nullptr;
		HANDLE hDummy = nullptr;
		uint8_t Type = 0;

		do
		{
			// Find Sandboxie API device inside our handle table.
			if (!__OpenDevice(xorstr_(L"\\Device\\Null"), GENERIC_READ, &hDummy))
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to open device"));
				break;
			}

			HandleTable = (PSYSTEM_HANDLE_INFORMATION)__GetSystemInfo(SystemHandleInformation);
			if (!HandleTable)
			{
				DEBUG_MSG(xorstr_(L"[!] Failed to get handle table"));
				break;
			}

			ULONG_PTR FileID = 0xFFFFFFFF;
			for (std::size_t k = 0; k < 2; k++)
			{
				for (std::size_t i = 0; i < HandleTable->NumberOfHandles; i++)
				{
					if (HandleTable->Handles[i].UniqueProcessId == (DWORD)NtCurrentProcessId())
					{
						if (k == 0)
						{
							if (HandleTable->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hDummy)
							{
								FileID = HandleTable->Handles[i].ObjectTypeIndex;
								break;
							}
						}
						else
						{
							if (HandleTable->Handles[i].ObjectTypeIndex == FileID)
							{
								WCHAR szObjectName[MAX_PATH + 1];
								RtlSecureZeroMemory(&szObjectName, sizeof(szObjectName));
								if (__QueryObjectName((HANDLE)(ULONG_PTR)HandleTable->Handles[i].HandleValue, szObjectName, MAX_PATH * sizeof(WCHAR)))
								{
									const auto wszSandboxie = stdext::stack(L"Sandboxie");
									if (wcsstr(szObjectName, wszSandboxie.data()) != NULL)
									{
										Type = 1;
										IsSB = true;
										break;
									}
								}
							}
						}
					}
				}
			}

			// Brute-force memory to locate Sandboxie injected code and locate sandboxie tag.
			auto i = (ULONG_PTR)g_siSysInfo.lpMinimumApplicationAddress;
			do
			{
				SIZE_T Length = 0;
				MEMORY_BASIC_INFORMATION RegionInfo;
				const auto ntStatus = s_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)i, MemoryBasicInformation, &RegionInfo, sizeof(MEMORY_BASIC_INFORMATION), &Length);
				if (NT_SUCCESS(ntStatus))
				{
					if (__IsExecutableCode(RegionInfo.AllocationProtect, RegionInfo.State))
					{
						for (std::size_t k = i; k < i + RegionInfo.RegionSize; k += sizeof(DWORD))
						{
							if (*(PDWORD)k == 'kuzt' ||
								*(PDWORD)k == 'xobs'
								)
							{
								IsSB = true;
								Type = 2;
								break;
							}
						}
					}
					i += RegionInfo.RegionSize;
				}
				else
				{
					i += 0x1000;
				}
			} while (i < (ULONG_PTR)g_siSysInfo.lpMaximumApplicationAddress);

			// Check if Sandboxie virtual registry present.
			IsSB = __IsSandboxieVirtualRegistryPresent();
			if (IsSB)
				Type = 3;

		} while (false);

		if (HandleTable)
			free(HandleTable);

		if (hDummy)
			s_winAPIs->NtClose(hDummy);

		nRfType = Type;
		return IsSB;
	}

	bool __CheckLoadedModules(DWORD& dwRefRetCode)
	{
		bool IsModulesChecked = false;

		const std::vector <std::wstring> vecBannedModules = {
			xorstr_(L"avghookx.dll"),		// AVG
			xorstr_(L"avghooka.dll"),		// AVG
			xorstr_(L"snxhk.dll"),		// Avast
			xorstr_(L"sbiedll.dll"),		// Sandboxie
			xorstr_(L"api_log.dll"),		// iDefense Lab
			xorstr_(L"dir_watch.dll"),	// iDefense Lab
			xorstr_(L"pstorec.dll"),		// SunBelt Sandbox
			xorstr_(L"vmcheck.dll"),		// Virtual PC
			xorstr_(L"wpespy.dll"),		// WPE Pro
			xorstr_(L"cmdvrt64.dll"),		// Comodo Container
			xorstr_(L"cmdvrt32.dll"),		// Comodo Container			
			xorstr_(L"sxin.dll"),
			xorstr_(L"sbiedllx.dll"),
			xorstr_(L"sf2.dll"),
			xorstr_(L"sandboxie"),
			xorstr_(L"comodo sandbox"),
			xorstr_(L"qihoo 360 sandbox"),
			xorstr_(L"cuckoo sandbox"),
			xorstr_(L"cuckoomon.dll"),
			xorstr_(L"virtual pc"),
			xorstr_(L"sunbelt sandbox"),
			xorstr_(L"avast sandbox"),
			xorstr_(L"snxhk.dll"),
			xorstr_(L"avg sandbox")
		};

		auto pPEB = NtCurrentPeb();
		auto CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
		while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != nullptr)
		{
			auto Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			const auto wstModuleFullName = stdext::to_lower_wide(std::wstring(Current->FullDllName.Buffer, Current->FullDllName.Length / sizeof(wchar_t)));
			const auto wstModuleName = stdext::to_lower_wide(std::wstring(Current->BaseDllName.Buffer, Current->BaseDllName.Length / sizeof(wchar_t)));

			auto it = std::find(vecBannedModules.begin(), vecBannedModules.end(), wstModuleName);
			if (it != vecBannedModules.end())
			{
				IsModulesChecked = true;
				dwRefRetCode = std::distance(vecBannedModules.begin(), it);
				break;
			}

			CurrentEntry = CurrentEntry->Flink;
		}

		return IsModulesChecked;
	}

	bool __CheckRunningProcesses(DWORD& dwRefRetCode)
	{
		bool IsChecked = false;

		const std::vector <std::wstring> vecBannedProcesses = {
			xorstr_(L"sample.exe"),
			xorstr_(L"bot.exe"),
			xorstr_(L"sandbox.exe"),
			xorstr_(L"malware.exe"),
		//	xorstr_(L"test.exe"),
			xorstr_(L"klavme.exe"),
		//	xorstr_(L"myapp.exe"),
		//	xorstr_(L"testapp.exe"),
			xorstr_(L"xenservice.exe"),
			xorstr_(L"VMSrvc.exe"),
			xorstr_(L"VMUSrvc.exe"),
			xorstr_(L"prl_cc.exe"),
			xorstr_(L"prl_tools.exe")
		};

		HANDLE hSnapshot = s_winAPIs->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			return false;
		
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		
		if (s_winAPIs->Process32FirstW(hSnapshot, &pe32))
		{
			do
			{
				const auto wstProcessName = stdext::to_lower_wide(std::wstring(pe32.szExeFile));
				auto it = std::find(vecBannedProcesses.begin(), vecBannedProcesses.end(), wstProcessName);
				if (it != vecBannedProcesses.end())
				{
					IsChecked = true;
					dwRefRetCode = std::distance(vecBannedProcesses.begin(), it);
					break;
				}
			} while (s_winAPIs->Process32NextW(hSnapshot, &pe32));
		}
		
		s_winAPIs->NtClose(hSnapshot);
		return IsChecked;
	}

	bool __CheckUserNames(DWORD& dwRefRetCode)
	{
		bool IsChecked = false;
		
		const std::vector <std::wstring> vecBannedProcesses = {
			/* Checked for by Gootkit
			 * https://www.sentinelone.com/blog/gootkit-banking-trojan-deep-dive-anti-analysis-features/ */
			// xorstr_(L"CurrentUser"),
			xorstr_(L"Sandbox"),

			/*
			// Checked for by ostap
			// https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/
			xorstr_(L"Emily"),
			xorstr_(L"HAPUBWS"),
			xorstr_(L"Hong Lee"),
			xorstr_(L"IT-ADMIN"),
			xorstr_(L"Johnson"), // Lastline Sandbox
			xorstr_(L"Miller"), // Lastline Sandbox
			xorstr_(L"milozs"),
			xorstr_(L"Peter Wilson"),
			xorstr_(L"timmy"),
			*/

			/* Checked for by Betabot (not including ones from above)
			 * https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/ */
			xorstr_(L"sand box"),
			xorstr_(L"malware"),
			xorstr_(L"maltest"),
			xorstr_(L"test user"),

			/* Checked for by Satan (not including ones from above)
			 * https://cofense.com/satan/ */
			xorstr_(L"virus"),

			/* Checked for by Emotet (not including ones from above)
			 * https://blog.trendmicro.com/trendlabs-security-intelligence/new-emotet-hijacks-windows-api-evades-sandbox-analysis/ */
			xorstr_(L"John Doe"), /* VirusTotal Cuckoofork Sandbox */
		};

		DWORD dwUserNameLen = 256;
		wchar_t wszUserName[256]{ L'\0' };
		if (s_winAPIs->GetUserNameW(wszUserName, &dwUserNameLen))
		{
			const auto wstUserName = stdext::to_lower_wide(std::wstring(wszUserName));
			auto it = std::find(vecBannedProcesses.begin(), vecBannedProcesses.end(), wstUserName);
			if (it != vecBannedProcesses.end())
			{
				IsChecked = true;
				dwRefRetCode = std::distance(vecBannedProcesses.begin(), it);
			}
		}
		
		return IsChecked;
	}

	bool __CheckHostNames(DWORD& dwRefRetCode)
	{
		bool IsChecked = false;
		
		const std::vector <std::wstring> vecBannedProcesses = {
			/* Checked for by Gootkit
			 * https://www.sentinelone.com/blog/gootkit-banking-trojan-deep-dive-anti-analysis-features/ */
			xorstr_(L"SANDBOX"),
			xorstr_(L"7SILVIA"),

			/* Checked for by ostap
			 * https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/ */
			xorstr_(L"HANSPETER-PC"),
			xorstr_(L"JOHN-PC"),
			xorstr_(L"MUELLER-PC"),
			xorstr_(L"WIN7-TRAPS"),

			/* Checked for by Shifu (not including ones from above)
			 * https://www.mcafee.com/blogs/other-blogs/mcafee-labs/japanese-banking-trojan-shifu-combines-malware-tools */
			xorstr_(L"FORTINET"),

			/* Checked for by Emotet (not including ones from above)
			 * https://blog.trendmicro.com/trendlabs-security-intelligence/new-emotet-hijacks-windows-api-evades-sandbox-analysis/ */
			xorstr_(L"TEQUILABOOMBOOM"), /* VirusTotal Cuckoofork Sandbox */
		};

		DWORD dwHostNameLen = 256;
		wchar_t wszHostName[256]{ L'\0' };
		wchar_t wszDnsHostName[256]{ L'\0' };
		if (s_winAPIs->GetComputerNameW(wszHostName, &dwHostNameLen) && s_winAPIs->GetComputerNameExW(ComputerNameDnsHostname, wszDnsHostName, &dwHostNameLen))
		{
			const auto wstHostName = stdext::to_lower_wide(std::wstring(wszHostName));
			const auto wstDnsHostName = stdext::to_lower_wide(std::wstring(wszDnsHostName));
			
			auto it = std::find(vecBannedProcesses.begin(), vecBannedProcesses.end(), wstHostName);
			if (it != vecBannedProcesses.end())
			{
				IsChecked = true;
				dwRefRetCode = std::distance(vecBannedProcesses.begin(), it);
			}
			else
			{
				it = std::find(vecBannedProcesses.begin(), vecBannedProcesses.end(), wstDnsHostName);
				if (it != vecBannedProcesses.end())
				{
					IsChecked = true;
					dwRefRetCode = std::distance(vecBannedProcesses.begin(), it);
				}
			}
		}
		
		return IsChecked;
	}

	bool __CheckExistFiles(DWORD& dwRefRetCode)
	{
		bool IsChecked = false;

		const std::vector <std::wstring> vecBannedProcesses = {
			xorstr_(L"System32\\drivers\\balloon.sys"),
			xorstr_(L"System32\\drivers\\netkvm.sys"),
			xorstr_(L"System32\\drivers\\pvpanic.sys"),
			xorstr_(L"System32\\drivers\\viofs.sys"),
			xorstr_(L"System32\\drivers\\viogpudo.sys"),
			xorstr_(L"System32\\drivers\\vioinput.sys"),
			xorstr_(L"System32\\drivers\\viorng.sys"),
			xorstr_(L"System32\\drivers\\vioscsi.sys"),
			xorstr_(L"System32\\drivers\\vioser.sys"),
			xorstr_(L"System32\\drivers\\viostor.sys")
		};

		wchar_t wszWinDir[MAX_PATH]{ L'\0' };
		s_winAPIs->GetWindowsDirectoryW(wszWinDir, MAX_PATH);

		PVOID OldValue = nullptr;
		if (g_IsWow64)
			s_winAPIs->Wow64DisableWow64FsRedirection(&OldValue);

		auto idx = 0;
		for (const auto& wstPath : vecBannedProcesses)
		{
			idx++;
			
			const auto wstFullPath = fmt::format(xorstr_(L"{0}\\{1}"), wszWinDir, wstPath);
			if (__IsFileExists(wstFullPath))
			{
				IsChecked = true;
				dwRefRetCode = idx;
				break;
			}
		}

		if (g_IsWow64)
			s_winAPIs->Wow64RevertWow64FsRedirection(&OldValue);

		return IsChecked;
	}

	bool __CheckExistDirectories(DWORD& dwRefRetCode)
	{
		wchar_t wszProgmamFiles[MAX_PATH]{ L'\0' };
		if (s_winAPIs->ExpandEnvironmentStringsW(g_IsWow64 ? xorstr_(L"%ProgramW6432%") : xorstr_(L"%ProgramFiles%"), wszProgmamFiles, MAX_PATH) && wszProgmamFiles[0] != L'\0')
		{
			if (s_winAPIs->GetFileAttributesW(wszProgmamFiles) == INVALID_FILE_ATTRIBUTES)
			{
				dwRefRetCode = 0;
				return true;
			}
		}

		const std::vector <std::wstring> vecBannedProcesses = {
			xorstr_(L"Virtio-Win"),
			xorstr_(L"qemu-ga"),
			xorstr_(L"SPICE Guest Tools"),
		};

		auto idx = 0;
		for (const auto& wstPath : vecBannedProcesses)
		{
			idx++;
			
			const auto wstFullPath = fmt::format(xorstr_(L"{0}\\{1}"), wszProgmamFiles, wstPath);
			if (__IsDirectoryExists(wstFullPath))
			{
				dwRefRetCode = idx;
				return true;
			}
		}
		
		return false;
	}

	bool __CheckExistRegEntries(DWORD& dwRefRetCode)
	{
		bool IsKVM = false;

		const std::vector <std::wstring> vecBannedProcesses = {
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\vioscsi"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\viostor"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\VirtioSerial"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\BALLOON"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\BalloonService"),
			xorstr_(L"SYSTEM\\ControlSet001\\Services\\netkvm"),
		};

		auto idx = 0;
		for (const auto& wstPath : vecBannedProcesses)
		{
			idx++;

			if (__IsRegKeyExists(HKEY_LOCAL_MACHINE, wstPath))
			{
				IsKVM = true;
				dwRefRetCode = idx;
				break;
			}
		}
		
		return IsKVM;
	}

	bool __CheckRemoteRequests(DWORD& dwRefRetCode)
	{
		bool IsChecked = false;



		return IsChecked;
	}

	bool __CheckDriverObjects(DWORD& dwRefRetCode)
	{
		const std::vector <std::wstring> vecBannedProcesses = {
			xorstr_(L"VMBusHID"),
			xorstr_(L"vmbus"),
			xorstr_(L"vmgid"),
			xorstr_(L"IndirectKmd"),
			xorstr_(L"HyperVideo"),
			xorstr_(L"hyperkbd")
		};

		auto find_idx = 0u;
		const auto bEnumRet = __EnumerateObjectDirectory(xorstr_(L"\\Driver"), [vecBannedProcesses, &find_idx](std::wstring wstObject) {
			auto idx = 0u;
			for (auto& bannedProcess : vecBannedProcesses)
			{
				idx++;
				if (wstObject.find(bannedProcess) != std::wstring::npos)
				{
					find_idx = idx;
					return false;
				}
			}

			return true;
		});
		if (!bEnumRet)
		{
			dwRefRetCode = find_idx;
			return true;
		}

		const std::vector <std::wstring> vecBannedProcesses2 = {
			xorstr_(L"VMBUS#"),
			xorstr_(L"VDRVROOT"),
			xorstr_(L"VmGenerationCounter"),
			xorstr_(L"VmGid")
		};

		auto find_idx2 = 0u;
		const auto bEnumRet2 = __EnumerateObjectDirectory(xorstr_(L"\\GLOBAL??"), [vecBannedProcesses2, &find_idx2](std::wstring wstObject) {
			auto idx = 0u;
			for (auto& bannedProcess : vecBannedProcesses2)
			{
				idx++;
				if (wstObject == bannedProcess)
				{
					find_idx2 = 100 + idx;
					return false;
				}
			}

			return true;
		});
		if (!bEnumRet2)
		{
			dwRefRetCode = find_idx2;
			return true;
		}

		return false;
	}

	bool __CheckGenericMethods(DWORD& dwRefRetCode)
	{
		wchar_t wszUserName[256]{ L'\0' };
		DWORD dwUserNameSize = sizeof(wszUserName);
		if (!s_winAPIs->GetUserNameW(wszUserName, &dwUserNameSize))
			return false;

		wchar_t wszComputerName[256]{ L'\0' };
		DWORD dwComputerNameSize = sizeof(wszComputerName);
		if (!s_winAPIs->GetComputerNameW(wszComputerName, &dwComputerNameSize))
			return false;

		if (wcscmp(wszUserName, xorstr_(L"Wilber")) == 0)
		{
			if (wcsncmp(wszComputerName, xorstr_(L"SC"), 2) == 0 || wcsncmp(wszComputerName, xorstr_(L"SW"), 2) == 0)
			{
				dwRefRetCode = 1;
				return true;
			}
		}

		if (wcscmp(wszUserName, xorstr_(L"admin")) == 0)
		{
			if (wcsncmp(wszComputerName, xorstr_(L"SystemIT"), 8) == 0)
			{
				dwRefRetCode = 2;
				return true;
			}
		}

		if (wcscmp(wszUserName, xorstr_(L"admin")) == 0)
		{
			if (wcsncmp(wszComputerName, xorstr_(L"KLONE_X64-PC"), 12) == 0)
			{
				dwRefRetCode = 3;
				return true;
			}
		}

		if (wcscmp(wszUserName, xorstr_(L"John")) == 0)
		{
			if (__IsFileExists(xorstr_(L"C:\\take_screenshot.ps1")) &&
				__IsFileExists(xorstr_(L"C:\\loaddll.exe")))
			{
				dwRefRetCode = 4;
				return true;
			}
		}

		if (__IsFileExists(xorstr_(L"C:\\email.doc")) &&
			__IsFileExists(xorstr_(L"C:\\email.htm")) &&
			__IsFileExists(xorstr_(L"C:\\123\\email.doc")) &&
			__IsFileExists(xorstr_(L"C:\\123\\email.docx")))
		{
			dwRefRetCode = 5;
			return true;
		}

		if (__IsFileExists(xorstr_(L"C:\\a\\foobar.bmp")) &&
			__IsFileExists(xorstr_(L"C:\\a\\foobar.doc")) &&
			__IsFileExists(xorstr_(L"C:\\a\\foobar.gif")))
		{
			dwRefRetCode = 6;
			return true;
		}
		
		return false;
	}
	
	// -----------------------------------------------------------------------------------

	uint32_t CApplication::__InitializeAntiEmulation()
	{
		auto ret = 0u;
		
		do
		{
			if (!__FillWinAPITable())
			{
				ret = 1u;
				break;
			}

			g_IsWin64 = __Is64BitWindows(g_IsWow64);
			if (g_IsWow64)
				s_winAPIs->GetNativeSystemInfo(&g_siSysInfo);
			else
				s_winAPIs->GetSystemInfo(&g_siSysInfo);

			if (!__FillWow64APITable())
			{
				ret = 1u;
				break;
			}

			if (__IsUnknownVM())
			{
				ret = 2u;
				break;
			}
			
			/*
			* // cause irrelevant delay
			if (__IsEmuTriggeredByTimer())
			{
				ret = 3u;
				break;
			}
			*/

			if (__IsSleepHooked())
			{
				ret = 4u;
				break;
			}

			/*
			// FIXME false positive
			if (__CheckInputDelay())
			{
				ret = 5u;
				break;
			}
			*/

			/*
			* // cause irrelevant delay
			if (__IsValidEnvName())
			{
				ret = 6u;
				break;
			}
			*/

			/*
			// FIXME false positive
			if (__HasWinnfsdLog())
			{
				ret = 7u;
				break;
			}
			*/

			// ----------------------

			DWORD dwErrRet = 0;
			if (__IsInSandboxEnvironment(dwErrRet))
			{
				ret = 1000u + dwErrRet;
				break;
			}

			if (__CheckLoadedModules(dwErrRet))
			{
				ret = 3000u + dwErrRet;
				break;
			}

			if (__CheckRunningProcesses(dwErrRet))
			{
				ret = 4000u + dwErrRet;
				break;
			}

			if (__CheckUserNames(dwErrRet))
			{
				ret = 5000u + dwErrRet;
				break;
			}

			if (__CheckHostNames(dwErrRet))
			{
				ret = 6000u + dwErrRet;
				break;
			}

			if (__CheckRemoteRequests(dwErrRet))
			{
				ret = 7000u + dwErrRet;
				break;
			}

			if (__CheckGenericMethods(dwErrRet))
			{
				ret = 8000u + dwErrRet;
				break;
			}

		} while (false);

		if (s_winAPIs)
		{
			delete s_winAPIs;
			s_winAPIs = nullptr;
		}

#if (FATAL_EXIT == true)
		if (ret)
			__AbortProcess(fmt::format(xorstr_(L"Emulation detected: {0}"), ret));
#endif
		return ret;
	}
};
