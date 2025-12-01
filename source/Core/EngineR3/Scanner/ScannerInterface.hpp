#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <mutex>
#include "../Common/Terminator.hpp"
#include "../../../Common/Locks.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"
#include <yaracpp/yaracpp.h>
#include <taskflow/taskflow.hpp>

namespace NoMercy
{
	struct SScanCacheCtx
	{
		uint8_t nScanType;
		std::wstring stScanContent;
	};

	struct SSnapshotContext
	{
		std::shared_ptr <PSS_VA_CLONE_INFORMATION> spVACloneInfo;
		std::shared_ptr <PSS_PERFORMANCE_COUNTERS> spPerfCounters;
		std::shared_ptr <PSS_PROCESS_INFORMATION> spProcInfo;
		std::shared_ptr <PSS_VA_SPACE_INFORMATION> spVASpaceInfo;
		std::shared_ptr <PSS_HANDLE_INFORMATION> spHandleInfo;
		std::shared_ptr <PSS_THREAD_INFORMATION> spThreadInfo;
		std::shared_ptr <PSS_HANDLE_TRACE_INFORMATION> spHandleTraceInfo;
		std::vector <std::shared_ptr <PSS_VA_SPACE_ENTRY>> vecSpaceEntries;
		std::vector <std::shared_ptr <PSS_HANDLE_ENTRY>> vecHandleEntries;
		std::vector <std::shared_ptr <PSS_THREAD_ENTRY>> vecThreadEntries;
	};

	struct SCDBBaseContext
	{
		uint32_t dwListIndex;
		std::wstring stID;
		bool bStreamed;
		bool bIsListed;
	};
	
	enum EScanCacheTypes : uint8_t
	{
		SCAN_CACHE_NULL,
		SCAN_CACHE_DRIVER,
		SCAN_CACHE_FILE,
		SCAN_CACHE_FOLDER,
		SCAN_CACHE_HANDLE,
		SCAN_CACHE_MODULE,
		SCAN_CACHE_PROCESS,
		SCAN_CACHE_THREAD,
		SCAN_CACHE_SECTION,
		SCAN_CACHE_HEAP,
		SCAN_CACHE_SERVICE,
		SCAN_CACHE_WINDOW,
		SCAN_CACHE_OBJECT_DIRECTORY
	};
	enum EFileScanTypes : uint8_t
	{
		FILE_SCAN_TYPE_NULL,
		FILE_SCAN_TYPE_PROCESS,
		FILE_SCAN_TYPE_TERMINATED_PROCESS,
		FILE_SCAN_TYPE_MODULE,
		FILE_SCAN_TYPE_SECTION,
		FILE_SCAN_TYPE_HOOK,
		FILE_SCAN_TYPE_SERVICE,
		FILE_SCAN_TYPE_DRIVER
	};
	struct SProcessCallbackCtx
	{
		bool	bCreated{ false };
		DWORD	dwProcessID{ 0 };
		int		iSID{ 0 };
		int		iThreadCount{ 0 };
		wchar_t	wszFileAndPathname[MAX_PATH * 2 + 1]{ L'\0' };
		wchar_t	wszFilename[MAX_PATH + 1]{ L'\0' };
		wchar_t	wszClassname[128]{ L'\0' };
		wchar_t	wszCommandline[8192]{ L'\0' };
	};
	struct SModuleCallbackCtx
	{
		DWORD		dwProcessID{ 0 };
		DWORD_PTR	dwBaseAddress{ 0 };
		SIZE_T		dwImageSize{ 0 };
		wchar_t		wszFilename[MAX_PATH + 1]{ L'\0' };
		wchar_t		wszExecutable[MAX_PATH * 2 + 1]{ L'\0' };
	};
	struct SThreadCallbackCtx
	{
		DWORD		dwTID{ 0 };
		DWORD		dwProcessId{ 0 };
		DWORD		dwWaitMode{ 0 };
		DWORD_PTR	dwStartAddress{ 0 };
	};
	struct SDriverCallbackCtx
	{
		wchar_t	wszName[MAX_PATH + 1]{ L'\0' };
		wchar_t	wszPath[MAX_PATH * 2 + 1]{ L'\0' };
		wchar_t	wszState[64]{ L'\0' };
		wchar_t	wszType[64]{ L'\0' };
		bool	bStarted{ false };
	};
	struct SModuleEnumContext
	{
		DWORD_PTR	pvBaseAddress{ 0 };
		SIZE_T		cbModuleSize{ 0 };
		wchar_t		wszModuleName[MAX_PATH]{ L'\0' };
	};
	struct SSectionEnumContext
	{
		ptr_t	BaseAddress{ 0 };
		ptr_t	AllocationBase{ 0 };
		ULONGLONG	RegionSize{ 0 };
		DWORD		State{ 0 };
		DWORD		Protect{ 0 };
		DWORD		BaseProtect{ 0 };
		DWORD		Type{ 0 };
	};
	struct SSectionScanContext
	{
		HANDLE	hProcess{ nullptr };
		DWORD	dwProcessId{ 0 };
		ptr_t	dwBase{ 0 };
		ULONG64 dwSize{ 0 };
	};
	struct SHeapScanContext
	{
		HANDLE		hProcess{ nullptr };
		DWORD_PTR	dwBase{ 0 };
		SIZE_T		dwAllocatedSize{ 0 };
		SIZE_T		dwComittedSize { 0 };
		DWORD		dwFlags { 0 };
		DWORD		dwBlockCount { 0 };
	};
	struct SObjectDirectoryScanContext
	{
		std::wstring wszRootDirectory{ L'\0' };
		std::wstring wszDirectory{ L'\0' };
		std::wstring wszType{ L'\0' };
	};
	struct SServiceScanContext
	{
		SC_HANDLE	hSvcManager{ 0 };
		std::wstring stServiceName;
		std::wstring stServiceDisplayName;
		std::wstring stServiceExecutable;
		DWORD dwServiceState{ 0 };
	};
	struct SHandleScanContext
	{
		ULONG_PTR hSourcePid{ 0 };
		HANDLE	hHandle{ nullptr };
		PVOID	pObject{ nullptr };
		USHORT	uTypeIndex{ 0 };
		DWORD	dwGrantedAccess{ 0 };
	};
	struct SDriverScanContext
	{
		std::size_t		nIdx{ 0 };
		ptr_t			pMappedBase{ nullptr };
		ptr_t			pImageBase{ nullptr };
		ULONG			ulImageSize{ 0 };
		ULONG			ulFlags{ 0 };
		USHORT			usLoadOrderIndex{ 0 };
		USHORT			usInitOrderIndex{ 0 };
		std::wstring	wstExecutable;
	};

	template <typename T>
	class IScan
	{
	public:
		IScan()
		{
			SCANNER_LOG(LL_SYS, L"IScan ctor begin");

			// Create queue worker thread
			m_hQueueWorkerThread = g_winAPIs->CreateThread(NULL, 0, StartQueueWorker, this, 0, NULL);
			if (!m_hQueueWorkerThread)
			{
				SCANNER_LOG(LL_ERR, L"CreateThread(StartQueueWorker) fail! Error: %u", g_winAPIs->GetLastError());
				return;
			}

			// Register wait object for queue worker thread
			const auto bRegWaitRet = g_winAPIs->RegisterWaitForSingleObject(&m_hQueueWorkerThreadWaitObject, m_hQueueWorkerThread, StartWaitCallback, this, INFINITE, WT_EXECUTEONLYONCE);
			if (!bRegWaitRet)
			{
				SCANNER_LOG(LL_ERR, L"RegisterWaitForSingleObject(StartWaitCallback) fail! Error: %u", g_winAPIs->GetLastError());
				return;
			}

			SCANNER_LOG(LL_SYS, L"IScan ctor end");
		}
		~IScan()
		{
			SCANNER_LOG(LL_SYS, L"IScan dtor begin");
			
			/*
			if (IS_VALID_HANDLE(m_hQueueWorkerThreadWaitObject) &&
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hQueueWorkerThreadWaitObject))
			{
				g_winAPIs->UnregisterWait(m_hQueueWorkerThreadWaitObject);
				g_winAPIs->CloseHandle(m_hQueueWorkerThreadWaitObject);
				m_hQueueWorkerThreadWaitObject = nullptr;
			}
			*/
			if (IS_VALID_HANDLE(m_hQueueWorkerThread) &&
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(m_hQueueWorkerThread))
			{
				g_winAPIs->TerminateThread(m_hQueueWorkerThread, 0);
				g_winAPIs->CloseHandle(m_hQueueWorkerThread);
				m_hQueueWorkerThread = nullptr;
			}

			SCANNER_LOG(LL_SYS, L"IScan dtor end");
		}
		
		virtual bool ScanAll() = 0;
		virtual void ScanSync(T item) = 0;
		virtual bool IsScanned(T item) = 0;
		virtual void AddScanned(T item) = 0;

		virtual void ScanAsync(T item)
		{			
			m_pkWorkQueue.try_enqueue(item);
		}
		
		DWORD QueueWorker(void)
		{
			while (true)
			{
				T item;
				if (m_pkWorkQueue.try_dequeue(item))
				{
					this->ScanSync(item);
				}
				g_winAPIs->Sleep(20); // 200
			}
			return 0;
		}
		static DWORD WINAPI StartQueueWorker(LPVOID lpParam)
		{
			const auto This = reinterpret_cast<IScan*>(lpParam);
			return This->QueueWorker();
		}

		DWORD OnWaitFire(void)
		{
			if (!this || !CApplication::InstancePtr() || !CApplication::Instance().AppIsInitiliazed())
				return 0;
			
			APP_TRACE_LOG(LL_CRI, L"Access lost to scan thread");
			
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif

			CApplication::Instance().OnCloseRequest(EXIT_ERR_ACCESS_LOST_TO_SCAN_THREAD, 0);
			return 0;
		}
		static VOID NTAPI StartWaitCallback(PVOID pvParam, BOOLEAN)
		{
			const auto This = reinterpret_cast<IScan*>(pvParam);
			This->OnWaitFire();
		}

	protected:
		mutable std::recursive_mutex m_rmMutex;
		moodycamel::ConcurrentQueue <T> m_pkWorkQueue;
		HANDLE m_hQueueWorkerThread{ nullptr };
		HANDLE m_hQueueWorkerThreadWaitObject{ nullptr };
	};

	class IProcessScanner : public IScan <DWORD>
	{
	public:
		IProcessScanner();
		~IProcessScanner();

		bool ScanAll() override;
		void ScanSync(DWORD dwProcessId) override;
		bool IsScanned(DWORD dwProcessId) override;
		void AddScanned(DWORD dwProcessId) override;
		
		void OnScanTerminatedProcess(HANDLE hProcess);

	private:
		std::unique_ptr <tf::Executor> m_upTaskExecutor;
	};
	class IWindowScanner : public IScan <HWND>
	{
	public:
		IWindowScanner();
		~IWindowScanner();

		bool ScanAll() override;
		void ScanSync(HWND hWnd) override;
		bool IsScanned(HWND hWnd) override;
		void AddScanned(HWND hWnd) override;

		bool ScanProcessWindows(HANDLE hProcess);
		void ScanOverlayWindow(HWND hWnd);
	};
	class IServiceScanner : public IScan <std::shared_ptr <SServiceScanContext>>
	{
	public:
		IServiceScanner();
		~IServiceScanner();

		bool ScanAll() override;
		void ScanSync(std::shared_ptr <SServiceScanContext> pServiceCtx) override;
		bool IsScanned(std::shared_ptr <SServiceScanContext> pServiceCtx) override;
		void AddScanned(std::shared_ptr <SServiceScanContext> pServiceCtx) override;
	};
	class IDriverScanner : public IScan <std::wstring>
	{
	public:
		IDriverScanner();
		~IDriverScanner();

		bool ScanAll() override;
		void ScanSync(std::wstring stDriverPath) override;
		bool IsScanned(std::wstring stDriverPath) override;
		void AddScanned(std::wstring stDriverPath) override;
	};
	class IHandleScanner : public IScan < std::shared_ptr <SHandleScanContext>>
	{
	public:
		IHandleScanner();
		~IHandleScanner();

		bool ScanProcess(DWORD dwProcessID);
		bool ScanLastObjects();
		bool ScanAll() override;
		void ScanSync(std::shared_ptr <SHandleScanContext> pHandleCtx) override;
		bool IsScanned(std::shared_ptr <SHandleScanContext> pHandleCtx) override;
		void AddScanned(std::shared_ptr <SHandleScanContext> pHandleCtx) override;

		bool IsUnopenedProcess(DWORD dwProcessId) const;
		void AddUnopenedProcess(DWORD dwProcessId);

		bool IsProtectedHandle(HANDLE hValue);
		bool KillHandle(DWORD dwProcessId, HANDLE hHandleValue);
		DWORD GetGrantedAccess(HANDLE hHandleValue);
		
	protected:
		std::vector <DWORD> m_vUnopenedProcesses;
		std::vector <std::tuple <DWORD, HANDLE, PVOID>> m_vScannedHandles;
		std::vector <DWORD> m_vecScannedPIDs;
		DWORD m_dwCurrentSessionId;
	};
	class IFolderScanner : public IScan <std::wstring>
	{
	public:
		IFolderScanner();
		~IFolderScanner();

		bool ScanAll() override;
		void ScanSync(std::wstring stPath) override;
		bool IsScanned(std::wstring stPath) override;
		void AddScanned(std::wstring stPath) override;
	};
	class IObjectDirectoryScanner : public IScan <std::shared_ptr <SObjectDirectoryScanContext>>
	{
	public:
		IObjectDirectoryScanner();
		~IObjectDirectoryScanner();

		bool ScanAll() override;
		void ScanSync(std::shared_ptr <SObjectDirectoryScanContext> ctx) override;
		bool IsScanned(std::shared_ptr <SObjectDirectoryScanContext> ctx) override;
		void AddScanned(std::shared_ptr <SObjectDirectoryScanContext> ctx) override;
		
	protected:
		bool EnumerateObjectDirectory(const std::wstring& wstRootDirName, std::function<bool(OBJECT_DIRECTORY_INFORMATION)> cb);
		std::wstring GetSymbolicLinkFromName(const std::wstring& directory, const std::wstring& name);
	};
	class IFileScanner : public IScan <std::wstring>
	{
	public:
		IFileScanner();
		~IFileScanner();

		bool ScanAll() override;
		void ScanSync(std::wstring stFileName) override;
		bool IsScanned(std::wstring stFileName) override;
		void AddScanned(std::wstring stFileName) override;
		
		void Scan(std::wstring stFileName, EFileScanTypes fileType);
		bool ScanProcessFile(HANDLE hProcess, EFileScanTypes scanType);
	};
	class IModuleScanner : public IScan <std::wstring>
	{
	public:
		IModuleScanner();
		~IModuleScanner();

		bool ScanAll() override;
		void ScanSync(std::wstring stModulePath) override;
		bool IsScanned(std::wstring stModulePath) override;
		void AddScanned(std::wstring stModulePath) override;
		
		void OnScan(HANDLE hProcess, const std::wstring& stModuleName, LPCVOID dwModuleBase, DWORD dwModuleSize);
		bool ScanProcessModules(HANDLE hProcess);
	};
	class ISectionScanner : public IScan <std::shared_ptr <SSectionScanContext>>
	{
	public:
		ISectionScanner();
		~ISectionScanner();

		bool ScanAll() override;
		void ScanSync(std::shared_ptr <SSectionScanContext> pkSectionCtx) override;
		bool IsScanned(std::shared_ptr <SSectionScanContext> pkSectionCtx) override;
		void AddScanned(std::shared_ptr <SSectionScanContext> pkSectionCtx) override;

		void OnScan(HANDLE hProcess, ptr_t dwBaseAddress, ptr_t dwAllocationBase, ULONG64 dwRegionSize, DWORD dwState, DWORD dwProtect, DWORD dwBaseProtect, DWORD dwType);
		bool ScanProcessSections(HANDLE hProcess);
	};
	class IThreadScanner : public IScan <DWORD>
	{
	public:
		IThreadScanner();
		~IThreadScanner();

		bool ScanAll() override;
		void ScanSync(DWORD dwThreadID) override;
		bool IsScanned(DWORD dwThreadID) override;
		void AddScanned(DWORD dwThreadID) override;

		void Scan(HANDLE hProcess, SYSTEM_THREAD_INFORMATION* pCurrThread);
		bool ScanProcessThreads(HANDLE hProcess);
	};
	class IHeapScanner : public IScan <std::shared_ptr <SHeapScanContext>>
	{
	public:
		IHeapScanner();
		~IHeapScanner();

		bool ScanAll() override;
		void ScanSync(std::shared_ptr <SHeapScanContext> pkHeapCtx) override;
		bool IsScanned(std::shared_ptr <SHeapScanContext> pkHeapCtx) override;
		void AddScanned(std::shared_ptr <SHeapScanContext> pkHeapCtx) override;

		bool ScanProcessHeaps(HANDLE hProcess);
	};

	struct STFScannerObserver : public tf::ObserverInterface
	{
		STFScannerObserver(const std::wstring& name)
		{
			APP_TRACE_LOG(LL_SYS, L"Constructing TF observer %s", name.c_str());
		}

		// set_up is a constructor-like method that will be called exactly once
		// passing the number of workers 
		void set_up(size_t num_workers) override final
		{
			APP_TRACE_LOG(LL_SYS, L"Setting up TF observer with %u workers", num_workers);
		}

		// on_entry will be called before a worker runs a task
		void on_entry(tf::WorkerView wv, tf::TaskView tv) override final
		{
			APP_TRACE_LOG(LL_TRACE, L"TF worker %u ready to run: %s", wv.id(), tv.name().c_str());
		}

		// on_exit will be called after a worker completes a task
		void on_exit(tf::WorkerView wv, tf::TaskView tv) override final
		{
			APP_TRACE_LOG(LL_TRACE, L"TF worker %u finished running: %s", wv.id(), tv.name().c_str());
		}
	};

	class IScanner : public std::enable_shared_from_this <IScanner>
	{
	public:
		// Constructor & destructor
		IScanner();
		virtual ~IScanner();

		// Initialization & Finalization
		bool InitializeScanner();
		bool RunFirstTimeScans(uint8_t& pFailStep);
		void FinalizeScanner();

		// Scan cache
		bool SaveScanCacheToFile();
		bool LoadScanCacheFromFile();
		bool IsCachedScanObject(uint8_t nScanType, const std::wstring& stObjectName);
		bool AddCachedScanObject(uint8_t nScanType, const std::wstring& stObjectName);
		uint32_t GetCachedScannedObjectCount(uint8_t nScanType);

		auto GetManualMapScanCache() const { return m_vThreadRegionScanList; };

		// Common 
		void SendViolationNotification(DWORD dwListIndex, const std::wstring& stID, bool bStreamed, std::wstring stMessage = L"");
		std::wstring PatchFileName(const std::wstring& stInFileName);

		// Scan methods
		bool CDB_IsProcessExistByName(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsProcessExistByChecksum(const SCDBBaseContext& kContext, const std::wstring& stSum);
		bool CDB_IsProcessExistByFileDesc(const SCDBBaseContext& kContext, const std::wstring& stDesc, const std::wstring& wstVer = L"");
		bool CDB_IsModuleExistByNameInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsModuleExistByNameInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsModuleExistByChecksum(const SCDBBaseContext& kContext, const std::wstring& stSum);
		bool CDB_IsWindowsExistByTitleClass(const SCDBBaseContext& kContext, const std::wstring& stTitle, const std::wstring& stClass);
		bool CDB_IsWindowsExistByStyleExstyle(const SCDBBaseContext& kContext, const std::wstring& stStyle, const std::wstring& stExstyle);
		bool CDB_IsFileExistByName(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_CheckFileSum(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stSum, const std::wstring& stShouldEqual);
		bool CDB_CheckFilePattern(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType, const std::wstring& wstAddress = L"");
		bool CDB_CheckFileSectionHash(const SCDBBaseContext& kContext, const std::wstring& stTargetName, const std::wstring& stSectionHash);
		bool CDB_IsRegionExistInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stLength, const std::wstring& stSum);
		bool CDB_IsRegionExistInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stLength, const std::wstring& stSum);
		bool CDB_IsPatternExistInGameProcesses(const SCDBBaseContext& kContext, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType);
		bool CDB_IsPatternExistInAllProcesses(const SCDBBaseContext& kContext, const std::wstring& stPattern, const std::wstring& stMask, const std::wstring& stPatternType, const DWORD dwTargetPID);
		bool CDB_IsMemDumpExist(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stMemCopy);
		bool CDB_IsFileMappingExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsMutexExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsEventExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsSemaphoreExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsJobObjectExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsSymLinkExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_CheckAPIModuleBound(const SCDBBaseContext& kContext, const std::wstring& stModuleName, const std::wstring& stAPIName);
		bool CDB_IsMemChecksumCorrupted(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stSize, const std::wstring& stCorrectHash, const std::wstring& stShouldEqual);
		bool CDB_IsMemCorrupted(const SCDBBaseContext& kContext, const std::wstring& stAddress, const std::wstring& stOffsetList, const std::wstring& stSize, const std::wstring& stCorrectChecksum, const std::wstring& stShouldEqual);
		bool CDB_IsEbpContextCorrupted(const SCDBBaseContext& kContext, const std::wstring& stOffset, const std::wstring& stRangeSize, const std::wstring& stPattern, const std::wstring& stPatternType);
		bool CDB_CheckYaraFile(const SCDBBaseContext& kContext, std::vector <std::uint8_t> stFileContext);
		bool CDB_CheckRegistryKeyExist(const SCDBBaseContext& kContext, const std::wstring& stKey, const std::wstring& stPath);
		bool CDB_IsWindowsStationExist(const SCDBBaseContext& kContext, const std::wstring& stStationID);
		bool CDB_IsWaitableTimerExist(const SCDBBaseContext& kContext, const std::wstring& stTimerID);
		bool CDB_IsHandleObjectExist(const SCDBBaseContext& kContext, const std::wstring& stHandleObjectName);
		bool CDB_IsServiceExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsServiceExistByHash(const SCDBBaseContext& kContext, const std::wstring& stTargetHash);
		bool CDB_IsDriverExist(const SCDBBaseContext& kContext, const std::wstring& stTargetName);
		bool CDB_IsDriverExistByHash(const SCDBBaseContext& kContext, const std::wstring& stTargetHash);
		bool CDB_IsCertContextExist(const SCDBBaseContext& kContext, const std::wstring& stProvider, const std::wstring& stSerial);
		bool CDB_CheckWindowTextHeuristic(const SCDBBaseContext& kContext, const std::wstring& stLookedText);

		/// Check methods
		bool IsCustomKernelSignersAllowed();
		bool IsTestSignEnabled(LPDWORD pdwReturnCode);
		bool IsSecureBootEnabled();
		bool CheckDnsServiceIntegrity();

		// Scan interfaces helper
		auto ProcessScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxProcessScanMutex);	return m_spProcessScanner;			};
		auto WindowScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxWindowScanMutex);	return m_spWindowScanner;			};
		auto ServiceScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxServiceScanMutex);	return m_spServiceScanner;			};
		auto DriverScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxDriverScanMutex);	return m_spDriverScanner;			};
		auto HandleScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxHandleScanMutex);	return m_spHandleScanner;			};
		auto FolderScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxFolderScanMutex);	return m_spFolderScanner;			};
		auto ObjectDirectoryScanner()	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxObjDirScanMutex);	return m_spObjectDirectoryScanner;	};
		auto FileScanner()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxFileScanMutex);	return m_spFileScanner;				};
		auto ModuleScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxModuleScanMutex);	return m_spModuleScanner;			};
		auto SectionScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxSectionScanMutex);	return m_spSectionScanner;			};
		auto ThreadScanner()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxThreadScanMutex);	return m_spThreadScanner;			};
		auto HeapScanner()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxHeapScanMutex);	return m_spHeapScanner;				};

		// Enumerations
		bool EnumerateHandles(std::function<bool(SHandleScanContext*)> cb);
		bool EnumerateModules(HANDLE hProcess, std::function<bool(std::shared_ptr <SModuleEnumContext>)> cb);
		bool EnumerateSections(HANDLE hProcess, bool bRwxOnly, std::function<void(std::shared_ptr <SSectionEnumContext>)> cb);
		bool EnumerateThreads(HANDLE hProcess, std::function<void(SYSTEM_THREAD_INFORMATION*)> cb);
		bool EnumerateHeaps(HANDLE hProcess, std::function<void(PVOID, SIZE_T, SIZE_T, DWORD, DWORD)> cb);
		bool EnumerateSystemVolumes(std::function<void(std::wstring)> cb, bool bFilterNTFS);
		bool EnumerateProcessPssSnapshotEntries(HANDLE hProcess, std::function <void(std::shared_ptr <SSnapshotContext>)> cb);
		bool EnumerateServices(std::function<bool(std::shared_ptr <SServiceScanContext>)> cb);
		bool EnumerateDrivers(std::function<bool(std::shared_ptr <SDriverScanContext>)> cb);

		// Utilities
		bool IsHandleInheritable(HANDLE hObject);
		std::wstring GetHandleObjectType(HANDLE hObject);
		std::wstring GetHandleObjectName(HANDLE hProcess, HANDLE hObject);

		// Watcher callbacks
		void OnWatcherWindowScan(HWND hWnd, uint32_t nReason);			// Window watcher from WindowWatcher.cpp
		void OnWatcherDriverScan(const std::wstring& stDriverPathName);	// Driver watcher from kernel image callback

		// Memory watchdog(Memory working set)
		bool InitializeMemoryWatchdogs(HANDLE hProcess);
		bool CheckMemoryWatchdogs(HANDLE hProcess);
		bool IsProtectedMemoryRegions(HANDLE hProcess, LPVOID lpMemBase);
		auto GetProtectedMemoryRegions(HANDLE hProcess);

		// One time control functions
		void CheckHiddenProcess();
		void CheckWow32ReservedHook();
		void CheckManualMappedModules(bool bFatal = false);
		void CheckDevices();
		void CheckDnsHistory();
		void CheckVpn();
		void CheckFirmwareTables();
		void CheckProcessJobs();
		void CheckLsassIntegrity();
		void CheckTcpConnections();
		void CheckUdpConnections();
		void CheckUsnJournal();
		void CheckVTableIntegrity();
		void CheckUnloadedModules();
		void CheckGameWindows();
		void CheckWindowHeuristic();
		void CheckForegroundWindowOwners();
		void CheckProcessShim(HANDLE hProcess);
		void CheckProcessHollow(HANDLE hProcess);
		void CheckExceptionHandlers();
		void CheckPresentHook();

		// Hook helper functions
		bool CheckStackTrace(PVOID* UnknownFrame = nullptr);
		
	protected:
		DWORD					ThreadRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		// Locks
		mutable std::recursive_mutex m_mtxScanCacheMutex;
		mutable std::recursive_mutex m_mtxMemWatchdogMutex;
		mutable std::recursive_mutex m_mtxProcessScanMutex;
		mutable std::recursive_mutex m_mtxWindowScanMutex;
		mutable std::recursive_mutex m_mtxServiceScanMutex;
		mutable std::recursive_mutex m_mtxDriverScanMutex;
		mutable std::recursive_mutex m_mtxHandleScanMutex;
		mutable std::recursive_mutex m_mtxFolderScanMutex;
		mutable std::recursive_mutex m_mtxObjDirScanMutex;
		mutable std::recursive_mutex m_mtxFileScanMutex;
		mutable std::recursive_mutex m_mtxModuleScanMutex;
		mutable std::recursive_mutex m_mtxSectionScanMutex;
		mutable std::recursive_mutex m_mtxThreadScanMutex;
		mutable std::recursive_mutex m_mtxHeapScanMutex;

		// Scan interfaces
		std::shared_ptr <IProcessScanner>			m_spProcessScanner;
		std::shared_ptr <IWindowScanner>			m_spWindowScanner;
		std::shared_ptr <IServiceScanner>			m_spServiceScanner;
		std::shared_ptr <IDriverScanner>			m_spDriverScanner;
		std::shared_ptr <IHandleScanner>			m_spHandleScanner;
		std::shared_ptr <IFolderScanner>			m_spFolderScanner;
		std::shared_ptr <IObjectDirectoryScanner>	m_spObjectDirectoryScanner;
		std::shared_ptr <IFileScanner>				m_spFileScanner;
		std::shared_ptr <IModuleScanner>			m_spModuleScanner;
		std::shared_ptr <ISectionScanner>			m_spSectionScanner;
		std::shared_ptr <IThreadScanner>			m_spThreadScanner;
		std::shared_ptr <IHeapScanner>				m_spHeapScanner;

		// Helpers
		std::unique_ptr <yaracpp::YaraDetector>		m_upYaraDetector;
		std::unique_ptr <tf::Executor>				m_upTaskExecutor;

		// Trap memorys
		std::map <HANDLE, LPVOID>					m_mapMemoryDummyPages;
		std::map <HANDLE, LPVOID>					m_mapMemoryWatchdogs;

		// Scan cache
		std::map <uint8_t, std::vector <std::wstring>>	m_mapScanCache;
		std::vector <MEMORY_BASIC_INFORMATION>			m_vThreadRegionScanList;
		std::vector <std::wstring>						m_vSentViolationMessageIDs;
	};
};
