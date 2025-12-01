#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <xorstr.hpp>
#include <lazy_importer.hpp>
#include <concurrentqueue/concurrentqueue.h>

#include "../../Common/WorkQueue.hpp"
#include "../../Common/StdExtended.hpp"
#include "../../Common/SimpleTimer.hpp"
#include "../../Common/GameCodes.hpp"
#include "../../Common/AbstractSingleton.hpp"
#include "../../Common/MutexHelper.hpp"
#include "../../Common/Locks.hpp"

#include "../../Core/EngineR3_Core/include/LogHelper.hpp"
#include "../../Core/EngineR3_Core/include/WinAPIManager.hpp"
#include "../../Core/EngineR3_Core/include/DirFunctions.hpp"
#include "../../Core/EngineR3_Core/include/Data.hpp"
#include "../../Core/EngineR3_Core/include/LDasm.hpp"
#include "../../Core/EngineR3_Core/include/ErrorIDs.hpp"
#include "../../Core/EngineR3_Core/include/SentryManager.hpp"

#include "Common/Quarentine.hpp"
#include "SDK/SDKManager.hpp"
#include "Thread/ThreadManagerHelper.hpp"
#include "Common/Functions.hpp"
#include "Access/Access.hpp"
#include "SelfProtection/Watchdog.hpp"
#include "Common/WMI.hpp"
#include "Common/Analyser.hpp"
#include "Thread/SelfThreadIdentifier.hpp"
#include "Hook/Hooks.hpp"
#include "Scanner/ScannerInterface.hpp"
#include "Common/DetectQueue.hpp"
#include "Network/NetManager.hpp"
#include "Common/FilterManager.hpp"
#include "Common/CheatDBManager.hpp"
#include "IO/DataLoader.hpp"
#include "Common/GameIntegrationCheck.hpp"
#include "Monitor/GameMemoryMonitor.hpp"
#include "Monitor/ModuleSectionMonitor.hpp"
#include "Window/WindowWatcher.hpp"
#include "Monitor/HardwareBreakpointWatcher.hpp"
#include "Monitor/TickCounterThread.hpp"
#include "Common/CheatQueueManager.hpp"
#include "Monitor/MemoryAllocationWatcher.hpp"
#include "Monitor/MemoryHookScanner.hpp"
#include "Monitor/ManualMapScanner.hpp"
#include "Anti/AntiInputInjection.hpp"
#include "Common/CacheManager.hpp"
#include "Monitor/WinDebugMonitor.hpp"

#define LOCK_MTX std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex)
#define LOCK_MTX_2 std::lock_guard <std::recursive_mutex> __lock(m_rmAppMutex2)

namespace NoMercy
{
	// Enqueued message types
	enum EQueueMessageTypes
	{
		QUEUE_MESSAGE_TYPE_NONE,
		QUEUE_MESSAGE_TYPE_CHEAT_DETECT,
		QUEUE_MESSAGE_TYPE_CHEAT_DETAILS
	};

	// Update specific data types
	enum EFileAttributes
	{
		FILE_ATTR_NONE = (1 << 0),
		FILE_ATTR_PATH_SYSTEM = (1 << 1),
		FILE_ATTR_PATH_GAME = (1 << 2),
		FILE_ATTR_PATH_LOCAL = (1 << 3),
		FILE_ATTR_HIDDEN = (1 << 4),
		FILE_ATTR_CRYPTED_1 = (1 << 5), // AES256
		FILE_ATTR_COMPRESSED_1 = (1 << 6), // LZ4
	};
	struct SDependecyContext
	{
		std::wstring stLocalTempFileName;
		std::wstring stFileName;
		std::wstring stLocalPath;
		uint32_t nFileSize{ 0 };
		uint32_t nAttributes{ 0 };
		std::wstring stFileHash;
		std::wstring stEggHash;
		std::wstring stURL;
		bool bShouldUpdate{ true };
	};

	// Type definitions
	using TInitializeEx = std::function<bool()>;
	using TPrepareCore = std::function<bool(int32_t)>;

	// Main class
	class CApplication : public CSingleton <CApplication>
	{
		// Lifecycle
		public:
			virtual ~CApplication();

			CApplication(const CApplication&) = delete;
			CApplication(CApplication&&) noexcept = delete;
			CApplication& operator=(const CApplication&) = delete;
			CApplication& operator=(CApplication&&) noexcept = delete;

		// Public methods
		public:

		// Constructor
			CApplication();

		// Initialization
			bool PrepareCore(uint8_t eAppType);

			bool Initialize();
			bool InitializeClientThreads();
			bool InitializeClient();

		// Finalization
			bool Finalize();
			bool FinalizeClient();

		// Routine
			bool CreateWebsocketConnection();
			bool InitializeClientMainCheckThread();
			bool InitSelfProtection(LDR_DATA_TABLE_ENTRY* pModuleInfo);
			bool RunClientSingleScanInstances();

		// Callback
			bool IsIgnoredCheatDetection(uint32_t id, uint32_t sub_id, const std::wstring& param);
			std::wstring OnCheatDetect(uint32_t id, uint32_t sub_id = 0, const std::wstring& param = L"", bool fatal = false, uint32_t system_error = -1, uint32_t client_pid = 0, const std::wstring& ref_id = L"");
			void OnCheatProcessDetect(const std::wstring& stRefID, HANDLE hProcess, const std::wstring& stFileName);
			void OnCloseRequest(EExitErrorCodes ullErrorCode, uint32_t dwSystemErrorCode, void* lpParam = nullptr, bool bSilent = false);
			void OnBackendConnected();
			void OnBackendDisconnected();
			void OnThreadAttach(DWORD dwThreadID);

		// Getter
			auto AppIsClient() const					{ return m_abClientProcess.load(); };
			auto AppIsPrepared() const					{ return m_abAppIsPrepared.load(); };
			auto AppIsReady() const						{ return m_abAppIsInitiliazed.load() && !m_abFinalizeTriggered.load() && !m_abIsCloseTriggered.load() && m_abInitThreadCompleted.load(); };
			auto AppIsInitiliazed() const				{ return m_abAppIsInitiliazed.load();   };
			auto AppIsFinalized() const					{ return m_abFinalizeTriggered.load();  };
			auto AppCloseTriggered() const				{ return m_abIsCloseTriggered.load();	};
			auto AppIsInitializedThreadCompleted() const{ return m_abInitThreadCompleted.load(); };
			auto IsConnectedToWS() const				{ return m_abNetworkReady.load(); };
			auto WSConnectionIsReady() const			{ return m_abWsConnIsReady.load(); };
			auto NetworkIsReady() const					{ return m_abNetworkReady.load() && m_abWsConnIsReady.load(); };
			auto GetInitStatusCode() const				{ LOCK_MTX; return m_dwInitStatusCode;	};
			auto GetInitSubStatusCode() const			{ LOCK_MTX; return m_dwInitSubErrorCode;};
			auto IsHooksInitialized() const				{ return m_abHooksIntiailized.load(); };
			auto GetTimerQueueHandle() const			{ LOCK_MTX; return m_hTimerQueue; };
			auto GetCurrentProcessSID() const			{ LOCK_MTX; return m_dwSessionID; };
			auto GetWatchdogTimerHandle() const			{ LOCK_MTX; return m_hWatchdogTimer; };
			auto GetWatchdogTimerQueue() const			{ LOCK_MTX; return m_hTimerQueue; };
			auto GetAntivirusInfo() const				{ LOCK_MTX; return m_stAntivirusInfo; };

		// Setter
			void SetWsConnectionReady(bool bStatus)				{ m_abWsConnIsReady.store(bStatus); };
			void SetHooksInitialized()							{ m_abHooksIntiailized.store(true); };
			void ResetWatchdogTimer()							{ LOCK_MTX; m_hWatchdogTimer = nullptr; };
			void SetAntivirusInfo(const std::wstring& stName)	{ LOCK_MTX; m_stAntivirusInfo = stName; };
			
		// Screen protector
			bool ChangeScreenProtectionStatus(HWND hWnd, bool bEnabled);
			void CheckScreenProtection(HWND hWnd);
			void InitScreenProtection(HWND hWnd);
			void RemoveScreenProtection(HWND hWnd);
			bool IsProtectedScreen(HWND hWnd);

		// WS
			void CreateWsQueueWorker();
			void ReleaseWsQueueWorker();
			void EnqueueWsMessage(const std::wstring& wstMessage);
			std::wstring DequeueWsMessage();

			void CreateWsHearbeatWorker();
			void ReleaseWsHeartbeatWorker();
			void AppendWsHearbeatRequest(uint8_t byKey);
			uint8_t DequeHeartbeatKey();
			void ProcessWsHearbeatRequest();

		// Class method wrappers
		public:
			auto SDKHelperInstance()				{ LOCK_MTX; return m_spSDKHelper;					};
			auto ThreadManagerInstance()			{ LOCK_MTX; return m_spThreadMgr;					};
			auto FunctionsInstance()				{ LOCK_MTX; return m_spFunctions;					};
			auto AccessHelperInstance()				{ LOCK_MTX; return m_spAccessHelper;				};
			auto WatchdogInstance()					{ LOCK_MTX; return m_spWatchdog;					};
			auto AnalyserInstance()					{ LOCK_MTX; return m_spAnalyser;					};
			auto SelfThreadIdentifierInstance()		{ LOCK_MTX_2; return m_spSelfThreadIdentifier;		};
			auto SelfHooksInstance()				{ LOCK_MTX; return m_spSelfHooks;					};
			auto NetworkMgrInstance()				{ LOCK_MTX; return m_spNetworkMgr;					};
			auto ScannerInstance()					{ LOCK_MTX; return m_spScannerInterface;			};
			auto QuarentineInstance()				{ LOCK_MTX; return m_spQuarentineMgr;				};
			auto FilterMgrInstance()				{ LOCK_MTX; return m_spFilterMgr;					};
			auto CheatDBManagerInstance()			{ LOCK_MTX; return m_spCheatDBMgr;					};
			auto DataLoaderInstance()				{ LOCK_MTX; return m_spDataLoader;					};
			auto GameIntegrationMgr()				{ LOCK_MTX; return m_spGameIntegrationMgr;			};
			auto CheatQueueInstance()				{ LOCK_MTX; return m_spCheatQueue;					};
			auto GameRegionMonitorInstance()		{ LOCK_MTX; return m_spGameRegionMonitor;			};
			auto ModuleSectionMonitorInstance()		{ LOCK_MTX; return m_spModuleSectionMonitor;		};
			auto WindowWatcherInstance()			{ LOCK_MTX; return m_spWindowWatcher;				};
			auto HwbpWatcherInstance()				{ LOCK_MTX; return m_spHwbpWatcher;					};
			auto TickCounterInstance()				{ LOCK_MTX; return m_spTickCounter;					};
			auto CheatQueueManagerInstance()		{ LOCK_MTX; return m_spCheatQueueManager;			};
			auto MemAllocWatcherInstance()			{ LOCK_MTX; return m_spMemoryAllocationWatcher;		};
			auto WMIManagerInstance()				{ LOCK_MTX; return m_spWMIManager;					};
			auto HookScannerInstance()				{ LOCK_MTX; return m_spHookScanner;					};
			auto ManualMapScannerInstance()			{ LOCK_MTX; return m_spManualMapScanner;			};
			auto InputInjectMonitorInstance()		{ LOCK_MTX; return m_spInputInjectMonitor;			};
			auto CacheManagerInstance()				{ LOCK_MTX; return m_spCacheManager;				};
			auto WinDebugStringMonitorInstance()	{ LOCK_MTX; return m_spWinDebugStrMonitor;			};

		// Self functions
		protected:
			bool __IsSentSentryLog(const std::wstring& c_stData);
			void __OnLogMessageCreated(uint8_t c_nLevel, const std::wstring& c_stData);

			void __OnCoreInitilizationFail(uint8_t nStep);
			inline bool __IsCorePrepared();
					
			inline bool __InitializeTestMode();
			void __InitTestFunctions();

		// Thread functions
		protected:
			DWORD					ClientInitThreadRoutine(void);
			static DWORD WINAPI		StartClientInitThreadRoutine(LPVOID lpParam);

		// Private class members
		private:
			mutable std::recursive_mutex m_rmAppMutex;
			mutable std::recursive_mutex m_rmAppMutex2;
			mutable std::recursive_mutex m_mtxTerminateProcess;
			mutable std::recursive_mutex m_mtxCloseProcess;

			DWORD m_dwSessionID;

			std::wstring m_stAntivirusInfo;
			
			std::vector <std::tuple <uint32_t, uint32_t, std::wstring>> m_vecSendCheatDetections;
			std::vector <std::wstring> m_vecSentSentryLogs;

			std::atomic_bool	m_abClientProcess;
			std::atomic_bool	m_abAppIsPrepared;
			std::atomic_bool	m_abAppIsInitiliazed;
			std::atomic_bool	m_abFinalizeTriggered;
			std::atomic_bool	m_abIsCloseTriggered;
			std::atomic_bool	m_abWsConnIsReady;
			std::atomic_bool 	m_abNetworkReady;
			std::atomic_bool	m_abHooksIntiailized;
			std::atomic_bool	m_abInitThreadCompleted;

			DWORD m_dwInitStatusCode;
			DWORD m_dwInitSubErrorCode;

			std::shared_ptr <CSDKManager>				m_spSDKHelper;
			std::shared_ptr <CThreadManager>			m_spThreadMgr;
			std::shared_ptr <CFunctions>				m_spFunctions;
			std::shared_ptr <CAccess>					m_spAccessHelper;
			std::shared_ptr <CWatchdog>					m_spWatchdog;
			std::shared_ptr <CAnalyser>					m_spAnalyser;
			std::shared_ptr <CSelfThreadIdentifier>		m_spSelfThreadIdentifier;
			std::shared_ptr <CSelfApiHooks>				m_spSelfHooks;
			std::shared_ptr <CNetworkManager>			m_spNetworkMgr;
			std::shared_ptr <IScanner>					m_spScannerInterface;
			std::shared_ptr <CQuarentine>				m_spQuarentineMgr;
			std::shared_ptr <CFilterManager>			m_spFilterMgr;
			std::shared_ptr <CCheatDBManager>			m_spCheatDBMgr;
			std::shared_ptr <CDataLoader>				m_spDataLoader;
			std::shared_ptr <CGameIntegrationManager>	m_spGameIntegrationMgr;
			std::shared_ptr <CCheatQueue>				m_spCheatQueue;
			std::shared_ptr <CGameMemoryMonitor>		m_spGameRegionMonitor;
			std::shared_ptr <CModuleSectionMonitor>		m_spModuleSectionMonitor;
			std::shared_ptr <CWindowWatcher>			m_spWindowWatcher;
			std::shared_ptr <CHardwareBreakpointWatcher>m_spHwbpWatcher;
			std::shared_ptr <CTickCounter>				m_spTickCounter;
			std::shared_ptr <CCheatQueueManager>		m_spCheatQueueManager;
			std::shared_ptr <CMemAllocWatcher>			m_spMemoryAllocationWatcher;
			std::shared_ptr <CWMI>						m_spWMIManager;
			std::shared_ptr <CHookScanner>				m_spHookScanner;
			std::shared_ptr <CManualMapScanner>			m_spManualMapScanner;
			std::shared_ptr <CInputInjectMonitor>		m_spInputInjectMonitor;
			std::shared_ptr <CCacheManager>				m_spCacheManager;
			std::shared_ptr <CWinDebugMonitor>			m_spWinDebugStrMonitor;

			moodycamel::ConcurrentQueue <std::wstring>	m_kMessageQueue;
			moodycamel::ConcurrentQueue <uint8_t>		m_kWSHeartbeatQueue;

			HANDLE m_hTimerQueue;
			HANDLE m_hWsQueueProcessorTimer;
			HANDLE m_hWsHeartbeatTimer;
			HANDLE m_hWatchdogTimer;

			CLimitSingleInstance m_kClientMutex;
	};
};

#undef LOCK_MTX
#undef LOCK_MTX_2
