#pragma once
#include "../../../Common/StdExtended.hpp"

#define LOCK_MTX std::lock_guard <std::recursive_mutex> __lock(m_rmMutex)

namespace NoMercyCore
{
	struct SStage
	{
		DWORD dwStage;
		std::wstring stStageKey;
	};

	enum EInitOptions // m_dwInitOptions
	{
		INIT_OPTION_RUN_SILENT_MODE									= (1 << 0), // Do not terminate process when any bad event or cheat detected, just on when initilization is fails
		INIT_OPTION_DISABLE_LOG_FILE_TELEMETRY						= (1 << 1),
		INIT_OPTION_BLOCK_SYSTEM_OWNED_HANDLE_ACCESS				= (1 << 2),
		INIT_OPTION_HOOK_GAME_PROCESS_CRITICAL_WINAPI_FUNCTIONS		= (1 << 3),
		INIT_OPTION_HOOK_GAME_ENGINE_CRITICAL_FUNCTIONS				= (1 << 4),
		INIT_OPTION_PROTECT_GRAPHIC_ENGINE_FUNCTIONS				= (1 << 5),
		INIT_OPTION_ALWAYS_PROTECT_GAME_SCREEN						= (1 << 6),
		INIT_OPTION_BLOCK_SWITCH_WINDOW								= (1 << 7),
		INIT_OPTION_DISABLE_DISPLAY_IN_TRAY							= (1 << 8),
		INIT_OPTION_ALLOW_VIRTUAL_MACHINE							= (1 << 9),
		INIT_OPTION_ALLOW_MOUSE_MACRO								= (1 << 10),
		INIT_OPTION_ALLOW_KEYBOARD_MACRO							= (1 << 11),
		INIT_OPTION_ALLOW_USER_DEBUGGER								= (1 << 12),
		INIT_OPTION_ALLOW_KERNEL_DEBUGGER							= (1 << 13),
		INIT_OPTION_ALLOW_SECURE_BOOT_DISABLE						= (1 << 14),
		INIT_OPTION_ALLOW_ENABLED_TEST_SIGNATURE 					= (1 << 15),
		INIT_OPTION_ALLOW_HVCI_DISABLE								= (1 << 16),
		INIT_OPTION_ALLOW_TPM_DISABLE								= (1 << 17),
		INIT_OPTION_DISABLE_GAME_MEMORY_ANTI_TAMPER					= (1 << 18),
		INIT_OPTION_DISABLE_WATCHDOG_INSIDE_GAME_PROCESS			= (1 << 19),
		INIT_OPTION_DISABLE_WIN32_MESSAGE_HOOK_INSIDE_GAME_PROCESS	= (1 << 20)
	};

	class CData : public CSingleton <CData>
	{
		public:
			CData(uint8_t eAppType = 0);
			virtual ~CData();

		// Setter
			void SetWatchdogFirstCheck()								{ LOCK_MTX; m_bWatchdogFirstChecked	= true;					};
			void SetTelemetryProcessId(DWORD dwProcessId)				{ LOCK_MTX; m_dwTelemetryProcessId	= dwProcessId; 			};
			void SetErrorCode(uint32_t dwErrorCode)						{ LOCK_MTX; m_dwErrorCode			= dwErrorCode;			};
			void SetLauncherName(const std::wstring& stLauncherName)		{ LOCK_MTX; m_strLauncherName		= stLauncherName;		};
			void SetPythonHandle(HMODULE hModule)						{ LOCK_MTX; m_hPythonHandle 		= hModule; 				};
			void SetPythonName(const std::wstring& strName)				{ LOCK_MTX; m_strPythonName 		= strName; 				};
			void SetPackedProcess(bool bRet)							{ LOCK_MTX; m_bIsProcessPacked 		= bRet; 				};
			void SetShadowInitialized(bool bRet)						{ LOCK_MTX; m_bIsShadowProcess 		= bRet; 				};
			void SetShadowProcessHandle(HANDLE hProcess)				{ LOCK_MTX; m_hShadowProcess 		= hProcess; 			};
			void SetNoMercyVersion(uint32_t dwVersion)					{ LOCK_MTX; m_dwNoMercyVersion		= dwVersion; 			};
			void SetProcessInstance(HINSTANCE hInstance)				{ LOCK_MTX; m_hInstance				= hInstance;			};
			void SetAppType(int iType)									{ LOCK_MTX; m_iAppType				= iType;				};
			void SetGameCode(int iCode)									{ LOCK_MTX; m_iGameCode				= iCode;				};
			void SetMainThreadId(DWORD dwThreadId)						{ LOCK_MTX; m_dwMainThreadId		= dwThreadId;			};
			void SetInitOptions(DWORD dwOptions)						{ LOCK_MTX; m_dwInitOptions			= dwOptions;			};
			void SetClientLimit(DWORD dwLimit)							{ LOCK_MTX; m_dwClientLimit			= dwLimit;				};
			void SetDisabled(bool bIsDisabled)  						{ LOCK_MTX; m_bIsDisabled			= bIsDisabled;			};
			void SetUseCrashHandler(bool bUseCrashHandler)				{ LOCK_MTX; m_bUseCrashHandler		= bUseCrashHandler;		};
			void SetCompabilityMode(bool bCompabilityMode)				{ LOCK_MTX; m_bCompabilityMode		= bCompabilityMode;		};
			void SetLicenseCode(const std::wstring& stLicenseCode)		{ LOCK_MTX; m_strLicenseCode		= stLicenseCode;		};
			void SetStage(DWORD dwStage, const std::wstring& stStage)	{ LOCK_MTX; m_dwStage = dwStage;	m_strStage = stStage;	};
			void SetStageKey(const std::wstring& stStageKey)			{ LOCK_MTX; m_strStageKey			= stStageKey;			};
			void SetGameVersion(DWORD dwVersion)						{ LOCK_MTX; m_dwVersion				= dwVersion;			};
			void SetUserToken(const std::wstring& stUserToken)			{ LOCK_MTX; m_strUserToken			= stUserToken;			};
			void SetHeartbeatEnabled(bool bHeartbeatEnabled)			{ LOCK_MTX; m_bHeartbeatEnabled		= bHeartbeatEnabled;	};
			void SetHeartbeatType(DWORD dwHeartbeatType)				{ LOCK_MTX; m_dwHeartbeatType		= dwHeartbeatType;		};
			void SetHeartbeatInterval(DWORD dwHeartbeatInterval)		{ LOCK_MTX; m_dwHeartbeatIntervalMs	= dwHeartbeatInterval;	};
			void SetHeartbeatSeed(uint32_t dwHeartbeatSeed)				{ LOCK_MTX; m_dwHeartbeatSeed		= dwHeartbeatSeed;		};
			void SetMainThreadHandle(HANDLE hThread)					{ LOCK_MTX; m_hMainThread			= hThread;				};
			void SetConnectedToAPIServer(bool bRet)						{ LOCK_MTX; m_bConnectedToBackend	= bRet;					};
			void SetLauncherUpdaterStatus(bool bBlockUpdate)			{ LOCK_MTX; m_bBlockLauncherUpdate	= bBlockUpdate;			};
			void SetNetGuardEnabled(bool bEnabled)  					{ LOCK_MTX; m_bNetGuardEnabled		= bEnabled;				};
			void SetNetGuardVersion(uint32_t dwVersion)					{ LOCK_MTX; m_dwNetGuardVersion		= dwVersion;			};
			void SetNetGuardSeed(uint64_t qwSeed)						{ LOCK_MTX; m_qwNetGuardSeed		= qwSeed;				};
			void SetLauncherIntegrityCheckEnabled(bool bEnabled) 		{ LOCK_MTX; m_bLauncherIntegrityCheckEnabled = bEnabled;	};
			void SetLauncherExecutable(const std::wstring& stExecutable){ LOCK_MTX; m_strLauncherExecutable = stExecutable;			};
			void SetLauncherExecutableHash(const std::wstring& stHash)	{ LOCK_MTX; m_strLauncherExecutableHash = stHash;			};
			void SetSecurityLevel(uint32_t dwLevel)						{ LOCK_MTX; m_dwSecurityLevel		= dwLevel;				};
			void SetDisabledFuncs(uint32_t dwFuncs)						{ LOCK_MTX; m_dwDisabledFuncs		= dwFuncs;				};
			void SetClientMainWindow(HWND hWnd)							{ LOCK_MTX; m_hClientWnd			= hWnd;					};
			void SetAdminEnvironment(bool bValue)						{ LOCK_MTX; m_bAdminEnv				= bValue;				};
			void SetDetectedEmulatorID(uint32_t dwID)					{ LOCK_MTX; m_dwEmulatorIndex		= dwID;					};

		// Getter
			auto IsConnectedToBackend() const				{ LOCK_MTX; return m_bConnectedToBackend;	};
			auto WatchdogIsFirstChecked() const				{ LOCK_MTX; return m_bWatchdogFirstChecked;	};
			auto GetTelemetryProcessId() const				{ LOCK_MTX; return m_dwTelemetryProcessId;	};
			auto GetErrorCode() const						{ LOCK_MTX; return m_dwErrorCode;			};
			auto GetLauncherName() const					{ LOCK_MTX; return m_strLauncherName;		};
			auto GetPythonHandle() const					{ LOCK_MTX; return m_hPythonHandle;			};
			auto GetPythonName() const						{ LOCK_MTX; return m_strPythonName;			};
			auto IsPackedProcess() const					{ LOCK_MTX; return m_bIsProcessPacked;		};
			auto IsShadowInitialized() const				{ LOCK_MTX; return m_bIsShadowProcess;		};
			auto GetShadowProcessHandle() const				{ LOCK_MTX; return m_hShadowProcess;		};
			auto GetNoMercyVersion() const					{ LOCK_MTX; return m_dwNoMercyVersion;		};
			auto GetAntiModuleInformations() const			{ LOCK_MTX; return m_pAntiModuleInfo;		};
			auto GetProcessInstance() const					{ LOCK_MTX; return m_hInstance;				};
			auto GetAppType() const							{ LOCK_MTX; return m_iAppType;				};
			auto GetGameCode() const						{ LOCK_MTX; return m_iGameCode;				};
			auto GetMainThreadId() const					{ LOCK_MTX; return m_dwMainThreadId;		};
			auto GetInitOptions() const						{ LOCK_MTX; return m_dwInitOptions;			};
			auto GetClientLimit() const						{ LOCK_MTX; return m_dwClientLimit;			};
			auto IsDisabled() const							{ LOCK_MTX; return m_bIsDisabled;			};
			auto IsCrashHandlerEnabled() const				{ LOCK_MTX; return m_bUseCrashHandler;		};
			auto GetLicenseCode() const						{ LOCK_MTX; return m_strLicenseCode;		};
			auto& GetLicensedIPs() const					{ LOCK_MTX; return m_vLicensedIPs;			};
			auto GetStage() const							{ LOCK_MTX; return m_dwStage;				};
			auto GetStageStr() const						{ LOCK_MTX; return m_strStage;				};
			auto GetStageKey() const						{ LOCK_MTX; return m_strStageKey;			};
			auto GetGameVersion() const						{ LOCK_MTX; return m_dwVersion;				};
			auto GetUserToken() const						{ LOCK_MTX; return m_strUserToken;			};
			auto GetHeartbeatEnabled() const				{ LOCK_MTX; return m_bHeartbeatEnabled;		};
			auto GetHeartbeatType() const					{ LOCK_MTX; return m_dwHeartbeatType;		};
			auto GetHeartbeatInterval() const				{ LOCK_MTX; return m_dwHeartbeatIntervalMs;	};
			auto GetHeartbeatSeed() const					{ LOCK_MTX; return m_dwHeartbeatSeed;		};
			auto GetMainThreadHandle() const				{ LOCK_MTX; return m_hMainThread;			};
			auto IsLauncherUpdatePassed() const				{ LOCK_MTX; return m_bBlockLauncherUpdate;	};
			auto IsNetGuardEnabled() const					{ LOCK_MTX; return m_bNetGuardEnabled;		};
			auto GetNetGuardVersion() const					{ LOCK_MTX; return m_dwNetGuardVersion;		};
			auto GetNetGuardSeed() const					{ LOCK_MTX; return m_qwNetGuardSeed;		};
			auto IsLauncherIntegrityCheckEnabled() const	{ LOCK_MTX; return m_bLauncherIntegrityCheckEnabled; };
			auto GetLauncherExecutable() const  			{ LOCK_MTX; return m_strLauncherExecutable; };
			auto GetLauncherExecutableHash() const  		{ LOCK_MTX; return m_strLauncherExecutableHash; };
			auto GetSecurityLevel() const					{ LOCK_MTX; return m_dwSecurityLevel; };
			auto GetDisabledFuncs() const					{ LOCK_MTX; return m_dwDisabledFuncs; };
			auto GetClientMainWindow() const				{ LOCK_MTX; return m_hClientWnd; };
			auto IsCompabilityModeEnabled() const			{ LOCK_MTX; return m_bCompabilityMode; };
			auto IsAdminEnvironment() const					{ LOCK_MTX; return m_bAdminEnv; };
			auto GetDetectedEmulatorIndex() const			{ LOCK_MTX; return m_dwEmulatorIndex; };

		// Module helper
			void SetAntiModuleInformations(LPCVOID c_lpModuleInfo);
			std::wstring GetAntiFileName() const;
			std::wstring GetAntiFullName() const;

		// License helper
			bool HasLicensedIp() const;
			bool IsLicensedIp(const std::wstring& stIP) const;
			void AddLicensedIp(const std::wstring& stIP);
			std::wstring GetLicensedIPsString();

		// Screen protection
			bool IsProtectedWindow(HWND hWnd) const;
			bool GetScreenProtectionStatus(HWND hWnd) const;
			void UpdateScreenProtectionStatus(HWND hWnd, bool bNew);

		// Builder
		protected:
			void __Initialize();

		// Members
		private:
			mutable std::recursive_mutex m_rmMutex;
			
			bool	m_bConnectedToBackend;
			bool	m_bConnectionDisconnected;

			bool	m_bWatchdogFirstChecked;
			bool	m_bAdminEnv;

			uint32_t	m_dwTelemetryProcessId;
			uint32_t	m_dwErrorCode;

			std::shared_ptr <LDR_DATA_TABLE_ENTRY> m_pAntiModuleInfo;
			std::wstring	m_strLauncherName;
			HMODULE		m_hPythonHandle;
			std::wstring	m_strPythonName;
			bool		m_bIsProcessPacked;
			bool		m_bIsShadowProcess;
			HANDLE		m_hShadowProcess;
			uint32_t    m_dwNoMercyVersion;
			bool		m_bBlockLauncherUpdate;

			std::map <HWND, bool> m_mScreenProtectionStatus;

			HINSTANCE		m_hInstance;
			uint8_t			m_iAppType;
			int				m_iGameCode;
			DWORD			m_dwMainThreadId;
			HANDLE			m_hMainThread;
			DWORD			m_dwInitOptions;
			DWORD			m_dwClientLimit;
			bool			m_bIsDisabled;
			bool			m_bUseCrashHandler;
			bool			m_bCompabilityMode;
			HWND			m_hClientWnd;

			std::vector <std::wstring>	m_vLicensedIPs;
			std::wstring					m_strLicenseCode;

			DWORD		m_dwStage;
			std::wstring m_strStage;
			std::wstring m_strStageKey;
			DWORD		m_dwVersion;
			
			bool		m_bHeartbeatEnabled;
			DWORD		m_dwHeartbeatType;
			DWORD		m_dwHeartbeatIntervalMs;
			uint32_t	m_dwHeartbeatSeed;
			
			bool		m_bNetGuardEnabled;
			DWORD		m_dwNetGuardVersion;
			uint64_t	m_qwNetGuardSeed;

			bool		m_bLauncherIntegrityCheckEnabled;
			std::wstring	m_strLauncherExecutable;
			std::wstring	m_strLauncherExecutableHash;

			std::wstring m_strUserToken;

			DWORD m_dwSecurityLevel;
			DWORD m_dwDisabledFuncs;
			DWORD m_dwEmulatorIndex;
	};
};

#undef LOCK_MTX
