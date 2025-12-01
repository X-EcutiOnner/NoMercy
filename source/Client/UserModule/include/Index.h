#ifndef __NOMERCY_LOADER__
#define __NOMERCY_LOADER__
#include <string.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef NOMERCY_EXPORTS
	#define NOMERCY_API __declspec(dllexport) 
#else
	#define NOMERCY_API __declspec(dllimport) 
#endif

#ifndef EXTERN_C
	#ifdef __cplusplus
		#define EXTERN_C extern "C"
	#else
		#define EXTERN_C
	#endif
#endif

#ifdef _MSC_VER
	#ifdef _M_IX86
		#define NM_CALLCONV	__stdcall
	#else
		#define NM_CALLCONV
	#endif
#else
	#define NM_CALLCONV
#endif

#ifdef __cplusplus
namespace NoMercy
{
#endif
	// SDK message redirector callback function template
	typedef void(NM_CALLCONV* TNMCallback)(int32_t nCode, const char* c_szMessage, const void* c_lpParam);

	// Pointer redirected function data contexts
	enum ERunningStatus
	{
		RUNNING_STATUS_NONE,
		RUNNING_STATUS_INTEGRITY_MONITOR_THREAD_CHECK,
		RUNNING_STATUS_WINDOW_WATCHDOG_CHECK,
		RUNNING_STATUS_SYNC_WATCHDOG_CHECK,
		RUNNING_STATUS_ALL
	};
	enum ELogLevel
	{
		LOG_LEVEL_NONE,
		LOG_LEVEL_CRITICAL,
		LOG_LEVEL_ERROR,
		LOG_LEVEL_WARNING,
		LOG_LEVEL_INFO,
		LOG_LEVEL_DEBUG
	};

	// Pointer redirected function templates
	typedef void(NM_CALLCONV* TPrintMessage)(const char* message);
	typedef void(NM_CALLCONV* TRequestRestart)(uint32_t reason);
	typedef void(NM_CALLCONV* TDisconnectPeer)(const char* reason);
	typedef void(NM_CALLCONV* TNetworkPacket)(void* packet, uint32_t length);
	typedef void(NM_CALLCONV* TSendReport)(uint32_t event_id, uint32_t sub_id, const char* details);
	typedef int32_t(NM_CALLCONV* TRunningStatusCheck)(uint8_t type);
	typedef void(NM_CALLCONV* TSendLog)(const char* message);
	/// Game specific
	// GAME_CODE_METIN2 (2)
	typedef void(NM_CALLCONV* TTraceError)(const char* format, ...);
	typedef bool(NM_CALLCONV* TIsMappedFileExist)(const char* filename);
	typedef uint32_t(NM_CALLCONV* TGetVID)();
	typedef uint8_t(NM_CALLCONV* TGetPhase)();
	typedef const char*(NM_CALLCONV* TGetPlayerName)();
	typedef uint32_t(NM_CALLCONV* TGetMappedFileHash)(const char* filename);
	typedef void(NM_CALLCONV* TSendSequence)();

	// Shared data context structures
	struct SSignalMsgCtx
	{
		uint32_t nSignalCode;

#ifdef __cplusplus
		SSignalMsgCtx()
		{
			nSignalCode = 0;
		}
#endif
	};
	struct SRenderEngineCtx
	{
		char szRenderer[32];

#ifdef __cplusplus
		SRenderEngineCtx()
		{
			memset(&szRenderer, 0, sizeof(szRenderer));
		}
#endif
	};
	struct SFileHashCtx
	{
		char szFileName[300];
		char szCorrectSum[64];

#ifdef __cplusplus
		SFileHashCtx()
		{
			memset(&szFileName, 0, sizeof(szFileName));
			memset(&szCorrectSum, 0, sizeof(szCorrectSum));
		}
#endif
	};
	struct SFuncHookCtx
	{
		uint8_t nIndex;
		void* lpFuncPointer;

#ifdef __cplusplus
		SFuncHookCtx()
		{
			nIndex = 0;
			lpFuncPointer = NULL;
		}
#endif
	};
	struct SProtectFuncCtx
	{
		uint8_t nIndex;
		void* lpFuncPointer;

#ifdef __cplusplus
		SProtectFuncCtx()
		{
			nIndex = 0;
			lpFuncPointer = NULL;
		}
#endif
	};
	struct SNetworkCryptKeyCtx
	{
		uint8_t byCryptKey[256];
		uint32_t nKeySize;

#ifdef __cplusplus
		SNetworkCryptKeyCtx()
		{
			memset(&byCryptKey, 0, sizeof(byCryptKey));
			nKeySize = 0;
		}
#endif
	};
	struct SNetworkMessageCtx
	{
		void* lpInPacketData;
		uint32_t nInPacketSize;
		void* lpOutPacketData;
		uint32_t nOutPacketSize;

#ifdef __cplusplus
		SNetworkMessageCtx()
		{
			lpInPacketData = NULL;
			nInPacketSize = 0;
			lpOutPacketData = NULL;
			nOutPacketSize = 0;
		}
#endif
	};
	struct SGameNetworkInfoCtx
	{
		void* lpSocketPtr;
		char szAddr[46];
		uint16_t nPort;
		char szType[8];

#ifdef __cplusplus
		SGameNetworkInfoCtx()
		{
			lpSocketPtr = NULL;
			memset(&szAddr, 0, sizeof(szAddr));
			nPort = 0;
			memset(&szType, 0, sizeof(szType));
		}
#endif
	};
	struct SUserToken
	{
		char szToken[255];
		uint32_t nTokenSize;

#ifdef __cplusplus
		SUserToken()
		{
			memset(&szToken, 0, sizeof(szToken));
			nTokenSize = 0;
		}
#endif
	};
	struct SPlatformToken
	{
		char szToken[255];
		uint32_t nTokenSize;

#ifdef __cplusplus
		SPlatformToken()
		{
			memset(&szToken, 0, sizeof(szToken));
			nTokenSize = 0;
		}
#endif
	};
	struct SVersionCtx
	{
		uint32_t nVersion;

#ifdef __cplusplus
		SVersionCtx()
		{
			nVersion = 0;
		}
#endif
	};
	struct SInitRetCtx
	{
		bool bIsInitialized;

#ifdef __cplusplus
		SInitRetCtx()
		{
			bIsInitialized = false;
		}
#endif
	};
	struct SSusEventCtx
	{
		uint32_t nType;
		char szMessage[2048];
		void* lpParam;

#ifdef __cplusplus
		SSusEventCtx()
		{
			nType = 0;
			memset(&szMessage, 0, sizeof(szMessage));
			lpParam = NULL;
		}
#endif
	};
	struct SPollEventCtx
	{
		uint32_t nTimestamp;

#ifdef __cplusplus
		SPollEventCtx()
		{
			nTimestamp = 0;
		}
#endif
	};
	struct SSessionIDCtx
	{
		char szSessionID[64];

#ifdef __cplusplus
		SSessionIDCtx()
		{
			memset(&szSessionID, 0, sizeof(szSessionID));
		}
#endif
	};
	struct STestMsgCtx
	{
		char szMessage[255];

#ifdef __cplusplus
		STestMsgCtx()
		{
			memset(&szMessage, 0, sizeof(szMessage));
		}
#endif
	};
	struct SPointerRedirectCtx
	{
		uint8_t pFuncIdx;
		void* lpFuncPointer;

#ifdef __cplusplus
		SPointerRedirectCtx()
		{
			pFuncIdx = 0;
			lpFuncPointer = NULL;
		}
#endif
	};

	// Shared data list enums
	enum ENMSignalIDs
	{
		NM_SIG_ID_NULL = 0,
		NM_SIG_SCREEN_PROTECTION_ON,
		NM_SIG_SCREEN_PROTECTION_OFF,
		NM_SIG_HEARTBEAT_V1_SETUP,
		NM_SIG_HEARTBEAT_V2_SETUP,
		NM_SIG_GAME_POLL_EVENT,
		NM_SIG_POINTER_REDIRECTION_COMPLETED,
		NM_SIG_CHECK_MULTI_GAME,
		NM_SIG_GAME_INIT,
		NM_SIG_SAVE_LOGS,
		NM_SIG_VERIFY_PROTECTED_FUNCS,
		NM_SIG_INIT_PYTHON_HOOKS,
		NM_SIG_DESTROY_PYTHON_HOOKS,
		NM_SIG_REMOVE_PYTHON_WATCHER,
		NM_SIG_CHECK_PYTHON_MODULES
	};
	enum ENMMsgCodes
	{
		NM_MSG_NULL = 0,
		NM_NOMERCY_CORE_INIT_FAIL,
		NM_NOMERCY_INTERNAL_ERROR,
		NM_MISSING_CONFIG_FILE,
		NM_INTERNET_IS_NOT_CONNECTED,
		NM_NOMERCY_API_SERVER_CONNECTION_FAIL,
		NM_GAME_LAUNCH_ERROR,
		NM_GAME_STARTED,
		NM_PROTECTION_INIT_COMPLETE,
		NM_API_SERVER_CONNECTED,
		NM_API_SERVER_AUTHENTICATED,
		NM_MOUSE_MACRO_DETECTED,
		NM_KEYBOARD_MACRO_DETECTED,
		NM_GAME_HACK_DETECTED,
		NM_MULTIPLE_GAME_DETECTED,
		NM_VERSION_MISMATCH
	};
	enum ENMDataCodes
	{
		NM_DATA_NULL, 	// Undefined
		// Common data
		NM_SIGNAL, 		// ENMSignalIDs
		NM_MESSAGE, 	// ENMMsgCodes
		NM_SET_VERBOSE,	// ELogLevel

		// Pointer redirections (general)
		NM_DATA_SEND_PRINT_MESSAGE = 1000,	// TPrintMessage
		NM_DATA_SEND_REQUEST_RESTART,		// TRequestRestart
		NM_DATA_SEND_DISCONNECT_PEER,		// TDisconnectPeer
		NM_DATA_SEND_NET_SEND_PACKET,		// TNetworkPacket
		NM_DATA_SEND_NET_RECV_PACKET,		// TNetworkPacket
		NM_DATA_SEND_REPORT_EVENT,			// TSendReport
		NM_DATA_SEND_CHECK_RUNNING_STATUS,	// TRunningStatusCheck
		NM_DATA_SEND_LOG_SEND,				// TSendLog

		// Utilities
		NM_DATA_SET_RENDER_ENGINE = 2000,		// SRenderEngineCtx
		NM_DATA_CHECK_FILE_HASH,				// SFileHashCtx
		NM_DATA_CHECK_FUNC_HOOK,				// SFuncHookCtx
		NM_DATA_PROTECT_FUNCTION,				// SProtectFuncCtx
		NM_DATA_SET_NETWORK_CRYPT_KEY,			// SNetworkCryptKey
		NM_DATA_GET_ENCRYPTED_NET_MESSAGE_SIZE, // SNetworkMessageCtx
		NM_DATA_GET_DECRYPTED_NET_MESSAGE_SIZE, // SNetworkMessageCtx		
		NM_DATA_ENCRYPT_NETWORK_MESSAGE,		// SNetworkMessageCtx
		NM_DATA_DECRYPT_NETWORK_MESSAGE,		// SNetworkMessageCtx
		NM_DATA_SEND_GAME_NETWORK_INFORMATIONS, // SGameNetworkInfo
		NM_DATA_SEND_USER_TOKEN,				// SUserToken     (Account/Player UUID)
		NM_DATA_SEND_PLATFORM_TOKEN,			// SPlatformToken (Platform token/Auth ticket/Publisher UUID)

		// Received data
		NM_DATA_RECV_VERSION = 3000,			// SVersionCtx
		NM_DATA_RECV_CORE_INIT_NOTIFICATION,	// NO PARAMETER
		NM_DATA_RECV_IS_INITIALIZED,			// SInitRetCtx
		NM_DATA_RECV_SUSPICIOUS_EVENT,			// SSusEventCtx
		NM_DATA_RECV_TICK_RESPONSE,				// SPollEventCtx
		NM_DATA_RECV_SESSION_ID,				// SSessionIDCtx

		// Game specific pointer redirections (Metin2)
		NM_DATA_SEND_TRACEERROR = 10000,	// TTraceError
		NM_DATA_SEND_MAPPED_FILE_EXIST,		// TIsMappedFileExist
		NM_DATA_SEND_VID,					// TGetVID
		NM_DATA_SEND_PHASE,					// TGetPhase
		NM_DATA_SEND_PLAYER_NAME,			// TGetPlayerName
		NM_DATA_SEND_MAPPED_FILE_HASH,		// TGetMappedFileHash
		NM_DATA_SEND_NET_SEND_SEQ,			// TSendSequence

		// Game specific received data (Python)
		NM_DATA_SEND_Py_InitModule4 = 11000,
		NM_DATA_SEND_PyParser_ASTFromString,
		NM_DATA_SEND_PyParser_ASTFromFile,
		NM_DATA_SEND_PyTuple_Check,
		NM_DATA_SEND_PyTuple_Size,
		NM_DATA_SEND_PyTuple_GetItem,
		NM_DATA_SEND_PyString_AsString,
		NM_DATA_SEND_PyImport_GetModuleDict,
		NM_DATA_SEND_PyDict_Next,
		NM_DATA_SEND_PyObject_HasAttrString,
		NM_DATA_SEND_PyObject_GetAttrString,
		NM_DATA_SEND_Py_DecRef,
		NM_DATA_SEND_Py_None,
		NM_DATA_SEND_PyRun_SimpleString,
		NM_DATA_SEND_PyRun_SimpleStringFlags,
		NM_DATA_SEND_PyRun_SimpleFile,
		NM_DATA_SEND_PyRun_SimpleFileFlags,
		NM_DATA_SEND_PyRun_SimpleFileEx,
		NM_DATA_SEND_PyRun_SimpleFileExFlags,
		NM_DATA_SEND_PyFile_FromString,
		NM_DATA_SEND_PyFile_FromStringFlags,
		NM_DATA_SEND_PyString_InternFromString,
		NM_DATA_SEND_PyThreadState_Get,
		NM_DATA_SEND_Python_Max = NM_DATA_SEND_PyThreadState_Get,
		
#ifdef _DEBUG
		// Test only
		NM_DATA_SEND_TEST_MESSAGE = 13371337,					// STestMsgCtx
		NM_DATA_RECV_TEST_MESSAGE = NM_DATA_SEND_TEST_MESSAGE	// STestMsgCtx
#endif
	};
#ifdef __cplusplus
}
#endif

// Public:
#ifdef __DISABLE_NOMERCY__
	static NOMERCY_API bool NM_Initialize(const uint32_t c_u32GameCode, const uint8_t c_u8NmVersion, const NoMercy::TNMCallback c_kMessageHandler) { return true; };
	static NOMERCY_API bool NM_Finalize() { return true; };
	static NOMERCY_API bool NM_ForwardMessage(const int32_t c_s32Code, const void* c_lpMessage) { return true; };
	static NOMERCY_API uint32_t NM_GetVersionNumber() { return 1; };
#else
	EXTERN_C NOMERCY_API bool NM_Initialize(const uint32_t c_u32GameCode, const uint8_t c_u8NmVersion, const NoMercy::TNMCallback c_kMessageHandler);
	EXTERN_C NOMERCY_API bool NM_Finalize();
	EXTERN_C NOMERCY_API bool NM_ForwardMessage(const int32_t c_s32Code, const void* c_lpMessage);
	EXTERN_C NOMERCY_API uint32_t NM_GetVersionNumber();
#endif

#endif
