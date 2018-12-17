#pragma once

enum EExitErrorCodes
{
	EXIT_ERR_NONE												= 0,
	EXIT_ERR_CTOS_PIPE_ALLOC_FAIL								= 1,
	EXIT_ERR_CTOS_PIPE_PING_FAIL								= 2,
	EXIT_ERR_CTOD_COMM_ALLOC_FAIL								= 3,
	EXIT_ERR_CTOD_COMM_PING_FAIL								= 4,
	EXIT_ERR_SELF_INTEGRITY_TIMEOUT_1							= 5,
	EXIT_ERR_SELF_INTEGRITY_TIMEOUT_2							= 6,
	EXIT_ERR_NETWORK_TIMER_CREATE_FAIL							= 7,
	EXIT_ERR_NETWORK_THREAD_CREATE_FAIL							= 8,
	EXIT_ERR_MMAP_THREAD_CREATE_FAIL							= 9,
	EXIT_ERR_SELF_API_HOOK_INIT_FAIL							= 10,

	EXIT_ERR_WOW64_FIX_FAIL										= 11,
	EXIT_ERR_MITIGATION_INIT_FAIL								= 12,
	EXIT_ERR_MMAP_ROUTINE_FAIL									= 13,
	EXIT_ERR_HOOK_LOGGER_INIT_FAIL								= 14,
	EXIT_ERR_HOOK_PATCH_INIT_FAIL								= 15,
	EXIT_ERR_HOOK_DETOUR_INIT_FAIL								= 16,
	EXIT_ERR_HOOK_PATCH_1_FAIL									= 17,
	EXIT_ERR_HOOK_PATCH_2_FAIL									= 18,
	EXIT_ERR_HOOK_PATCH_3_FAIL									= 19,
	EXIT_ERR_HOOK_PATCH_4_FAIL									= 20,

	EXIT_ERR_HOOK_PATCH_5_FAIL									= 21,
	EXIT_ERR_HOOK_PATCH_6_FAIL									= 22,
	EXIT_ERR_HOOK_PATCH_7_FAIL									= 23,
	EXIT_ERR_HOOK_PATCH_8_FAIL									= 24,
	EXIT_ERR_HOOK_PATCH_9_FAIL									= 25,
	EXIT_ERR_HOOK_DETOUR_CLASS_ALLOC_FAIL						= 26,
	EXIT_ERR_HOOK_DETOUR_MAPPED_MODULE_1_FAIL					= 27,
	EXIT_ERR_HOOK_DETOUR_MAPPED_MODULE_2_FAIL					= 28,
	EXIT_ERR_HOOK_DETOUR_MAPPED_MODULE_3_FAIL					= 29,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_1_FAIL						= 30,

	EXIT_ERR_HOOK_DETOUR_INIT_1_FAIL							= 31,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_2_FAIL						= 32,
	EXIT_ERR_HOOK_DETOUR_INIT_2_FAIL							= 33,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_3_FAIL						= 34,
	EXIT_ERR_HOOK_DETOUR_INIT_3_FAIL							= 35,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_4_FAIL						= 36,
	EXIT_ERR_HOOK_DETOUR_INIT_4_FAIL							= 37,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_5_FAIL						= 38,
	EXIT_ERR_HOOK_DETOUR_INIT_5_FAIL							= 39,
	EXIT_ERR_HOOK_EXCEPTION_PATCH_FAIL							= 40,

	EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_FOUND_FAIL				= 41,
	EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_BASE_FOUND_FAIL			= 42,
	EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_PATCH_ADDR_FOUND_FAIL	= 43,
	EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_PRE_PROTECT_FAIL			= 44,
	EXIT_ERR_HOOK_EXCEPTION_DISPATCHER_WRITE_FAIL				= 45,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_6_FAIL						= 46,
	EXIT_ERR_HOOK_DETOUR_INIT_6_FAIL							= 47,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_7_FAIL						= 48,
	EXIT_ERR_HOOK_DETOUR_INIT_7_FAIL							= 49,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_8_FAIL						= 50,

	EXIT_ERR_HOOK_DETOUR_INIT_8_FAIL							= 51,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_9_FAIL						= 52,
	EXIT_ERR_HOOK_DETOUR_INIT_9_FAIL							= 53,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_10_FAIL						= 54,
	EXIT_ERR_HOOK_DETOUR_INIT_10_FAIL							= 55,
	EXIT_ERR_HOOK_DETOUR_API_FOUND_11_FAIL						= 56,
	EXIT_ERR_HOOK_DETOUR_INIT_11_FAIL							= 57,
	EXIT_ERR_FOLDER_CHECK_THREAD_CREATE_FAIL					= 58,
	EXIT_ERR_MAIN_THREAD_CREATE_FAIL							= 59,
	EXIT_ERR_SOFTBP_THREAD_CREATE_FAIL							= 60,

	EXIT_ERR_ANTI_MACRO_THREAD_CREATE_FAIL						= 61,
	EXIT_ERR_CHECKSUM_SCAN_THREAD_CREATE_FAIL					= 62,
	EXIT_ERR_TICK_CHECK_THREAD_CREATE_FAIL						= 63,
	EXIT_ERR_SCANNER_LOGGER_INIT_FAIL							= 64,
	EXIT_ERR_SDK_LOGGER_INIT_FAIL								= 65,
	EXIT_ERR_WMI_CREATE_THREAD_FAIL								= 66,
	EXIT_ERR_WMI_INIT_FAIL_1									= 67,
	EXIT_ERR_WMI_INIT_FAIL_2									= 68,
	EXIT_ERR_WMI_INIT_FAIL_3									= 69,
	EXIT_ERR_WMI_INIT_FAIL_4									= 70,

	EXIT_ERR_WMI_QUERY_FAIL_1									= 71,
	EXIT_ERR_WMI_QUERY_FAIL_2									= 72,
	EXIT_ERR_WMI_QUERY_FAIL_3									= 73,
	EXIT_ERR_WMI_QUERY_FAIL_4									= 74,
	EXIT_ERR_WMI_QUERY_FAIL_5									= 75,
	EXIT_ERR_WMI_QUERY_FAIL_6									= 76,
	EXIT_ERR_WinEventHook_FAIL									= 77,
	EXIT_ERR_WinEventHook_TIMEOUT								= 78,
	EXIT_ERR_WINDOW_CHECK_THREAD_TIMEOUT						= 79,
	EXIT_ERR_TICK_THREAD_TIMEOUT								= 80,

	EXIT_ERR_WATCHDOG_THREAD_TIMEOUT							= 81,
	EXIT_ERR_WATCHDOG_LOAD_FAIL									= 82,
	EXIT_ERR_WATCHDOG_CHECK_FAIL								= 83,
	EXIT_ERR_WATCHDOG_BACKUP_CHECK_FAIL							= 84,
	EXIT_ERR_TICK_CHECKER_THREAD_CORRUPTED						= 85,
	EXIT_ERR_SHADOW_PROCESS_TERMINATED							= 86,
	EXIT_ERR_SHADOW_NULL_MODULE_INFO							= 87,
	EXIT_ERR_SHADOW_SYS_PATH_FAIL								= 88,
	EXIT_ERR_SHADOW_CREATE_FAIL									= 89,
	EXIT_ERR_SHADOW_HANDLE_NOT_VALID							= 90,

	EXIT_ERR_SHADOW_TERMINATE_FAIL								= 91,
	EXIT_ERR_SHADOW_PID_NOT_EXIST								= 92,
	EXIT_ERR_SHADOW_STILL_WORKS									= 93,
	EXIT_ERR_SHADOW_RUN_FAIL									= 94,
	EXIT_ERR_SHADOW_SHADOW_NOT_FOUND							= 95,

	EXIT_ERR_SHADOW_PID_NOT_EXIST_2								= 96,
	EXIT_ERR_SHADOW_NOT_WORKS									= 97,
	EXIT_ERR_SHADOW_EXIT_CALLBACK_ALLOC_FAIL					= 98,
	EXIT_ERR_SHADOW_EXIT_CALLBACK_INIT_FAIL						= 99,
	EXIT_ERR_SHADOW_ADJUST_PRIV_FAIL							= 100,

	EXIT_ERR_SHADOW_HANDLE_CREATE_FAIL							= 101,
	EXIT_ERR_SHADOW_PROTECTED_PROCESS_NOT_ALIVE					= 102,
	EXIT_ERR_SHADOW_SUSPEND_DETECTED							= 103,
	EXIT_ERR_THREAD_COMMUNICATION_FAIL							= 104,
	EXIT_ERR_THREAD_INTEGRITY_FAIL								= 105,

	EXIT_ERR_SCREEN_PROTECTION_STATUS_CORRUPTED					= 106,
	EXIT_ERR_MAIN_THREAD_TIMEOUT								= 107,
	EXIT_ERR_UNKNOWN_THREAD_ATTACHED							= 108,
	EXIT_ERR_MANUALMAP_THREAD_TIMEOUT							= 109,
	EXIT_ERR_MODULE_NOT_FOUND									= 110,

	EXIT_ERR_MODULE_MANIPULATION_DETECTED						= 111,
	EXIT_ERR_WINAPI_INIT_FAIL									= 112,
	EXIT_ERR_ANTI_MACRO_THREAD_TIMEOUT							= 113,
	EXIT_ERR_MOUSE_MACRO_HOOK_INIT_FAIL							= 114,
	EXIT_ERR_KEYBOARD_MACRO_HOOK_INIT_FAIL						= 115,

	EXIT_ERR_ANTI_MACRO_MSG_FAIL								= 116,
	EXIT_ERR_DIR_CHECK_THREAD_TIMEOUT							= 117,
	EXIT_ERR_SECTION_HASH_THREAD_TIMEOUT						= 118,
	EXIT_ERR_WOW32RESERVED_HOOK_DETECTED						= 119,
	EXIT_ERR_NET_QUEUE_THREAD_TIMEOUT							= 120,

	EXIT_ERR_NETWORK_THREAD_TIMEOUT								= 121,
	EXIT_ERR_WATCHDOG_CORRUPTED									= 122,
	EXIT_ERR_SYNC_HANDLE_CORRUPTED								= 123,
	EXIT_ERR_TIMER_CHECK_THREAD_TIMEOUT							= 124,
	EXIT_ERR_WATCHDOG_TIMER_INTEGRITY_FAIL						= 125,

	EXIT_ERR_WNDPROC_HOOK										= 126,
	EXIT_ERR_MAPVIEWSECTION_HOOK								= 127,
	EXIT_ERR_MODULEHANDLE_HOOK									= 128,
	EXIT_ERR_MODULELOAD_HOOK_1									= 129,
	EXIT_ERR_MODULELOAD_HOOK_2									= 130,

	EXIT_ERR_THREADLOAD_HOOK									= 131,
	EXIT_ERR_RAISEEXCEPTION_HOOK								= 132,
	EXIT_ERR_PATCH_API_NOT_FOUND								= 133,
	EXIT_ERR_PATCH_API_1_VP_1_FAIL								= 134,
	EXIT_ERR_PATCH_API_1_VP_2_FAIL								= 135,

	EXIT_ERR_PATCH_API_2_VP_1_FAIL								= 136,
	EXIT_ERR_PATCH_API_2_VP_2_FAIL								= 137,
	EXIT_ERR_CUSTOM_THREAD_ALREADY_EXIST						= 138,
	EXIT_ERR_CUSTOM_THREAD_CREATE_FAIL							= 139,
	EXIT_ERR_CUSTOM_THREAD_ACCESS_1_FAIL						= 140,

	EXIT_ERR_CUSTOM_THREAD_ACCESS_2_FAIL						= 141,
	EXIT_ERR_CUSTOM_THREAD_ALLOC_CLASS_FAIL						= 142,
	EXIT_ERR_CUSTOM_THREAD_ALLOC_CONTAINER_FAIL					= 143,
	EXIT_ERR_CUSTOM_THREAD_OPEN_FAIL							= 144,
	EXIT_ERR_THREAD_ENUM_QUERY_FAIL								= 145,

	EXIT_ERR_DEBUG_PRIV_LIMIT_EXCEED							= 146,
	EXIT_ERR_SERVER_ELEVATION_1_FAIL							= 147,
	EXIT_ERR_SERVER_ELEVATION_2_FAIL							= 148,
	EXIT_ERR_BACKEND_CONNECTION_CHECK_FAIL						= 149,
	EXIT_ERR_DIR_FUNC_1_FAIL									= 150,

	EXIT_ERR_DIR_FUNC_2_FAIL									= 151,
	EXIT_ERR_DIR_FUNC_3_FAIL									= 152,
	EXIT_ERR_DIR_FUNC_4_FAIL									= 153,
	EXIT_ERR_DIR_FUNC_5_FAIL									= 154,
	EXIT_ERR_DIR_FUNC_6_FAIL									= 155,

	EXIT_ERR_DIR_FUNC_7_FAIL									= 156,
	EXIT_ERR_DIR_FUNC_8_FAIL									= 157,
	EXIT_ERR_DIR_FUNC_9_FAIL									= 158,
	EXIT_ERR_DIR_FUNC_10_FAIL									= 159,
	EXIT_ERR_DIR_FUNC_11_FAIL									= 160,

	EXIT_ERR_DIR_FUNC_12_FAIL									= 161,
	EXIT_ERR_DIR_FUNC_13_FAIL									= 162,
	EXIT_ERR_DIR_FUNC_14_FAIL									= 163,
	EXIT_ERR_DIR_FUNC_15_FAIL									= 164,
	EXIT_ERR_DIR_FUNC_16_FAIL									= 165,

	EXIT_ERR_DIR_FUNC_17_FAIL									= 166,
	EXIT_ERR_DIR_FUNC_18_FAIL									= 167,
	EXIT_ERR_DIR_FUNC_19_FAIL									= 168,
	EXIT_ERR_DIR_FUNC_20_FAIL									= 169,
	EXIT_ERR_DIR_FUNC_21_FAIL									= 170,

	EXIT_ERR_DIR_FUNC_22_FAIL									= 171,
	EXIT_ERR_DIR_FUNC_23_FAIL									= 172,
	EXIT_ERR_SOFTBP_THREAD_TIMEOUT								= 173,
	EXIT_ERR_VEH_SINGLE_STEP_EXCEPTION							= 174,
	EXIT_ERR_VEH_PAGE_GUARD_EXCEPTION							= 175,

	EXIT_ERR_VEH_BREAKPOINT_EXCEPTION							= 176,
	EXIT_ERR_SEH_SINGLE_STEP_EXCEPTION							= 177,
	EXIT_ERR_SEH_PAGE_GUARD_EXCEPTION							= 178,
	EXIT_ERR_SEH_BREAKPOINT_EXCEPTION							= 179,
	EXIT_ERR_WMI_QUERY_FAIL_7									= 180,

	EXIT_ERR_WMI_QUERY_FAIL_8									= 181,
	EXIT_ERR_WMI_QUERY_FAIL_9									= 182,
	EXIT_ERR_WMI_QUERY_FAIL_10									= 183,
	EXIT_ERR_WMI_QUERY_FAIL_11									= 184,
	EXIT_ERR_WMI_QUERY_FAIL_12									= 185,

	EXIT_ERR_WMI_QUERY_FAIL_13									= 186,
	EXIT_ERR_WMI_QUERY_FAIL_14									= 187,
	EXIT_ERR_WMI_QUERY_FAIL_15									= 188,
	EXIT_ERR_WMI_QUERY_FAIL_16									= 189,
	EXIT_ERR_WMI_QUERY_FAIL_17									= 190,

	EXIT_ERR_WMI_QUERY_FAIL_18									= 191,
	EXIT_ERR_WMI_QUERY_FAIL_19									= 192,
	EXIT_ERR_SERVICE_NOT_WORKS									= 193,
	EXIT_ERR_NET_UNKNOWN_SOURCE									= 194,
	EXIT_ERR_NET_MSERVER_CONFIG_FAIL							= 195,

	EXIT_ERR_NET_RSA_INIT_FAIL									= 196,
	EXIT_ERR_NET_LOGGER_INIT_FAIL								= 197,
	EXIT_ERR_ANTI_DUMP_INIT_FAIL								= 198,
	EXIT_ERR_CUSTOM_THREAD_EXIT_WATCHER_ALLOC_FAIL				= 199,
	EXIT_ERR_CUSTOM_THREAD_EXIT_WATCHER_INIT_FAIL				= 200,

	EXIT_ERR_WINDOWS_WATCHDOG_THREAD_FAIL						= 201,
	EXIT_ERR_CLIENT_THREADS_INIT_FAIL							= 202,
	EXIT_ERR_UI_CLASS_ALLOC_FAIL								= 203,
	EXIT_ERR_UI_CLASS_INIT_FAIL									= 204,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_NULL_PARAM						= 205,

	EXIT_ERR_GAME_LAUNCH_ROUTINE_NULL_PROC_NAME					= 206,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_NULL_HELPER_PID				= 207,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_SVC_COMM_ALLOC_FAIL			= 208,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_SVC_COMM_INIT_FAIL				= 209,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_SVC_PRE_MSG_FAIL				= 210,

	EXIT_ERR_GAME_LAUNCH_ROUTINE_FILE_EXIST_CHECK_FAIL			= 211,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_OPEN_CURR_PROC_FAIL			= 212,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_OPEN_HELPER_PROC_FAIL			= 213,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_LAUNCH_GAME_FAIL				= 214,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_RESUME_GAME_FAIL				= 215,

	EXIT_ERR_GAME_LAUNCH_ROUTINE_SVC_POST_MSG_FAIL							= 216,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_GAME_ALIVE_CHECK_FAIL						= 217,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_GAME_HANDLE_OPEN_FAIL						= 218,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_GAME_WAIT_FAIL								= 219,
	EXIT_ERR_GAME_LAUNCH_ROUTINE_LAUNCH_PARAM_CONTAINER_ALLOC_FAIL			= 220,

	EXIT_ERR_GAME_LAUNCH_ROUTINE_LAUNCH_THREAD_PARAM_CONTAINER_ALLOC_FAIL	= 221,
	EXIT_ERR_PROCESS_WATCHER_THREAD_EXIT									= 222,
	EXIT_ERR_FILTER_OB_CALLBACK_WATCHER_ALLOC_FAIL							= 223,
	EXIT_ERR_FILTER_PROCESS_CALLBACK_WATCHER_ALLOC_FAIL						= 224,
	EXIT_ERR_FILTER_THREAD_CALLBACK_WATCHER_ALLOC_FAIL						= 225,

	EXIT_ERR_FILTER_IMAGE_CALLBACK_WATCHER_ALLOC_FAIL						= 226,
	EXIT_ERR_FILTER_DEVICE_HANDLE_WATCHER_ALLOC_FAIL						= 227,
	EXIT_ERR_FILTER_DEVICE_IO_WATCHER_ALLOC_FAIL							= 228,
	EXIT_ERR_FILTER_OB_CALLBACK_WATCHER_INIT_FAIL							= 229,
	EXIT_ERR_FILTER_PROCESS_CALLBACK_WATCHER_INIT_FAIL						= 230,

	EXIT_ERR_FILTER_THREAD_CALLBACK_WATCHER_INIT_FAIL						= 231,
	EXIT_ERR_FILTER_IMAGE_CALLBACK_WATCHER_INIT_FAIL						= 232,
	EXIT_ERR_FILTER_DEVICE_HANDLE_WATCHER_INIT_FAIL							= 233,
	EXIT_ERR_FILTER_DEVICE_IO_WATCHER_INIT_FAIL								= 234,
	EXIT_ERR_MMAP_HOOK_CHECK_TIMEOUT										= 235,
};

enum EInitMgrErrorCodes
{
	INIT_ERR_SUCCESS,							// 0
	INIT_ERR_PROTECTION_CHECK_FAIL,
	INIT_ERR_ELEVATION_FAIL_FIRST,
	INIT_ERR_ELEVATION_FAIL_SECOND,
	INIT_ERR_DEBUG_PRIV_FAIL,
	INIT_ERR_DRIVER_LOAD_PRIV_FAIL,				// 5
	INIT_ERR_TCB_PRIV_FAIL,
	INIT_ERR_EXCEPTION_HANDLER_SETUP_FAIL,
	INIT_ERR_MODULE_NOT_FOUND,
	INIT_ERR_LOGO_NOT_FOUND,
	INIT_ERR_LOGO_CHECKSUM_FAIL,				// 10
	INIT_ERR_LAUNCHER_CONFIG_NOT_FOUND,
	INIT_ERR_SERVICE_NOT_FOUND,
	INIT_ERR_HELPERAPP_NOT_FOUND,
	INIT_ERR_MMAP_RELOAD_FAIL,
	INIT_ERR_PARENT_PID_FAIL,					// 15
	INIT_ERR_PARENT_NAME_FAIL,
	INIT_ERR_PARENT_NOT_VALID,
	INIT_ERR_PARENT_NOT_ALIVE,
	INIT_ERR_UNSUPPORTED_OS,
	INIT_ERR_FAKE_OS,							// 20
	INIT_ERR_FAKE_OS_VERSION,
	INIT_ERR_SAFE_MODE,
	INIT_ERR_PARSE_LAUNCHER_CONFIG,
	INIT_ERR_LAUNCHER_CLASS_ALLOC_FAIL,
	INIT_ERR_LAUNCHER_ROUTINE_FAIL,				// 25
	INIT_ERR_HELPER_START_FAIL,
	INIT_ERR_HELPER_RESUME_FAIL,
	INIT_ERR_HELPER_PIPE_CLASS_ALLOC_FAIL,
	INIT_ERR_HELPER_PIPE_INIT_FAIL,
	INIT_ERR_HELPER_PIPE_PING_FAIL,				// 30
	INIT_ERR_HELPER_PIPE_RECV_INIT_FAIL,
	INIT_ERR_HELPER_EXIST_LAST_FAIL,
	INIT_ERR_MUTEX_CLASS_ALLOC_FAIL,
	INIT_ERR_MUTEX_OBJ_FAIL,
	INIT_ERR_MUTEX_CLASS_ALLOC_2_FAIL,			// 35
	INIT_ERR_SERVICE_EXIST_LAST_2_FAIL,
	INIT_ERR_ENUM_ALLOC_FAIL,
	INIT_ERR_ENUM_SVC_FAIL,
	INIT_ERR_TERMINATE_USELESS_SERVICE_FAIL,
	INIT_ERR_SERVICE_EXIST_ENUM_FAIL,			// 40
	INIT_ERR_SERVICE_EXIST_MUTEX_FAIL,
	INIT_ERR_SERVICE_EXIST_PID_CHECK_FAIL,
	INIT_ERR_SERVICE_EXIST_LAST_FAIL,
	INIT_ERR_SERVICE_PIPE_GAME_REQ_SEND_FAIL,
	INIT_ERR_SERVICE_UNKNOWN_STATUS,			// 45
	INIT_ERR_PROTECTED_APP_NOT_EXIST,
	INIT_ERR_PROTECTED_APP_LAUNCH_FAIL,
	INIT_ERR_PROTECTED_APP_FIND_FAIL,
	INIT_ERR_SERVICE_LAUNCH_FAIL,
	INIT_ERR_SERVICE_LAUNCH_CHECK_FAIL,			// 50
	INIT_ERR_SERVICE_FIND_FAIL,
	INIT_ERR_PIPE_CLASS_ALLOC_FAIL,
	INIT_ERR_SVC_PIPE_INIT_FAIL,
	INIT_ERR_SVC_PIPE_PING_FAIL,
	INIT_ERR_PIPE_CLOSE_1_FAIL,					// 55
	INIT_ERR_PIPE_REOPEN_1_FAIL,
	INIT_ERR_PIPE_CLOSE_2_FAIL,
	INIT_ERR_SRV_PIPE_CLASS_ALLOC_FAIL,
	INIT_ERR_SRV_SVC_PIPE_INIT_FAIL,
	INIT_ERR_SRV_SVC_PIPE_RECV_INIT_FAIL,		// 60
	INIT_ERR_CURR_PATH_FAIL,
	INIT_ERR_PARENT_CHECK_FAIL,
	INIT_ERR_PARENT_OPEN_1_FAIL,
	INIT_ERR_PARENT_OPEN_2_FAIL,
	INIT_ERR_SERVICE_NOT_FOUND_WITH_PATH,		// 65
	INIT_ERR_SERVICE_HELPER_ALLOC_FAIL,
	INIT_ERR_SERVICE_UNKNOWN_CURR_STATUS_FAIL,
	INIT_ERR_SERVICE_ALREADY_EXIST,
	INIT_ERR_SERVICE_PRE_STOP_FAIL,
	INIT_ERR_SERVICE_UNLOAD_FAIL,				// 70
	INIT_ERR_DRIVER_NOT_FOUND_WITH_PATH,
	INIT_ERR_DRIVER_HELPER_ALLOC_FAIL,
	INIT_ERR_DRIVER_ALREADY_EXIST,
	INIT_ERR_DRIVER_PRE_STOP_FAIL,
	INIT_ERR_DRIVER_UNLOAD_FAIL,				// 75
	INIT_ERR_DRIVER_SIGN_FAIL,
	INIT_ERR_DRIVER_STOP_FAIL,
	INIT_ERR_DRIVER_ALREADY_RUNNING,
	INIT_ERR_DRIVER_COMM_HELPER_ALLOC_FAIL,
	INIT_ERR_DRIVER_COMM_HELPER_INIT_FAIL,		// 80
	INIT_ERR_DRIVER_COMM_HELPER_PING_FAIL,
	INIT_ERR_DRIVER_COMM_HELPER_PID_SEND_FAIL,
	INIT_ERR_TIMER_QUEUE_SETUP_FAIL,
	INIT_ERR_COMM_CHECK_TIMER_SETUP_FAIL,
	INIT_ERR_PROCESS_WATCHER_THREAD_FAIL,		// 85
	INIT_SVC_ERR_HELPER_PIPE_CLASS_ALLOC_FAIL,
	INIT_SVC_ERR_HELPER_PIPE_INIT_FAIL, 
	INIT_SVC_ERR_HELPER_PIPE_PING_FAIL,
	INIT_SVC_ERR_HELPER_PIPE_FINALIZE_FAIL,
	INIT_SVC_ERR_SERVICE_PIPE_FINALIZE_FAIL,	// 90
	INIT_ERR_SYNC_WATCHER_OPEN_FAIL,
	INIT_ERR_SYNC_WATCHER_SETUP_FAIL,
	INIT_ERR_WATCHDOG_TIMER_SETUP_FAIL,
	INIT_ERR_PROC_PRIORITY_FAIL,
	INIT_ERR_TIMER_CHECK_THREAD_SIZE_FAIL,		// 95
	INIT_ERR_TIMER_CHECK_THREAD_CREATE_FAIL,
	INIT_ERR_TIMER_CHECK_THREAD_WATCHER_INIT_FAIL,
	INIT_ERR_TIMER_CHECK_THREAD_WATCHER_SETUP_FAIL,
	INIT_ERR_HWID_MGR_INIT_FAIL,
	INIT_ERR_HWBP_CHECK_FAIL,					// 100
	INIT_ERR_EPBP_CHECK_FAIL,
	INIT_ERR_MEMBP_CHECK_FAIL,
	INIT_ERR_HYPERVISOR_CHECK_FAIL,
	INIT_ERR_WOW64_RDR_CHECK_FAIL,
	INIT_ERR_MEM_WATCHDOG_INIT_FAIL,			// 105
	INIT_ERR_ACCESS_ADJUST_1_FAIL,
	INIT_ERR_ACCESS_ADJUST_2_FAIL,	
	INIT_ERR_ACCESS_ADJUST_3_FAIL,
	INIT_ERR_ACCESS_ADJUST_4_FAIL,
	INIT_ERR_ACCESS_ADJUST_5_FAIL,				// 110
	INIT_ERR_ACCESS_ADJUST_6_FAIL,
	INIT_ERR_ACCESS_ADJUST_7_FAIL,
	INIT_ERR_CURR_TOKEN_FAIL,
	INIT_ERR_SERVICE_THREAD_INIT_FAIL,
	INIT_ERR_GRANT_DACL_ACCESS_FAIL,			// 115
	INIT_SVC_ERR_HELPER_PIPE_NULL_PTR,
	INIT_SVC_ERR_HELPER_PIPE_PID_FAIL,
	INIT_ERR_SCR_BOOT_CHECK_FAIL,
	INIT_SVC_ERR_TIMER_QUEUE_INIT_FAIL,
	INIT_ERR_PLUGIN_LOAD_FAIL,					// 120
	INIT_ERR_PLUGIN_EXECUTE_FAIL,
	INIT_ERR_DRIVER_FILTER_SETUP_FAIL,
	INIT_ERR_OLDEST_OS,
	INIT_ERR_UI_THREAD_CREATE_FAIL,
	INIT_ERR_UI_THREAD_INIT_FAIL,				// 125
	INIT_SVC_ERR_HELPER_ENUM_FAIL,
	INIT_SVC_ERR_HELPER_NAME_CHECK_FAIL,
	INIT_ERR_SERVICE_FILTER_CALLBACK_INIT_FAIL,

	INIT_ERR_FINALIZE_BASE = 1000,
	INIT_ERR_SVC_PIPE_FINALIZE_FAIL,
	INIT_ERR_HELPER_PIPE_FINALIZE_FAIL,
	INIT_ERR_LAUNCHER_FINALIZE_FAIL,

	INIT_ERR_REMOTE_ERROR_BASE = 2000,
	REMOTE_ERR_INT_CLASS_ALLOC_FAIL,
	REMOTE_ERR_CHECK_CONNECTION_FAIL,
	REMOTE_ERR_CHECK_STATUS_FAIL,
	REMOTE_ERR_UNKNOWN_WEB_STATUS,
	REMOTE_ERR_READ_MAIN_FAIL,
	REMOTE_ERR_CHECK_MAIN_FAIL,
	REMOTE_ERR_READ_LICENSE_FAIL,
	REMOTE_ERR_CHECK_LICENSE_FAIL,
	REMOTE_ERR_READ_CHECKSUM_FAIL,
	REMOTE_ERR_CHECK_CHECKSUM_FAIL,

	INIT_ERR_REMOTE_EXCEPTION_BASE = 2100,

	INIT_ERR_DRIVER_LOAD_ERR_BASE = 2200,

	INIT_ERR_DRIVER_START_ERR_BASE = 2300,

	INIT_ERR_SERVICE_LOAD_ERR_BASE = 2400,

	INIT_ERR_SERVICE_START_ERR_BASE = 2500,

	INIT_ERR_TEST_SIGN_ENABLED_BASE = 2600,

	INIT_ERR_DEBUG_CHECK_FAIL_BASE = 2700,

	INIT_ERR_EMULATION_CHECK_FAIL_BASE = 2800,

	INIT_ERR_VIRTUALIZE_CHECK_FAIL_BASE = 2900,

	INIT_ERR_WIN_MOD_CHECK_FAIL_BASE = 3000,
};
