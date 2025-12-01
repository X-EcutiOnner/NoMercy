#pragma once

namespace NoMercy
{
	enum EBlockedToolScanMethods : uint32_t
	{
		BLOCKED_TOOL_SCAN_BASE = 0,

		BLOCKED_TOOL_SCAN_FILE_NAME,
		BLOCKED_TOOL_SCAN_FILE_SHA1,
		BLOCKED_TOOL_SCAN_FILE_DESC,
		BLOCKED_TOOL_SCAN_FILE_DESC_W_VER,
		BLOCKED_TOOL_SCAN_FILE_PATTERN,
		BLOCKED_TOOL_SCAN_FILE_PATTERN_W_ADDR,
		BLOCKED_TOOL_SCAN_FILE_SECTION_SHA256,
		BLOCKED_TOOL_SCAN_SERVICE_NAME,
		BLOCKED_TOOL_SCAN_SERVICE_SHA1,
		BLOCKED_TOOL_SCAN_DRIVER_NAME,
		BLOCKED_TOOL_SCAN_DRIVER_SHA1,
		BLOCKED_TOOL_SCAN_CERT_PROVIDER_NAME,
		BLOCKED_TOOL_SCAN_CERT_SERIAL,
		BLOCKED_TOOL_SCAN_CERT_CTX,
		BLOCKED_TOOL_SCAN_MODULE_NAME,
		BLOCKED_TOOL_SCAN_WINDOW_TITLE,
		BLOCKED_TOOL_SCAN_WINDOW_CLASS,
		BLOCKED_TOOL_SCAN_WINDOW_CTX,
		BLOCKED_TOOL_SCAN_WINDOW_HEURISTIC,

		BLOCKED_TOOL_SCAN_MAX,
	};

	enum ECheatViolationIDs : uint32_t
	{
		CHEAT_VIOLATION_BASE = 0,
		CHEAT_VIOLATION_HOOK_1, // LdrInitializeThunk/ClientThreadSetup Suspicious event
		CHEAT_VIOLATION_HOOK_2, // RtlGetFullPathName_U Suspicious event
		CHEAT_VIOLATION_HOOK_3, // NtCreateSection Suspicious event
		CHEAT_VIOLATION_HOOK_4, // NtMapViewOfSection Suspicious event
		CHEAT_VIOLATION_HOOK_5, // RtlDispatchException Suspicious event
		CHEAT_VIOLATION_HOOK_6, // connect Suspicious event
		CHEAT_VIOLATION_HOOK_7, // SetWindowLongA/W Suspicious event
		CHEAT_VIOLATION_HOOK_8, // LdrGetDllHandleEx Suspicious event
		CHEAT_VIOLATION_HOOK_9, // NtDelayExecution Suspicious event
		CHEAT_VIOLATION_HOOK_10, // NtContinue/NtSetContextThread Suspicious event
		CHEAT_VIOLATION_HOOK_11, // ImmGetHotKey/ImmActivateLayout Suspicious event
		CHEAT_VIOLATION_HOOK_12, // KiUserApcDispatcher Suspicious event

		CHEAT_VIOLATION_ID_BASE = 100,

		CHEAT_VIOLATION_CDB,
		CHEAT_VIOLATION_MALFORMED_SYS_QUERY_RESULT,
		CHEAT_VIOLATION_MAIN_FOLDER,
		CHEAT_VIOLATION_HIDDEN_PROCESS,
		CHEAT_VIOLATION_WOW32RESERVED_HOOK,
		CHEAT_VIOLATION_MANUAL_MAPPED_MODULE,
		CHEAT_VIOLATION_PROCESS_SCAN,
		CHEAT_VIOLATION_TICK_COUNT,
		CHEAT_VIOLATION_HOOK_DETECT,
		CHEAT_VIOLATION_MOUSE_INPUT_INJECTION,
		CHEAT_VIOLATION_KEYBOARD_INPUT_INJECTION,
		CHEAT_VIOLATION_SERVICE_SCAN,
		CHEAT_VIOLATION_FILE_SCAN,
		CHEAT_VIOLATION_WINDOW_HEURISTIC,
		CHEAT_VIOLATION_FOREGROUND_WINDOW,
		CHEAT_VIOLATION_UNKNOWN_GAME_WINDOW,
		CHEAT_VIOLATION_WINDOW_SCAN,
		CHEAT_VIOLATION_MAPPED_MODULE,
		CHEAT_VIOLATION_HOOK_OUT_OF_BOUND_MODULE,
		CHEAT_VIOLATION_CORE_DRIVER_INVALID_INDEX,
		CHEAT_VIOLATION_SINGLE_STEP_WATCHER,
		CHEAT_VIOLATION_DEBUG_STRING,
		CHEAT_VIOLATION_SECTION_SCAN,
		CHEAT_VIOLATION_REMOTE_HANDLE_ACCESS,

		CHEAT_VIOLATION_MAX
	};

	enum EMalformedSysQueryResTypes : uint8_t
	{
		MALFORMED_RESULT_NONE,
		MALFORMED_RESULT_WINDOW_SCAN,
	};
	
	enum EHiddenProcessSubTypes : uint8_t
	{
		HIDDEN_PROCESS_SCAN_NONE,
		HIDDEN_PROCESS_SCAN_1,
		HIDDEN_PROCESS_SCAN_2,
		HIDDEN_PROCESS_SCAN_3,
		HIDDEN_PROCESS_SCAN_4
	};

	enum EHookSuspiciousEvents : uint8_t
	{
		Thread_event_base = 0,
		Thread_stack_malformed,
		Thread_outofbound_memory,
		Thread_rwx_memory,
		Thread_suspicious_shellcode,
		Thread_suspicious_startaddress,
		Thread_remotethread,
		Thread_suspendedthread,
		Thread_already_loaded_module_base,
		Thread_debug_injection,
		Thread_has_debug_register,
		Thread_memory_ep_base,
		Thread_memory_ep_base_2,
		Thread_unknown_module,
		Thread_unknown_module_memory,
		Thread_module_info_fail,
		Thread_outofbound_module,
		Thread_module_not_signed,
		Thread_module_sign_not_valid,
		Thread_module_already_allocated,
		Thread_not_in_module,
		Thread_unknown_mem_type,
		Thread_unallowed_memory,
		Thread_unallowed_memory_protection,
		Thread_unallowed_memory_type,
		Thread_stack_invalid_address,
		Thread_stack_invalid_text_execution,
		Thread_stack_invalid_image_section,
		Thread_stack_invalid_matched_file,
		Thread_stack_invalidated_file,
		Thread_stack_invalid_loader,
		Thread_stack_invalid_thread_address,
		Thread_stack_invalid_instruction_pointer_address,
		Thread_stack_invalid_instruction_pointer,
		Thread_stack_has_debug_register,
		Thread_stack_invalid_thread_frames,
		Thread_stack_wow32reserved_hook,

		Module_event_base = 0,
		Stack_is_malformed,
		Module_file_not_exist,
		Module_file_open_fail,
		Module_file_read_fail,
		Module_file_create_hash_fail,
		Module_file_unknown_path,
		Module_address_not_found,
		Module_not_linked,
		Module_file_hijacked,
		Module_PE_DOS_header_invalid,
		Module_PE_NT_header_invalid,
		Module_PE_file_header_invalid,
		Module_PE_section_count_invalid,
		Module_PE_first_section_invalid,
		Module_PE_dynamic_code,

		Section_event_base = 0,
		Section_file_not_exist,

		Exception_event_base = 0,
		Exception_single_step,
		Exception_guard_page,
		Exception_breakpoint,
		Exception_breakpoint_mem,
		Exception_not_in_module,
		Exception_not_committed_mem,
		Exception_changed_protection,
		
		Connection_event_base = 0,
		Connection_unknown_target,

		Window_long_event_base = 0,
		Window_long_unknown_module,

		Modulerequest_event_base = 0,
		Modulerequest_anticheat,
		Modulerequest_python,

		Delayexecution_event_base = 0,
		Delayexecution_alertable,
	};

	enum EMetin2SdkCheatEvents : uint8_t
	{
		M2_CHEAT_NONE,
		M2_CHEAT_MAIN_FOLDER_UNALLOWED_EXTENSION,
		M2_CHEAT_MAIN_FOLDER_CORRUPTED_MILESDLL,
		M2_CHEAT_MAIN_FOLDER_CORRUPTED_DEVILDLL,
		M2_CHEAT_MAIN_FOLDER_UNALLOWED_LIB_FOLDER,
		M2_CHEAT_MILES_FOLDER_FILE_COUNT_OVERFLOW,
		M2_CHEAT_MILES_FOLDER_MISSING_FILE,
		M2_CHEAT_MILES_FOLDER_CORRUPTED_FILE,
		M2_CHEAT_YMIR_FOLDER
	};

	enum EProcessScanCheatEvents : uint8_t
	{
		PROCESS_SCAN_NONE,
		PROCESS_SCAN_DIFFERENT_PROCESS_ID,
		PROCESS_SCAN_UNACCESSIBLE_PROCESS,
		PROCESS_SCAN_HEAVY_PROTECTED_PROCESS,
		PROCESS_SCAN_GET_LITE_DATA_FAIL
	};

	enum EFileScanCheatEvents : uint8_t
	{
		FILE_SCAN_NONE,
		FILE_SCAN_PATTERN_CHECK,
		FILE_SCAN_BLACKLISTED_REGION_HASH,
		FILE_SCAN_OEP_NOT_IN_TEXT_SECTION,
		FILE_SCAN_BLACKLISTED_SECTION_CHARACTERISTIC,
		FILE_SCAN_SUSPICIOUS_SECTION_ENTROPY,
		FILE_SCAN_BLACKLISTED_SECTION,
		FILE_SCAN_NO_TEXT_SECTION,
		FILE_SCAN_VMPROTECT,
		FILE_SCAN_ENIGMA,
		FILE_SCAN_MPRESS,
		FILE_SCAN_UPX,
		FILE_SCAN_YODA,
		FILE_SCAN_SHIELDEN,
		FILE_SCAN_MOLEBOX,
		FILE_SCAN_THEMIDA,
		FILE_SCAN_BLACKLISTED_EXPORT,
		FILE_SCAN_CHECKSUM,
		FILE_SCAN_BLACKLISTED_STRING,
		FILE_SCAN_TLSH_DIFF,
		FILE_SCAN_CERTIFICATE_EXIST,
		FILE_SCAN_CERTIFICATE_QUERY,
		FILE_SCAN_CERTIFICATE_VERIFACTION,
		FILE_SCAN_CERTIFICATE_CHECK,
		FILE_SCAN_FILE_NAME_BLACKLIST,
		FILE_SCAN_FILE_MD5_BLACKLIST,
		FILE_SCAN_FILE_SHA2_BLACKLIST,
		FILE_SCAN_VERSION_FILE_COMPANY_NAME_BLACKLIST,
		FILE_SCAN_VERSION_FILE_PRODUCT_NAME_BLACKLIST,
		FILE_SCAN_VERSION_FILE_FILE_DESCRIPTION_BLACKLIST,
		FILE_SCAN_VERSION_FILE_FILE_VERSION_BLACKLIST,
		FILE_SCAN_VERSION_FILE_INTERNAL_NAME_BLACKLIST,
		FILE_SCAN_VERSION_FILE_DESCRIPTION_BLACKLIST,
		FILE_SCAN_VERSION_FILE_NAME_BLACKLIST,
		FILE_SCAN_PE_BLACKLIST,
		FILE_SCAN_METADATA_BLACKLIST,
		FILE_SCAN_FILE_NOT_EXIST
	};

	enum EMMapScanCheatCodes : uint8_t
	{
		MANUAL_MAP_SCAN_ERROR_NONE,
		MANUAL_MAP_SCAN_UNVALIDATED_MODULE,
		MANUAL_MAP_SCAN_CORRUPTED_IMAGE,
		MANUAL_MAP_SCAN_MODULE_LIST_NULL,
		MANUAL_MAP_SCAN_UNKNOWN_REGION_BASE,
		MANUAL_MAP_SCAN_COW_DETECT,
		MANUAL_MAP_SCAN_UNKNOWN_OWNER_NAME,
		MANUAL_MAP_SCAN_HIDDEN_VAD,
		MANUAL_MAP_SCAN_HIGH_SIZE_BLOCK,
		MANUAL_MAP_SCAN_UNACCESSIBLE_PE_HEADER,
		MANUAL_MAP_SCAN_CLEARED_PE_HEADER,
		MANUAL_MAP_SCAN_SUSPICIOUS_MODULE,
		MANUAL_MAP_SCAN_UNLINKED_MODULE,
		MANUAL_MAP_SCAN_BLACKLISTED_PATTERN,
		MANUAL_MAP_SCAN_SECTION_LIST_NULL
	};

};
