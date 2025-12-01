# Top project settings 
cmake_minimum_required(VERSION 3.8 FATAL_ERROR)
project(NoMercyLite)

message(STATUS "CMake version: ${CMAKE_VERSION}")

# Default build type 
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
		"Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
	set(DEBUG_POSTFIX "_d")
endif()

# Maximum error level
#set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Branch name: ${BRANCH_NAME}")
message(STATUS "CI Build: ${CI_BUILD}")

if (MSVC)
	message(STATUS "MSVC: ${MSVC_VERSION}")
endif()

# Version
file (STRINGS "VERSION.txt" MAJOR_VERSION)

# Build options
option(BUILD_UTILITIES "Build the common utilities" ON)
option(BUILD_CLIENT "Build the client binaries" ON)
option(ENABLE_STATIC_ANALYSIS "Enable static code analysis with PVS Studio" OFF)
option(ENABLE_AUTO_RELEASE "Enable auto release create in git repo" OFF)
option(ENABLE_AUTO_PROTECT "Protect public executables after than build" ON)

option(TEST_MODE "Enable test mode" OFF)
option(RELEASE_DEBUG_MODE "Enable debugging in release mode" OFF)
option(CLOSE_GAME_ON_EXIT "Close game when exit func is triggered" ON)
option(BLOCK_CONSOLE_WINDOW "Block console window allocation" OFF)
option(ALLOW_VIRTUAL_ENVIRONMENT "Allow run on virtual environment" OFF)
option(WEBSOCKET_USE_SSL "Use SSL (TLS) connection in websocket client" ON)
option(ALWAYS_DEBUG_LOGS "Enable always log debug logs" ON)
option(SIGN_BINARY "Enable binary signings" OFF)

if (BRANCH_NAME) # CI Build
	add_definitions(-DBRANCH_NAME=${BRANCH_NAME})
else()
	add_definitions(-DBRANCH_NAME=dev)
endif()
if ("${BRANCH_NAME}" STREQUAL "dev")
	set(RING3_ONLY_MODE OFF)
endif()

if (RING3_ONLY_MODE)
	set(TEST_MODE OFF)
	add_definitions(-DRING3_ONLY_MODE)
endif()


if(EXISTS "C:\\Users\\Koray" AND "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
	set(RELEASE_DEBUG_MODE ON)
	set(ENABLE_AUTO_PROTECT OFF)
endif()

if (RELEASE_DEBUG_MODE)
	add_definitions(-D_RELEASE_DEBUG_MODE_)
endif()
#if (RELEASE_DEBUG_MODE AND "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
#	add_definitions(-DBYPASS_NOMERCY_SYSTEM_PATH)
#endif()

if (TEST_MODE)
	add_definitions(-DTEST_MODE=TRUE)
else()
	add_definitions(-DTEST_MODE=FALSE)
endif()
if (CLOSE_GAME_ON_EXIT)
	add_definitions(-DCLOSE_GAME_ON_EXIT=TRUE)
else()
	add_definitions(-DCLOSE_GAME_ON_EXIT=FALSE)
endif()
if (BLOCK_CONSOLE_WINDOW)
	add_definitions(-DBLOCK_CONSOLE_WINDOW=TRUE)
else()
	add_definitions(-DBLOCK_CONSOLE_WINDOW=FALSE)
endif()
if (ALLOW_VIRTUAL_ENVIRONMENT)
	add_definitions(-DALLOW_VIRTUAL_ENVIRONMENT=TRUE)
else()
	add_definitions(-DALLOW_VIRTUAL_ENVIRONMENT=FALSE)
endif()
if (WEBSOCKET_USE_SSL)
	add_definitions(-DWEBSOCKET_USE_SSL=TRUE)
else()
	add_definitions(-DWEBSOCKET_USE_SSL=FALSE)
endif()
if (ALWAYS_DEBUG_LOGS)
	add_definitions(-DDEBUG_LOGS_DEBUG_BUILD_ONLY=FALSE)
else()
	add_definitions(-DDEBUG_LOGS_DEBUG_BUILD_ONLY=TRUE)
endif()

add_definitions(-DNOMERCY_CDB_VERSION=1)
add_definitions(-DNOMERCY_FILE_CRYPT_VERSION=1)
add_definitions(-DNOMERCY_GAME_DATA_VERSION=1)
add_definitions(-DNOMERCY_GAME_INTEGRATION_VERSION=1)
add_definitions(-DNOMERCY_DATA_VERSION=1)
add_definitions(-DNOMERCY_HWID_VERSION=1)
add_definitions(-DNOMERCY_WS_API_VERSION=1)
add_definitions(-DNOMERCY_LOGGER_API_VERSION=1)

add_definitions(-DNOMERCY_WS_CUSTOM_CRYPT=1)

set(PROTECTOR_NAME "themida")
add_definitions(-DUSE_THEMIDA_SDK=1)

#set(PROTECTOR_NAME "vmprotect")
#add_definitions(-DUSE_VMPROTECT_SDK=1)

# Output dir
set(OUTPUT_DIR ${PROJECT_SOURCE_DIR}/Bin)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL ${OUTPUT_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO ${OUTPUT_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${OUTPUT_DIR})

set(PDB_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(PDB_OUTPUT_DIRECTORY_DEBUG ${OUTPUT_DIR})
set(PDB_OUTPUT_DIRECTORY_RELEASE ${OUTPUT_DIR})
set(PDB_OUTPUT_DIRECTORY_MINSIZEREL ${OUTPUT_DIR})
set(PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO ${OUTPUT_DIR})

# Colored output configration
SET(CMAKE_COLOR_MAKEFILE ON)

# C++ options
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global definations
add_definitions(-DUMDF_USING_NTSTATUS) # ntstatus.h(66,1): warning C4005: 'STATUS_WAIT_0': macro redefinition / winnt.h(2510): message : see previous definition of 'STATUS_WAIT_0'
add_definitions(-DJM_XORSTR_DISABLE_AVX_INTRINSICS) # xorstr
add_definitions(-DCRYPTOPP_ENABLE_NAMESPACE_WEAK=1) # cryptopp
add_definitions(-DLAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS) # lazy_importer
add_definitions(-DASIO_STANDALONE) # websocketpp
add_definitions(-D_WEBSOCKETPP_CPP11_STL_) # websocketpp
add_definitions(-DFMT_HEADER_ONLY) # fmt
add_definitions(-DPHNT_NO_INLINE_INIT_STRING) # phnt - lazy_import incompability
add_definitions(-DPHNT_VERSION=PHNT_WINXP) # add_definitions(-DPHNT_VERSION=PHNT_WIN7) # phnt
add_definitions(-DSPDLOG_NO_TLS) # spdlog
add_definitions(-DSQLITE_HAS_CODEC) # sqlite3
add_definitions(-DSODIUM_STATIC) # libsodium
add_definitions(-DSENTRY_BUILD_STATIC=1) # sentry
add_definitions(-DPROMISE_HEADONLY) # promise-cpp
add_definitions(-DZYCORE_STATIC_BUILD) # Zycore
add_definitions(-DZYDIS_STATIC_BUILD) # Zydis
add_definitions(-DSERDEPP_USE_RAPIDJSON=ON) # serdepp
add_definitions(-DRAPIDJSON_HAS_STDSTRING=1) # serdepp
add_definitions(-DCXXOPTS_WCHAR) # cxxopts
add_definitions(-DLIBZIPPP_WITH_ENCRYPTION) # libzippp
add_definitions(-DZIP_CM_BZIP2) # libzippp

# Disabled global warnings
add_definitions(-D_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING)

# Platform defination
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_definitions(-DNM_PLATFORM=64)
	set(PLATFORM_NAME_STR "64")
	set(PLATFORM_NUM 64)
else() 
	add_definitions(-DNM_PLATFORM=86)
	set(PLATFORM_NAME_STR "86")
	set(PLATFORM_NUM 86)
endif()

# Languages
enable_language(ASM_MASM)
enable_language(RC)

# Git
# Function to get Git commit hash
function(get_git_hash _git_hash)
    execute_process(
        COMMAND git rev-parse --short HEAD
        OUTPUT_VARIABLE _git_hash_val
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    if(NOT _git_hash_val)
        set(${_git_hash} "unknown" PARENT_SCOPE)
    else()
        set(${_git_hash} "${_git_hash_val}" PARENT_SCOPE)
    endif()
endfunction()

# Get git hash
get_git_hash(GIT_HASH)

# Initialize version variable
set(BUILD_VERSION "unknown")

# Check CI environments in order of preference
if(DEFINED ENV{GITHUB_RUN_NUMBER})
    # GitHub Actions
    set(BUILD_VERSION $ENV{GITHUB_RUN_NUMBER})
    set(CI_SYSTEM "GitHub")
elseif(DEFINED ENV{CI_PIPELINE_ID})
    # GitLab CI
    set(BUILD_VERSION $ENV{CI_PIPELINE_ID})
    set(CI_SYSTEM "GitLab")
elseif(DEFINED ENV{BUILD_NUMBER})
    # Jenkins
    math(EXPR BUILD_VERSION "$ENV{BUILD_NUMBER}+25000")
    set(CI_SYSTEM "Jenkins")
else()
    # Local build - use timestamp as fallback
    #string(TIMESTAMP BUILD_VERSION "%Y%m%d%H%M" UTC)
    set(BUILD_VERSION 69)
    set(CI_SYSTEM "Local")
endif()

# Set the GitREV variable
set(GitREV "${BUILD_VERSION}-${GIT_HASH}")

# Output the results
message(STATUS "Build System: ${CI_SYSTEM}")
message(STATUS "Build Version: ${BUILD_VERSION}")
message(STATUS "Git Hash: ${GIT_HASH}")
message(STATUS "GitREV=${GitREV}")

add_definitions(-D_GIT_VERSION_=${BUILD_VERSION})
if (WIN32)
	add_definitions(-D_HOSTNAME_="${USERNAME}")
else()
	add_definitions(-D_HOSTNAME_="${HOSTNAME}")
endif()
add_definitions(-D_DIRECTORY_="${CMAKE_SOURCE_DIR}")

add_definitions(-D__MAJOR_VERSION__="${MAJOR_VERSION}")
add_definitions(-D__PRODUCT_VERSION__="${MAJOR_VERSION}.${BUILD_VERSION}")
add_definitions(-D__FILE_VERSION__=${MAJOR_VERSION},${BUILD_VERSION},0,0)
add_definitions(-D__NOMERCY_VERSION__=${MAJOR_VERSION}${BUILD_VERSION})

# CMake modules
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/extern/cmake")
include(${CMAKE_MODULE_PATH}/DetectOS.cmake)
if (ENABLE_STATIC_ANALYSIS)
	include(${CMAKE_MODULE_PATH}/PVS-Studio.cmake)
endif()

# WDK
SET(WDK_NOMERCY_FILE "NoMercy_SystemModule_${HOST_PLATFORM}")
SET(WDK_NOMERCY_CAT_FILE "NoMercy_${HOST_PLATFORM}.cat")
SET(WDK_NOMERCY_VERSION "${MAJOR_VERSION}.${gitVersion}")

find_package(WDK REQUIRED)

set(OPENSSL_EXE "C:/Program Files/Git/usr/bin/openssl.exe")
set(WINDDK ${WDK_ROOT}/bin/${WDK_VERSION}/x${PLATFORM_NAME_STR})

# MSVC specific build configrations
if(MSVC)
	set(LIB_RT_SUFFIX "mt")
	set(LIB_RT_OPTION "/MT")

	foreach(flag_var  CMAKE_C_FLAGS  CMAKE_CXX_FLAGS)
		 foreach(config_name  ""  DEBUG  RELEASE  MINSIZEREL  RELWITHDEBINFO)
			set(var_name "${flag_var}")

			if(NOT "${config_name}" STREQUAL "")
				set(var_name "${var_name}_${config_name}")
			endif()
			
			string(REPLACE "/MD" "${LIB_RT_OPTION}" ${var_name} "${${var_name}}")
			set(${var_name} "${${var_name}}" CACHE STRING "" FORCE)
		endforeach()
	endforeach()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")

	if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	else()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
	endif()

	set(WARNINGS_DISABLE
		# ignore
		4100 # unreferenced formal parameter
#		4172 # returning address of local variable or temporary: szSymbolName
		4189 # wow64pp.hpp(843): warning C4189: 'fn_ret': local variable is initialized but not referenced
		4191 # DynamicWinAPI.cpp(912,178): warning C4191: '<function-style-cast>': unsafe conversion from 'FARPROC' to 'DWORD (__stdcall *)(HANDLE)'
		4201 # phnt\ntldr.h(649): warning C4201: nonstandard extension used: nameless struct/union
#		4273 # 'NoMercy::NM_Initialize' ... : inconsistent dll linkage
		4302 # wow64pp.hpp(688): warning C4302: 'reinterpret_cast': truncation from 'uint32_t *' to 'uint32_t'
#		4311 # wow64pp.hpp(688): warning C4311: 'reinterpret_cast': pointer truncation from 'uint32_t *' to 'uint32_t'
#		4312 # wow64pp.hpp(359): warning C4312: 'reinterpret_cast': conversion from 'uint32_t' to 'const void *' of greater size
		4324 # phnt\ntlpcapi.h(438,57): warning C4324: '_ALPC_COMPLETION_LIST_HEADER': structure was padded due to alignment specifier
		4505 # unreferenced local function has been removed
		4804 # ProcessHelper.cpp(864,5): warning C4804: '<': unsafe use of type 'bool' in operation
	)

	foreach(d ${WARNINGS_DISABLE})
		set(WARNINGS "${WARNINGS} /wd${d}")
	endforeach(d)

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNINGS} ${MT_BUILD}")

	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /FORCE:MULTIPLE /ignore:4099") 
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /FORCE:MULTIPLE /ignore:4099") 
	set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /ignore:4099") 
endif()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug") 
	set(BIN_EXTRA_LIBS
		crypt32 libcryptod libssld # OpenSSL (Required by ASIO)
		sqlite3d
		Zycored Zydisd
	)
else()
	set(BIN_EXTRA_LIBS
		crypt32 libcrypto libssl
		sqlite3
		Zycore Zydis
	)
endif()

# Check build modes
if("${BUILD_CLIENT}" STREQUAL "OFF" AND "${BUILD_UTILITIES}" STREQUAL "OFF")
	message(FATAL_ERROR "Nothing to build")
endif()

# Register include directories
include_directories(${PROJECT_SOURCE_DIR}/extern/include)
include_directories(${PROJECT_SOURCE_DIR}/extern/include/crashpad)
include_directories(${PROJECT_SOURCE_DIR}/extern/include/phnt)
include_directories(${PROJECT_SOURCE_DIR}/extern/protectors/Themida)
include_directories(${PROJECT_SOURCE_DIR}/extern/protectors/VMProtect)

# Register lib directory
link_directories(${PROJECT_SOURCE_DIR}/extern/lib_x${PLATFORM_NAME_STR})
link_directories(${PROJECT_SOURCE_DIR}/extern/lib_x${PLATFORM_NAME_STR}/ziplib)

# Register sub project paths
add_subdirectory(${PROJECT_SOURCE_DIR}/source/Utilities)
add_subdirectory(${PROJECT_SOURCE_DIR}/source/Core)
add_subdirectory(${PROJECT_SOURCE_DIR}/source/Client)
