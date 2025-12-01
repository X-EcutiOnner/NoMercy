cmake_minimum_required(VERSION 3.2)
project(PatchUploader CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ../..)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-DNOMINMAX)
add_definitions(-DFMT_HEADER_ONLY) # fmt
add_definitions(-DUMDF_USING_NTSTATUS) # ntstatus.h(66,1): warning C4005: 'STATUS_WAIT_0': macro redefinition / winnt.h(2510): message : see previous definition of 'STATUS_WAIT_0'
add_definitions(-DCRYPTOPP_ENABLE_NAMESPACE_WEAK=1) # cryptopp

include_directories(${PROJECT_SOURCE_DIR}/../../include)
include_directories(${PROJECT_SOURCE_DIR}/../../include/phnt)
link_directories(${PROJECT_SOURCE_DIR}/../../lib_x86)
link_directories(${PROJECT_SOURCE_DIR}/../../lib_x86/aws)
link_directories(${PROJECT_SOURCE_DIR}/../../lib_x86/ziplib)

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

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MT_BUILD}")
endif()

file(GLOB APP_HEADERS
	"${PROJECT_SOURCE_DIR}/../../include/mini-printf/*.h"
	"${PROJECT_SOURCE_DIR}/include/*.hpp"
)
file(GLOB APP_SOURCES
	"${PROJECT_SOURCE_DIR}/../../include/mini-printf/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/*.cpp"
)
add_executable(${PROJECT_NAME}
	${APP_HEADERS}
	${APP_SOURCES}
)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug") 
	set(EXTRA_LIBS ${EXTRA_LIBS}
		lz4d
		cryptopp_staticd
		xxhashd
		pthreadVCE3d mbedcryptod mbedtlsd libsshd
		libcryptod libssld
		zlibd lz4d ZipLibd lzmad bzip2d
		libcurld cprd
		aws-c-authd aws-c-cald aws-c-commond aws-c-compressiond aws-c-event-streamd aws-checksumsd aws-c-httpd aws-c-iod aws-c-mqttd aws-c-s3d
		aws-cpp-sdk-cored aws-cpp-sdk-s3d aws-crt-cppd aws-cpp-sdk-transferd
	)
else()
	set(EXTRA_LIBS ${EXTRA_LIBS}
		lz4
		cryptopp_static
		xxhash
		pthreadVCE3 mbedcrypto mbedtls libssh
		libcrypto libssl
		zlib lz4 ZipLib lzma bzip2
		libcurl cpr
		aws-c-auth aws-c-cal aws-c-common aws-c-compression aws-c-event-stream aws-checksums aws-c-http aws-c-io aws-c-mqtt aws-c-s3
		aws-cpp-sdk-core aws-cpp-sdk-s3 aws-crt-cpp aws-cpp-sdk-transfer
	)
endif()

target_link_libraries(${PROJECT_NAME} crypt32 dbghelp ws2_32 winhttp wininet userenv secur32 ncrypt shlwapi version ${EXTRA_LIBS})
