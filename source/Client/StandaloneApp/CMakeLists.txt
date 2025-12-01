cmake_minimum_required(VERSION 3.8)
project(StandaloneApp)
set(EXE_NAME "NoMercy_Standalone_x${PLATFORM_NAME_STR}${DEBUG_POSTFIX}")

add_definitions(-DNOMINMAX)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)

# Project files
set(HEADER_FILE_LIST
)
set(SOURCE_FILE_LIST
	${PROJECT_SOURCE_DIR}/src/main.cpp
)

add_executable(${EXE_NAME}
	WIN32
	${HEADER_FILE_LIST}
	${SOURCE_FILE_LIST}
)

# External libraries
set(EXTRA_LIBS
	crypt32
	dbghelp
	imagehlp
	iphlpapi
	FltLib
	gdiplus
	mpr
	Netapi32
	ntdll
	shlwapi
	tdh
	wininet
	ws2_32
	wintrust
	wbemuuid
	wer
	winmm
	winhttp
	windowscodecs
	wtsapi32
	Wldap32
	userenv
	version
)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug") 
	set(EXTRA_LIBS ${EXTRA_LIBS}
		zlibd lz4d ZipLibd lzmad bzip2d
		bz2d zipd libzipppd
		cryptopp_staticd
		xxhashd
		libssld libcurld cprd
		minhookd
		jansson_d libyarad yaracppd
		SecureEngineSDK
		# python27d
		tlshd
		libsodiumd
		crashpad/crashpad_clientd crashpad/crashpad_utild crashpad/mini_chromiumd crashpad/sentryd
	)
else()
	set(EXTRA_LIBS ${EXTRA_LIBS}
		zlib lz4 ZipLib lzma bzip2
		bz2 zip libzippp
		cryptopp_static
		xxhash
		libssl libcurl cpr
		minhook
		jansson libyara yaracpp
		SecureEngineSDK
		# python27
		tlsh
		libsodium
		crashpad/crashpad_client crashpad/crashpad_util crashpad/mini_chromium crashpad/sentry
	)
endif()

add_custom_command(TARGET ${EXE_NAME}
	PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Priv"
)
add_custom_command(TARGET ${EXE_NAME}
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E echo "LINKING: ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.exe ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/${EXE_NAME}.exe"
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.exe ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Priv/${EXE_NAME}.exe
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.pdb ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb/${EXE_NAME}.pdb
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.exe ${OUTPUT_DIR}/../Bin_public/.debug/${EXE_NAME}.exe
)

target_link_libraries(${EXE_NAME} "R3Engine_x${PLATFORM_NAME_STR}" "TLSEngine_x${PLATFORM_NAME_STR}" ${EXTRA_LIBS} ${BIN_EXTRA_LIBS})

SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator'\" /LARGEADDRESSAWARE")
