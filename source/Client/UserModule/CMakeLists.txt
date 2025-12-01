cmake_minimum_required(VERSION 3.8)
project(DynamicModule)
set(EXE_NAME "NoMercy_Module_x${PLATFORM_NAME_STR}${DEBUG_POSTFIX}")
add_definitions(-D__OUTPUT__="${EXE_NAME}.dll")

add_definitions(-DNOMINMAX)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-DNOMERCY_EXPORTS)

file(GLOB MODULE_HEADERS
	"${PROJECT_SOURCE_DIR}/include/*.h"
)
file(GLOB MODULE_SOURCES
	"${PROJECT_SOURCE_DIR}/src/*.cpp"
)
set(MODULE_RESOURCES
	"${PROJECT_SOURCE_DIR}/../../Core/EngineR3_Core/resource.rc"
)

add_library(${EXE_NAME}
	SHARED
	${MODULE_SOURCES}
	${MODULE_HEADERS}
	${MODULE_RESOURCES}
#	"${PROJECT_SOURCE_DIR}/definitions.def"
)

# Manifest
#if (NOT "${PROTECTOR_NAME}" STREQUAL "themida")
	add_custom_command(
		TARGET ${EXE_NAME}
		POST_BUILD
		COMMAND "mt.exe" -manifest \"${PROJECT_SOURCE_DIR}/SupportedOS.manifest\" -outputresource:"$(TargetDir)$(TargetFileName)"\;\#1
		COMMENT "Adding manifest..." 
	)
#endif()

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
		# zlibd lz4d ZipLibd lzmad bzip2d
		zlibd lz4d bz2d zipd libzipppd
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
		# zlib lz4 ZipLib lzma bzip2
		zlib lz4 bz2 zip libzippp
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

# Protection
# if (ENABLE_AUTO_PROTECT AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND NOT RELEASE_DEBUG_MODE AND "${BRANCH_NAME}" STREQUAL "live")
if (ENABLE_AUTO_PROTECT AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND NOT RELEASE_DEBUG_MODE)
	# RTTI obfuscator
	set(OBFUSCATOR_NAME "${OUTPUT_DIR}/../Bin/NoMercyProtector.exe")

	add_custom_command(
		TARGET ${EXE_NAME}
		POST_BUILD

		COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.dll ${OUTPUT_DIR}/${EXE_NAME}_non_rtti.dll.bak
		COMMAND ${CMAKE_COMMAND} -E echo "OBFUSCATING: ${OBFUSCATOR_NAME} -i ${OUTPUT_DIR}/${EXE_NAME}.dll -o ${OUTPUT_DIR}/${EXE_NAME}.dll"
		COMMAND ${OBFUSCATOR_NAME} -i ${OUTPUT_DIR}/${EXE_NAME}.dll -o ${OUTPUT_DIR}/${EXE_NAME}.dll
	)

	if ("${PROTECTOR_NAME}" STREQUAL "themida")

		# Themida
		if (CMAKE_SIZEOF_VOID_P EQUAL 8)
			set(PROTECTOR_NAME "Themida/Themida64.exe")
		else()
			set(PROTECTOR_NAME "Themida/Themida.exe")
		endif()

		add_custom_command(
			TARGET ${EXE_NAME}
			POST_BUILD

			COMMAND ${CMAKE_COMMAND} -E echo "PROTECTING: ${OUTPUT_DIR}/../Bin_public/.protector/${PROTECTOR_NAME} /protect ${OUTPUT_DIR}/../Bin_public/.protector/module_template.tmd /inputfile ${OUTPUT_DIR}/${EXE_NAME}.dll /outputfile ${OUTPUT_DIR}/${EXE_NAME}.dll /shareconsole"
			COMMAND ${OUTPUT_DIR}/../Bin_public/.protector/${PROTECTOR_NAME} /protect ${OUTPUT_DIR}/../Bin_public/.protector/module_template.tmd /inputfile ${OUTPUT_DIR}/${EXE_NAME}.dll /outputfile ${OUTPUT_DIR}/${EXE_NAME}.dll /shareconsole
		)

	elseif ("${PROTECTOR_NAME}" STREQUAL "vmprotect")

		# VMProtect
		set(PROTECTOR_NAME "VMProtect/VMProtect_Con.exe")

		add_custom_command(
			TARGET ${EXE_NAME}
			POST_BUILD

			COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.dll ${OUTPUT_DIR}/${EXE_NAME}.dll.bak
			COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/../extern/cert/rest/NoMercy.crt ${OUTPUT_DIR}/NoMercy.crt
			COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/../extern/cert/rest/NoMercy.key ${OUTPUT_DIR}/NoMercy.key
			COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/../extern/cert/rest/NoMercy.pfx ${OUTPUT_DIR}/NoMercy.pfx
			COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/../Bin_public/.protector/NoMercy_Module_x86.dll.vmp ${OUTPUT_DIR}/NoMercy_Module_x86.dll.vmp
			COMMAND ${CMAKE_COMMAND} -E echo "DIR: ${OUTPUT_DIR}"
			WORKING_DIRECTORY ${OUTPUT_DIR}
			COMMAND ${CMAKE_COMMAND} -E echo "PROTECTING: ${OUTPUT_DIR}/../Bin_public/.protector/${PROTECTOR_NAME} ${OUTPUT_DIR}/NoMercy_Module_x86.dll.vmp"
			COMMAND ${OUTPUT_DIR}/../Bin_public/.protector/${PROTECTOR_NAME} ${OUTPUT_DIR}/NoMercy_Module_x86.dll.vmp
		)

	endif()

endif()

# Sign
if (SIGN_BINARY)
	add_custom_command(
		TARGET ${EXE_NAME}
		POST_BUILD
		COMMENT "Signing ${EXE_NAME}.dll with ${OUTPUT_DIR}/../extern/cert/nomercy_bin/nomercy_bin.pfx"
		COMMAND "${WINDDK}/signtool.exe" sign /fd SHA1 /a /f ${OUTPUT_DIR}/../extern/cert/nomercy_bin/nomercy_bin.pfx /p "jvYewT8J9kWQU2" ${OUTPUT_DIR}/${EXE_NAME}.dll
	)
endif()

if (NOT PROXY_DLL)
	# File forward
	add_custom_command(TARGET ${EXE_NAME}
		PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}"
		COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb"
		COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/SDK"
	)
	add_custom_command(TARGET ${EXE_NAME}
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E echo "LINKING: ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.dll ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/${EXE_NAME}.dll"
		COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.dll ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/${EXE_NAME}.dll
		COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.pdb ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb/${EXE_NAME}.pdb
		COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${EXE_NAME}.dll ${OUTPUT_DIR}/../Bin_public/.debug/${EXE_NAME}.dll
	)
endif()

# Git release
if (ENABLE_AUTO_RELEASE)
	add_custom_command(
		TARGET ${EXE_NAME}
		POST_BUILD

		COMMAND git tag -f -a ${MAJOR_VERSION}.${gitVersion} -m \"Automated post-build release\" dev
		COMMAND git push -f --tags
	)
endif()

# Link
target_link_libraries(${EXE_NAME}
	"R3Engine_x${PLATFORM_NAME_STR}" "TLSEngine_x${PLATFORM_NAME_STR}"
	${EXTRA_LIBS} ${BIN_EXTRA_LIBS}
)

# Enable map file output & handle large addresses
SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES LINK_FLAGS "/MAP /LARGEADDRESSAWARE")
