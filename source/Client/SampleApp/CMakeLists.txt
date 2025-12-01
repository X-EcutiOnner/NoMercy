cmake_minimum_required(VERSION 3.8)
project(SampleApp)
set(EXE_NAME "NoMercy_Sample_x${PLATFORM_NAME_STR}${DEBUG_POSTFIX}")
add_definitions(-D__OUTPUT__="${EXE_NAME}.exe")

add_definitions(-DNOMINMAX)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)

# Project files
file(GLOB SOURCE_FILE_LIST
	"${PROJECT_SOURCE_DIR}/src/main.cpp"
)
set(RESOURCE_FILE_LIST
	"${PROJECT_SOURCE_DIR}/../../Core/EngineR3_Core/resource.rc"
)

add_executable(${EXE_NAME}
#	WIN32
	${SOURCE_FILE_LIST}
	${RESOURCE_FILE_LIST}
)

# Only add ResourceHacker step if tool and license file exist at configure time
set(_res_hacker_path "${CMAKE_SOURCE_DIR}/extern/bin/ResourceHacker.exe")
set(_eula_path "${CMAKE_SOURCE_DIR}/document/license_files/EULA.txt")
if(EXISTS "${_res_hacker_path}" AND EXISTS "${_eula_path}")
	add_custom_command(TARGET ${EXE_NAME}
		POST_BUILD
		WORKING_DIRECTORY ${OUTPUT_DIR}
		COMMAND ${CMAKE_COMMAND} -E echo "Adding RCDATA resource via ResourceHacker"
		COMMAND ${_res_hacker_path} -open ${OUTPUT_DIR}/${EXE_NAME}.exe -save ${OUTPUT_DIR}/${EXE_NAME}.exe -action add -mask RCDATA,9092,1033 -resource ${OUTPUT_DIR}/../document/license_files/EULA.txt
	)
else()
	add_custom_command(TARGET ${EXE_NAME}
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E echo "Warning: ResourceHacker or EULA not found; skipping resource embed step"
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

target_link_libraries(${EXE_NAME} "NoMercy_Module_x${PLATFORM_NAME_STR}${DEBUG_POSTFIX}" ${BIN_EXTRA_LIBS})

SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator'\" /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE")