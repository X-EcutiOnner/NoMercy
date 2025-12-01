cmake_minimum_required(VERSION 3.8)
project(R3CoreEngine)
set(EXE_NAME "R3CoreEngine_x${PLATFORM_NAME_STR}")

add_definitions(-DNOMINMAX)
add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-DPSAPI_VERSION=1)
add_definitions(-DSTRICT_TYPED_ITEMIDS)
add_definitions(-D_WIN32_DCOM)

file(GLOB LIB_HEADERS
	"${PROJECT_SOURCE_DIR}/include/*.h"
	"${PROJECT_SOURCE_DIR}/include/WMI/*.hpp"
	"${PROJECT_SOURCE_DIR}/include/*.hpp"
	"${PROJECT_SOURCE_DIR}/../../../extern/include/mini-printf/*.h"
)
file(GLOB LIB_SOURCES
	"${PROJECT_SOURCE_DIR}/src/Common/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/DigitalSignature/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/Hwid/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/Syscall/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/System/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/WinAPI/*.cpp"
	"${PROJECT_SOURCE_DIR}/src/*.cpp"
	"${PROJECT_SOURCE_DIR}/../../../extern/include/mini-printf/*.cpp"
)
file(GLOB LIB_ASSEMBLYS
	"${PROJECT_SOURCE_DIR}/*.asm"
)

add_library(${EXE_NAME}
	STATIC
	${LIB_SOURCES}
	${LIB_HEADERS}
	${LIB_ASSEMBLYS}
)

set_source_files_properties(
	${LIB_ASSEMBLYS}
    PROPERTIES
    COMPILE_FLAGS "/safeseh"
)

target_compile_options(${EXE_NAME} PRIVATE "/Zi")   
target_compile_options(${EXE_NAME} PRIVATE "/Ob0")   
target_compile_options(${EXE_NAME} PRIVATE "/Od")   
target_compile_options(${EXE_NAME} PRIVATE "/RTC1")   

set_property(TARGET ${EXE_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${EXE_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${EXE_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

target_precompile_headers(${EXE_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include/PCH.hpp)

if (ENABLE_STATIC_ANALYSIS)
	pvs_studio_add_target(
		TARGET r3core_engine.analyze ALL
		OUTPUT FORMAT errorfile
		ANALYZE ${EXE_NAME}
		LOG r3core_engine_analysis.err
	)
endif()

SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES LINK_FLAGS "/LARGEADDRESSAWARE")

target_link_libraries(${EXE_NAME} dbghelp)
