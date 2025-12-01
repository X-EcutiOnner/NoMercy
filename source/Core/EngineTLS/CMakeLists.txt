cmake_minimum_required(VERSION 3.8)
project(TLSEngine)
set(EXE_NAME "TLSEngine_x${PLATFORM_NAME_STR}")

file(GLOB MODULE_HEADERS
	"${PROJECT_SOURCE_DIR}/include/*.h"
	"${PROJECT_SOURCE_DIR}/include/*.hpp"
)
file(GLOB MODULE_SOURCES
	"${PROJECT_SOURCE_DIR}/src/*.cpp"
	"${PROJECT_SOURCE_DIR}/../EngineR3_Core/src/Cleancall.cpp"
)

add_library(${EXE_NAME}
	STATIC
	${MODULE_SOURCES}
	${MODULE_HEADERS}
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
		TARGET tls_engine.analyze ALL
		OUTPUT FORMAT errorfile
		ANALYZE ${EXE_NAME}
		LOG tls_engine_analysis.err
	)
endif()
